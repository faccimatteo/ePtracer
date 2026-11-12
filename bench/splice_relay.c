/*
 * splice_relay — a TCP relay driving src/tracers/tls_splice.c, for the
 * end-to-end test (bench/e2e_splice.py) and the latency bench.
 *
 * It sits where the ePtracer interceptor sits (the kernel redirect is replaced
 * by the client simply connecting here) and takes the session secrets from an
 * NSS keylog file, the stand-in for the eBPF key capture: the file is re-read
 * whenever the splice asks for keys, which is how the ring buffer consumer will
 * be drained in the real thing.
 *
 *   splice_relay --upstream PORT --keylog FILE
 *                [--edit-c2s FROM=TO] [--edit-s2c FROM=TO] [--split-c2s]
 *                [--plain-log] [--once]
 *
 * --edit-*  intercept that direction and replace FROM with TO in every record
 *           (what Burp's Match & Replace does once the bridge is in place);
 * --split-c2s  re-send every client record as two records, so the sequence
 *           numbers of the two legs diverge and translation is exercised;
 * --plain-log  print the decrypted plaintext of both directions to stderr;
 * --once       exit after the first connection (tests wait for the stats).
 *
 * Prints "PORT n" on stdout once listening; serves connections one at a time.
 */

#include "tls_keys.h"
#include "tls_splice.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct relay {
	int client_fd, server_fd;
	struct tls_splice *s;
	const char *keylog;
	const char *edit_from[2], *edit_to[2];
	int split_c2s;
	int plain_log;
	int once;
};

static int write_all(int fd, const uint8_t *b, size_t n)
{
	while (n) {
		ssize_t w = write(fd, b, n);
		if (w <= 0)
			return -1;
		b += w;
		n -= (size_t)w;
	}
	return 0;
}

static int hook_forward(void *user, enum splice_dir to, const uint8_t *b, size_t n)
{
	struct relay *r = user;
	return write_all(to == SPLICE_C2S ? r->server_fd : r->client_fd, b, n);
}

static void hook_need_keys(void *user)
{
	struct relay *r = user;
	tls_keys_load_keylog_file(0, r->keylog);
}

/* replace every occurrence of from with to; returns a malloc'd buffer */
static uint8_t *replace_all(const uint8_t *in, size_t len, const char *from,
			    const char *to, size_t *out_len)
{
	size_t fl = strlen(from), tl = strlen(to);
	uint8_t *out = malloc(len * (tl > fl ? tl / (fl ? fl : 1) + 2 : 1) + 1);
	size_t o = 0;
	for (size_t i = 0; i < len;) {
		if (fl && i + fl <= len && memcmp(in + i, from, fl) == 0) {
			memcpy(out + o, to, tl);
			o += tl;
			i += fl;
		} else {
			out[o++] = in[i++];
		}
	}
	*out_len = o;
	return out;
}

static void hook_plaintext(void *user, enum splice_dir dir, uint8_t inner,
			   const uint8_t *b, size_t n)
{
	struct relay *r = user;

	if (r->plain_log && inner == TLS_CT_APPLICATION_DATA)
		fprintf(stderr, "[splice %s %zu B]\n%.*s\n",
			dir == SPLICE_C2S ? "c2s" : "s2c", n, (int)n, (const char *)b);

	if (!r->edit_from[dir])
		return;   /* passthrough direction: notification only */

	/* intercepted direction: we must send it back ourselves */
	size_t ol = n;
	uint8_t *edited = NULL;
	const uint8_t *payload = b;
	if (inner == TLS_CT_APPLICATION_DATA) {
		edited = replace_all(b, n, r->edit_from[dir], r->edit_to[dir], &ol);
		payload = edited;
	}

	if (dir == SPLICE_C2S && r->split_c2s && inner == TLS_CT_APPLICATION_DATA && ol > 1) {
		size_t half = ol / 2;
		tls_splice_send(r->s, dir, inner, payload, half);
		tls_splice_send(r->s, dir, inner, payload + half, ol - half);
	} else {
		tls_splice_send(r->s, dir, inner, payload, ol);
	}
	free(edited);
}

static int parse_edit(const char *arg, const char **from, const char **to)
{
	char *dup = strdup(arg), *eq = strchr(dup, '=');
	if (!eq)
		return -1;
	*eq = '\0';
	*from = dup;
	*to = eq + 1;
	return 0;
}

/* A relay that re-frames records writes them one by one: with Nagle on, the
 * second small write waits for the peer's delayed ACK (~40 ms). Both legs. */
static void nodelay(int fd)
{
	int one = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

static void serve_one(struct relay *r, int upstream_port)
{
	struct sockaddr_in sa = { .sin_family = AF_INET,
				  .sin_port = htons((uint16_t)upstream_port) };
	inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
	r->server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(r->server_fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		perror("connect upstream");
		close(r->server_fd);
		return;
	}
	nodelay(r->server_fd);
	nodelay(r->client_fd);

	unsigned mask = (r->edit_from[0] ? 1u << SPLICE_C2S : 0) |
			(r->edit_from[1] ? 1u << SPLICE_S2C : 0);
	struct tls_splice_hooks h = {
		.forward = hook_forward,
		.plaintext = hook_plaintext,
		.need_keys = hook_need_keys,
		.user = r,
	};
	r->s = tls_splice_new(0, mask, &h);

	struct pollfd p[2] = { { r->client_fd, POLLIN, 0 }, { r->server_fd, POLLIN, 0 } };
	uint8_t buf[65536];
	for (;;) {
		if (poll(p, 2, 10000) <= 0)
			break;
		int done = 0;
		for (int i = 0; i < 2; i++) {
			if (!(p[i].revents & (POLLIN | POLLHUP | POLLERR)))
				continue;
			ssize_t n = read(p[i].fd, buf, sizeof(buf));
			if (n <= 0) { done = 1; break; }
			enum splice_dir dir = i == 0 ? SPLICE_C2S : SPLICE_S2C;
			if (tls_splice_feed(r->s, dir, buf, (size_t)n) != 0) {
				fprintf(stderr, "[splice] FAILED state, closing\n");
				done = 1;
				break;
			}
		}
		if (done)
			break;
	}

	struct tls_splice_stats st;
	tls_splice_get_stats(r->s, &st);
	const char *names[] = { "HANDSHAKE", "ACTIVE", "OPAQUE", "FAILED" };
	fprintf(stderr,
		"[splice] sni=%s state=%s keyed c2s=%d s2c=%d | "
		"c2s opened=%llu verbatim=%llu resealed=%llu | "
		"s2c opened=%llu verbatim=%llu resealed=%llu\n",
		tls_splice_sni(r->s), names[tls_splice_state(r->s)],
		tls_splice_keyed(r->s, SPLICE_C2S), tls_splice_keyed(r->s, SPLICE_S2C),
		(unsigned long long)st.records_opened[0], (unsigned long long)st.records_verbatim[0],
		(unsigned long long)st.records_resealed[0],
		(unsigned long long)st.records_opened[1], (unsigned long long)st.records_verbatim[1],
		(unsigned long long)st.records_resealed[1]);

	tls_splice_free(r->s);
	close(r->server_fd);
}

int main(int argc, char **argv)
{
	struct relay r;
	memset(&r, 0, sizeof(r));
	int upstream = 0;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--upstream") && i + 1 < argc)
			upstream = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--keylog") && i + 1 < argc)
			r.keylog = argv[++i];
		else if (!strcmp(argv[i], "--edit-c2s") && i + 1 < argc)
			parse_edit(argv[++i], &r.edit_from[0], &r.edit_to[0]);
		else if (!strcmp(argv[i], "--edit-s2c") && i + 1 < argc)
			parse_edit(argv[++i], &r.edit_from[1], &r.edit_to[1]);
		else if (!strcmp(argv[i], "--split-c2s"))
			r.split_c2s = 1;
		else if (!strcmp(argv[i], "--plain-log"))
			r.plain_log = 1;
		else if (!strcmp(argv[i], "--once"))
			r.once = 1;
	}
	if (!upstream || !r.keylog) {
		fprintf(stderr, "usage: %s --upstream PORT --keylog FILE [...]\n", argv[0]);
		return 2;
	}
	if (r.split_c2s && !r.edit_from[0]) {
		/* splitting needs the direction intercepted: an identity edit */
		r.edit_from[0] = "";
		r.edit_to[0] = "";
	}

	int ls = socket(AF_INET, SOCK_STREAM, 0);
	int one = 1;
	setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	struct sockaddr_in la = { .sin_family = AF_INET };
	inet_pton(AF_INET, "127.0.0.1", &la.sin_addr);
	if (bind(ls, (struct sockaddr *)&la, sizeof(la)) != 0 || listen(ls, 16) != 0) {
		perror("listen");
		return 1;
	}
	socklen_t sl = sizeof(la);
	getsockname(ls, (struct sockaddr *)&la, &sl);
	printf("PORT %d\n", ntohs(la.sin_port));
	fflush(stdout);

	for (;;) {
		r.client_fd = accept(ls, NULL, NULL);
		if (r.client_fd < 0)
			continue;
		serve_one(&r, upstream);
		close(r.client_fd);
		if (r.once)
			return 0;
	}
}
