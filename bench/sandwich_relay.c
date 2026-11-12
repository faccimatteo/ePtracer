/*
 * sandwich_relay — drives src/tracers/splice_bridge.c for the end-to-end test
 * (bench/e2e_sandwich.py): accepts the app, connects to the real server, and
 * runs one spliced flow per connection through a Burp-style proxy.
 *
 * Keys come from the app's keylog file (stand-in for the eBPF capture); with
 * --key-delay-ms the file is ignored for that long after the first connection,
 * which reproduces a key event arriving late on the ring buffer.
 *
 *   sandwich_relay --upstream PORT --keylog FILE --proxy-port P --bridge-port B
 *                  [--strict] [--hold-ms N] [--key-delay-ms N] [--timeout-ms N]
 *
 * Prints "PORT n" once listening. Bridge decisions are logged on stderr; on
 * SIGTERM the counters are printed as a "[stats]" line.
 */

#include "splice_bridge.h"
#include "tls_keys.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static const char *keylog;
static int server_port, key_delay_ms, as_candidates;
static volatile uint64_t first_conn_ms;
static pthread_mutex_t key_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void need_keys(void *user)
{
	(void)user;
	if (key_delay_ms && now_ms() - first_conn_ms < (uint64_t)key_delay_ms)
		return;   /* the key event has not "arrived" yet */
	pthread_mutex_lock(&key_lock);
	if (!as_candidates) {
		tls_keys_load_keylog_file(0, keylog);
	} else {
		/* what the HMAC probe reports: secrets with no label, no client
		 * random, no library handle — trial decryption has to sort them */
		FILE *f = fopen(keylog, "r");
		char line[512], label[64], cr[80], hex[160];
		while (f && fgets(line, sizeof(line), f)) {
			struct tls_secret_event_t ev;
			if (sscanf(line, "%63s %79s %159s", label, cr, hex) != 3 || label[0] == '#')
				continue;
			memset(&ev, 0, sizeof(ev));
			ev.source = KEYSRC_HMAC;
			ev.secret_len = (__u8)(strlen(hex) / 2);
			for (unsigned i = 0; i < ev.secret_len; i++)
				sscanf(hex + 2 * i, "%2hhx", &ev.secret[i]);
			tls_keys_add(&ev);
		}
		if (f)
			fclose(f);
	}
	pthread_mutex_unlock(&key_lock);
}

static void log_line(void *user, const char *line)
{
	(void)user;
	fprintf(stderr, "%s\n", line);
	fflush(stderr);
}

static void on_term(int sig)
{
	(void)sig;
	struct splice_bridge_stats st;
	splice_bridge_get_stats(&st);
	fprintf(stderr, "[stats] flows=%lu requests=%lu delivered=%lu dup=%lu late=%lu "
		"unknown=%lu dropped=%lu abandoned=%lu bypassed=%lu\n",
		st.flows, st.requests, st.delivered, st.rejected_duplicate, st.rejected_late,
		st.rejected_unknown, st.dropped_by_proxy, st.abandoned, st.bypassed);
	fflush(stderr);
	_exit(0);
}

static void *flow_thread(void *arg)
{
	int client_fd = (int)(intptr_t)arg;
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons((uint16_t)server_port) };
	inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
	int server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(server_fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		close(server_fd);
		close(client_fd);
		return NULL;
	}
	int rc = splice_bridge_run_flow(client_fd, server_fd, 0, "127.0.0.1", 443);
	fprintf(stderr, "[flow] ended rc=%d\n", rc);
	fflush(stderr);
	return NULL;
}

int main(int argc, char **argv)
{
	struct splice_bridge_cfg cfg;
	memset(&cfg, 0, sizeof(cfg));
	snprintf(cfg.proxy_host, sizeof(cfg.proxy_host), "127.0.0.1");
	cfg.need_keys = need_keys;
	cfg.log = log_line;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--upstream") && i + 1 < argc)
			server_port = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--keylog") && i + 1 < argc)
			keylog = argv[++i];
		else if (!strcmp(argv[i], "--proxy-port") && i + 1 < argc)
			cfg.proxy_port = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--bridge-port") && i + 1 < argc)
			cfg.upstream_port = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--strict"))
			cfg.strict = 1;
		else if (!strcmp(argv[i], "--hold-ms") && i + 1 < argc)
			cfg.hold_ms = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--key-delay-ms") && i + 1 < argc)
			key_delay_ms = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--keys-as-candidates"))
			as_candidates = 1;
		else if (!strcmp(argv[i], "--timeout-ms") && i + 1 < argc)
			cfg.response_timeout_ms = atoi(argv[++i]);
	}
	if (!server_port || !keylog || !cfg.proxy_port) {
		fprintf(stderr, "usage: %s --upstream PORT --keylog FILE --proxy-port P "
			"[--bridge-port B] [...]\n", argv[0]);
		return 2;
	}

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, on_term);
	if (splice_bridge_start(&cfg) != 0) {
		perror("bridge");
		return 1;
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
	printf("PORT %d\nBRIDGE %d\n", ntohs(la.sin_port), splice_bridge_upstream_port());
	fflush(stdout);

	for (;;) {
		int c = accept(ls, NULL, NULL);
		if (c < 0)
			continue;
		if (!first_conn_ms)
			first_conn_ms = now_ms();
		pthread_t t;
		if (pthread_create(&t, NULL, flow_thread, (void *)(intptr_t)c) == 0)
			pthread_detach(t);
		else
			close(c);
	}
}
