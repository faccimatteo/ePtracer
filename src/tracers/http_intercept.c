/*
 * Putting ePtracer in the path of the traced process.
 *
 * The rationale, and how the original destination survives the redirect, are
 * documented in include/http_intercept.h. This file is the userspace half:
 * it attaches the redirect programs to the cgroup hierarchy, accepts the
 * connections that land on the loopback slot addresses, works out which
 * authority each of them was meant for, and tunnels the bytes to the
 * intercepting proxy — or straight to the original server when no proxy was
 * asked for.
 *
 * Every connection is handled on its own thread and nothing is buffered: the
 * proxy is on the wire, so stalling a request in its Intercept tab has to
 * stall the application too, which is the whole point.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* cgroup v2 root the redirect programs are attached to. The hooks run for
 * every process on the machine and filter on the traced PID in kernel space,
 * the same way the tracepoints already do. */
#define INTERCEPT_CGROUP_ROOT   "/sys/fs/cgroup"
/* Bytes peeked from a new connection to recognize the authority it is for */
#define INTERCEPT_PEEK_MAX      4096
/* How long a connection is given to send its first bytes before it is
 * tunnelled by IP address alone */
#define INTERCEPT_PEEK_TIMEOUT_MS 2000
/* How long each poll of that wait blocks for */
#define INTERCEPT_PEEK_POLL_MS  100
/* Relay buffer, one per direction and per connection */
#define INTERCEPT_RELAY_BUF     (32 * 1024)
/* Connections tunnelled at the same time */
#define INTERCEPT_MAX_ACTIVE    512
/* Accept poll granularity, so that stopping stays responsive */
#define INTERCEPT_ACCEPT_TIMEOUT_MS 500
/* Upper bound on the CONNECT reply read back from the proxy */
#define INTERCEPT_CONNECT_REPLY 4096

/* Everything one tunnel thread needs to know */
struct intercept_session {
	int   client_fd;
	int   slot;
	struct intercept_conn_t orig;
};

static int intercept_enabled = 0;
static int intercept_block_quic = 0;   /* refuse the target's UDP/443 */
static int intercept_listen_fd = -1;
static int intercept_listen_port = INTERCEPT_DEFAULT_PORT;
static int intercept_direct = 0;             /* no proxy behind ePtracer */
static char intercept_upstream_host[256] = INTERCEPT_DEFAULT_UPSTREAM_HOST;
static int  intercept_upstream_port = INTERCEPT_DEFAULT_UPSTREAM_PORT;
static int  intercept_orig_dst_fd = -1;
static int  intercept_config_fd = -1;
static int  intercept_cgroup_fd = -1;
static volatile int intercept_running = 0;
static unsigned long intercept_connections = 0;
static unsigned long intercept_failed = 0;

/* One redirect hook and how it ended up attached: BPF links are the modern
 * way, but they only exist from 5.7 onwards and ePtracer also runs on older
 * kernels, where the program is attached to the cgroup directly. */
struct intercept_hook {
	struct bpf_program  *prog;
	enum bpf_attach_type type;
	struct bpf_link     *link;
	int                  attached;
};

static struct intercept_hook intercept_hooks[3];
static int intercept_hook_count = 0;

/* The syscall-entry redirect, when the cgroup connect hook is not ours to use */
static struct bpf_link *intercept_raw_links[2];

/*
 * http_intercept_needs_raw_redirect
 *
 * Description:
 * Tells, before the BPF object is loaded, whether connect(2) will have to be
 * redirected at the syscall entry: the cgroup root already holds a connect4
 * program attached without BPF_F_ALLOW_MULTI — netd's, from Android 15 — so
 * the kernel refuses ours anywhere in the hierarchy. Asked up front because
 * the fallback programs are only loaded when needed: their helper is refused
 * by a kernel in lockdown, which would fail the whole load for everyone.
 *
 * Return:
 * 1 when the fallback is needed (or the hook cannot be queried), 0 otherwise.
 * */
int http_intercept_needs_raw_redirect(void)
{
	__u32 flags = 0, count = 0;
	int fd = -1, ret = 0;

	/* for the test suite: exercise the Android 15+ path on any kernel */
	if (getenv("EPTRACER_FORCE_RAW_REDIRECT"))
		return 1;
	fd = open(INTERCEPT_CGROUP_ROOT, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;   /* no cgroup v2: interception fails later, and says why */
	if (bpf_prog_query(fd, BPF_CGROUP_INET4_CONNECT, 0, &flags, NULL, &count) != 0)
		ret = 1;
	else
		ret = count > 0 && !(flags & BPF_F_ALLOW_MULTI);
	close(fd);
	return ret;
}

/* Attaches the syscall-entry redirect: 0 when connect(2) is covered by it */
static int intercept_attach_raw(struct eptracer_bpf *skel)
{
	if (bpf_program__fd(skel->progs.intercept_raw_connect) < 0)
		return -1;   /* not loaded: the cgroup hook looked available */
	intercept_raw_links[0] = bpf_program__attach(skel->progs.intercept_raw_connect);
	intercept_raw_links[1] = bpf_program__attach(skel->progs.intercept_raw_connect_exit);
	if (!intercept_raw_links[0] || !intercept_raw_links[1]) {
		bpf_link__destroy(intercept_raw_links[0]);
		bpf_link__destroy(intercept_raw_links[1]);
		intercept_raw_links[0] = intercept_raw_links[1] = NULL;
		return -1;
	}
	log_info("[+] The cgroup connect hook is held exclusively (netd, Android 15+): "
		 "connect(2) is redirected at the syscall entry instead");
	return 0;
}

static pthread_t intercept_accept_thread;
static int intercept_accept_started = 0;

/* Sockets of the tunnels in flight, so that stopping does not wait for them */
static int intercept_active[INTERCEPT_MAX_ACTIVE];
static int intercept_active_count = 0;
static pthread_mutex_t intercept_active_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * intercept_track / intercept_untrack
 *
 * Description:
 * Keeps the list of the client sockets currently tunnelled. Stopping shuts
 * them down instead of waiting for a peer that may never send anything.
 *
 * Params:
 * int fd: client socket to add or remove.
 * */
static void intercept_track(int fd)
{
	pthread_mutex_lock(&intercept_active_lock);
	if (intercept_active_count < INTERCEPT_MAX_ACTIVE)
		intercept_active[intercept_active_count++] = fd;
	pthread_mutex_unlock(&intercept_active_lock);
}

static void intercept_untrack(int fd)
{
	int i = 0;

	pthread_mutex_lock(&intercept_active_lock);
	for (i = 0; i < intercept_active_count; i++) {
		if (intercept_active[i] == fd) {
			intercept_active[i] = intercept_active[--intercept_active_count];
			break;
		}
	}
	pthread_mutex_unlock(&intercept_active_lock);
}

/*
 * intercept_parse_upstream
 *
 * Description:
 * Reads the proxy endpoint the intercepted connections are tunnelled to.
 * Accepts "host:port", a bare host, a bare port and the "direct" keyword,
 * which keeps ePtracer in the path with nothing behind it.
 *
 * Params:
 * const char *spec: endpoint as it was written on the command line.
 *
 * Return:
 * 0 on success, -1 when the endpoint cannot be understood.
 * */
static int intercept_parse_upstream(const char *spec)
{
	const char *colon = NULL;
	char *end = NULL;
	long value = 0;
	size_t host_len = 0;

	if (!spec || !spec[0])
		return 0;

	if (strcasecmp(spec, INTERCEPT_UPSTREAM_DIRECT) == 0) {
		intercept_direct = 1;
		return 0;
	}

	/* A bare number is a port on the loopback default */
	value = strtol(spec, &end, 10);
	if (end && *end == '\0' && value > 0 && value < 65536) {
		intercept_upstream_port = (int)value;
		return 0;
	}

	colon = strrchr(spec, ':');
	if (!colon) {
		snprintf(intercept_upstream_host, sizeof(intercept_upstream_host), "%s", spec);
		return 0;
	}

	host_len = (size_t)(colon - spec);
	if (host_len == 0 || host_len >= sizeof(intercept_upstream_host))
		return -1;

	value = strtol(colon + 1, &end, 10);
	if (!end || *end != '\0' || value <= 0 || value >= 65536)
		return -1;

	memcpy(intercept_upstream_host, spec, host_len);
	intercept_upstream_host[host_len] = '\0';
	intercept_upstream_port = (int)value;
	return 0;
}

/*
 * intercept_parse_ports
 *
 * Description:
 * Turns a comma separated destination port list into the kernel side filter.
 * An empty list redirects every TCP port the process connects to.
 *
 * Params:
 * const char *spec: port list, may be NULL or empty.
 * struct intercept_config_t *cfg: configuration being built.
 *
 * Return:
 * 0 on success, -1 when a port cannot be parsed or the list is too long.
 * */
static int intercept_parse_ports(const char *spec, struct intercept_config_t *cfg)
{
	char buffer[256];
	char *token = NULL;
	char *save = NULL;

	cfg->port_count = 0;
	if (!spec || !spec[0])
		return 0;

	snprintf(buffer, sizeof(buffer), "%s", spec);
	for (token = strtok_r(buffer, ",", &save); token; token = strtok_r(NULL, ",", &save)) {
		char *end = NULL;
		long value = 0;

		while (*token == ' ' || *token == '\t')
			token++;
		value = strtol(token, &end, 10);
		if (!end || (*end != '\0' && *end != ' ') || value <= 0 || value >= 65536) {
			log_error("[!] '%s' is not a valid destination port", token);
			return -1;
		}
		if (cfg->port_count >= INTERCEPT_MAX_PORTS) {
			log_error("[!] At most %d destination ports can be intercepted",
				  INTERCEPT_MAX_PORTS);
			return -1;
		}
		cfg->ports[cfg->port_count++] = (__u16)value;
	}
	return 0;
}

/*
 * intercept_push_config
 *
 * Description:
 * Publishes the redirect configuration the kernel programs read on every
 * connect(2).
 *
 * Params:
 * struct eptracer_bpf *skel: loaded skeleton.
 * const char *port_spec: destination ports to restrict the redirect to.
 *
 * Return:
 * 0 on success, -1 otherwise.
 * */
static int intercept_push_config(struct eptracer_bpf *skel, const char *port_spec)
{
	struct intercept_config_t cfg = {0};
	__u32 key = 0;

	if (intercept_parse_ports(port_spec, &cfg) < 0)
		return -1;

	cfg.enabled     = 1;
	cfg.block_quic  = (__u8)intercept_block_quic;
	cfg.listen_port = (__u16)intercept_listen_port;
	cfg.tracer_pid  = (__u32)getpid();

	intercept_config_fd = bpf_map__fd(skel->maps.intercept_config_map);
	if (bpf_map_update_elem(intercept_config_fd, &key, &cfg, BPF_ANY) < 0) {
		log_error("[!] Cannot publish the interception configuration: %s",
			  strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * intercept_attach_cgroup
 *
 * Description:
 * Attaches the redirect programs to the cgroup v2 root. getpeername4 is best
 * effort: it needs a 5.8 kernel and only makes the redirect invisible to a
 * process that asks who it is connected to.
 *
 * Params:
 * struct eptracer_bpf *skel: loaded skeleton.
 *
 * Return:
 * 0 when connect(2) is being redirected, -1 otherwise.
 * */
static int intercept_attach_one(struct bpf_program *prog, enum bpf_attach_type type)
{
	struct intercept_hook *hook = &intercept_hooks[intercept_hook_count];

	hook->prog = prog;
	hook->type = type;
	hook->link = bpf_program__attach_cgroup(prog, intercept_cgroup_fd);
	if (hook->link) {
		hook->attached = 1;
		intercept_hook_count++;
		return 0;
	}

	/* No BPF link support: attach the program to the cgroup itself, asking
	 * to coexist with whatever is already hooked there — a container
	 * runtime or systemd may well own a connect(2) program of its own. */
	if (bpf_prog_attach(bpf_program__fd(prog), intercept_cgroup_fd, type,
			    BPF_F_ALLOW_MULTI) < 0)
		return -1;

	hook->attached = 1;
	intercept_hook_count++;
	return 0;
}

static int intercept_attach_cgroup(struct eptracer_bpf *skel)
{
	intercept_cgroup_fd = open(INTERCEPT_CGROUP_ROOT, O_RDONLY);
	if (intercept_cgroup_fd < 0) {
		log_error("[!] Cannot open %s: %s. Interception needs a cgroup v2 "
			  "hierarchy mounted there", INTERCEPT_CGROUP_ROOT, strerror(errno));
		return -1;
	}

	if (getenv("EPTRACER_FORCE_RAW_REDIRECT"))
		return intercept_attach_raw(skel);

	if (intercept_attach_one(skel->progs.intercept_connect4,
				 BPF_CGROUP_INET4_CONNECT) < 0) {
		int err = errno;

		/* EPERM: another program owns the hook exclusively. The
		 * syscall-entry redirect covers IPv4 and IPv6 alike */
		if (err == EPERM && intercept_attach_raw(skel) == 0)
			return 0;
		log_error("[!] Cannot attach the IPv4 redirect: %s", strerror(err));
		return -1;
	}

	/* Losing IPv6 narrows the coverage, it does not break anything: a
	 * process that only talks IPv4 is still fully intercepted */
	if (intercept_attach_one(skel->progs.intercept_connect6,
				 BPF_CGROUP_INET6_CONNECT) < 0)
		log_error("[!] Cannot attach the IPv6 redirect: %s. IPv6 connections "
			  "will not be intercepted", strerror(errno));

	if (intercept_attach_one(skel->progs.intercept_getpeername4,
				 BPF_CGROUP_INET4_GETPEERNAME) < 0)
		log_debug("[?] getpeername(2) rewriting unavailable (%s): a redirected "
			  "socket reports the loopback address it was sent to",
			  strerror(errno));

	return 0;
}

/*
 * intercept_listen
 *
 * Description:
 * Brings up the listener the redirected connections land on. It is bound to
 * every address rather than to 127.0.0.1 because each connection is redirected
 * to a *different* loopback address — that address is how the original
 * destination is recovered — and a socket can only be bound to one of them.
 * Connections whose peer is not loopback are refused right after accept(2).
 *
 * Return:
 * 0 on success, -1 otherwise.
 * */
static int intercept_listen()
{
	struct sockaddr_in addr = {0};
	int fd = -1, on = 1;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		log_error("[!] Cannot create the interception listener: %s", strerror(errno));
		return -1;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons((__u16)intercept_listen_port);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		log_error("[!] Cannot bind the interception listener on port %d: %s",
			  intercept_listen_port, strerror(errno));
		if (errno == EADDRINUSE)
			log_error("[!] Something else already listens there — a second "
				  "proxy listener, often. Move it with --intercept-port");
		close(fd);
		return -1;
	}

	if (listen(fd, 128) < 0) {
		log_error("[!] Cannot listen on port %d: %s", intercept_listen_port,
			  strerror(errno));
		close(fd);
		return -1;
	}

	intercept_listen_fd = fd;
	return 0;
}

/*
 * intercept_lookup_slot
 *
 * Description:
 * Recovers the destination the process asked for, from the loopback address
 * the connection was redirected to.
 *
 * Params:
 * int fd: accepted socket.
 * struct intercept_conn_t *out: destination, filled on success.
 *
 * Return:
 * The slot number on success, -1 when the connection did not come from the
 * redirect.
 * */
static int intercept_lookup_slot(int fd, struct intercept_conn_t *out)
{
	struct sockaddr_in local = {0};
	socklen_t len = sizeof(local);
	__u32 host_addr = 0, slot = 0;

	if (getsockname(fd, (struct sockaddr *)&local, &len) < 0)
		return -1;

	if (local.sin_family != AF_INET)
		return -1;

	host_addr = ntohl(local.sin_addr.s_addr);
	if ((host_addr >> 24) != 127)
		return -1;
	if ((host_addr & 0x00ffffffu) < INTERCEPT_SLOT_BASE)
		return -1;

	slot = (host_addr & 0x00ffffffu) - INTERCEPT_SLOT_BASE;
	if (slot >= INTERCEPT_MAX_SLOTS)
		return -1;

	if (bpf_map_lookup_elem(intercept_orig_dst_fd, &slot, out) < 0)
		return -1;

	if (!out->in_use)
		return -1;

	return (int)slot;
}

/*
 * intercept_head_complete
 *
 * Description:
 * Tells whether a peeked buffer already holds a whole request head, so that
 * waiting for more bytes would only delay the connection.
 *
 * Params:
 * const char *buf: peeked bytes.
 * size_t len: how many of them are there.
 *
 * Return:
 * 1 when the blank line separating head from body is there, 0 otherwise.
 * */
static int intercept_head_complete(const char *buf, size_t len)
{
	size_t i = 0;

	for (i = 0; i + 4 <= len; i++) {
		if (buf[i] == '\r' && buf[i + 1] == '\n' &&
		    buf[i + 2] == '\r' && buf[i + 3] == '\n')
			return 1;
	}
	return 0;
}

/*
 * intercept_peek
 *
 * Description:
 * Looks at the bytes the client is about to send without consuming them, so
 * that the authority can be recovered before a single byte is forwarded. The
 * peek is repeated as data arrives: a ClientHello is not necessarily delivered
 * in one segment.
 *
 * Params:
 * int fd: client socket.
 * char *buf: buffer receiving the peeked bytes.
 * size_t cap: buffer size.
 *
 * Return:
 * Number of bytes available, 0 when the client said nothing in time.
 * */
static size_t intercept_peek(int fd, char *buf, size_t cap)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	struct timespec started = {0}, now = {0};
	struct timespec pause = { .tv_sec = 0, .tv_nsec = 20 * 1000 * 1000 };
	size_t available = 0;
	long elapsed_ms = 0;

	clock_gettime(CLOCK_MONOTONIC, &started);

	while (elapsed_ms < INTERCEPT_PEEK_TIMEOUT_MS) {
		int ready = poll(&pfd, 1, INTERCEPT_PEEK_POLL_MS);
		ssize_t got = 0;

		if (ready < 0 && errno != EINTR)
			break;

		if (ready > 0) {
			got = recv(fd, buf, cap, MSG_PEEK | MSG_DONTWAIT);
			if (got == 0)
				break;   /* the client hung up without saying anything */
			if (got < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
				break;

			if (got > 0 && (size_t)got > available) {
				available = (size_t)got;

				if (available >= cap)
					return available;

				/* A handshake record states its own length: once it is
				 * all there, nothing more can change the answer */
				if ((unsigned char)buf[0] == 0x16) {
					if (available >= 5) {
						size_t record = ((size_t)(unsigned char)buf[3] << 8) |
								 (size_t)(unsigned char)buf[4];
						if (available >= record + 5)
							return available;
					}
				} else if (intercept_head_complete(buf, available)) {
					return available;
				}
			} else {
				/* Readable but nothing new: the peer is mid message and
				 * polling again would spin */
				nanosleep(&pause, NULL);
			}
		}

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - started.tv_sec) * 1000 +
			     (now.tv_nsec - started.tv_nsec) / 1000000;
	}

	return available;
}

/*
 * intercept_tls_sni
 *
 * Description:
 * Extracts the server name from a TLS ClientHello. This is what lets the proxy
 * see the authority the application meant, instead of the bare IP address the
 * redirect started from — Burp then mints its certificate for the right host,
 * and its history reads like the application's own.
 *
 * Params:
 * const unsigned char *buf: bytes peeked from the connection.
 * size_t len: how many of them are there.
 * char *out: buffer receiving the name.
 * size_t out_size: its size.
 *
 * Return:
 * 1 when a name was found, 0 otherwise.
 * */
static int intercept_tls_sni(const unsigned char *buf, size_t len, char *out, size_t out_size)
{
	size_t pos = 0, end = 0, ext_end = 0;

	/* Handshake record carrying a ClientHello */
	if (len < 45 || buf[0] != 0x16 || buf[5] != 0x01)
		return 0;

	end = ((size_t)buf[3] << 8 | buf[4]) + 5;
	if (end > len)
		end = len;

	/* record header, handshake header, client version, random */
	pos = 5 + 4 + 2 + 32;
	if (pos >= end)
		return 0;

	pos += 1 + buf[pos];                                   /* session id */
	if (pos + 2 > end)
		return 0;
	pos += 2 + ((size_t)buf[pos] << 8 | buf[pos + 1]);     /* cipher suites */
	if (pos + 1 > end)
		return 0;
	pos += 1 + buf[pos];                                   /* compression */
	if (pos + 2 > end)
		return 0;

	ext_end = pos + 2 + ((size_t)buf[pos] << 8 | buf[pos + 1]);
	pos += 2;
	if (ext_end > end)
		ext_end = end;

	while (pos + 4 <= ext_end) {
		size_t type = (size_t)buf[pos] << 8 | buf[pos + 1];
		size_t size = (size_t)buf[pos + 2] << 8 | buf[pos + 3];

		pos += 4;
		if (pos + size > ext_end)
			return 0;

		/* server_name extension: list length, name type, name length */
		if (type == 0x0000 && size >= 5 && buf[pos + 2] == 0x00) {
			size_t name_len = (size_t)buf[pos + 3] << 8 | buf[pos + 4];

			if (name_len == 0 || name_len + 5 > size || name_len >= out_size)
				return 0;
			memcpy(out, buf + pos + 5, name_len);
			out[name_len] = '\0';
			return 1;
		}
		pos += size;
	}

	return 0;
}

/*
 * intercept_http_host
 *
 * Description:
 * Reads the Host header of a cleartext request, so that a proxy sees the same
 * authority the application used rather than the address it resolved to.
 *
 * Params:
 * const char *buf: bytes peeked from the connection.
 * size_t len: how many of them are there.
 * char *out: buffer receiving the host, port stripped.
 * size_t out_size: its size.
 *
 * Return:
 * 1 when a host was found, 0 otherwise.
 * */
static int intercept_http_host(const char *buf, size_t len, char *out, size_t out_size)
{
	const char *line = NULL;
	size_t i = 0, value_len = 0;

	for (i = 0; i + 6 < len; i++) {
		if (buf[i] != '\n')
			continue;
		if (strncasecmp(buf + i + 1, "host:", 5) != 0)
			continue;

		line = buf + i + 6;
		while (line < buf + len && (*line == ' ' || *line == '\t'))
			line++;
		while (line + value_len < buf + len && line[value_len] != '\r' &&
		       line[value_len] != '\n' && line[value_len] != ':')
			value_len++;

		if (value_len == 0 || value_len >= out_size)
			return 0;
		memcpy(out, line, value_len);
		out[value_len] = '\0';
		return 1;
	}
	return 0;
}

/*
 * intercept_dial
 *
 * Description:
 * Opens a TCP connection to a host, by name or by address.
 *
 * Params:
 * const char *host: name or textual address.
 * int port: destination port.
 *
 * Return:
 * The connected socket, -1 on failure.
 * */
static int intercept_dial(const char *host, int port)
{
	struct addrinfo hints = {0}, *res = NULL, *it = NULL;
	char service[16];
	int fd = -1, on = 1;

	snprintf(service, sizeof(service), "%d", port);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(host, service, &hints, &res) != 0)
		return -1;

	for (it = res; it; it = it->ai_next) {
		fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
		if (fd < 0)
			continue;
		if (connect(fd, it->ai_addr, it->ai_addrlen) == 0)
			break;
		close(fd);
		fd = -1;
	}

	freeaddrinfo(res);

	if (fd >= 0)
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	return fd;
}

/*
 * intercept_write_all
 *
 * Description:
 * Writes a whole buffer to a socket, retrying on short writes.
 *
 * Return:
 * 0 on success, -1 otherwise.
 * */
static int intercept_write_all(int fd, const char *data, size_t len)
{
	size_t sent = 0;

	while (sent < len) {
		ssize_t written = send(fd, data + sent, len - sent, MSG_NOSIGNAL);

		if (written < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (written == 0)
			return -1;
		sent += (size_t)written;
	}
	return 0;
}

/*
 * intercept_open_tunnel
 *
 * Description:
 * Opens the connection the intercepted bytes are handed to. With a proxy in
 * front, that is a CONNECT tunnel towards the authority the client meant, which
 * is what makes the proxy treat the exchange as a real client request: it can
 * hold it, edit it, drop it. Without one, the original server is dialled
 * directly and ePtracer is a transparent relay.
 *
 * Params:
 * const char *host: authority the client is after.
 * int port: its port.
 *
 * Return:
 * The connected socket, -1 on failure.
 * */
static int intercept_open_tunnel(const char *host, int port)
{
	char request[1024];
	char reply[INTERCEPT_CONNECT_REPLY];
	size_t filled = 0;
	int fd = -1, status = 0;

	if (intercept_direct)
		return intercept_dial(host, port);

	fd = intercept_dial(intercept_upstream_host, intercept_upstream_port);
	if (fd < 0) {
		log_error("[!] Cannot reach the proxy at %s:%d: %s", intercept_upstream_host,
			  intercept_upstream_port, strerror(errno));
		return -1;
	}

	snprintf(request, sizeof(request),
		 "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Connection: keep-alive\r\n\r\n",
		 host, port, host, port);

	if (intercept_write_all(fd, request, strlen(request)) < 0) {
		close(fd);
		return -1;
	}

	/* The tunnel is established as soon as the status line says so: the
	 * bytes after the blank line already belong to the server */
	while (filled < sizeof(reply) - 1) {
		ssize_t got = recv(fd, reply + filled, sizeof(reply) - 1 - filled, 0);

		if (got <= 0)
			break;
		filled += (size_t)got;
		reply[filled] = '\0';
		if (strstr(reply, "\r\n\r\n"))
			break;
	}

	if (filled < 12 || strncmp(reply, "HTTP/1.", 7) != 0) {
		log_error("[!] The proxy did not answer the CONNECT for %s:%d", host, port);
		close(fd);
		return -1;
	}

	status = atoi(reply + 9);
	if (status != 200) {
		log_error("[!] The proxy refused the tunnel to %s:%d (status %d)", host,
			  port, status);
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * intercept_relay
 *
 * Description:
 * Moves bytes between the application and the tunnel until either side is
 * done. Nothing is held back: a request stalled in the proxy Intercept tab
 * stalls the application, which is exactly the behaviour a configured proxy
 * has.
 *
 * Params:
 * int client_fd: socket of the traced application.
 * int upstream_fd: socket of the proxy, or of the real server.
 * */
static void intercept_relay(int client_fd, int upstream_fd)
{
	char buffer[INTERCEPT_RELAY_BUF];
	struct pollfd fds[2];
	int open_ends = 2;

	fds[0].fd = client_fd;
	fds[1].fd = upstream_fd;
	fds[0].events = fds[1].events = POLLIN;

	while (intercept_running && open_ends > 0) {
		int ready = poll(fds, 2, INTERCEPT_ACCEPT_TIMEOUT_MS);
		int i = 0;

		if (ready < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (ready == 0)
			continue;

		for (i = 0; i < 2; i++) {
			int peer = fds[1 - i].fd;
			ssize_t got = 0;

			if (fds[i].fd < 0 || !(fds[i].revents & (POLLIN | POLLHUP | POLLERR)))
				continue;

			got = recv(fds[i].fd, buffer, sizeof(buffer), 0);
			if (got > 0) {
				/* The other end went away while this one still had
				 * something to say: the tunnel is over */
				if (peer < 0 || intercept_write_all(peer, buffer, (size_t)got) < 0)
					return;
				continue;
			}
			if (got < 0 && (errno == EINTR || errno == EAGAIN))
				continue;

			/* This direction is over: let the peer flush what it still
			 * owes before tearing the tunnel down */
			if (peer >= 0)
				shutdown(peer, SHUT_WR);
			fds[i].fd = -1;
			fds[i].events = 0;
			open_ends--;
		}
	}
}

/*
 * intercept_format_authority
 *
 * Description:
 * Renders "host" or "host:port" for a request line, omitting the port when it
 * is the default one and bracketing an IPv6 literal.
 *
 * Params:
 * const char *host: host or address, without brackets.
 * int port: destination port.
 * int default_port: port to leave implicit.
 * char *out: destination buffer.
 * size_t out_size: its size.
 * */
static void intercept_format_authority(const char *host, int port, int default_port,
				       char *out, size_t out_size)
{
	int v6 = host[0] != '[' && strchr(host, ':') != NULL;

	if (port == default_port)
		snprintf(out, out_size, v6 ? "[%s]" : "%s", host);
	else
		snprintf(out, out_size, v6 ? "[%s]:%d" : "%s:%d", host, port);
}

/*
 * intercept_forward_cleartext
 *
 * Description:
 * Forwards a redirected cleartext connection to the proxy the way a
 * proxy-configured client does: the request line is rewritten from origin-form
 * ("GET /path") to absolute-form ("GET http://host/path"), with no CONNECT
 * tunnel. That is what makes the proxy route the request through its
 * interception engine — so Burp's Intercept tab can hold, edit or drop it —
 * instead of only recording a tunnel in its history.
 *
 * The head ePtracer already peeked at is consumed here and its rewritten copy
 * is what reaches the proxy; everything after it is relayed untouched by the
 * caller.
 *
 * Params:
 * int client_fd: socket of the traced application.
 * int upstream_fd: socket already connected to the proxy.
 * const char *host: authority the client meant.
 * int port: its port.
 * size_t peeked_len: bytes the peek made available.
 *
 * Return:
 * 0 when the head was forwarded, -1 on a socket error (the connection is dead
 * and the caller must not fall back).
 * */
static int intercept_forward_cleartext(int client_fd, int upstream_fd, const char *host,
				       int port, size_t peeked_len)
{
	char buf[INTERCEPT_PEEK_MAX];
	char authority[300];
	char scheme_authority[320];
	size_t got = 0, sp = 0;

	if (peeked_len > sizeof(buf))
		peeked_len = sizeof(buf);

	/* Consume the peeked head, so the rewritten copy is the one that goes out */
	while (got < peeked_len) {
		ssize_t n = recv(client_fd, buf + got, peeked_len - got, 0);

		if (n <= 0)
			return -1;
		got += (size_t)n;
	}

	/* Find the target in "METHOD SP TARGET SP VERSION" */
	while (sp < got && buf[sp] != ' ')
		sp++;

	/* Only an origin-form target ("/path") needs rewriting. Anything else —
	 * already absolute, "OPTIONS *", or unparsable — is sent as captured; the
	 * proxy still receives it and decides how to handle the odd case. */
	if (sp + 1 >= got || buf[sp + 1] != '/')
		return intercept_write_all(upstream_fd, buf, got);

	intercept_format_authority(host, port, 80, authority, sizeof(authority));
	snprintf(scheme_authority, sizeof(scheme_authority), "http://%s", authority);

	if (intercept_write_all(upstream_fd, buf, sp + 1) < 0 ||                        /* "METHOD " */
	    intercept_write_all(upstream_fd, scheme_authority, strlen(scheme_authority)) < 0 ||
	    intercept_write_all(upstream_fd, buf + sp + 1, got - (sp + 1)) < 0)         /* "/path HTTP/1.1\r\n..." */
		return -1;

	return 0;
}

#include "splice_session.c"

/*
 * intercept_session_thread
 *
 * Description:
 * Handles one redirected connection end to end: names the authority it was
 * meant for, opens the path to the proxy (a CONNECT tunnel for TLS, an
 * absolute-form proxied request for cleartext) and relays.
 *
 * Params:
 * void *arg: struct intercept_session, owned by this thread.
 * */
static void *intercept_session_thread(void *arg)
{
	struct intercept_session *session = (struct intercept_session *)arg;
	char peeked[INTERCEPT_PEEK_MAX];
	char authority[256];
	char literal[INET6_ADDRSTRLEN];
	size_t peeked_len = 0;
	int upstream_fd = -1;
	int is_tls = 0;
	int port = session->orig.dport;

	inet_ntop(session->orig.family == 6 ? AF_INET6 : AF_INET, session->orig.daddr,
		  literal, sizeof(literal));
	snprintf(authority, sizeof(authority), "%s", literal);

	peeked_len = intercept_peek(session->client_fd, peeked, sizeof(peeked));
	if (peeked_len > 0) {
		if (intercept_tls_sni((const unsigned char *)peeked, peeked_len, authority,
				      sizeof(authority)))
			is_tls = 1;
		else if ((unsigned char)peeked[0] == 0x16)
			is_tls = 1;   /* TLS without SNI: the address is all we have */
		else
			intercept_http_host(peeked, peeked_len, authority, sizeof(authority));
	}

	log_info("[>] intercept %s:%d  %s  pid=%u comm=%s  via %s", authority, port,
		 is_tls ? "TLS" : "plain", session->orig.pid, session->orig.comm,
		 intercept_direct ? "direct" : is_tls && splice_running ? "splice" : "proxy");

	if (is_tls && splice_running) {
		/* the app's own session to the real server, decrypted with its keys */
		splice_session(session, literal, port, authority);
		goto out;
	}

	if (intercept_direct) {
		/* No proxy behind us: relay straight to the real server, untouched */
		upstream_fd = intercept_dial(authority, port);
	} else if (!is_tls && peeked_len > 0) {
		/* Cleartext through the proxy: hand it over as an absolute-form proxied
		 * request so the proxy routes it through interception, not just history */
		upstream_fd = intercept_dial(intercept_upstream_host, intercept_upstream_port);
		if (upstream_fd >= 0 &&
		    intercept_forward_cleartext(session->client_fd, upstream_fd, authority,
						port, peeked_len) < 0) {
			close(upstream_fd);
			upstream_fd = -1;
		}
	} else {
		/* TLS (CONNECT tunnel, the proxy does the MITM), or cleartext whose head
		 * never arrived: fall back to a tunnel */
		upstream_fd = intercept_open_tunnel(authority, port);
	}

	if (upstream_fd < 0) {
		/* An application whose connection is dropped here would look like a
		 * network failure: say so rather than letting it guess */
		intercept_failed++;
		log_error("[!] Interception of %s:%d failed, the application sees a "
			  "closed connection", authority, port);
		goto out;
	}

	intercept_relay(session->client_fd, upstream_fd);

out:
	if (upstream_fd >= 0)
		close(upstream_fd);
	intercept_untrack(session->client_fd);
	close(session->client_fd);
	free(session);
	return NULL;
}

/*
 * intercept_accept_loop
 *
 * Description:
 * Accepts the redirected connections and hands each of them to its own thread.
 * A connection that did not come from the redirect — anything reaching the
 * listener from outside the loopback, or whose slot is gone — is closed
 * straight away.
 * */
static void *intercept_accept_loop(void *unused)
{
	(void)unused;

	while (intercept_running) {
		struct pollfd pfd = { .fd = intercept_listen_fd, .events = POLLIN };
		struct sockaddr_in peer = {0};
		socklen_t peer_len = sizeof(peer);
		struct intercept_session *session = NULL;
		pthread_t thread;
		int fd = -1, on = 1, slot = 0;
		int ready = poll(&pfd, 1, INTERCEPT_ACCEPT_TIMEOUT_MS);

		if (ready < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (ready == 0)
			continue;

		fd = accept(intercept_listen_fd, (struct sockaddr *)&peer, &peer_len);
		if (fd < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			break;
		}

		/* The listener is bound to every address because the redirect uses a
		 * whole /8: refuse anything that did not come from this machine */
		if (peer.sin_family != AF_INET ||
		    (ntohl(peer.sin_addr.s_addr) >> 24) != 127) {
			log_error("[!] Refused a connection to the interception port from "
				  "outside the loopback");
			close(fd);
			continue;
		}

		session = calloc(1, sizeof(*session));
		if (!session) {
			close(fd);
			continue;
		}

		slot = intercept_lookup_slot(fd, &session->orig);
		if (slot < 0) {
			log_error("[!] A connection reached the interception port without "
				  "being redirected: closing it");
			free(session);
			close(fd);
			continue;
		}

		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
		session->client_fd = fd;
		session->slot = slot;
		intercept_track(fd);
		intercept_connections++;

		if (pthread_create(&thread, NULL, intercept_session_thread, session) != 0) {
			log_error("[!] Cannot start the tunnel thread: %s", strerror(errno));
			intercept_untrack(fd);
			free(session);
			close(fd);
			continue;
		}
		pthread_detach(thread);
	}

	return NULL;
}

/*
 * http_intercept_start
 *
 * Description:
 * Documented in include/http_intercept.h.
 * */
void http_intercept_set_block_quic(int on)
{
	intercept_block_quic = on;
}

int http_intercept_start(struct eptracer_bpf *skel, const char *upstream,
			 int listen_port, const char *port_spec)
{
	if (!skel)
		return -1;

	if (listen_port > 0 && listen_port < 65536)
		intercept_listen_port = listen_port;

	if (intercept_parse_upstream(upstream) < 0) {
		log_error("[!] Cannot parse the interception endpoint '%s'", upstream);
		return -1;
	}

	intercept_orig_dst_fd = bpf_map__fd(skel->maps.orig_dst_map);
	if (intercept_orig_dst_fd < 0) {
		log_error("[!] The interception maps are not available");
		return -1;
	}

	/* The bridge must be listening before the first connection is
	 * redirected: none may take the MITM path by accident */
	if (splice_requested && splice_start_bridge() < 0)
		return -1;

	/* The listener has to be up before the redirect starts, or the first
	 * connections would be sent to a closed port */
	if (intercept_listen() < 0)
		return -1;

	intercept_running = 1;
	if (pthread_create(&intercept_accept_thread, NULL, intercept_accept_loop, NULL) != 0) {
		log_error("[!] Cannot start the interception listener thread");
		goto fail;
	}
	intercept_accept_started = 1;

	if (intercept_push_config(skel, port_spec) < 0)
		goto fail;

	if (intercept_attach_cgroup(skel) < 0)
		goto fail;

	intercept_enabled = 1;

	if (intercept_direct) {
		log_info("[+] Intercepting the traced process on 127.0.0.0/8:%d, "
			 "relaying straight to the original servers", intercept_listen_port);
	} else if (splice_running) {
		log_info("[+] Intercepting the traced process through the proxy at %s:%d, "
			 "TLS spliced: the app keeps the server's real certificate, so "
			 "pinning holds, and no proxy CA has to be trusted",
			 intercept_upstream_host, intercept_upstream_port);
	} else {
		log_info("[+] Intercepting the traced process through the proxy at %s:%d",
			 intercept_upstream_host, intercept_upstream_port);
		log_info("[+] The proxy is now in the path: Intercept, drop and edit all "
			 "work. For a spawned process its CA is trusted automatically; an "
			 "attached one must already trust it (pinning aside)");
	}

	return 0;

fail:
	http_intercept_stop();
	return -1;
}

/*
 * http_intercept_join
 *
 * Description:
 * Documented in include/http_intercept.h.
 * */
void http_intercept_join()
{
	if (!intercept_accept_started)
		return;
	pthread_join(intercept_accept_thread, NULL);
	intercept_accept_started = 0;
}

/*
 * http_intercept_stop
 *
 * Description:
 * Documented in include/http_intercept.h.
 * */
void http_intercept_stop()
{
	struct intercept_config_t cfg = {0};
	__u32 key = 0;
	int i = 0;

	if (!intercept_running && !intercept_enabled && intercept_listen_fd < 0)
		return;

	/* Stop redirecting before tearing anything down, so that a connection
	 * opened right now is not sent to a listener that is going away */
	for (i = 0; i < intercept_hook_count; i++) {
		struct intercept_hook *hook = &intercept_hooks[i];

		if (!hook->attached)
			continue;
		if (hook->link)
			bpf_link__destroy(hook->link);
		else
			bpf_prog_detach2(bpf_program__fd(hook->prog), intercept_cgroup_fd,
					 hook->type);
		hook->attached = 0;
		hook->link = NULL;
	}
	intercept_hook_count = 0;
	for (i = 0; i < 2; i++) {
		bpf_link__destroy(intercept_raw_links[i]);
		intercept_raw_links[i] = NULL;
	}

	if (intercept_config_fd >= 0)
		bpf_map_update_elem(intercept_config_fd, &key, &cfg, BPF_ANY);

	intercept_running = 0;

	if (intercept_listen_fd >= 0)
		shutdown(intercept_listen_fd, SHUT_RDWR);

	if (intercept_accept_started) {
		pthread_join(intercept_accept_thread, NULL);
		intercept_accept_started = 0;
	}

	if (intercept_listen_fd >= 0) {
		close(intercept_listen_fd);
		intercept_listen_fd = -1;
	}

	/* Tunnels in flight are on detached threads: closing their sockets is
	 * what makes them notice */
	pthread_mutex_lock(&intercept_active_lock);
	for (i = 0; i < intercept_active_count; i++)
		shutdown(intercept_active[i], SHUT_RDWR);
	pthread_mutex_unlock(&intercept_active_lock);

	if (intercept_cgroup_fd >= 0) {
		close(intercept_cgroup_fd);
		intercept_cgroup_fd = -1;
	}

	if (intercept_enabled)
		log_info("[+] Interception stopped: %lu connections, %lu could not be "
			 "tunnelled", intercept_connections, intercept_failed);

	if (splice_running) {
		struct splice_bridge_stats st;

		splice_bridge_get_stats(&st);
		log_info("[+] TLS splice: %lu requests, %lu delivered once, %lu duplicates "
			 "and %lu late forwards refused, %lu dropped by the proxy, %lu "
			 "abandoned by the app, %lu flows relayed without the proxy",
			 st.requests, st.delivered, st.rejected_duplicate, st.rejected_late,
			 st.dropped_by_proxy, st.abandoned, st.bypassed);
	}
	splice_stop();

	intercept_enabled = 0;
}
