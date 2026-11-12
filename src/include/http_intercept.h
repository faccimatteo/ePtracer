/*
 * In-path interception — putting ePtracer on the wire with eBPF.
 *
 * The HTTP tracer (include/http_tracing.h) is an observer: it reads payloads
 * inside the traced process, which is what makes certificate pinning
 * irrelevant, but also what makes it unable to hold a request while somebody
 * edits it. Burp's Intercept tab never sees that traffic.
 *
 * This module closes that gap without configuring the application, without
 * iptables and without a network namespace: a `cgroup/connect4` program
 * rewrites the destination of every TCP connection the traced process opens,
 * so the connection lands on a loopback listener ePtracer owns. From there the
 * bytes are tunnelled to a real intercepting proxy, which is therefore in the
 * path for good — it can stall, edit, drop and replay, exactly as it does for
 * a client configured to use it.
 *
 * Recovering the original destination
 * -----------------------------------
 * connect(2) is rewritten before the source port exists, so the usual
 * (saddr, sport) correlation is not available yet, and SO_ORIGINAL_DST belongs
 * to netfilter. Instead the destination is *encoded in the address the
 * connection is redirected to*: 127.0.0.0/8 is 16 million locally deliverable
 * addresses, so connection number N is redirected to 127.0.0.0 | (N + 2) and
 * its real destination is stored in orig_dst_map[N]. The listener recovers N
 * with a plain getsockname(2) on the accepted socket — no race, no correlation
 * heuristics, no extra kernel hook.
 *
 * How it compares to plain observation
 * ------------------------------------
 *  - `-H/--show-http` reads a *copy* of what was decoded inside the process.
 *    Pinning-proof, read only: the exchange is shown, never held.
 *  - `--intercept` routes the connection *through* the proxy. Full
 *    interception, at the price of being a real man in the middle: the proxy
 *    CA has to be trusted by the application (done automatically for a spawned
 *    process, see include/http_ca.h) and pinning applies again.
 *
 * They are complementary and can be used together: the uprobes keep decoding
 * the plaintext even when the TLS handshake through the proxy is refused,
 * which is exactly what tells pinning apart from a broken CA setup.
 */

#ifndef EPTRACER_HTTP_INTERCEPT_H
#define EPTRACER_HTTP_INTERCEPT_H

/* Connections that can be redirected before the slot table wraps around */
#define INTERCEPT_MAX_SLOTS   8192
/* The slot table is partitioned per CPU so that two cores never hand the same
 * slot to two connections: a plain shared counter would need an atomic
 * fetch-and-add, which the BPF ISA only offers from -mcpu=v3 onwards. */
#define INTERCEPT_MAX_CPUS      64
#define INTERCEPT_SLOTS_PER_CPU (INTERCEPT_MAX_SLOTS / INTERCEPT_MAX_CPUS)
/* Destination ports the redirect can be restricted to (0 entries = every port) */
#define INTERCEPT_MAX_PORTS   16
/* Loopback address the redirect starts from: 127.0.0.0 | (slot + SLOT_BASE).
 * Starting at 2 keeps 127.0.0.0 and 127.0.0.1 out of the encoding, so a
 * connection the application really made to localhost can never be mistaken
 * for a redirected one. */
#define INTERCEPT_SLOT_BASE   2
/* Loopback port the interceptor listens on */
#define INTERCEPT_DEFAULT_PORT 8081
/* Proxy the intercepted connections are tunnelled to */
#define INTERCEPT_DEFAULT_UPSTREAM_HOST "127.0.0.1"
#define INTERCEPT_DEFAULT_UPSTREAM_PORT 8080
/* `--intercept direct` keeps ePtracer in the path with no proxy behind it */
#define INTERCEPT_UPSTREAM_DIRECT "direct"

#ifndef HTTP_COMM_LEN
#define HTTP_COMM_LEN 16
#endif

/* Original destination of a redirected connection, indexed by slot number */
struct intercept_conn_t {
	__u64 timestamp_ns;
	__u8  daddr[16];      /* IPv4 in the first 4 bytes when family == 4 */
	__u32 pid;
	__u32 tid;
	__u16 dport;          /* host byte order */
	__u8  family;         /* 4 AF_INET, 6 AF_INET6 mapped to IPv4 */
	__u8  in_use;
	char  comm[HTTP_COMM_LEN];
};

/* Runtime configuration, pushed by userspace in intercept_config_map */
struct intercept_config_t {
	__u8  enabled;
	__u8  port_count;     /* 0: redirect every TCP destination port */
	__u8  block_quic;     /* refuse the target's UDP/443: it falls back to TCP */
	__u16 listen_port;    /* host byte order */
	__u32 tracer_pid;     /* ePtracer itself is never redirected */
	__u16 ports[INTERCEPT_MAX_PORTS];
};

#ifndef __bpf__
/*
 * Starts the interceptor: loads the redirect programs into the cgroup
 * hierarchy and brings the loopback listener up.
 *
 * struct eptracer_bpf *skel: loaded skeleton, the cgroup programs are attached
 *   here rather than by eptracer_bpf__attach().
 * const char *upstream: "host:port", "port" or INTERCEPT_UPSTREAM_DIRECT.
 * int listen_port: loopback port the interceptor accepts on.
 * const char *port_spec: comma separated destination ports to redirect, NULL
 *   or empty for every port.
 *
 * Returns 0 when the traffic is being redirected, -1 otherwise; capture goes
 * on either way.
 */
int http_intercept_start(struct eptracer_bpf *skel, const char *upstream,
			 int listen_port, const char *port_spec);

/* Blocks until the interceptor stops. Used when interception is the only
 * thing ePtracer was asked for and there is no tracer thread to wait on. */
void http_intercept_join(void);

/* Detaches the redirect and stops the listener. Safe to call when the
 * interceptor was never started. */
void http_intercept_stop(void);

/* Refuse the target's UDP/443 so QUIC/HTTP3 falls back to TCP (which the
 * redirect covers). Call before http_intercept_start(). */
void http_intercept_set_block_quic(int on);

/*
 * `--tls-mode splice` (tracers/splice_session.c): splice TLS with the app's own
 * keys instead of tunnelling it to a MITM proxy. Call before
 * http_intercept_start(), with splice_capture_start() installing the key probes
 * on the target's TLS libraries (it returns how many were probed).
 */
void http_intercept_use_splice(int strict, int hold_ms, int bridge_port, const char *proxy_ca);
int splice_capture_start(struct eptracer_bpf *skel, pid_t pid, const char *program,
			 const char *lib_spec);
/* --package/--uid: probe what the processes of that uid already run */
void splice_capture_uid(uid_t uid);
#endif /* __bpf__ */

#endif /* EPTRACER_HTTP_INTERCEPT_H */
