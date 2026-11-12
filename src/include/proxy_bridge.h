/*
 * Proxy bridge — the "sandwich" that puts Burp/Caido in the splice path.
 *
 * In the splice design (docs/design/tls-splice-proxy.md §8) ePtracer has the
 * decrypted plaintext but must let the proxy *modify* it without the proxy
 * opening its own connection to the origin (that connection already exists: it
 * is the app's real TLS session, whose keys we hold). So ePtracer sits on both
 * sides of the proxy:
 *
 *   FRONT    — ePtracer is a CLIENT of the proxy: for each spliced connection it
 *              opens `CONNECT <authority>:443` to the proxy and speaks TLS to it
 *              with the proxy's own CA (a Burp-style HTTP proxy). The decrypted
 *              request is written here; the (possibly edited) request comes back.
 *   UPSTREAM — ePtracer is the proxy's UPSTREAM proxy: it receives the edited
 *              request after the proxy processed it and routes it onto the right
 *              server leg. (built in a later phase)
 *
 * This header exposes the FRONT side, which is the first thing to validate
 * against a real Burp-style proxy and is independent of the eBPF machinery, so
 * it is unit-tested standalone (bench/test_proxy_bridge.c + bench/burp_style_proxy.py).
 */

#ifndef EPTRACER_PROXY_BRIDGE_H
#define EPTRACER_PROXY_BRIDGE_H

#include <stddef.h>

/* Configuration of the downstream proxy ePtracer tunnels through (FRONT). */
struct proxy_bridge_cfg {
	char proxy_host[256];
	int  proxy_port;
	/* PEM file with the proxy CA to verify the MITM certificate against.
	 * Empty string => do not verify (test / `--intercept direct` style). */
	char ca_file[512];
};

/* An opaque FRONT connection: a TLS session tunnelled to the proxy. */
struct proxy_front;

/*
 * Open a CONNECT tunnel to the Burp-style proxy for `authority:port`, then
 * complete a TLS handshake towards the proxy as a client. On success *out holds
 * a ready connection and 0 is returned; on failure a negative code is returned
 * and *out is left NULL.
 *
 * Verification: when cfg->ca_file is set, the proxy's leaf certificate is
 * verified against that CA and matched against `authority` (SNI + hostname
 * check), exactly as a browser configured to use the proxy would. This is the
 * safe default — a Burp-style proxy presents a cert minted by its own CA.
 */
int proxy_front_open(const struct proxy_bridge_cfg *cfg,
		     const char *authority, int port,
		     struct proxy_front **out);

/* Write/read decrypted application bytes to/from the proxy. Return the byte
 * count, 0 on clean close, negative on error. In non-blocking mode a read with
 * nothing to return yields PROXY_FRONT_AGAIN, and a write waits for room. */
#define PROXY_FRONT_AGAIN (-2)
long proxy_front_write(struct proxy_front *pf, const void *buf, size_t len);
long proxy_front_read(struct proxy_front *pf, void *buf, size_t cap);

/*
 * Switch the connection to non-blocking reads, for an owner that polls it next
 * to other sockets. Needed because a poll that sees the socket readable does
 * not mean application data: a TLS 1.3 proxy sends NewSessionTicket records
 * right after the handshake, and a blocking SSL_read would consume them and
 * then sit waiting for an answer that cannot come while the owner is stuck.
 */
int proxy_front_set_nonblocking(struct proxy_front *pf);

/* Close and free. Safe on NULL. */
void proxy_front_close(struct proxy_front *pf);

/* Socket to poll for readability, and decrypted bytes already buffered by TLS
 * (poll does not see those: read them before polling again). */
int proxy_front_fd(const struct proxy_front *pf);
int proxy_front_pending(const struct proxy_front *pf);

/*
 * TLS server context for the UPSTREAM side: the certificate ePtracer presents to
 * the proxy when the proxy uses it as its upstream. From cert_file/key_file
 * (PEM) when both are given, otherwise a self-signed P-256 certificate made in
 * memory: Burp does not verify its upstream by default, and nothing has to be
 * installed anywhere. Returns an SSL_CTX *, NULL on failure.
 */
struct ssl_ctx_st *proxy_upstream_ctx(const char *cert_file, const char *key_file);

/* Last human-readable error on this thread, for logs/tests. */
const char *proxy_bridge_last_error(void);

#endif /* EPTRACER_PROXY_BRIDGE_H */
