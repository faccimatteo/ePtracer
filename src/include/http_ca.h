/*
 * Automatic trust of the intercepting proxy's CA.
 *
 * Interception (include/http_intercept.h) puts the proxy in the path as a real
 * man in the middle: for an HTTPS connection the proxy terminates TLS and
 * presents a certificate signed by its own CA, which the traced process rejects
 * unless that CA is trusted. Making the operator install the CA by hand — with
 * update-ca-certificates, certutil or a browser dialog — is exactly the manual
 * step this module removes.
 *
 * It works entirely through the environment, so nothing on the machine is
 * touched and there is nothing to undo besides a temporary file: the proxy CA
 * is obtained (fetched from the proxy itself, or read from a file the operator
 * points at), merged with the system trust store into a temporary bundle, and
 * the environment variables the common TLS stacks read for their trust store
 * are exported before the traced process is spawned. The child inherits them,
 * so OpenSSL, BoringSSL, Go crypto/tls, GnuTLS-based tools, Node, Python and
 * curl all trust the proxy with no configuration of their own.
 *
 * It only covers a *spawned* process (-p): an already running one (-P) cannot
 * be handed a new environment. And it cannot defeat certificate pinning, which
 * ignores the trust store on purpose — but the uprobe capture still decodes the
 * plaintext there, which is the whole point of reading it inside the process.
 */

#ifndef EPTRACER_HTTP_CA_H
#define EPTRACER_HTTP_CA_H

/*
 * Sets up automatic trust of the proxy CA for the process about to be spawned.
 * Must be called before fork()/execvp(), so the child inherits the exported
 * environment.
 *
 * const char *intercept_endpoint: the --intercept value, used to reach the
 *   proxy when the CA has to be fetched. "direct" needs no CA and is a no-op.
 * const char *ca_path: a CA certificate the operator supplied (PEM or DER),
 *   NULL or empty to fetch it from the proxy.
 *
 * Returns 0 when the trust was set up, -1 otherwise. Interception works either
 * way; on failure TLS handshakes through the proxy fail unless the application
 * already trusts the CA.
 */
int http_ca_autotrust(const char *intercept_endpoint, const char *ca_path);

/* Removes the temporary bundle. Safe to call when nothing was prepared. */
void http_ca_cleanup(void);

#endif /* EPTRACER_HTTP_CA_H */
