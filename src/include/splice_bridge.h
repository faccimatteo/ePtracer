/*
 * Splice bridge — Burp/Caido in the path of a spliced TLS connection, with every
 * request reaching the real server at most once, on the app's own TLS session.
 *
 *   app ──TLS(app keys)──▶ splice ──plaintext──▶ FRONT ──▶ proxy ──▶ UPSTREAM ──┐
 *                                                                              │ deliver once
 *   server ◀──────────── TLS(app keys) ◀── splice ◀─────────────────────────────┘
 *
 *  - The app's handshake reached the real server untouched (include/tls_splice.h);
 *    with the keys captured by eBPF the bridge reads each request the app sends.
 *  - FRONT: each request goes to the proxy as a client of the proxy would
 *    (CONNECT + TLS), untouched, on a connection of its own whose CONNECT port
 *    is unique to it: that port is the request's identity.
 *  - UPSTREAM: the proxy is configured to use ePtracer as its upstream proxy. What
 *    the proxy forwards — edited or not — lands here; the proxy asks for the
 *    same port, which says which app connection and which request it is, and
 *    the request is sealed into that connection's session towards the server.
 *  - The server's answer goes back the same way: to the proxy (which may edit
 *    it), then from FRONT to the app.
 *  - After a 101 (WebSocket) the connection is two byte streams, both through
 *    the proxy: app <-> FRONT, and the UPSTREAM connection that delivered the
 *    upgrade <-> the server. The proxy sees, holds and edits the messages as it
 *    does for any WebSocket; nothing is parsed on the way.
 *
 * At-most-once
 * ------------
 * Every request the app sends has a state: PENDING when it is handed to the
 * proxy, then exactly one of
 *   DELIVERED  the proxy forwarded it and it was written to the server,
 *   DROPPED    the proxy answered the app without forwarding it (Drop, error),
 *   ABANDONED  the app went away before the proxy decided.
 * Only a PENDING request can be delivered, and the transition to DELIVERED and
 * the write to the server happen under the same lock (bridge_deliver()). So a
 * second copy of a request — Repeater, a proxy retry, a forward that comes
 * after the app gave up, a target edited to another port — is refused
 * (409 / 410 / 400 to the proxy) and never reaches the server. A request that
 * cannot be framed (not HTTP/1.x) is never sent twice either: it is relayed
 * once without the proxy, or the connection is closed under strict.
 */

#ifndef EPTRACER_SPLICE_BRIDGE_H
#define EPTRACER_SPLICE_BRIDGE_H

#include <stdint.h>


struct splice_bridge_cfg {
	char proxy_host[256];     /* the proxy listener FRONT connects to */
	int  proxy_port;
	char proxy_ca[512];       /* proxy CA to verify FRONT against, "" = no check */
	char upstream_host[64];   /* where UPSTREAM listens, "" = 127.0.0.1 */
	int  upstream_port;       /* 0 = ephemeral, see splice_bridge_upstream_port() */
	char cert_file[512];      /* UPSTREAM certificate, "" = self-signed */
	char key_file[512];
	int  strict;              /* never let a byte the proxy could not see through */
	int  hold_ms;             /* how long a client record waits for its key */
	int  response_timeout_ms; /* server answer deadline, then the flow is closed */
	void (*need_keys)(void *user);   /* drain pending key events into tls_keys */
	void (*log)(void *user, const char *line);
	void *user;
};

struct splice_bridge_stats {
	unsigned long flows;
	unsigned long requests;          /* handed to the proxy */
	unsigned long delivered;         /* written to the server, once each */
	unsigned long rejected_duplicate;/* already delivered: 409 */
	unsigned long rejected_late;     /* dropped or abandoned before: 410 */
	unsigned long rejected_unknown;  /* port never issued: 400 */
	unsigned long dropped_by_proxy;
	unsigned long abandoned;
	unsigned long bypassed;          /* flows relayed without the proxy */
};

/* Start the UPSTREAM listener. Returns 0 or -1. */
int splice_bridge_start(const struct splice_bridge_cfg *cfg);
int splice_bridge_upstream_port(void);

/*
 * Run one spliced connection in the calling thread until either side closes.
 * client_fd: the app's connection (its ClientHello not consumed yet);
 * server_fd: connected to the real server. Both are closed on return.
 * authority/port: what the app asked for (SNI wins when present).
 * Returns 0 on a clean end, -1 if the connection had to be torn down.
 */
int splice_bridge_run_flow(int client_fd, int server_fd, uint32_t pid,
			   const char *authority, int port);

void splice_bridge_get_stats(struct splice_bridge_stats *out);
void splice_bridge_stop(void);

#endif /* EPTRACER_SPLICE_BRIDGE_H */
