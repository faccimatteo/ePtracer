/*
 * Splice bridge — see include/splice_bridge.h.
 */

#include "splice_bridge.h"
#include "http1_frame.h"
#include "proxy_bridge.h"
#include "tls_keys.h"
#include "tls_splice.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/ssl.h>

/* Requests of one connection that can be in flight at once: far beyond what an
 * HTTP/1.1 client does on a single connection */
#define BRIDGE_MSG_RING        256
/* Requests of one HTTP/2 connection handed to the proxy at once, each on its
 * own connection (what a browser opens per host). HTTP/1.1 answers must reach
 * the app in order, so one at a time there. */
#define BRIDGE_FRONT_PARALLEL  8
/* How long a request whose proxy connection died unanswered waits before it is
 * sent again: the proxy may still be forwarding the first copy */
#define BRIDGE_RESEND_GRACE_MS 300
/* Biggest message buffered whole on its way through the proxy */
#define BRIDGE_MAX_MESSAGE     (64u * 1024 * 1024)
#define BRIDGE_DEFAULT_TIMEOUT (120 * 1000)

enum msg_state {
	MSG_FREE = 0,
	MSG_PENDING,
	MSG_DELIVERED,
	MSG_DROPPED,
	MSG_ABANDONED,
};

struct dbuf {
	char  *p;
	size_t len, cap;
};

struct bridge_msg {
	uint64_t n;
	enum msg_state state;
	int is_head;
	struct dbuf req;         /* the request as the proxy gets it, until answered */
	uint16_t port;           /* its CONNECT port towards the proxy: its identity */
	int32_t app_stream;      /* HTTP/2: the app's stream; 0 on HTTP/1.1 */
	int32_t srv_stream;      /* HTTP/2: the stream it was delivered on */
	struct dbuf resp;        /* HTTP/2: the server's answer, as HTTP/1.1 */
	int resp_state;          /* HTTP/2: 0 waiting, 1 complete, -1 failed */
	int resends;             /* sent again after the proxy hung up unanswered */
	/* Each request travels on a connection to the proxy of its own, closed
	 * once answered: what comes back on it can only be its answer. */
	struct proxy_front *front;
	struct dbuf front_in;
	int sending;             /* being handed to a new connection right now */
	int answered;            /* the app has its answer */
	/* The proxy hung up on it without answering. If it was delivered the app
	 * gets the server's answer straight from UPSTREAM (the proxy did see it
	 * on its way); if not, it is sent again after a grace period, in case the
	 * proxy was still about to forward it. */
	int lost;
	uint64_t lost_ms;
	struct dbuf answer;      /* the server's answer, kept until the app has one */
};

struct bridge_h2;

struct bridge_flow {
	uint64_t id;
	int refs;                         /* under bridge_lock */
	struct bridge_flow *next;

	pthread_mutex_t lock;             /* everything below */
	pthread_cond_t  cond;             /* server bytes arrived, or the flow ended */
	int alive;
	int client_fd, server_fd;
	uint32_t pid;
	char authority[256];
	int port;
	struct tls_splice *s;
	int bypass;                       /* not HTTP/1.x: relayed without the proxy */
	int opaque_logged;                /* the "relayed opaque" note was already made */
	int fail;                         /* tear down after the current step */

	/* app -> proxy. Requests go to the proxy one at a time: the next one is
	 * sent when the previous answer is back, which never relies on the proxy
	 * supporting pipelining, and lets a request the app cancelled while it
	 * waited in the queue never be shown at all. */
	struct dbuf c2s;                  /* app plaintext not framed yet */
	uint64_t next_msg;
	struct bridge_msg msgs[BRIDGE_MSG_RING];
	struct bridge_h2 *h2;             /* the app negotiated HTTP/2 */

	/* proxy -> app */
	uint64_t front_floor;             /* oldest request not settled yet */
	struct proxy_front *front;        /* after a 101: the app side of the stream */

	/* server -> UPSTREAM */
	struct dbuf resp;
	int server_closed;

	/* After a 101 (WebSocket) the connection carries two byte streams, both
	 * through the proxy: app <-> FRONT here, and the UPSTREAM connection that
	 * delivered the upgrade <-> the server (bridge_ws_relay()). */
	int ws;                           /* the server answered 101 */
	int ws_front;                     /* the proxy's 101 reached the app as well */
	int ws_evfd;                      /* wakes the UPSTREAM relay */
	struct dbuf ws_out;               /* app bytes waiting for FRONT */
};

/* HTTP/2 on both legs of the app's session (tracers/splice_bridge_h2.c) */
static int  bridge_h2_detect(const uint8_t *b, size_t n);
static struct bridge_h2 *bridge_h2_new(struct bridge_flow *f);
static void bridge_h2_free(struct bridge_h2 *h);
static int  bridge_h2_app_data(struct bridge_flow *f, const uint8_t *b, size_t n);
static int  bridge_h2_server_data(struct bridge_flow *f, const uint8_t *b, size_t n);
static void bridge_request_host(const char *req, size_t len, char *out, size_t cap);
static void bridge_request_path(const char *req, size_t len, char *out, size_t cap);
static int  bridge_h2_deliver(struct bridge_flow *f, struct bridge_msg *m,
			      const char *req, size_t len);
static int  bridge_h2_app_response(struct bridge_flow *f, struct bridge_msg *m,
				   const char *resp, size_t len);

static uint64_t bridge_now_ms(void);

/*
 * Request identity, with nothing added to the request. Each one goes to the
 * proxy as CONNECT host:<a port of its own>; the proxy opens its upstream to
 * that same destination, so the port UPSTREAM is asked for names the request.
 * A port is only reused half an hour after it was issued, and never while its
 * request still waits: a late copy (Repeater, a retry) can only ever point at
 * its own request, which refuses it.
 */
#define BRIDGE_PORT_FIRST    10000
#define BRIDGE_PORT_COUNT    55000
#define BRIDGE_PORT_QUIET_MS (30 * 60 * 1000)

struct bridge_port {
	uint64_t flow, msg;
	uint64_t issued_ms;
	int used;
};
static struct bridge_port bridge_ports[BRIDGE_PORT_COUNT];
static unsigned bridge_port_cursor;

static struct splice_bridge_cfg bridge_cfg;
static struct splice_bridge_stats bridge_stats;
static pthread_mutex_t bridge_lock = PTHREAD_MUTEX_INITIALIZER;
static struct bridge_flow *bridge_flows;
static uint64_t bridge_next_id = 1;
static SSL_CTX *bridge_upstream_ctx;
static int bridge_listen_fd = -1;
static int bridge_port;
static volatile int bridge_running;
static pthread_t bridge_accept_thread;

/* ---- small helpers ----------------------------------------------------- */

static void bridge_log(const char *fmt, ...)
{
	if (!bridge_cfg.log)
		return;
	char line[512];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	bridge_cfg.log(bridge_cfg.user, line);
}

static void bridge_count(unsigned long *counter)
{
	pthread_mutex_lock(&bridge_lock);
	(*counter)++;
	pthread_mutex_unlock(&bridge_lock);
}

static int dbuf_put(struct dbuf *b, const void *d, size_t n)
{
	if (n > BRIDGE_MAX_MESSAGE * 2 || b->len > BRIDGE_MAX_MESSAGE * 2 - n)
		return -1;
	if (b->len + n > b->cap) {
		size_t cap = b->cap ? b->cap : 16384;
		while (cap < b->len + n)
			cap *= 2;
		char *p = realloc(b->p, cap);
		if (!p)
			return -1;
		b->p = p;
		b->cap = cap;
	}
	memcpy(b->p + b->len, d, n);
	b->len += n;
	return 0;
}

static void dbuf_drop(struct dbuf *b, size_t n)
{
	if (n >= b->len) {
		b->len = 0;
		return;
	}
	memmove(b->p, b->p + n, b->len - n);
	b->len -= n;
}

static void dbuf_free(struct dbuf *b)
{
	free(b->p);
	memset(b, 0, sizeof(*b));
}

static int bridge_write_all(int fd, const void *buf, size_t len)
{
	const char *p = buf;
	while (len) {
		ssize_t n = write(fd, p, len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return -1;
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

static void bridge_nodelay(int fd)
{
	int one = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

static struct bridge_msg *bridge_msg(struct bridge_flow *f, uint64_t n)
{
	struct bridge_msg *m = &f->msgs[n % BRIDGE_MSG_RING];
	return m->state != MSG_FREE && m->n == n ? m : NULL;
}

/* ---- flow table -------------------------------------------------------- */

static struct bridge_flow *flow_get(uint64_t id)
{
	struct bridge_flow *f;
	pthread_mutex_lock(&bridge_lock);
	for (f = bridge_flows; f; f = f->next)
		if (f->id == id) {
			f->refs++;
			break;
		}
	pthread_mutex_unlock(&bridge_lock);
	return f;
}

static void flow_put(struct bridge_flow *f)
{
	int last;
	pthread_mutex_lock(&bridge_lock);
	last = --f->refs == 0;
	if (last) {
		struct bridge_flow **pp = &bridge_flows;
		while (*pp && *pp != f)
			pp = &(*pp)->next;
		if (*pp)
			*pp = f->next;
	}
	pthread_mutex_unlock(&bridge_lock);
	if (!last)
		return;
	bridge_h2_free(f->h2);
	tls_splice_free(f->s);
	if (f->ws_evfd >= 0)
		close(f->ws_evfd);
	dbuf_free(&f->ws_out);
	dbuf_free(&f->c2s);
	dbuf_free(&f->resp);
	for (size_t i = 0; i < BRIDGE_MSG_RING; i++) {
		dbuf_free(&f->msgs[i].req);
		dbuf_free(&f->msgs[i].resp);
		dbuf_free(&f->msgs[i].front_in);
		dbuf_free(&f->msgs[i].answer);
	}
	pthread_mutex_destroy(&f->lock);
	pthread_cond_destroy(&f->cond);
	free(f);
}

/* ---- the at-most-once point -------------------------------------------- */

/*
 * The only place a request coming back from the proxy can reach the server.
 * Called with f->lock held. Returns the HTTP status to answer the proxy with
 * when the request is refused, 0 when it was delivered.
 */
static int bridge_deliver(struct bridge_flow *f, uint64_t n, const char *req, size_t len)
{
	struct bridge_msg *m = bridge_msg(f, n);

	if (!m) {
		bridge_count(&bridge_stats.rejected_unknown);
		bridge_log("[bridge] %llu.%llu refused: never issued",
			   (unsigned long long)f->id, (unsigned long long)n);
		return 400;
	}
	if (m->state == MSG_DELIVERED) {
		bridge_count(&bridge_stats.rejected_duplicate);
		bridge_log("[bridge] %llu.%llu refused: already delivered (duplicate)",
			   (unsigned long long)f->id, (unsigned long long)n);
		return 409;
	}
	if (m->state != MSG_PENDING || !f->alive) {
		bridge_count(&bridge_stats.rejected_late);
		bridge_log("[bridge] %llu.%llu refused: %s",
			   (unsigned long long)f->id, (unsigned long long)n,
			   m->state == MSG_DROPPED ? "the proxy already answered the app" :
			   "the app abandoned it");
		return 410;
	}
	/* Delivered from now on, whatever the write below does: a partial write
	 * may already have reached the server, and it must never be retried. */
	m->state = MSG_DELIVERED;
	bridge_count(&bridge_stats.delivered);
	char dhost[256], dpath[512];
	bridge_request_host(req, len, dhost, sizeof(dhost));
	bridge_request_path(req, len, dpath, sizeof(dpath));
	bridge_log("[bridge] %llu.%llu %s%s delivered (%zu bytes)",
		   (unsigned long long)f->id, (unsigned long long)n,
		   dhost[0] ? dhost : f->authority, dpath, len);
	int rc = f->h2 ? bridge_h2_deliver(f, m, req, len) :
			 tls_splice_send(f->s, SPLICE_C2S, TLS_CT_APPLICATION_DATA,
					 (const uint8_t *)req, len);
	if (rc != 0) {
		/* HTTP/1.1 has no way to resynchronize after a broken write; an
		 * HTTP/2 stream that could not be opened only fails itself */
		if (!f->h2)
			f->fail = 1;
		return 502;
	}
	return 0;
}

/* The app is gone (or the proxy is): whatever it still waits for must never
 * be delivered. Called with f->lock held. */
static void bridge_settle_pending(struct bridge_flow *f, enum msg_state to)
{
	for (size_t i = 0; i < BRIDGE_MSG_RING; i++)
		if (f->msgs[i].state == MSG_PENDING) {
			f->msgs[i].state = to;
			bridge_count(to == MSG_DROPPED ? &bridge_stats.dropped_by_proxy :
						    &bridge_stats.abandoned);
			bridge_log("[bridge] %llu.%llu %s", (unsigned long long)f->id,
				   (unsigned long long)f->msgs[i].n,
				   to == MSG_DROPPED ? "dropped (proxy closed)" : "abandoned by the app");
		}
}

/* Wake the UPSTREAM relay of a WebSocket flow: server bytes, or the end */
static void bridge_ws_wake(struct bridge_flow *f)
{
	uint64_t one = 1;
	if (f->ws_evfd >= 0 && write(f->ws_evfd, &one, sizeof(one)) < 0) {
		/* the counter is full: the relay is awake already */
	}
}

/* ---- splice hooks (called with f->lock held) --------------------------- */

static int bridge_forward(void *user, enum splice_dir to, const uint8_t *b, size_t n)
{
	struct bridge_flow *f = user;
	return bridge_write_all(to == SPLICE_C2S ? f->server_fd : f->client_fd, b, n);
}

static void bridge_need_keys(void *user)
{
	(void)user;
	if (bridge_cfg.need_keys)
		bridge_cfg.need_keys(bridge_cfg.user);
}

/* Is the request that owns port slot p still waiting? Called with bridge_lock
 * held; the request's state is read without its flow lock, a stale value only
 * delays the reuse. */
static int bridge_port_waiting(const struct bridge_port *p)
{
	for (struct bridge_flow *f = bridge_flows; f; f = f->next)
		if (f->id == p->flow) {
			const struct bridge_msg *m = &f->msgs[p->msg % BRIDGE_MSG_RING];
			return m->n == p->msg && m->state == MSG_PENDING;
		}
	return 0;
}

static uint16_t bridge_port_take(uint64_t flow, uint64_t msg)
{
	uint64_t now = bridge_now_ms();
	uint16_t port = 0;

	pthread_mutex_lock(&bridge_lock);
	for (unsigned k = 0; k < BRIDGE_PORT_COUNT && !port; k++) {
		unsigned i = (bridge_port_cursor + k) % BRIDGE_PORT_COUNT;
		struct bridge_port *p = &bridge_ports[i];
		if (p->used && (now - p->issued_ms < BRIDGE_PORT_QUIET_MS || bridge_port_waiting(p)))
			continue;
		*p = (struct bridge_port){ flow, msg, now, 1 };
		bridge_port_cursor = i + 1;
		port = (uint16_t)(BRIDGE_PORT_FIRST + i);
	}
	pthread_mutex_unlock(&bridge_lock);
	return port;
}

/* The request a CONNECT port stands for. 0, or -1 if the port was never issued. */
static int bridge_port_lookup(unsigned port, uint64_t *flow, uint64_t *msg)
{
	int rc = -1;
	if (port < BRIDGE_PORT_FIRST || port >= BRIDGE_PORT_FIRST + BRIDGE_PORT_COUNT)
		return -1;
	pthread_mutex_lock(&bridge_lock);
	const struct bridge_port *p = &bridge_ports[port - BRIDGE_PORT_FIRST];
	if (p->used) {
		*flow = p->flow;
		*msg = p->msg;
		rc = 0;
	}
	pthread_mutex_unlock(&bridge_lock);
	return rc;
}

/*
 * Register one complete HTTP/1.1 request of the app (for HTTP/2, the stream
 * already rendered as HTTP/1.1) as PENDING and queue it for the proxy, as it
 * is. Called with f->lock held. Returns 0, or -1 when it cannot be queued.
 */
static int bridge_new_msg(struct bridge_flow *f, const char *req, size_t total,
			  size_t head_len, int is_head, const char *method, int32_t app_stream)
{
	struct bridge_msg *slot = &f->msgs[f->next_msg % BRIDGE_MSG_RING];
	(void)head_len;
	if (slot->state == MSG_PENDING)
		return -1;   /* 256 requests waiting on one connection */

	uint16_t port = bridge_port_take(f->id, f->next_msg);
	if (!port)
		return -1;   /* every port issued in the last half hour still in use */

	dbuf_free(&slot->req);
	dbuf_free(&slot->resp);
	if (dbuf_put(&slot->req, req, total) != 0)
		return -1;
	slot->port = port;

	slot->n = f->next_msg++;
	slot->state = MSG_PENDING;
	slot->is_head = is_head;
	slot->app_stream = app_stream;
	slot->srv_stream = 0;
	slot->resp_state = 0;
	slot->resends = 0;
	slot->sending = 0;
	slot->answered = 0;
	slot->lost = 0;
	slot->front_in.len = 0;
	dbuf_free(&slot->answer);
	bridge_count(&bridge_stats.requests);
	char qhost[256], qpath[512];
	bridge_request_host(req, total, qhost, sizeof(qhost));
	bridge_request_path(req, total, qpath, sizeof(qpath));
	bridge_log("[bridge] %llu.%llu %s %s%s queued for the proxy%s", (unsigned long long)f->id,
		   (unsigned long long)slot->n, method, qhost[0] ? qhost : f->authority, qpath,
		   app_stream ? " (HTTP/2)" : "");
	return 0;
}

/* App plaintext: cut it into requests, tag each, queue them for the proxy. */
static void bridge_app_data(struct bridge_flow *f, const uint8_t *b, size_t n)
{
	if (f->ws) {
		/* the other protocol's bytes, for the proxy as they are */
		if (dbuf_put(&f->ws_out, b, n) != 0)
			f->fail = 1;
		return;
	}
	if (f->h2) {
		if (bridge_h2_app_data(f, b, n) != 0)
			f->fail = 1;
		return;
	}
	if (!f->bypass && f->next_msg == 0 && f->c2s.len == 0 && bridge_h2_detect(b, n)) {
		/* HTTP/2 connection preface: terminate HTTP/2 on both legs */
		f->h2 = bridge_h2_new(f);
		if (!f->h2 || bridge_h2_app_data(f, b, n) != 0)
			f->fail = 1;
		return;
	}
	if (f->bypass) {
		tls_splice_send(f->s, SPLICE_C2S, TLS_CT_APPLICATION_DATA, b, n);
		return;
	}
	if (dbuf_put(&f->c2s, b, n) != 0) {
		f->fail = 1;
		return;
	}

	for (;;) {
		struct h1_info info;
		enum h1_result r = h1_frame(f->c2s.p, f->c2s.len, H1_REQUEST, 0, &info);
		if (r == H1_INCOMPLETE)
			return;
		if (r != H1_COMPLETE || info.total > BRIDGE_MAX_MESSAGE) {
			/* Not something that can be framed. Never sent twice either:
			 * relayed once without the proxy, or not at all under strict. */
			if (bridge_cfg.strict) {
				bridge_log("[bridge] %llu: not HTTP/1.x, closed (strict)",
					   (unsigned long long)f->id);
				f->fail = 1;
				return;
			}
			bridge_log("[bridge] %llu: not HTTP/1.x (HTTP/2? upgraded?), relayed "
				   "without the proxy", (unsigned long long)f->id);
			bridge_count(&bridge_stats.bypassed);
			f->bypass = 1;
			tls_splice_send(f->s, SPLICE_C2S, TLS_CT_APPLICATION_DATA,
					(const uint8_t *)f->c2s.p, f->c2s.len);
			f->c2s.len = 0;
			return;
		}

		if (bridge_new_msg(f, f->c2s.p, info.total, info.head_len, info.is_head,
				   info.method, 0) != 0) {
			f->fail = 1;
			return;
		}
		dbuf_drop(&f->c2s, info.total);
	}
}

static void bridge_plaintext(void *user, enum splice_dir dir, uint8_t inner,
			     const uint8_t *b, size_t n)
{
	struct bridge_flow *f = user;

	if (dir == SPLICE_C2S) {
		if (inner == TLS_CT_APPLICATION_DATA) {
			bridge_app_data(f, b, n);
			return;
		}
		/* An alert from the app ends its interest in what is pending */
		if (inner == TLS_CT_ALERT)
			bridge_settle_pending(f, MSG_ABANDONED);
		/* alerts and post-handshake messages keep the session coherent */
		tls_splice_send(f->s, SPLICE_C2S, inner, b, n);
		return;
	}

	/* server -> app */
	if (inner == TLS_CT_APPLICATION_DATA && f->h2) {
		if (bridge_h2_server_data(f, b, n) != 0)
			f->fail = 1;
		pthread_cond_broadcast(&f->cond);
		return;
	}
	if (inner != TLS_CT_APPLICATION_DATA || f->bypass) {
		/* NewSessionTicket, KeyUpdate, alerts; or a bypassed flow */
		tls_splice_send(f->s, SPLICE_S2C, inner, b, n);
		return;
	}
	if (dbuf_put(&f->resp, b, n) != 0)
		f->fail = 1;
	pthread_cond_broadcast(&f->cond);
	bridge_ws_wake(f);
}

/* ---- FRONT: the proxy's answers to the app ----------------------------- */

static int bridge_seal_to_app(struct bridge_flow *f, uint8_t inner, const void *b, size_t n)
{
	if (!tls_splice_keyed(f->s, SPLICE_S2C) && tls_splice_prime(f->s, SPLICE_S2C) != 0) {
		bridge_log("[bridge] %llu: server key unknown, cannot answer the app",
			   (unsigned long long)f->id);
		return -1;
	}
	return tls_splice_send(f->s, SPLICE_S2C, inner, b, n);
}

/* Give the app the server's own answer to m (the proxy saw it, but its
 * connection to us died before it could pass it on). Called with f->lock held. */
static void bridge_answer_from_upstream(struct bridge_flow *f, struct bridge_msg *m,
					const char *resp, size_t len)
{
	bridge_log("[bridge] %llu.%llu: answered with the server's response (the proxy "
		   "connection was gone)", (unsigned long long)f->id, (unsigned long long)m->n);
	int rc = f->h2 ? bridge_h2_app_response(f, m, resp, len) :
			 bridge_seal_to_app(f, TLS_CT_APPLICATION_DATA, resp, len);
	if (rc != 0)
		f->fail = 1;
	m->answered = 1;
	m->lost = 0;
	dbuf_free(&m->req);
	dbuf_free(&m->answer);
}

/*
 * What the proxy sent back on m's connection: its answer, delivered to the app,
 * after which the connection is closed. Called with f->lock held.
 */
static void bridge_front_answer(struct bridge_flow *f, struct bridge_msg *m, int closed)
{
	while (m->front_in.len) {
		struct h1_info info;
		enum h1_result r = h1_frame(m->front_in.p, m->front_in.len, H1_RESPONSE,
					    m->is_head, &info);
		size_t take;

		if (r == H1_INCOMPLETE || (r == H1_UNTIL_CLOSE && !closed))
			return;
		if (r == H1_INVALID) {
			f->fail = 1;   /* the proxy speaks something else */
			return;
		}
		take = r == H1_COMPLETE ? info.total : m->front_in.len;

		int interim = r == H1_COMPLETE && info.status / 100 == 1 && info.status != 101;
		if (!interim && m->state == MSG_PENDING) {
			/* answered without ever reaching UPSTREAM: dropped in the
			 * proxy, or refused there. It can never be delivered now. */
			m->state = MSG_DROPPED;
			bridge_count(&bridge_stats.dropped_by_proxy);
			bridge_log("[bridge] %llu.%llu dropped: the proxy answered the app itself",
				   (unsigned long long)f->id, (unsigned long long)m->n);
		}
		int rc = f->h2 ? bridge_h2_app_response(f, m, m->front_in.p, take) :
				 bridge_seal_to_app(f, TLS_CT_APPLICATION_DATA, m->front_in.p, take);
		if (rc != 0) {
			f->fail = 1;
			return;
		}
		dbuf_drop(&m->front_in, take);
		if (interim)
			continue;

		m->answered = 1;
		dbuf_free(&m->req);   /* answered: never sent again */
		dbuf_free(&m->answer);
		if (r == H1_COMPLETE && info.status == 101 && f->ws) {
			/* this connection now carries the other protocol, both ways */
			f->ws_front = 1;
			f->front = m->front;
			m->front = NULL;
			if (m->front_in.len &&
			    bridge_seal_to_app(f, TLS_CT_APPLICATION_DATA, m->front_in.p, m->front_in.len) != 0)
				f->fail = 1;
			dbuf_free(&m->front_in);
			return;
		}
		proxy_front_close(m->front);
		m->front = NULL;
		dbuf_free(&m->front_in);
		return;
	}
}

/*
 * The proxy closed m's connection without answering. Delivered: the app gets
 * the server's answer, now or when it comes. Not delivered: sent again after
 * BRIDGE_RESEND_GRACE_MS, unless the proxy forwards it meanwhile (should it
 * forward a second copy, UPSTREAM refuses it). Out of retries: a 502.
 * Called with f->lock held.
 */
static void bridge_front_lost(struct bridge_flow *f, struct bridge_msg *m)
{
	static const char lost[] =
		"HTTP/1.1 502 Bad Gateway\r\ncontent-type: text/plain\r\ncontent-length: 59\r\n\r\n"
		"ePtracer: the proxy closed the connection before answering\n";

	proxy_front_close(m->front);
	m->front = NULL;
	dbuf_free(&m->front_in);

	if (m->state == MSG_DELIVERED) {
		if (m->answer.len)
			bridge_answer_from_upstream(f, m, m->answer.p, m->answer.len);
		else
			m->lost = 1;   /* UPSTREAM hands the answer over when it comes */
		return;
	}
	if (m->state == MSG_PENDING && m->req.len && m->resends < 3) {
		m->lost = 1;
		m->lost_ms = bridge_now_ms();
		return;
	}
	if (m->state == MSG_PENDING) {
		m->state = MSG_DROPPED;
		bridge_count(&bridge_stats.dropped_by_proxy);
	}
	bridge_log("[bridge] %llu.%llu: the proxy closed the connection before answering",
		   (unsigned long long)f->id, (unsigned long long)m->n);
	int rc = f->h2 ? bridge_h2_app_response(f, m, lost, sizeof(lost) - 1) :
			 bridge_seal_to_app(f, TLS_CT_APPLICATION_DATA, lost, sizeof(lost) - 1);
	if (rc != 0)
		f->fail = 1;
	m->answered = 1;
	dbuf_free(&m->req);
}

/* ---- the flow thread --------------------------------------------------- */

/*
 * The host a request is for, as the proxy should see it: its Host header (for
 * HTTP/2, :authority rendered as host), not the SNI seen on the wire — with
 * Encrypted Client Hello that is only the provider's public name
 * (cloudflare-ech.com), the real one travels encrypted.
 */
static void bridge_request_host(const char *req, size_t len, char *out, size_t cap)
{
	struct h1_info info;
	out[0] = '\0';
	if (h1_frame(req, len, H1_REQUEST, 0, &info) != H1_COMPLETE)
		return;
	for (size_t i = 0; i + 6 < info.head_len; i++) {
		if (req[i] != '\n' || strncasecmp(req + i + 1, "host:", 5) != 0)
			continue;
		const char *v = req + i + 6, *end = req + info.head_len;
		while (v < end && (*v == ' ' || *v == '\t'))
			v++;
		const char *e = v;
		while (e < end && *e != '\r' && *e != ':' && *e != ' ')
			e++;   /* without any :port, the CONNECT carries the port */
		size_t n = (size_t)(e - v) < cap - 1 ? (size_t)(e - v) : cap - 1;
		memcpy(out, v, n);
		out[n] = '\0';
		return;
	}
}

/* The request target (origin-form path or absolute-form URI) from the start
 * line "METHOD SP TARGET SP VERSION", for diagnostics only. */
static void bridge_request_path(const char *req, size_t len, char *out, size_t cap)
{
	out[0] = '\0';
	size_t i = 0;
	while (i < len && req[i] != ' ' && req[i] != '\r' && req[i] != '\n')
		i++;                       /* skip METHOD */
	while (i < len && req[i] == ' ')
		i++;                       /* skip the space(s) */
	size_t start = i;
	while (i < len && req[i] != ' ' && req[i] != '\r' && req[i] != '\n')
		i++;                       /* TARGET */
	size_t n = i - start < cap - 1 ? i - start : cap - 1;
	memcpy(out, req + start, n);
	out[n] = '\0';
}

static struct proxy_front *bridge_front_connect(struct bridge_flow *f, const char *host,
						uint16_t port)
{
	struct proxy_bridge_cfg pc;
	struct proxy_front *pf = NULL;
	const char *sni = tls_splice_sni(f->s);
	const char *name = host && *host ? host : sni && *sni ? sni : f->authority;

	memset(&pc, 0, sizeof(pc));
	snprintf(pc.proxy_host, sizeof(pc.proxy_host), "%s", bridge_cfg.proxy_host);
	pc.proxy_port = bridge_cfg.proxy_port;
	snprintf(pc.ca_file, sizeof(pc.ca_file), "%s", bridge_cfg.proxy_ca);
	if (proxy_front_open(&pc, name, port, &pf) != 0) {
		bridge_log("[bridge] %llu: proxy %s:%d unreachable (%s), connection closed",
			   (unsigned long long)f->id, bridge_cfg.proxy_host, bridge_cfg.proxy_port,
			   proxy_bridge_last_error());
		return NULL;
	}
	bridge_nodelay(proxy_front_fd(pf));
	proxy_front_set_nonblocking(pf);
	return pf;
}

/* Is m settled as far as the proxy is concerned? */
static int bridge_msg_settled(const struct bridge_msg *m)
{
	return !m || (!m->front && !m->sending && (m->answered || m->state != MSG_PENDING));
}

/*
 * Hand the requests waiting for the proxy over, each on a new connection, as
 * many at once as the protocol allows. Requests the app gave up on while they
 * waited are skipped: the proxy never sees them. Flow thread only.
 */
static int bridge_flush_front(struct bridge_flow *f)
{
	if (f->ws) {
		struct dbuf out;
		pthread_mutex_lock(&f->lock);
		out = f->ws_out;
		memset(&f->ws_out, 0, sizeof(f->ws_out));
		pthread_mutex_unlock(&f->lock);
		int rc = !out.len || (f->front && proxy_front_write(f->front, out.p, out.len) == (long)out.len) ?
			 0 : -1;
		dbuf_free(&out);
		return rc;
	}

	for (;;) {
		struct dbuf out = { 0 };
		struct bridge_msg *pick = NULL;
		uint64_t n = 0;
		uint16_t port = 0;
		int inflight = 0, max = f->h2 ? BRIDGE_FRONT_PARALLEL : 1;
		uint64_t now = bridge_now_ms();

		pthread_mutex_lock(&f->lock);
		while (f->front_floor < f->next_msg && bridge_msg_settled(bridge_msg(f, f->front_floor)))
			f->front_floor++;
		for (uint64_t i = f->front_floor; i < f->next_msg; i++) {
			struct bridge_msg *m = bridge_msg(f, i);
			if (!m)
				continue;
			if (m->front || m->sending)
				inflight++;
			else if (!pick && m->state == MSG_PENDING && !m->answered && m->req.len &&
				 (!m->lost || now - m->lost_ms >= BRIDGE_RESEND_GRACE_MS))
				pick = m;
		}
		if (pick && inflight < max) {
			n = pick->n;
			port = pick->port;
			pick->sending = 1;
			if (pick->lost) {
				pick->lost = 0;
				pick->resends++;
				bridge_log("[bridge] %llu.%llu: never reached the server, sent to the "
					   "proxy again", (unsigned long long)f->id, (unsigned long long)n);
			}
			dbuf_put(&out, pick->req.p, pick->req.len);
		}
		pthread_mutex_unlock(&f->lock);
		if (!out.len)
			return 0;

		char host[256];
		bridge_request_host(out.p, out.len, host, sizeof(host));
		struct proxy_front *pf = bridge_front_connect(f, host, port);
		int wrote = pf && proxy_front_write(pf, out.p, out.len) == (long)out.len;
		dbuf_free(&out);

		pthread_mutex_lock(&f->lock);
		struct bridge_msg *m = bridge_msg(f, n);
		if (m) {
			m->sending = 0;
			m->front = pf;
			if (pf && !wrote)
				bridge_front_lost(f, m);
		} else {
			proxy_front_close(pf);
		}
		pthread_mutex_unlock(&f->lock);
		if (!pf)
			return -1;   /* fail closed: the proxy never saw the request */
	}
}

static uint64_t bridge_now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Make the silent fallback visible: when a connection cannot be decrypted it is
 * relayed byte for byte and never reaches the proxy. Say so once, with why. */
static void bridge_note_opaque(struct bridge_flow *f)
{
	if (f->opaque_logged || tls_splice_state(f->s) != SPLICE_OPAQUE)
		return;
	f->opaque_logged = 1;
	bridge_log("[bridge] %llu %s: not decryptable (keys missing or unsupported "
		   "cipher), relayed opaque — NOT shown to the proxy",
		   (unsigned long long)f->id, f->authority[0] ? f->authority : "?");
}

int splice_bridge_run_flow(int client_fd, int server_fd, uint32_t pid,
			   const char *authority, int port)
{
	struct bridge_flow *f = calloc(1, sizeof(*f));
	if (!f) {
		close(client_fd);
		close(server_fd);
		return -1;
	}
	pthread_mutex_init(&f->lock, NULL);
	pthread_cond_init(&f->cond, NULL);
	f->alive = 1;
	f->ws_evfd = -1;
	f->client_fd = client_fd;
	f->server_fd = server_fd;
	f->pid = pid;
	f->port = port;
	snprintf(f->authority, sizeof(f->authority), "%s", authority ? authority : "");
	bridge_nodelay(client_fd);
	bridge_nodelay(server_fd);

	struct tls_splice_hooks h = {
		.forward = bridge_forward,
		.plaintext = bridge_plaintext,
		.need_keys = bridge_need_keys,
		.user = f,
	};
	f->s = tls_splice_new(pid, 1u << SPLICE_C2S | 1u << SPLICE_S2C, &h);
	if (!f->s) {
		free(f);
		close(client_fd);
		close(server_fd);
		return -1;
	}
	tls_splice_set_policy(f->s, bridge_cfg.strict, bridge_cfg.hold_ms);

	pthread_mutex_lock(&bridge_lock);
	f->id = bridge_next_id++;
	f->refs = 1;
	f->next = bridge_flows;
	bridge_flows = f;
	bridge_stats.flows++;
	pthread_mutex_unlock(&bridge_lock);

	uint8_t buf[65536];
	int rc = 0;

	for (;;) {
		struct pollfd p[3 + BRIDGE_FRONT_PARALLEL];
		uint64_t pmsg[3 + BRIDGE_FRONT_PARALLEL];
		int np = 0, ic = -1, is = -1, iws = -1;
		p[np] = (struct pollfd){ client_fd, POLLIN, 0 }; ic = np++;
		if (!f->server_closed) { p[np] = (struct pollfd){ server_fd, POLLIN, 0 }; is = np++; }
		if (f->front) { p[np] = (struct pollfd){ proxy_front_fd(f->front), POLLIN, 0 }; iws = np++; }
		int first_front = np;
		pthread_mutex_lock(&f->lock);
		for (uint64_t i = f->front_floor; i < f->next_msg && np < (int)(sizeof(p) / sizeof(*p)); i++) {
			struct bridge_msg *m = bridge_msg(f, i);
			if (m && m->front) {
				pmsg[np] = i;
				p[np++] = (struct pollfd){ proxy_front_fd(m->front), POLLIN, 0 };
			}
		}
		pthread_mutex_unlock(&f->lock);

		/* short timeout: a request waiting out its resend grace period */
		if (poll(p, (nfds_t)np, 100) < 0) {
			if (errno == EINTR)
				continue;
			rc = -1;
			break;
		}

		if (p[ic].revents) {
			ssize_t n = read(client_fd, buf, sizeof(buf));
			if (n <= 0)
				break;   /* the app closed: pending requests are abandoned */
			pthread_mutex_lock(&f->lock);
			int r = tls_splice_feed(f->s, SPLICE_C2S, buf, (size_t)n);
			int fail = f->fail;
			bridge_note_opaque(f);
			pthread_mutex_unlock(&f->lock);
			if (r != 0 || fail || bridge_flush_front(f) != 0) {
				rc = -1;
				break;
			}
		}

		if (is >= 0 && p[is].revents) {
			ssize_t n = read(server_fd, buf, sizeof(buf));
			pthread_mutex_lock(&f->lock);
			int r = 0;
			if (n <= 0)
				f->server_closed = 1;
			else
				r = tls_splice_feed(f->s, SPLICE_S2C, buf, (size_t)n);
			pthread_cond_broadcast(&f->cond);
			bridge_ws_wake(f);
			int fail = f->fail;
			bridge_note_opaque(f);
			pthread_mutex_unlock(&f->lock);
			if (r != 0 || fail) {
				rc = -1;
				break;
			}
		}

		/* after a 101: the proxy's side of the stream, towards the app */
		if (iws >= 0 && p[iws].revents) {
			int closed = 0;
			do {
				long n = proxy_front_read(f->front, buf, sizeof(buf));
				if (n == PROXY_FRONT_AGAIN)
					break;
				if (n <= 0) {
					closed = 1;
					break;
				}
				pthread_mutex_lock(&f->lock);
				if (bridge_seal_to_app(f, TLS_CT_APPLICATION_DATA, buf, (size_t)n) != 0)
					f->fail = 1;
				pthread_mutex_unlock(&f->lock);
			} while (proxy_front_pending(f->front) > 0);
			if (closed)
				break;   /* the stream is over */
		}

		/* answers from the proxy, one connection per request */
		for (int k = first_front; k < np; k++) {
			if (!p[k].revents)
				continue;
			pthread_mutex_lock(&f->lock);
			struct bridge_msg *m = bridge_msg(f, pmsg[k]);
			struct proxy_front *pf = m ? m->front : NULL;
			pthread_mutex_unlock(&f->lock);
			if (!pf)
				continue;
			int closed = 0;
			do {
				long n = proxy_front_read(pf, buf, sizeof(buf));
				if (n == PROXY_FRONT_AGAIN)
					break;   /* a ticket or a partial record, nothing yet */
				if (n <= 0) {
					closed = 1;
					break;
				}
				dbuf_put(&m->front_in, buf, (size_t)n);
			} while (proxy_front_pending(pf) > 0);

			pthread_mutex_lock(&f->lock);
			bridge_front_answer(f, m, closed);
			if (closed && m->front)
				bridge_front_lost(f, m);
			pthread_mutex_unlock(&f->lock);
		}
		if (bridge_flush_front(f) != 0) {
			rc = -1;
			break;
		}

		pthread_mutex_lock(&f->lock);
		int fail = f->fail;
		pthread_mutex_unlock(&f->lock);
		if (fail) {
			rc = -1;
			break;
		}
	}

	/* From here nothing pending can be delivered any more */
	pthread_mutex_lock(&f->lock);
	f->alive = 0;
	bridge_settle_pending(f, MSG_ABANDONED);
	pthread_cond_broadcast(&f->cond);
	bridge_ws_wake(f);
	pthread_mutex_unlock(&f->lock);

	proxy_front_close(f->front);
	f->front = NULL;
	for (size_t i = 0; i < BRIDGE_MSG_RING; i++) {
		proxy_front_close(f->msgs[i].front);
		f->msgs[i].front = NULL;
	}
	close(client_fd);
	close(server_fd);
	flow_put(f);
	return rc;
}

/* ---- UPSTREAM: requests coming back from the proxy --------------------- */

static void bridge_reply(SSL *ssl, int status, const char *why)
{
	char resp[512];
	const char *text = status == 409 ? "Conflict" : status == 410 ? "Gone" :
			   status == 400 ? "Bad Request" : status == 504 ? "Gateway Timeout" :
			   "Bad Gateway";
	int n = snprintf(resp, sizeof(resp),
			 "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\n"
			 "Content-Length: %zu\r\n\r\n%s\n",
			 status, text, strlen(why) + 1, why);
	SSL_write(ssl, resp, n);
}

/* Read one whole request from the proxy into *b. 1 ok, 0 closed, -1 error. */
static int bridge_read_request(SSL *ssl, struct dbuf *b, struct h1_info *info)
{
	char tmp[65536];
	for (;;) {
		if (b->len) {
			enum h1_result r = h1_frame(b->p, b->len, H1_REQUEST, 0, info);
			if (r == H1_COMPLETE)
				return 1;
			if (r != H1_INCOMPLETE)
				return -1;
		}
		int n = SSL_read(ssl, tmp, sizeof(tmp));
		if (n <= 0)
			return b->len ? -1 : 0;
		if (dbuf_put(b, tmp, (size_t)n) != 0)
			return -1;
	}
}

/* Wait for the server's answer to a delivered request and hand it back.
 * Called with f->lock held; returns with it held. */
static int bridge_take_response(struct bridge_flow *f, struct bridge_msg *m, int is_head,
				struct dbuf *out)
{
	int timeout = bridge_cfg.response_timeout_ms > 0 ? bridge_cfg.response_timeout_ms :
							  BRIDGE_DEFAULT_TIMEOUT;
	uint64_t deadline = bridge_now_ms() + (uint64_t)timeout;

	for (;;) {
		if (f->h2) {
			/* HTTP/2 answers are routed by stream, not by order */
			if (m->resp_state == 1) {
				dbuf_put(out, m->resp.p, m->resp.len);
				dbuf_free(&m->resp);
				return 0;
			}
			if (m->resp_state < 0)
				return -1;
		} else if (f->resp.len) {
			struct h1_info info;
			enum h1_result r = h1_frame(f->resp.p, f->resp.len, H1_RESPONSE, is_head, &info);
			size_t take = 0;
			if (r == H1_COMPLETE)
				take = info.total;
			else if (r == H1_UNTIL_CLOSE && f->server_closed)
				take = f->resp.len;
			else if (r == H1_INVALID)
				return -1;
			if (take) {
				dbuf_put(out, f->resp.p, take);
				dbuf_drop(&f->resp, take);
				/* an interim 1xx: the final answer follows */
				if (r == H1_COMPLETE && info.status / 100 == 1 && info.status != 101)
					continue;
				return 0;
			}
		}
		if (!f->alive || f->server_closed || (f->fail && !f->h2))
			return -1;
		uint64_t now = bridge_now_ms();
		if (now >= deadline)
			return -2;
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		uint64_t wait = deadline - now < 200 ? deadline - now : 200;
		ts.tv_nsec += (long)(wait * 1000000);
		ts.tv_sec += ts.tv_nsec / 1000000000;
		ts.tv_nsec %= 1000000000;
		pthread_cond_timedwait(&f->cond, &f->lock, &ts);
	}
}

static int bridge_ssl_write_all(SSL *ssl, int fd, const char *p, size_t len)
{
	while (len) {
		int n = SSL_write(ssl, p, (int)len);
		if (n > 0) {
			p += n;
			len -= (size_t)n;
			continue;
		}
		int e = SSL_get_error(ssl, n);
		struct pollfd pf = { fd, e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, 0 };
		if ((e != SSL_ERROR_WANT_WRITE && e != SSL_ERROR_WANT_READ) || poll(&pf, 1, 10000) <= 0)
			return -1;
	}
	return 0;
}

/*
 * After the server's 101, this UPSTREAM connection is the proxy's end of the
 * server side of the stream: server bytes go to the proxy, and what the proxy
 * sends (the app's messages, as it let them through) goes into the app's
 * session towards the server. Holds a reference to f; returns when either end
 * closes, and then ends the whole connection.
 */
static void bridge_ws_relay(SSL *ssl, int fd, struct bridge_flow *f)
{
	char buf[65536];
	int fl = fcntl(fd, F_GETFL);

	if (fl >= 0)
		fcntl(fd, F_SETFL, fl | O_NONBLOCK);

	for (;;) {
		struct dbuf out;
		int done;

		pthread_mutex_lock(&f->lock);
		out = f->resp;
		memset(&f->resp, 0, sizeof(f->resp));
		done = !f->alive || f->fail || (f->server_closed && !out.len);
		pthread_mutex_unlock(&f->lock);

		int bad = out.len && bridge_ssl_write_all(ssl, fd, out.p, out.len) != 0;
		dbuf_free(&out);
		if (bad || done)
			break;

		if (!SSL_pending(ssl)) {
			struct pollfd p[2] = { { fd, POLLIN, 0 }, { f->ws_evfd, POLLIN, 0 } };
			if (poll(p, 2, 500) < 0 && errno != EINTR)
				break;
			if (p[1].revents & POLLIN) {
				uint64_t v;
				if (read(f->ws_evfd, &v, sizeof(v)) < 0) {
					/* nothing to clear */
				}
			}
			if (!(p[0].revents & (POLLIN | POLLHUP | POLLERR)))
				continue;
		}

		int closed = 0;
		for (;;) {
			int n = SSL_read(ssl, buf, sizeof(buf));
			if (n > 0) {
				pthread_mutex_lock(&f->lock);
				int r = tls_splice_send(f->s, SPLICE_C2S, TLS_CT_APPLICATION_DATA,
							(const uint8_t *)buf, (size_t)n);
				pthread_mutex_unlock(&f->lock);
				if (r != 0) {
					closed = 1;
					break;
				}
				continue;
			}
			int e = SSL_get_error(ssl, n);
			if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
				closed = 1;
			break;
		}
		if (closed)
			break;
	}

	/* one end of the stream is gone: so is the connection */
	pthread_mutex_lock(&f->lock);
	f->fail = 1;
	shutdown(f->client_fd, SHUT_RDWR);
	pthread_mutex_unlock(&f->lock);
	bridge_log("[bridge] %llu: switched-protocol stream ended", (unsigned long long)f->id);
}

static void *bridge_upstream_conn(void *arg)
{
	int fd = (int)(intptr_t)arg;
	SSL *ssl = NULL;
	char head[4096];
	size_t used = 0;

	/* CONNECT host:port from the proxy, answered before any TLS */
	while (used < sizeof(head) - 1) {
		ssize_t n = read(fd, head + used, sizeof(head) - 1 - used);
		if (n <= 0)
			goto out;
		used += (size_t)n;
		head[used] = '\0';
		if (strstr(head, "\r\n\r\n"))
			break;
	}
	if (strncmp(head, "CONNECT ", 8) != 0) {
		static const char nope[] = "HTTP/1.1 405 Method Not Allowed\r\n"
			"Content-Length: 0\r\nConnection: close\r\n\r\n";
		bridge_write_all(fd, nope, sizeof(nope) - 1);
		goto out;
	}
	static const char ok[] = "HTTP/1.1 200 Connection established\r\n\r\n";
	if (bridge_write_all(fd, ok, sizeof(ok) - 1) != 0)
		goto out;

	/* CONNECT host:port — the port names the request (see bridge_port_take) */
	unsigned cport = 0;
	{
		char *sp = strchr(head + 8, ' '), *colon = NULL;
		if (sp)
			*sp = '\0';
		colon = strrchr(head + 8, ':');
		if (colon)
			cport = (unsigned)atoi(colon + 1);
	}

	ssl = SSL_new(bridge_upstream_ctx);
	if (!ssl)
		goto out;
	SSL_set_fd(ssl, fd);
	if (SSL_accept(ssl) != 1)
		goto out;

	struct dbuf req = { 0 };
	for (;;) {
		struct h1_info info;
		int r = bridge_read_request(ssl, &req, &info);
		if (r <= 0)
			break;

		size_t len = info.total;
		uint64_t id = 0, n = 0;
		if (bridge_port_lookup(cport, &id, &n) != 0) {
			bridge_count(&bridge_stats.rejected_unknown);
			bridge_log("[bridge] request for port %u refused: not a request of a spliced "
				   "connection", cport);
			bridge_reply(ssl, 400, "ePtracer: not a request of a spliced connection "
					      "(its CONNECT port was never issued)");
			dbuf_drop(&req, len);
			continue;
		}

		struct bridge_flow *f = flow_get(id);
		if (!f) {
			bridge_count(&bridge_stats.rejected_late);
			bridge_log("[bridge] %llu.%llu refused: the connection is gone",
				   (unsigned long long)id, (unsigned long long)n);
			bridge_reply(ssl, 410, "ePtracer: the app connection is gone, not delivered");
			dbuf_drop(&req, len);
			continue;
		}

		struct dbuf answer = { 0 };
		int status = 0, ws = 0;
		pthread_mutex_lock(&f->lock);
		struct bridge_msg *m = bridge_msg(f, n);
		int is_head = m ? m->is_head : 0;
		status = bridge_deliver(f, n, req.p, len);
		if (status == 0) {
			int t = bridge_take_response(f, m, is_head, &answer);
			if (t == -2) {
				status = 504;
				if (!f->h2) {
					/* HTTP/1.1: an answer arriving later would be
					 * attributed to the next request */
					f->fail = 1;
					shutdown(f->client_fd, SHUT_RDWR);
				}
			} else if (t != 0) {
				status = 502;
			}
			if (status == 0 && m && !m->answered) {
				if (m->lost)
					bridge_answer_from_upstream(f, m, answer.p, answer.len);
				else
					dbuf_put(&m->answer, answer.p, answer.len);
			}
			struct h1_info ai;
			if (status == 0 && !f->h2 &&
			    h1_frame(answer.p, answer.len, H1_RESPONSE, 0, &ai) == H1_COMPLETE &&
			    ai.status == 101) {
				/* WebSocket: this connection becomes the proxy's end of
				 * the server side; whatever the server already sent behind
				 * the 101 (a gateway's HELLO) is still in f->resp */
				f->ws = 1;
				f->ws_evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
				ws = f->ws_evfd >= 0;
				if (!ws)
					f->fail = 1;
				bridge_log("[bridge] %llu: switched protocols (WebSocket?), now "
					   "a byte stream through the proxy", (unsigned long long)f->id);
			}
		}
		pthread_mutex_unlock(&f->lock);
		if (!ws)
			flow_put(f);

		if (status == 0)
			SSL_write(ssl, answer.p, (int)answer.len);
		else
			bridge_reply(ssl, status,
				     status == 409 ? "ePtracer: already delivered once, not sent again" :
				     status == 410 ? "ePtracer: dropped or abandoned, not delivered" :
				     status == 504 ? "ePtracer: delivered, the server did not answer in time" :
				     status == 400 ? "ePtracer: unknown request" :
				     "ePtracer: the server connection failed");
		dbuf_free(&answer);
		dbuf_drop(&req, len);
		if (ws) {
			bridge_ws_relay(ssl, fd, f);
			flow_put(f);
			break;   /* this connection was the stream */
		}
	}
	dbuf_free(&req);
out:
	if (ssl) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	close(fd);
	return NULL;
}

static void *bridge_accept_loop(void *unused)
{
	(void)unused;
	while (bridge_running) {
		struct pollfd p = { bridge_listen_fd, POLLIN, 0 };
		if (poll(&p, 1, 300) <= 0)
			continue;
		struct sockaddr_in peer;
		socklen_t pl = sizeof(peer);
		int fd = accept(bridge_listen_fd, (struct sockaddr *)&peer, &pl);
		if (fd < 0)
			continue;
		/* only the proxy, on this machine */
		if (peer.sin_family != AF_INET ||
		    (ntohl(peer.sin_addr.s_addr) >> 24) != 127) {
			close(fd);
			continue;
		}
		bridge_nodelay(fd);
		pthread_t t;
		if (pthread_create(&t, NULL, bridge_upstream_conn, (void *)(intptr_t)fd) != 0) {
			close(fd);
			continue;
		}
		pthread_detach(t);
	}
	return NULL;
}

int splice_bridge_start(const struct splice_bridge_cfg *cfg)
{
	bridge_cfg = *cfg;
	if (bridge_cfg.hold_ms <= 0)
		bridge_cfg.hold_ms = 200;

	bridge_upstream_ctx = proxy_upstream_ctx(cfg->cert_file, cfg->key_file);
	if (!bridge_upstream_ctx)
		return -1;

	bridge_listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	int one = 1;
	setsockopt(bridge_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	struct sockaddr_in a = { .sin_family = AF_INET,
				 .sin_port = htons((uint16_t)cfg->upstream_port) };
	inet_pton(AF_INET, cfg->upstream_host[0] ? cfg->upstream_host : "127.0.0.1", &a.sin_addr);
	if (bridge_listen_fd < 0 || bind(bridge_listen_fd, (struct sockaddr *)&a, sizeof(a)) != 0 ||
	    listen(bridge_listen_fd, 64) != 0) {
		if (bridge_listen_fd >= 0)
			close(bridge_listen_fd);
		bridge_listen_fd = -1;
		SSL_CTX_free(bridge_upstream_ctx);
		bridge_upstream_ctx = NULL;
		return -1;
	}
	socklen_t al = sizeof(a);
	getsockname(bridge_listen_fd, (struct sockaddr *)&a, &al);
	bridge_port = ntohs(a.sin_port);

	bridge_running = 1;
	if (pthread_create(&bridge_accept_thread, NULL, bridge_accept_loop, NULL) != 0) {
		bridge_running = 0;
		close(bridge_listen_fd);
		bridge_listen_fd = -1;
		SSL_CTX_free(bridge_upstream_ctx);
		bridge_upstream_ctx = NULL;
		return -1;
	}
	return 0;
}

int splice_bridge_upstream_port(void) { return bridge_port; }

void splice_bridge_get_stats(struct splice_bridge_stats *out)
{
	pthread_mutex_lock(&bridge_lock);
	*out = bridge_stats;
	pthread_mutex_unlock(&bridge_lock);
}

void splice_bridge_stop(void)
{
	if (bridge_running) {
		bridge_running = 0;
		pthread_join(bridge_accept_thread, NULL);
	}
	if (bridge_listen_fd >= 0) {
		close(bridge_listen_fd);
		bridge_listen_fd = -1;
	}
	if (bridge_upstream_ctx) {
		SSL_CTX_free(bridge_upstream_ctx);
		bridge_upstream_ctx = NULL;
	}
}

#include "splice_bridge_h2.c"
