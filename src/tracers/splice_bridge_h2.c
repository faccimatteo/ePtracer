/*
 * HTTP/2 through the proxy sandwich — #included by tracers/splice_bridge.c.
 *
 * An app that negotiated h2 with the real server multiplexes its requests and
 * compresses their headers with HPACK, whose state spans the whole connection:
 * its frames cannot be edited and passed on. So HTTP/2 is terminated on both
 * legs of the app's own TLS session:
 *
 *   app ──h2──▶ [app session: we are its server] ──HTTP/1.1──▶ proxy
 *   proxy ──▶ UPSTREAM ──▶ [srv session: we are the client] ──h2──▶ server
 *
 * Each app stream becomes one HTTP/1.1 request for the proxy and goes through
 * exactly the same at-most-once path as an HTTP/1.1 request
 * (bridge_new_msg() / bridge_deliver()); only the last step differs, the
 * request being submitted as a new stream of the server session. Answers come
 * back by stream id, so a late one can never be attributed to another request.
 *
 * Framing, HPACK and flow control are nghttp2's. What the conversion does:
 *  - pseudo headers <-> start line and Host;
 *  - cookie fields joined with "; " for HTTP/1.1 (RFC 9113 §8.2.3);
 *  - connection-specific fields dropped (forbidden in h2);
 *  - Content-Length restated from the body that is actually sent;
 *  - response trailers (gRPC's grpc-status) carried as chunked trailers.
 * Not handled: request trailers, server push (disabled), extended CONNECT.
 *
 * All entry points are called with f->lock held.
 */

#include <nghttp2/nghttp2.h>

/* Large local windows: the bridge buffers whole messages anyway, and fewer
 * WINDOW_UPDATE round trips means less latency */
#define H2_LOCAL_WINDOW (16 * 1024 * 1024)
#define H2_MAX_FIELDS   256

static const char h2_preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/* One stream, on either session: what is received is assembled as HTTP/1.1,
 * what is sent (a body, then maybe trailers) is served by h2_read_body(). */
struct h2_stream {
	int32_t  id;
	uint64_t msg;               /* srv session: the bridge request it answers */
	int      is_head;
	char     method[16];
	struct dbuf path, authority;
	struct dbuf head;           /* "name: value\r\n" lines */
	struct dbuf cookie;
	struct dbuf trailers;
	struct dbuf body;
	int      status;
	int      interim;           /* last header block was a 1xx */
	int      in_trailers;
	int      complete;

	/* outgoing */
	char    *out;
	size_t   out_len, out_off;
	char    *trailer_store;
	nghttp2_nv *out_trailers;
	size_t   n_out_trailers;
};

struct bridge_h2 {
	struct bridge_flow *f;
	nghttp2_session *app;
	nghttp2_session *srv;
};

static void h2_stream_free(struct h2_stream *st)
{
	if (!st)
		return;
	dbuf_free(&st->path);
	dbuf_free(&st->authority);
	dbuf_free(&st->head);
	dbuf_free(&st->cookie);
	dbuf_free(&st->trailers);
	dbuf_free(&st->body);
	free(st->out);
	free(st->trailer_store);
	free(st->out_trailers);
	free(st);
}

static int h2_is(const uint8_t *s, size_t n, const char *lit)
{
	return strlen(lit) == n && memcmp(s, lit, n) == 0;
}

/* Fields that only mean something to an HTTP/1.1 connection */
static int h2_hop_by_hop(const char *n, size_t l)
{
	static const char *const hop[] = { "connection", "keep-alive", "proxy-connection",
					   "transfer-encoding", "upgrade" };
	for (size_t i = 0; i < sizeof(hop) / sizeof(*hop); i++)
		if (strlen(hop[i]) == l && strncasecmp(hop[i], n, l) == 0)
			return 1;
	return 0;
}

static int h2_put_line(struct dbuf *d, const void *n, size_t nl, const void *v, size_t vl)
{
	return dbuf_put(d, n, nl) || dbuf_put(d, ": ", 2) || dbuf_put(d, v, vl) ||
	       dbuf_put(d, "\r\n", 2);
}

static int h2_flush(struct bridge_flow *f, nghttp2_session *sess, enum splice_dir dir)
{
	for (;;) {
		const uint8_t *data;
		ssize_t n = nghttp2_session_mem_send(sess, &data);
		if (n < 0)
			return -1;
		if (n == 0)
			return 0;
		if (tls_splice_send(f->s, dir, TLS_CT_APPLICATION_DATA, data, (size_t)n) != 0)
			return -1;
	}
}

static ssize_t h2_read_body(nghttp2_session *session, int32_t stream_id, uint8_t *buf,
			    size_t length, uint32_t *data_flags, nghttp2_data_source *source,
			    void *user)
{
	(void)user;
	struct h2_stream *st = source->ptr;
	size_t n = st->out_len - st->out_off;
	if (n > length)
		n = length;
	memcpy(buf, st->out + st->out_off, n);
	st->out_off += n;
	if (st->out_off == st->out_len) {
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;
		if (st->n_out_trailers) {
			*data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
			nghttp2_submit_trailer(session, stream_id, st->out_trailers,
					       st->n_out_trailers);
		}
	}
	return (ssize_t)n;
}

/* ---- parsing an HTTP/1.1 message from the proxy ------------------------ */

struct h1_field {
	char  *name;     /* lowercased in place */
	size_t nl;
	char  *value;
	size_t vl;
};

struct h1_parsed {
	char  *start;    /* start line, NUL terminated in place */
	struct h1_field f[H2_MAX_FIELDS];
	size_t nf;
	struct h1_field t[H2_MAX_FIELDS];   /* trailers */
	size_t nt;
	struct dbuf body;
};

/* Split "name: value\r\n" lines in [p, end) into fields. Lowercases the names. */
static int h2_fields(char *p, char *end, struct h1_field *out, size_t *n)
{
	*n = 0;
	while (p < end) {
		char *le = memmem(p, (size_t)(end - p), "\r\n", 2);
		if (!le)
			le = end;
		if (le == p)
			break;
		char *colon = memchr(p, ':', (size_t)(le - p));
		if (colon) {
			if (*n == H2_MAX_FIELDS)
				return -1;
			char *v = colon + 1, *ve = le;
			while (v < ve && (*v == ' ' || *v == '\t'))
				v++;
			while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t'))
				ve--;
			for (char *c = p; c < colon; c++)
				*c = (char)tolower((unsigned char)*c);
			out[*n] = (struct h1_field){ p, (size_t)(colon - p), v, (size_t)(ve - v) };
			(*n)++;
		}
		p = le + 2;
	}
	return 0;
}

/* Parse a complete message (a mutable copy: names are lowercased in place). */
static int h2_parse_h1(char *msg, size_t len, enum h1_kind kind, int is_head,
		       struct h1_parsed *out)
{
	struct h1_info info;
	memset(out, 0, sizeof(*out));
	enum h1_result r = h1_frame(msg, len, kind, is_head, &info);
	if (r != H1_COMPLETE && r != H1_UNTIL_CLOSE)
		return -1;
	size_t total = r == H1_COMPLETE ? info.total : len;

	char *eol = memmem(msg, info.head_len, "\r\n", 2);
	*eol = '\0';
	out->start = msg;
	if (h2_fields(eol + 2, msg + info.head_len - 2, out->f, &out->nf) != 0)
		return -1;

	char *p = msg + info.head_len, *end = msg + total;
	/* the same decision h1_frame framed the message with: a second,
	 * looser test could de-chunk a body whose framing was never checked */
	if (!info.chunked || r != H1_COMPLETE)
		return dbuf_put(&out->body, p, (size_t)(end - p));

	/* de-chunk; h1_frame already proved the framing, the checks below
	 * only keep a mistake there from turning into a wild copy */
	for (;;) {
		char *le = memmem(p, (size_t)(end - p), "\r\n", 2);
		if (!le)
			return -1;
		unsigned long size = strtoul(p, NULL, 16);
		p = le + 2;
		if (size == 0)
			return h2_fields(p, end, out->t, &out->nt);
		if (size > (size_t)(end - p) || (size_t)(end - p) - size < 2)
			return -1;
		if (dbuf_put(&out->body, p, size) != 0)
			return -1;
		p += size + 2;
	}
}

static int h2_status_ok(const char *start, int *status)
{
	/* "HTTP/1.1 200 ..." */
	if (strncmp(start, "HTTP/1.", 7) != 0 || strlen(start) < 12)
		return -1;
	*status = atoi(start + 9);
	return *status >= 100 && *status <= 999 ? 0 : -1;
}

static const char *h2_reason(int status)
{
	switch (status) {
	case 200: return "OK";
	case 201: return "Created";
	case 204: return "No Content";
	case 206: return "Partial Content";
	case 301: return "Moved Permanently";
	case 302: return "Found";
	case 304: return "Not Modified";
	case 400: return "Bad Request";
	case 401: return "Unauthorized";
	case 403: return "Forbidden";
	case 404: return "Not Found";
	case 500: return "Internal Server Error";
	case 502: return "Bad Gateway";
	case 503: return "Service Unavailable";
	default:  return "";
	}
}

#define H2_NV(n, nl, v, vl) ((nghttp2_nv){ (uint8_t *)(n), (uint8_t *)(v), (nl), (vl), \
					   NGHTTP2_NV_FLAG_NONE })

/* Copy trailers into storage owned by the stream: they are submitted later,
 * from the data callback, after the body. */
static int h2_keep_trailers(struct h2_stream *st, const struct h1_field *t, size_t nt)
{
	size_t bytes = 0;
	for (size_t i = 0; i < nt; i++)
		bytes += t[i].nl + t[i].vl;
	st->trailer_store = malloc(bytes ? bytes : 1);
	st->out_trailers = calloc(nt ? nt : 1, sizeof(nghttp2_nv));
	if (!st->trailer_store || !st->out_trailers)
		return -1;
	char *p = st->trailer_store;
	for (size_t i = 0; i < nt; i++) {
		memcpy(p, t[i].name, t[i].nl);
		memcpy(p + t[i].nl, t[i].value, t[i].vl);
		st->out_trailers[i] = H2_NV(p, t[i].nl, p + t[i].nl, t[i].vl);
		p += t[i].nl + t[i].vl;
	}
	st->n_out_trailers = nt;
	return 0;
}

/* ---- app session: we are the app's server ------------------------------ */

static int h2_app_begin_headers(nghttp2_session *s, const nghttp2_frame *fr, void *user)
{
	(void)user;
	if (fr->hd.type != NGHTTP2_HEADERS)
		return 0;
	struct h2_stream *st = nghttp2_session_get_stream_user_data(s, fr->hd.stream_id);
	if (fr->headers.cat == NGHTTP2_HCAT_REQUEST) {
		st = calloc(1, sizeof(*st));
		if (!st)
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		st->id = fr->hd.stream_id;
		nghttp2_session_set_stream_user_data(s, fr->hd.stream_id, st);
	} else if (st) {
		st->in_trailers = 1;   /* request trailers: not carried (see top) */
	}
	return 0;
}

static int h2_app_header(nghttp2_session *s, const nghttp2_frame *fr, const uint8_t *name,
			 size_t nl, const uint8_t *value, size_t vl, uint8_t flags, void *user)
{
	(void)flags; (void)user;
	struct h2_stream *st = nghttp2_session_get_stream_user_data(s, fr->hd.stream_id);
	if (!st || st->in_trailers)
		return 0;
	int bad = 0;
	if (h2_is(name, nl, ":method")) {
		size_t n = vl < sizeof(st->method) - 1 ? vl : sizeof(st->method) - 1;
		memcpy(st->method, value, n);
		st->method[n] = '\0';
	} else if (h2_is(name, nl, ":path")) {
		bad = dbuf_put(&st->path, value, vl);
	} else if (h2_is(name, nl, ":authority")) {
		bad = dbuf_put(&st->authority, value, vl);
	} else if (nl && name[0] == ':') {
		/* :scheme, :protocol: implied by the connection */
	} else if (h2_is(name, nl, "cookie")) {
		bad = (st->cookie.len && dbuf_put(&st->cookie, "; ", 2)) ||
		      dbuf_put(&st->cookie, value, vl);
	} else if (h2_is(name, nl, "content-length") || h2_is(name, nl, "host")) {
		/* restated from what is actually sent */
	} else {
		bad = h2_put_line(&st->head, name, nl, value, vl);
	}
	return bad ? NGHTTP2_ERR_CALLBACK_FAILURE : 0;
}

static int h2_app_data_chunk(nghttp2_session *s, uint8_t flags, int32_t id,
			     const uint8_t *data, size_t len, void *user)
{
	(void)flags; (void)user;
	struct h2_stream *st = nghttp2_session_get_stream_user_data(s, id);
	if (st && dbuf_put(&st->body, data, len) != 0)
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	return 0;
}

/* A complete request from the app: render it as HTTP/1.1, queue it */
static int h2_app_request(struct bridge_h2 *h, struct h2_stream *st)
{
	struct bridge_flow *f = h->f;
	struct dbuf r = { 0 };
	int rc = -1;

	if (!st->method[0] || !st->path.len || !strcmp(st->method, "CONNECT"))
		goto refuse;   /* extended CONNECT (WebSocket over h2) is not carried */

	const char *auth = st->authority.p;
	size_t al = st->authority.len;
	if (!al) {
		auth = f->authority;
		al = strlen(f->authority);
	}
	int with_length = st->body.len || !strcmp(st->method, "POST") ||
			  !strcmp(st->method, "PUT") || !strcmp(st->method, "PATCH");
	char cl[48];
	snprintf(cl, sizeof(cl), "content-length: %zu\r\n", st->body.len);

	if (dbuf_put(&r, st->method, strlen(st->method)) || dbuf_put(&r, " ", 1) ||
	    dbuf_put(&r, st->path.p, st->path.len) || dbuf_put(&r, " HTTP/1.1\r\nhost: ", 17) ||
	    dbuf_put(&r, auth, al) || dbuf_put(&r, "\r\n", 2) ||
	    (st->head.len && dbuf_put(&r, st->head.p, st->head.len)) ||
	    (st->cookie.len && h2_put_line(&r, "cookie", 6, st->cookie.p, st->cookie.len)) ||
	    (with_length && dbuf_put(&r, cl, strlen(cl))) || dbuf_put(&r, "\r\n", 2))
		goto refuse;
	size_t head_len = r.len;
	if (st->body.len && dbuf_put(&r, st->body.p, st->body.len))
		goto refuse;

	if (bridge_new_msg(f, r.p, r.len, head_len, !strcmp(st->method, "HEAD"),
			   st->method, st->id) == 0)
		rc = 0;
refuse:
	dbuf_free(&r);
	if (rc != 0)
		nghttp2_submit_rst_stream(h->app, NGHTTP2_FLAG_NONE, st->id, NGHTTP2_REFUSED_STREAM);
	return 0;
}

static int h2_app_frame_recv(nghttp2_session *s, const nghttp2_frame *fr, void *user)
{
	struct bridge_h2 *h = user;
	if ((fr->hd.type != NGHTTP2_HEADERS && fr->hd.type != NGHTTP2_DATA) ||
	    !(fr->hd.flags & NGHTTP2_FLAG_END_STREAM))
		return 0;
	struct h2_stream *st = nghttp2_session_get_stream_user_data(s, fr->hd.stream_id);
	if (st && !st->complete) {
		st->complete = 1;
		h2_app_request(h, st);
	}
	return 0;
}

static int h2_app_stream_close(nghttp2_session *s, int32_t id, uint32_t error, void *user)
{
	struct bridge_h2 *h = user;
	struct bridge_flow *f = h->f;

	if (error != NGHTTP2_NO_ERROR) {
		/* RST_STREAM from the app: it no longer wants this one */
		for (size_t i = 0; i < BRIDGE_MSG_RING; i++) {
			struct bridge_msg *m = &f->msgs[i];
			if (m->state == MSG_PENDING && m->app_stream == id) {
				m->state = MSG_ABANDONED;
				bridge_count(&bridge_stats.abandoned);
				bridge_log("[bridge] %llu.%llu abandoned: the app reset its stream",
					   (unsigned long long)f->id, (unsigned long long)m->n);
			}
		}
	}
	h2_stream_free(nghttp2_session_get_stream_user_data(s, id));
	nghttp2_session_set_stream_user_data(s, id, NULL);
	return 0;
}

/* ---- srv session: we are the server's client --------------------------- */

static int h2_srv_begin_headers(nghttp2_session *s, const nghttp2_frame *fr, void *user)
{
	(void)user;
	if (fr->hd.type != NGHTTP2_HEADERS)
		return 0;
	struct h2_stream *st = nghttp2_session_get_stream_user_data(s, fr->hd.stream_id);
	if (!st)
		return 0;
	if (st->interim) {
		/* the final answer after a 1xx */
		st->interim = 0;
		st->status = 0;
		st->head.len = 0;
	} else if (fr->headers.cat == NGHTTP2_HCAT_HEADERS && st->status) {
		st->in_trailers = 1;
	}
	return 0;
}

static int h2_srv_header(nghttp2_session *s, const nghttp2_frame *fr, const uint8_t *name,
			 size_t nl, const uint8_t *value, size_t vl, uint8_t flags, void *user)
{
	(void)flags; (void)user;
	struct h2_stream *st = nghttp2_session_get_stream_user_data(s, fr->hd.stream_id);
	if (!st)
		return 0;
	if (h2_is(name, nl, ":status")) {
		char tmp[8] = { 0 };
		memcpy(tmp, value, vl < 7 ? vl : 7);
		st->status = atoi(tmp);
		st->interim = st->status / 100 == 1;
		return 0;
	}
	if (nl && name[0] == ':')
		return 0;
	struct dbuf *d = st->in_trailers ? &st->trailers : &st->head;
	/* a HEAD answer keeps the length of the body it does not carry */
	if (!st->in_trailers && h2_is(name, nl, "content-length") && !st->is_head)
		return 0;
	return h2_put_line(d, name, nl, value, vl) ? NGHTTP2_ERR_CALLBACK_FAILURE : 0;
}

/* The server's complete answer, as HTTP/1.1 for the proxy */
static void h2_srv_response(struct bridge_h2 *h, struct h2_stream *st)
{
	struct bridge_msg *m = bridge_msg(h->f, st->msg);
	if (!m || m->srv_stream != st->id)
		return;

	struct dbuf r = { 0 };
	char line[96];
	int bad;
	snprintf(line, sizeof(line), "HTTP/1.1 %d %s\r\n", st->status, h2_reason(st->status));
	bad = dbuf_put(&r, line, strlen(line)) ||
	      (st->head.len && dbuf_put(&r, st->head.p, st->head.len));
	if (st->trailers.len) {
		/* trailers only exist in HTTP/1.1 with chunked transfer */
		snprintf(line, sizeof(line), "%zx\r\n", st->body.len);
		bad = bad || dbuf_put(&r, "transfer-encoding: chunked\r\n\r\n", 30) ||
		      (st->body.len && (dbuf_put(&r, line, strlen(line)) ||
					dbuf_put(&r, st->body.p, st->body.len) ||
					dbuf_put(&r, "\r\n", 2))) ||
		      dbuf_put(&r, "0\r\n", 3) || dbuf_put(&r, st->trailers.p, st->trailers.len) ||
		      dbuf_put(&r, "\r\n", 2);
	} else {
		if (!st->is_head) {
			snprintf(line, sizeof(line), "content-length: %zu\r\n", st->body.len);
			bad = bad || dbuf_put(&r, line, strlen(line));
		}
		bad = bad || dbuf_put(&r, "\r\n", 2) ||
		      (st->body.len && !st->is_head && dbuf_put(&r, st->body.p, st->body.len));
	}
	if (bad) {
		dbuf_free(&r);
		m->resp_state = -1;
		return;
	}
	dbuf_free(&m->resp);
	m->resp = r;
	m->resp_state = 1;
}

static int h2_srv_frame_recv(nghttp2_session *s, const nghttp2_frame *fr, void *user)
{
	if ((fr->hd.type != NGHTTP2_HEADERS && fr->hd.type != NGHTTP2_DATA) ||
	    !(fr->hd.flags & NGHTTP2_FLAG_END_STREAM))
		return 0;
	struct h2_stream *st = nghttp2_session_get_stream_user_data(s, fr->hd.stream_id);
	if (st && !st->complete) {
		st->complete = 1;
		h2_srv_response(user, st);
	}
	return 0;
}

static int h2_srv_stream_close(nghttp2_session *s, int32_t id, uint32_t error, void *user)
{
	(void)error;
	struct bridge_h2 *h = user;
	struct h2_stream *st = nghttp2_session_get_stream_user_data(s, id);
	if (st && !st->complete) {
		/* reset by the server, or GOAWAY: delivered, unanswered, never retried */
		struct bridge_msg *m = bridge_msg(h->f, st->msg);
		if (m && m->srv_stream == id)
			m->resp_state = -1;
	}
	h2_stream_free(st);
	nghttp2_session_set_stream_user_data(s, id, NULL);
	return 0;
}

/* ---- entry points ------------------------------------------------------ */

static int bridge_h2_detect(const uint8_t *b, size_t n)
{
	size_t cmp = n < sizeof(h2_preface) - 1 ? n : sizeof(h2_preface) - 1;
	return cmp >= 3 && memcmp(b, h2_preface, cmp) == 0;
}

static struct bridge_h2 *bridge_h2_new(struct bridge_flow *f)
{
	struct bridge_h2 *h = calloc(1, sizeof(*h));
	nghttp2_session_callbacks *cb = NULL;
	if (!h || nghttp2_session_callbacks_new(&cb) != 0)
		goto fail;
	h->f = f;

	nghttp2_session_callbacks_set_on_begin_headers_callback(cb, h2_app_begin_headers);
	nghttp2_session_callbacks_set_on_header_callback(cb, h2_app_header);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, h2_app_data_chunk);
	nghttp2_session_callbacks_set_on_frame_recv_callback(cb, h2_app_frame_recv);
	nghttp2_session_callbacks_set_on_stream_close_callback(cb, h2_app_stream_close);
	if (nghttp2_session_server_new(&h->app, cb, h) != 0)
		goto fail;

	nghttp2_session_callbacks_set_on_begin_headers_callback(cb, h2_srv_begin_headers);
	nghttp2_session_callbacks_set_on_header_callback(cb, h2_srv_header);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, h2_app_data_chunk);
	nghttp2_session_callbacks_set_on_frame_recv_callback(cb, h2_srv_frame_recv);
	nghttp2_session_callbacks_set_on_stream_close_callback(cb, h2_srv_stream_close);
	if (nghttp2_session_client_new(&h->srv, cb, h) != 0)
		goto fail;
	nghttp2_session_callbacks_del(cb);
	cb = NULL;

	nghttp2_settings_entry app_iv[] = {
		{ NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 },
		{ NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, H2_LOCAL_WINDOW },
	};
	nghttp2_settings_entry srv_iv[] = {
		{ NGHTTP2_SETTINGS_ENABLE_PUSH, 0 },
		{ NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, H2_LOCAL_WINDOW },
	};
	if (nghttp2_submit_settings(h->app, NGHTTP2_FLAG_NONE, app_iv, 2) != 0 ||
	    nghttp2_submit_settings(h->srv, NGHTTP2_FLAG_NONE, srv_iv, 2) != 0)
		goto fail;
	nghttp2_session_set_local_window_size(h->app, NGHTTP2_FLAG_NONE, 0, H2_LOCAL_WINDOW);
	nghttp2_session_set_local_window_size(h->srv, NGHTTP2_FLAG_NONE, 0, H2_LOCAL_WINDOW);

	/* our own preface towards the server: the app's went to our app session */
	if (h2_flush(f, h->srv, SPLICE_C2S) != 0)
		goto fail;
	/* An h2 server may speak first: its SETTINGS leave as soon as its
	 * handshake ends, so they can be here before the app's preface. They
	 * open the server session and must not be lost. */
	if (f->resp.len) {
		if (nghttp2_session_mem_recv(h->srv, (const uint8_t *)f->resp.p, f->resp.len) < 0)
			goto fail;
		f->resp.len = 0;
		if (h2_flush(f, h->srv, SPLICE_C2S) != 0)
			goto fail;
	}
	/* and our SETTINGS towards the app, which needs the server key already */
	if (!tls_splice_keyed(f->s, SPLICE_S2C) && tls_splice_prime(f->s, SPLICE_S2C) != 0)
		goto fail;
	if (h2_flush(f, h->app, SPLICE_S2C) != 0)
		goto fail;
	bridge_log("[bridge] %llu: HTTP/2, terminated on both legs", (unsigned long long)f->id);
	return h;
fail:
	if (cb)
		nghttp2_session_callbacks_del(cb);
	bridge_h2_free(h);
	return NULL;
}

static void bridge_h2_free(struct bridge_h2 *h)
{
	if (!h)
		return;
	/* deleting a session closes its streams through the close callback */
	if (h->app)
		nghttp2_session_del(h->app);
	if (h->srv)
		nghttp2_session_del(h->srv);
	free(h);
}

static int bridge_h2_app_data(struct bridge_flow *f, const uint8_t *b, size_t n)
{
	if (nghttp2_session_mem_recv(f->h2->app, b, n) < 0)
		return -1;
	return h2_flush(f, f->h2->app, SPLICE_S2C);
}

static int bridge_h2_server_data(struct bridge_flow *f, const uint8_t *b, size_t n)
{
	if (nghttp2_session_mem_recv(f->h2->srv, b, n) < 0)
		return -1;
	return h2_flush(f, f->h2->srv, SPLICE_C2S);
}

/* The request the proxy released becomes a new stream towards the server */
static int bridge_h2_deliver(struct bridge_flow *f, struct bridge_msg *m,
			     const char *req, size_t len)
{
	struct bridge_h2 *h = f->h2;
	char *copy = malloc(len + 1);
	struct h1_parsed *p = calloc(1, sizeof(*p));
	struct h2_stream *st = calloc(1, sizeof(*st));
	nghttp2_nv *nva = calloc(H2_MAX_FIELDS + 5, sizeof(*nva));
	int rc = -1;
	if (!copy || !p || !st || !nva)
		goto out;
	memcpy(copy, req, len);
	if (h2_parse_h1(copy, len, H1_REQUEST, 0, p) != 0)
		goto out;

	/* "METHOD target HTTP/1.1" */
	char *sp1 = strchr(p->start, ' '), *sp2 = sp1 ? strrchr(p->start, ' ') : NULL;
	if (!sp1 || sp2 == sp1)
		goto out;
	*sp1 = '\0';
	*sp2 = '\0';
	char *method = p->start, *target = sp1 + 1;

	const char *auth = f->authority;
	size_t al = strlen(f->authority);
	for (size_t i = 0; i < p->nf; i++)
		if (h2_is((uint8_t *)p->f[i].name, p->f[i].nl, "host")) {
			auth = p->f[i].value;
			al = p->f[i].vl;
		}
	/* absolute-form, as some proxies rewrite it: split it back */
	if (!strncmp(target, "https://", 8)) {
		char *slash = strchr(target + 8, '/');
		auth = target + 8;
		al = slash ? (size_t)(slash - auth) : strlen(auth);
		target = slash ? slash : "/";
	}

	size_t n = 0;
	nva[n++] = H2_NV(":method", 7, method, strlen(method));
	nva[n++] = H2_NV(":scheme", 7, "https", 5);
	nva[n++] = H2_NV(":authority", 10, auth, al);
	nva[n++] = H2_NV(":path", 5, target, strlen(target));
	for (size_t i = 0; i < p->nf; i++) {
		struct h1_field *fl = &p->f[i];
		if (h2_hop_by_hop(fl->name, fl->nl) || h2_is((uint8_t *)fl->name, fl->nl, "host") ||
		    h2_is((uint8_t *)fl->name, fl->nl, "content-length"))
			continue;
		/* TE is allowed in h2 only as "trailers" (gRPC needs it) */
		if (h2_is((uint8_t *)fl->name, fl->nl, "te") &&
		    !(fl->vl == 8 && !strncasecmp(fl->value, "trailers", 8)))
			continue;
		nva[n++] = H2_NV(fl->name, fl->nl, fl->value, fl->vl);
	}
	char cl[24];
	if (p->body.len || strcmp(method, "GET")) {
		snprintf(cl, sizeof(cl), "%zu", p->body.len);
		nva[n++] = H2_NV("content-length", 14, cl, strlen(cl));
	}

	st->msg = m->n;
	st->is_head = m->is_head;
	st->out = p->body.p;
	st->out_len = p->body.len;
	p->body.p = NULL;
	nghttp2_data_provider prd = { .source.ptr = st, .read_callback = h2_read_body };
	int32_t id = nghttp2_submit_request(h->srv, NULL, nva, n,
					    st->out_len ? &prd : NULL, st);
	if (id < 0)
		goto out;
	st->id = id;
	m->srv_stream = id;
	st = NULL;   /* owned by the session now, freed on stream close */
	rc = h2_flush(f, h->srv, SPLICE_C2S);
out:
	if (p)
		dbuf_free(&p->body);
	h2_stream_free(st);
	free(p);
	free(nva);
	free(copy);
	return rc;
}

/* The proxy's answer goes back on the app's stream */
static int bridge_h2_app_response(struct bridge_flow *f, struct bridge_msg *m,
				  const char *resp, size_t len)
{
	struct bridge_h2 *h = f->h2;
	if (!m->app_stream)
		return 0;
	struct h2_stream *st = nghttp2_session_get_stream_user_data(h->app, m->app_stream);
	if (!st)
		return 0;   /* the app reset that stream: nobody to answer */

	char *copy = malloc(len + 1);
	struct h1_parsed *p = calloc(1, sizeof(*p));
	nghttp2_nv *nva = calloc(H2_MAX_FIELDS + 2, sizeof(*nva));
	int rc = -1, status = 0;
	if (!copy || !p || !nva)
		goto out;
	memcpy(copy, resp, len);
	if (h2_parse_h1(copy, len, H1_RESPONSE, m->is_head, p) != 0 ||
	    h2_status_ok(p->start, &status) != 0)
		goto out;
	if (status / 100 == 1) {
		rc = 0;   /* interim answers are not relayed to the app */
		goto out;
	}

	char sbuf[8], cl[24];
	snprintf(sbuf, sizeof(sbuf), "%d", status);
	size_t n = 0;
	nva[n++] = H2_NV(":status", 7, sbuf, strlen(sbuf));
	for (size_t i = 0; i < p->nf; i++) {
		struct h1_field *fl = &p->f[i];
		if (h2_hop_by_hop(fl->name, fl->nl) ||
		    (h2_is((uint8_t *)fl->name, fl->nl, "content-length") && !m->is_head))
			continue;
		nva[n++] = H2_NV(fl->name, fl->nl, fl->value, fl->vl);
	}
	if (!m->is_head) {
		snprintf(cl, sizeof(cl), "%zu", p->body.len);
		nva[n++] = H2_NV("content-length", 14, cl, strlen(cl));
	}

	free(st->out);
	st->out = m->is_head ? NULL : p->body.p;
	st->out_len = m->is_head ? 0 : p->body.len;
	st->out_off = 0;
	if (!m->is_head)
		p->body.p = NULL;
	if (p->nt && h2_keep_trailers(st, p->t, p->nt) != 0)
		goto out;
	nghttp2_data_provider prd = { .source.ptr = st, .read_callback = h2_read_body };
	if (nghttp2_submit_response(h->app, m->app_stream, nva, n,
				    st->out_len || st->n_out_trailers ? &prd : NULL) != 0)
		goto out;
	rc = h2_flush(f, h->app, SPLICE_S2C);
out:
	if (p)
		dbuf_free(&p->body);
	free(p);
	free(nva);
	free(copy);
	return rc;
}
