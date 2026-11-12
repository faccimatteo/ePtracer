/*
 * HTTP/2 message reassembly.
 *
 * On the wire an HTTP/2 message is not text: it is a series of frames, and its
 * headers are HPACK compressed against a dynamic table that is built up over
 * the whole connection. There is therefore no raw form to print, only a
 * reconstruction — the same one an intercepting proxy shows: the pseudo headers
 * turned back into a start line, the header fields as they were sent, and the
 * DATA frames concatenated as the body.
 *
 * HPACK is decoded with the inflater from libnghttp2, which ePtracer already
 * links against. One inflater per connection and per direction, fed the header
 * blocks in order, is what keeps the dynamic table in sync with the peer.
 */

#include <nghttp2/nghttp2.h>

#define HTTP2_MAX_CONNS         128
#define HTTP2_MAX_STREAMS       512
#define HTTP2_FRAME_HEADER_LEN  9
#define HTTP2_MAX_MESSAGE_BYTES (8 * 1024 * 1024)
/* A header block is a few KB: anything near this is a CONTINUATION flood */
#define HTTP2_MAX_HEADER_BLOCK  (256 * 1024)
/* Decoded fields: HPACK indexes let a small block expand a lot */
#define HTTP2_MAX_HEADER_BYTES  (1024 * 1024)
#define HTTP2_PREFACE           "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

/* Frame types, RFC 9113 section 6 */
#define HTTP2_DATA          0x00
#define HTTP2_HEADERS       0x01
#define HTTP2_RST_STREAM    0x03
#define HTTP2_PUSH_PROMISE  0x05
#define HTTP2_CONTINUATION  0x09

#define HTTP2_FLAG_END_STREAM  0x01
#define HTTP2_FLAG_END_HEADERS 0x04
#define HTTP2_FLAG_PADDED      0x08
#define HTTP2_FLAG_PRIORITY    0x20

/* A growable byte buffer */
struct http2_buf {
	char  *data;
	size_t len;
	size_t cap;
};

/* One direction of one HTTP/2 request or response being reassembled */
struct http2_half {
	int    open;
	int    saw_pseudo;          /* the block being decoded carried pseudo headers */
	__u64  first_ts;
	struct http2_buf headers;   /* rendered "name: value" lines */
	struct http2_buf body;      /* concatenated DATA payloads */
	char   start_line[HTTP_URL_MAX];
	char   summary[HTTP_URL_MAX];
	char   authority[256];
};

/* One HTTP/2 stream, holding both halves of the exchange */
struct http2_stream {
	int    in_use;
	__u64  conn_id;
	__u32  id;
	char   request_summary[HTTP_REQUEST_LINE_MAX];
	struct http2_half half[2];  /* indexed by enum http_direction */
};

/* One direction of one connection: the frame parser and its HPACK state */
struct http2_conn {
	int    in_use;
	__u64  conn_id;
	__u8   direction;
	__u8   source;
	__u32  pid;
	__u32  tid;
	char   comm[HTTP_COMM_LEN];
	struct conn_info_t conn;
	__u64  last_ts;
	nghttp2_hd_inflater *inflater;
	struct http2_buf frames;      /* bytes not yet forming a complete frame */
	struct http2_buf block;       /* header block across CONTINUATION frames */
	__u32  block_stream;
	int    block_end_stream;
	int    broken;                /* HPACK desynchronized: stop decoding */
};

static struct http2_conn http2_conns[HTTP2_MAX_CONNS];
static struct http2_stream http2_streams[HTTP2_MAX_STREAMS];

/*
 * http2_buf_append
 *
 * Description:
 * Appends bytes to a growable buffer.
 *
 * Params:
 * struct http2_buf *buf: destination buffer.
 * const void *data: bytes to append.
 * size_t len: number of bytes.
 *
 * Return:
 * 0 on success, -1 on allocation failure.
 * */
static int http2_buf_append(struct http2_buf *buf, const void *data, size_t len)
{
	size_t needed = buf->len + len;
	char *bigger = NULL;

	if (len == 0)
		return 0;

	if (needed > buf->cap) {
		size_t cap = buf->cap ? buf->cap : 1024;

		while (cap < needed)
			cap *= 2;
		bigger = realloc(buf->data, cap);
		if (!bigger)
			return -1;
		buf->data = bigger;
		buf->cap = cap;
	}

	memcpy(buf->data + buf->len, data, len);
	buf->len = needed;
	return 0;
}

/*
 * http2_buf_reset
 *
 * Description:
 * Releases a buffer content, keeping the structure reusable.
 *
 * Params:
 * struct http2_buf *buf: buffer to empty.
 * */
static void http2_buf_reset(struct http2_buf *buf)
{
	free(buf->data);
	buf->data = NULL;
	buf->len = 0;
	buf->cap = 0;
}

/*
 * find_http2_conn
 *
 * Description:
 * Returns the parser state of one direction of one connection, creating it
 * when needed. Each entry owns an HPACK inflater, so recycling a slot also
 * throws away the dynamic table that went with it.
 *
 * Params:
 * const struct http_event_t *ev: event being processed.
 *
 * Return:
 * The connection state, or NULL when no slot could be allocated.
 * */
static struct http2_conn *find_http2_conn(const struct http_event_t *ev)
{
	struct http2_conn *oldest = NULL;
	int i = 0, free_slot = -1;

	for (i = 0; i < HTTP2_MAX_CONNS; i++) {
		struct http2_conn *conn = &http2_conns[i];

		if (conn->in_use && conn->conn_id == ev->stream_id &&
		    conn->direction == ev->direction)
			return conn;
		if (!conn->in_use && free_slot < 0)
			free_slot = i;
		if (conn->in_use && (!oldest || conn->last_ts < oldest->last_ts))
			oldest = conn;
	}

	if (free_slot < 0) {
		if (!oldest)
			return NULL;
		free_slot = (int)(oldest - http2_conns);
		nghttp2_hd_inflate_del(oldest->inflater);
		http2_buf_reset(&oldest->frames);
		http2_buf_reset(&oldest->block);
		memset(oldest, 0, sizeof(*oldest));
	}

	memset(&http2_conns[free_slot], 0, sizeof(http2_conns[free_slot]));
	if (nghttp2_hd_inflate_new(&http2_conns[free_slot].inflater) != 0) {
		log_error("[!] Cannot create the HPACK decoder");
		return NULL;
	}

	http2_conns[free_slot].in_use = 1;
	http2_conns[free_slot].conn_id = ev->stream_id;
	http2_conns[free_slot].direction = ev->direction;
	return &http2_conns[free_slot];
}

/*
 * find_http2_stream
 *
 * Description:
 * Returns the record of one HTTP/2 stream, creating it when needed.
 *
 * Params:
 * __u64 conn_id: connection the stream belongs to.
 * __u32 id: HTTP/2 stream identifier.
 *
 * Return:
 * The stream record, or NULL when no slot could be allocated.
 * */
static struct http2_stream *find_http2_stream(__u64 conn_id, __u32 id)
{
	int i = 0, free_slot = -1;

	for (i = 0; i < HTTP2_MAX_STREAMS; i++) {
		if (http2_streams[i].in_use && http2_streams[i].conn_id == conn_id &&
		    http2_streams[i].id == id)
			return &http2_streams[i];
		if (!http2_streams[i].in_use && free_slot < 0)
			free_slot = i;
	}

	if (free_slot < 0)
		return NULL;

	memset(&http2_streams[free_slot], 0, sizeof(http2_streams[free_slot]));
	http2_streams[free_slot].in_use = 1;
	http2_streams[free_slot].conn_id = conn_id;
	http2_streams[free_slot].id = id;
	return &http2_streams[free_slot];
}

/*
 * release_http2_half
 *
 * Description:
 * Frees the buffers of one direction of a stream, and the stream itself once
 * both directions are done with.
 *
 * Params:
 * struct http2_stream *stream: stream to clean up.
 * __u8 direction: direction that just finished.
 * */
static void release_http2_half(struct http2_stream *stream, __u8 direction)
{
	struct http2_half *half = &stream->half[direction];

	http2_buf_reset(&half->headers);
	http2_buf_reset(&half->body);
	memset(half, 0, sizeof(*half));

	if (!stream->half[HTTP_EGRESS].open && !stream->half[HTTP_INGRESS].open)
		stream->in_use = 0;
}

/*
 * render_http2_message
 *
 * Description:
 * Assembles and prints one HTTP/2 message. The pseudo headers become a start
 * line, the header fields follow as they were sent, and the DATA frames make
 * up the body. A Content-Length is added when the peer did not send one, so
 * that what is printed is a message another tool can frame and replay.
 *
 * Params:
 * struct http2_conn *conn: connection the message was captured on.
 * struct http2_stream *stream: HTTP/2 stream carrying the message.
 * __u8 direction: direction of the message.
 * int complete: the message was terminated by END_STREAM.
 * */
static void render_http2_message(struct http2_conn *conn, struct http2_stream *stream,
				 __u8 direction, int complete)
{
	struct http2_half *half = &stream->half[direction];
	struct http_stream context;
	struct http2_buf message = {0};
	char content_length[64] = {0};
	char length_header[64] = {0};
	char *decoded = NULL;
	const char *body = half->body.data;
	size_t body_len = half->body.len, decoded_len = 0, body_off = 0;
	char encoding[64] = {0};
	int is_response = direction == HTTP_INGRESS;

	if (!half->start_line[0])
		goto out;

	/* The banner is shared with the HTTP/1 renderer */
	memset(&context, 0, sizeof(context));
	context.stream_id = conn->conn_id;
	context.source = conn->source;
	context.pid = conn->pid;
	context.tid = conn->tid;
	context.conn = conn->conn;
	context.first_ts = half->first_ts;
	memcpy(context.comm, conn->comm, sizeof(context.comm));

	if (http2_buf_append(&message, half->start_line, strlen(half->start_line)) < 0 ||
	    http2_buf_append(&message, half->headers.data, half->headers.len) < 0) {
		log_error("[!] Out of memory while rebuilding an HTTP/2 message");
		goto out;
	}

	/* HTTP/2 carries no Content-Length unless the peer chose to send one:
	 * stating it keeps the rendered message framable by another tool */
	if (!header_value(message.data, message.len, "content-length",
			  content_length, sizeof(content_length))) {
		snprintf(length_header, sizeof(length_header), "content-length: %zu\r\n", body_len);
		if (http2_buf_append(&message, length_header, strlen(length_header)) < 0)
			goto out;
	}

	if (http2_buf_append(&message, "\r\n", 2) < 0) {
		log_error("[!] Out of memory while rebuilding an HTTP/2 message");
		goto out;
	}
	body_off = message.len;

	if (http_decode_bodies &&
	    header_value(message.data, body_off, "content-encoding", encoding, sizeof(encoding)) &&
	    (contains_ci(encoding, "gzip") || contains_ci(encoding, "deflate"))) {
		decoded = inflate_body(body, body_len, &decoded_len);
		if (decoded) {
			body = decoded;
			body_len = decoded_len;
		}
	}

	if (http2_buf_append(&message, body, body_len) < 0) {
		log_error("[!] Out of memory while rebuilding an HTTP/2 message");
		goto out;
	}

	print_message_banner(&context, half->summary, message.len, is_response, complete,
			     is_response ? stream->request_summary : NULL);

	dump_message_to_file(http_message_seq, is_response, message.data, message.len);

	if (decoded) {
		/* The body no longer matches the encoding headers it came with */
		print_decoded_headers(message.data, body_off, body_len);
		http_out_write(body, body_len);
	} else {
		http_out_write(message.data, message.len);
	}
	if (message.len == 0 || message.data[message.len - 1] != '\n')
		printf("\n");
	fflush(stdout);

	if (!is_response)
		snprintf(stream->request_summary, sizeof(stream->request_summary), "%.*s",
			 (int)sizeof(stream->request_summary) - 1, half->summary);

out:
	free(decoded);
	http2_buf_reset(&message);
	release_http2_half(stream, direction);
}

/*
 * http2_emit_header
 *
 * Description:
 * Stores one decoded header field. Pseudo headers build the start line, every
 * other field is appended to the header block as it was received, lowercase
 * names included: that is how HTTP/2 sends them.
 *
 * Params:
 * struct http2_half *half: message being assembled.
 * const nghttp2_nv *nv: decoded header field.
 * */
static void http2_emit_header(struct http2_half *half, const nghttp2_nv *nv)
{
	const char *name = (const char *)nv->name;
	const char *value = (const char *)nv->value;

	if (nv->namelen > 0 && name[0] == ':') {
		half->saw_pseudo = 1;
		if (nv->namelen == 7 && !memcmp(name, ":method", 7))
			snprintf(half->start_line, sizeof(half->start_line), "%.*s",
				 (int)nv->valuelen, value);
		else if (nv->namelen == 5 && !memcmp(name, ":path", 5))
			snprintf(half->summary, sizeof(half->summary), "%.*s",
				 (int)nv->valuelen, value);
		else if (nv->namelen == 10 && !memcmp(name, ":authority", 10))
			snprintf(half->authority, sizeof(half->authority), "%.*s",
				 (int)nv->valuelen, value);
		else if (nv->namelen == 7 && !memcmp(name, ":status", 7))
			snprintf(half->start_line, sizeof(half->start_line), "%.*s",
				 (int)nv->valuelen, value);
		return;
	}

	if (half->headers.len + nv->namelen + nv->valuelen + 4 > HTTP2_MAX_HEADER_BYTES)
		return;   /* past the cap, the remaining fields are dropped */

	http2_buf_append(&half->headers, name, nv->namelen);
	http2_buf_append(&half->headers, ": ", 2);
	http2_buf_append(&half->headers, value, nv->valuelen);
	http2_buf_append(&half->headers, "\r\n", 2);
}

/*
 * http2_finish_headers
 *
 * Description:
 * Turns the pseudo headers collected while decoding into the start line of the
 * message, the way a proxy renders an HTTP/2 exchange.
 *
 * Params:
 * struct http2_half *half: message being assembled.
 * __u8 direction: direction of the message.
 * int is_tls: the exchange travelled inside TLS.
 * */
static void http2_finish_headers(struct http2_half *half, __u8 direction, int is_tls)
{
	char method[32] = {0}, path[HTTP_URL_MAX] = {0};

	if (direction == HTTP_INGRESS) {
		char status[32] = {0};

		snprintf(status, sizeof(status), "%.*s", (int)sizeof(status) - 1, half->start_line);
		snprintf(half->start_line, sizeof(half->start_line), "HTTP/2 %s\r\n", status);
		snprintf(half->summary, sizeof(half->summary), "HTTP/2 %s", status);
		return;
	}

	snprintf(method, sizeof(method), "%.*s", (int)sizeof(method) - 1, half->start_line);
	snprintf(path, sizeof(path), "%.*s", (int)sizeof(path) - 1, half->summary);
	snprintf(half->start_line, sizeof(half->start_line), "%s %s HTTP/2\r\nhost: %s\r\n",
		 method, path, half->authority);
	snprintf(half->summary, sizeof(half->summary), "%s %s://%s%s", method,
		 is_tls ? "https" : "http", half->authority, path);
}

/*
 * http2_decode_block
 *
 * Description:
 * Runs a complete header block through the HPACK inflater and feeds every
 * decoded field to the message being assembled. A failure here desynchronizes
 * the dynamic table, so the connection is marked broken and left alone.
 *
 * Params:
 * struct http2_conn *conn: connection owning the inflater.
 * struct http2_half *half: message being assembled.
 *
 * Return:
 * 0 on success, -1 when the block could not be decoded.
 * */
static int http2_decode_block(struct http2_conn *conn, struct http2_half *half)
{
	const __u8 *in = (const __u8 *)conn->block.data;
	size_t inlen = conn->block.len;

	for (;;) {
		nghttp2_nv nv;
		int inflate_flags = 0;
		ssize_t consumed = nghttp2_hd_inflate_hd2(conn->inflater, &nv, &inflate_flags,
							  in, inlen, 1);

		if (consumed < 0) {
			log_error("[!] HPACK decoding failed: %s",
				  nghttp2_strerror((int)consumed));
			conn->broken = 1;
			return -1;
		}

		in += consumed;
		inlen -= (size_t)consumed;

		if (inflate_flags & NGHTTP2_HD_INFLATE_EMIT)
			http2_emit_header(half, &nv);

		if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
			nghttp2_hd_inflate_end_headers(conn->inflater);
			break;
		}

		if ((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 && inlen == 0)
			break;
	}

	return 0;
}

/*
 * http2_handle_frame
 *
 * Description:
 * Processes one complete frame: header blocks are accumulated across
 * CONTINUATION frames and decoded once END_HEADERS shows up, DATA payloads are
 * appended to the body, and END_STREAM renders the message.
 *
 * Params:
 * struct http2_conn *conn: connection the frame belongs to.
 * const char *frame: frame header followed by its payload.
 * __u32 payload_len: payload length.
 * __u64 timestamp: capture timestamp of the chunk carrying the frame.
 * */
static void http2_handle_frame(struct http2_conn *conn, const char *frame,
			       __u32 payload_len, __u64 timestamp)
{
	const char *payload = frame + HTTP2_FRAME_HEADER_LEN;
	__u8 type = (__u8)frame[3];
	__u8 flags = (__u8)frame[4];
	__u32 stream_id = (((__u32)(unsigned char)frame[5] << 24) |
			   ((__u32)(unsigned char)frame[6] << 16) |
			   ((__u32)(unsigned char)frame[7] << 8)  |
			    (__u32)(unsigned char)frame[8]) & 0x7fffffffU;
	struct http2_stream *stream = NULL;
	struct http2_half *half = NULL;
	size_t offset = 0, length = payload_len;

	if (stream_id == 0 || conn->broken)
		return;

	if (type != HTTP2_DATA && type != HTTP2_HEADERS &&
	    type != HTTP2_CONTINUATION && type != HTTP2_RST_STREAM)
		return;

	stream = find_http2_stream(conn->conn_id, stream_id);
	if (!stream)
		return;
	half = &stream->half[conn->direction];

	if (type == HTTP2_RST_STREAM) {
		if (half->open)
			render_http2_message(conn, stream, conn->direction, 0);
		return;
	}

	if (!half->open) {
		half->open = 1;
		half->first_ts = timestamp;
	}

	/* Padding and priority fields sit around the useful payload */
	if (flags & HTTP2_FLAG_PADDED) {
		__u8 padding = 0;

		if (length < 1)
			return;
		padding = (__u8)payload[0];
		offset = 1;
		if (padding + offset > length)
			return;
		length -= padding + offset;
	}
	if (type == HTTP2_HEADERS && (flags & HTTP2_FLAG_PRIORITY)) {
		if (length < 5)
			return;
		offset += 5;
		length -= 5;
	}

	if (type == HTTP2_DATA) {
		if (http2_buf_append(&half->body, payload + offset, length) < 0 ||
		    half->body.len > HTTP2_MAX_MESSAGE_BYTES) {
			log_error("[!] Dropping an oversized HTTP/2 body");
			release_http2_half(stream, conn->direction);
			return;
		}
	} else {
		if (conn->block.len + length > HTTP2_MAX_HEADER_BLOCK) {
			/* The HPACK context cannot be kept in sync without the
			 * whole block: stop decoding this connection */
			log_error("[!] Oversized HTTP/2 header block, giving up on this connection");
			http2_buf_reset(&conn->block);
			conn->broken = 1;
			return;
		}
		if (http2_buf_append(&conn->block, payload + offset, length) < 0)
			return;
		conn->block_stream = stream_id;
		if (flags & HTTP2_FLAG_END_STREAM)
			conn->block_end_stream = 1;

		if (flags & HTTP2_FLAG_END_HEADERS) {
			int decoded = 0;

			half->saw_pseudo = 0;
			decoded = http2_decode_block(conn, half) == 0;
			conn->block.len = 0;
			/* Trailers carry no pseudo header and must not rebuild
			 * the start line, an interim 1xx response must */
			if (decoded && half->saw_pseudo)
				http2_finish_headers(half, conn->direction,
						     conn->source == HTTP_SRC_TLS);
			if (conn->block_end_stream)
				flags |= HTTP2_FLAG_END_STREAM;
			conn->block_end_stream = 0;
		} else {
			/* Wait for the CONTINUATION frames before decoding */
			return;
		}
	}

	if (flags & HTTP2_FLAG_END_STREAM)
		render_http2_message(conn, stream, conn->direction, 1);
}

/*
 * http2_stream_push
 *
 * Description:
 * Feeds a captured chunk to the HTTP/2 parser: the bytes are buffered until
 * they form complete frames, which are then processed in order.
 *
 * Params:
 * const struct http_event_t *ev: event delivered by the ring buffer.
 * */
static void http2_stream_push(const struct http_event_t *ev)
{
	struct http2_conn *conn = find_http2_conn(ev);
	size_t offset = 0;

	if (!conn) {
		print_chunk_event(ev);
		return;
	}

	conn->last_ts = ev->timestamp_ns;
	conn->source = ev->source;
	conn->pid = ev->pid;
	conn->tid = ev->tid;
	conn->conn = ev->conn;
	memcpy(conn->comm, ev->comm, sizeof(conn->comm));

	if (http2_buf_append(&conn->frames, ev->data, ev->data_len) < 0) {
		log_error("[!] Out of memory while reassembling an HTTP/2 stream");
		conn->frames.len = 0;
		return;
	}

	/* Bytes piling up without ever completing a frame mean the parser lost
	 * the frame boundaries: nothing sensible can be decoded any more */
	if (conn->frames.len > HTTP2_MAX_MESSAGE_BYTES) {
		log_error("[!] HTTP/2 frame boundaries lost, giving up on this connection");
		conn->frames.len = 0;
		conn->broken = 1;
		return;
	}

	/* The client opens with the connection preface, which is not a frame */
	if (conn->frames.len >= sizeof(HTTP2_PREFACE) - 1 &&
	    memcmp(conn->frames.data, HTTP2_PREFACE, sizeof(HTTP2_PREFACE) - 1) == 0)
		offset = sizeof(HTTP2_PREFACE) - 1;

	while (offset + HTTP2_FRAME_HEADER_LEN <= conn->frames.len) {
		const char *frame = conn->frames.data + offset;
		__u32 payload_len = ((__u32)(unsigned char)frame[0] << 16) |
				    ((__u32)(unsigned char)frame[1] << 8) |
				     (__u32)(unsigned char)frame[2];

		if (offset + HTTP2_FRAME_HEADER_LEN + payload_len > conn->frames.len)
			break;

		http2_handle_frame(conn, frame, payload_len, ev->timestamp_ns);
		offset += HTTP2_FRAME_HEADER_LEN + payload_len;
	}

	/* Keep whatever does not form a complete frame yet */
	if (offset > 0) {
		conn->frames.len -= offset;
		memmove(conn->frames.data, conn->frames.data + offset, conn->frames.len);
	}
}

/*
 * http2_stream_sweep
 *
 * Description:
 * Renders the HTTP/2 messages left open by a connection that stopped sending:
 * without an END_STREAM flag they would otherwise be buffered forever.
 * */
static void http2_stream_sweep()
{
	struct timespec now;
	__u64 now_ns = 0;
	int i = 0, j = 0;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return;
	now_ns = (__u64)now.tv_sec * 1000000000ULL + (__u64)now.tv_nsec;

	for (i = 0; i < HTTP2_MAX_CONNS; i++) {
		struct http2_conn *conn = &http2_conns[i];

		if (!conn->in_use || now_ns < conn->last_ts + HTTP_STREAM_IDLE_NS)
			continue;

		for (j = 0; j < HTTP2_MAX_STREAMS; j++) {
			struct http2_stream *stream = &http2_streams[j];

			if (!stream->in_use || stream->conn_id != conn->conn_id)
				continue;
			if (stream->half[conn->direction].open)
				render_http2_message(conn, stream, conn->direction, 0);
		}

		conn->last_ts = now_ns;
	}
}
