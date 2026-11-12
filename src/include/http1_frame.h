/*
 * HTTP/1.1 message framing for the proxy bridge (include/splice_bridge.h).
 *
 * The bridge works one whole message at a time: a request from the app goes to
 * the proxy whole; a request coming back from the proxy is
 * delivered to the server only when it is complete; a response is routed to
 * whoever is waiting for it once it is complete. All of that needs to know
 * where a message ends, which is what this does — over a buffer, without state,
 * so that it is trivially testable and cannot get out of sync.
 *
 * Framing follows RFC 9112 §6: Transfer-Encoding chunked wins over
 * Content-Length; a request with neither has no body; a response to HEAD, a
 * 1xx, 204 or 304 has no body; any other response with neither is delimited by
 * the end of the connection.
 *
 * (tracers/http_message.c frames too, but for the display of captured chunks;
 * it owns per-connection state fed by BPF events, which does not fit here.)
 */

#ifndef EPTRACER_HTTP1_FRAME_H
#define EPTRACER_HTTP1_FRAME_H

#include <stddef.h>

/* Longest header block accepted before calling the stream broken */
#define H1_MAX_HEAD (64 * 1024)

enum h1_kind {
	H1_REQUEST  = 0,
	H1_RESPONSE = 1,
};

enum h1_result {
	H1_INCOMPLETE  = 0,   /* need more bytes */
	H1_COMPLETE    = 1,   /* *total is the message length */
	H1_UNTIL_CLOSE = 2,   /* response body runs to the end of the connection */
	H1_INVALID     = -1,  /* not HTTP/1.x, or malformed */
};

struct h1_info {
	size_t head_len;      /* start line + headers + blank line */
	size_t total;         /* whole message, valid when H1_COMPLETE */
	int    status;        /* responses */
	char   method[16];    /* requests */
	int    is_head;       /* request method is HEAD */
	int    chunked;       /* body framed by Transfer-Encoding: chunked */
};

/*
 * Frame the message at the start of buf. For a response, `request_was_head`
 * tells whether it answers a HEAD (no body whatever the headers say).
 */
enum h1_result h1_frame(const char *buf, size_t len, enum h1_kind kind,
			int request_was_head, struct h1_info *info);

#endif /* EPTRACER_HTTP1_FRAME_H */
