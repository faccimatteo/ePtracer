/*
 * HTTP/1.x message reassembly.
 *
 * The eBPF probes deliver whatever the process handed to (or got back from)
 * the TLS library, in chunks of at most MAX_HTTP_DATA_SIZE bytes: a single
 * request can span several events, and a keep-alive connection carries several
 * messages in a row. This file buffers those chunks per connection and per
 * direction, follows the HTTP/1.x framing rules to find where each message
 * ends, and renders the result the way an intercepting proxy does: the request
 * and the response exactly as they were exchanged.
 */

#include <errno.h>
#include <stdint.h>
#include <strings.h>
#include <zlib.h>

/* Connections tracked at the same time, per direction */
#define HTTP_MAX_STREAMS        512
/* Connections whose request line is remembered to pair the responses */
#define HTTP_MAX_CONNS          256
/* A message bigger than this is rendered as truncated instead of being buffered */
#define HTTP_MESSAGE_MAX_BYTES  (4 * 1024 * 1024)
/* A message left incomplete this long is flushed as is */
#define HTTP_STREAM_IDLE_NS     (2ULL * 1000000000ULL)
#define HTTP_REQUEST_LINE_MAX   512
#define HTTP_URL_MAX            1024

/* Result of the framing analysis of a buffered message */
enum http_frame_state {
	HTTP_FRAME_NEED_MORE,    /* the message is not complete yet */
	HTTP_FRAME_COMPLETE,     /* message length known and fully buffered */
	HTTP_FRAME_UNTIL_CLOSE,  /* body ends with the connection: flush when idle */
	HTTP_FRAME_INVALID,      /* not an HTTP/1.x message */
};

/* One direction of one connection */
struct http_stream {
	int    in_use;
	__u64  stream_id;
	__u8   direction;
	__u8   source;
	__u32  pid;
	__u32  tid;
	char   comm[HTTP_COMM_LEN];
	struct conn_info_t conn;
	__u64  first_ts;
	__u64  last_ts;
	char  *data;
	size_t len;
	size_t cap;
	int    lost_bytes;       /* an event was truncated: framing cannot be trusted */
};

/* What a connection turned out to be carrying */
enum http_conn_class {
	HTTP_CLASS_UNKNOWN = 0,
	HTTP_CLASS_HTTP1,
	HTTP_CLASS_HTTP2,
	HTTP_CLASS_OTHER,      /* TLS payload that is not HTTP at all */
};

/* Per connection state, used to pair a response with its request */
struct http_conn_state {
	int    in_use;
	__u64  last_use;         /* LRU tick, so a full table evicts the coldest slot */
	__u64  stream_id;
	char   request_line[HTTP_REQUEST_LINE_MAX];
	int    head_request;
	__u8   protocol_class;
};

static struct http_stream http_streams[HTTP_MAX_STREAMS];
static struct http_conn_state http_conns[HTTP_MAX_CONNS];
/* Monotonic counter driving the LRU eviction of http_conns */
static __u64 http_conn_tick = 0;
static unsigned int http_message_seq = 0;
/* Unchunk and decompress bodies, rewriting the headers that describe them */
static int http_decode_bodies = 0;
/* Directory where each message is written verbatim, empty when not requested */
static char http_dump_dir[PATH_MAX] = {0};

/* Defined in http.c, used for payloads that are not HTTP/1.x messages */
static void print_chunk_event(const struct http_event_t *ev);

/* stdout is a terminal: captured bytes go through http_out_write */
static int http_out_tty = -1;

/*
 * http_out_write
 *
 * Description:
 * Writes captured traffic to stdout. Redirected to a file or a pipe, the bytes
 * go out exactly as exchanged. On a terminal, the C0 control characters other
 * than tab and the line endings, and DEL, are shown as \xNN: a server must not
 * be able to drive the analyst's terminal with escape sequences (retitling it,
 * rewriting what was printed, OSC 52 clipboard writes, ...).
 *
 * Params:
 * const char *data: bytes to print.
 * size_t len: their number.
 * */
static void http_out_write(const char *data, size_t len)
{
	size_t start = 0, i = 0;

	if (http_out_tty < 0)
		http_out_tty = isatty(STDOUT_FILENO);
	if (!http_out_tty) {
		fwrite(data, 1, len, stdout);
		return;
	}

	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)data[i];

		if ((c >= 0x20 && c != 0x7f) || c == '\n' || c == '\r' || c == '\t')
			continue;
		fwrite(data + start, 1, i - start, stdout);
		printf("\\x%02x", c);
		start = i + 1;
	}
	fwrite(data + start, 1, len - start, stdout);
}

/*
 * http_safe_text
 *
 * Description:
 * Replaces, in place, the control characters of a string built from captured
 * traffic (request line, Host, :authority, SNI) before it is shown in a
 * banner, for the same reason as http_out_write.
 *
 * Params:
 * char *s: NUL terminated string.
 *
 * Return:
 * s.
 * */
static char *http_safe_text(char *s)
{
	for (char *p = s; *p; p++)
		if ((unsigned char)*p < 0x20 || (unsigned char)*p == 0x7f)
			*p = '?';
	return s;
}

/*
 * contains_ci
 *
 * Description:
 * Case insensitive substring search, used on header values.
 *
 * Params:
 * const char *haystack: string to search.
 * const char *needle: substring to look for.
 *
 * Return:
 * 1 when the substring is present, 0 otherwise.
 * */
static int contains_ci(const char *haystack, const char *needle)
{
	size_t needle_len = strlen(needle);
	size_t i = 0, haystack_len = strlen(haystack);

	if (needle_len == 0 || haystack_len < needle_len)
		return 0;

	for (i = 0; i + needle_len <= haystack_len; i++) {
		if (strncasecmp(haystack + i, needle, needle_len) == 0)
			return 1;
	}

	return 0;
}

/*
 * memfind
 *
 * Description:
 * Locates a byte sequence inside a buffer.
 *
 * Params:
 * const char *haystack: buffer to search.
 * size_t haystack_len: buffer length.
 * const char *needle: sequence to look for.
 * size_t needle_len: sequence length.
 *
 * Return:
 * Offset of the first occurrence, or -1 when not found.
 * */
static ssize_t memfind(const char *haystack, size_t haystack_len,
		       const char *needle, size_t needle_len)
{
	const char *hit = NULL;

	if (needle_len == 0 || haystack_len < needle_len)
		return -1;

	hit = memmem(haystack, haystack_len, needle, needle_len);
	return hit ? (ssize_t)(hit - haystack) : -1;
}

/*
 * header_value
 *
 * Description:
 * Extracts the value of a header from a header block. Header names are matched
 * case insensitively, as required by RFC 9110.
 *
 * Params:
 * const char *header: header block, start line included.
 * size_t header_len: header block length.
 * const char *name: header name to look for, without the colon.
 * char *out: destination buffer for the value.
 * size_t out_size: destination buffer size.
 *
 * Return:
 * 1 when the header was found, 0 otherwise.
 * */
static int header_value(const char *header, size_t header_len, const char *name,
			char *out, size_t out_size)
{
	size_t name_len = strlen(name);
	size_t pos = 0;

	/* The start line is not a header */
	while (pos < header_len && header[pos] != '\n')
		pos++;
	if (pos < header_len)
		pos++;

	while (pos < header_len) {
		size_t eol = pos, line_end = 0, value = 0, value_len = 0;

		while (eol < header_len && header[eol] != '\n')
			eol++;
		line_end = eol;
		if (line_end > pos && header[line_end - 1] == '\r')
			line_end--;

		if (line_end > pos + name_len &&
		    strncasecmp(header + pos, name, name_len) == 0 &&
		    header[pos + name_len] == ':') {
			value = pos + name_len + 1;
			while (value < line_end && (header[value] == ' ' || header[value] == '\t'))
				value++;
			value_len = line_end - value;
			if (value_len >= out_size)
				value_len = out_size - 1;
			memcpy(out, header + value, value_len);
			out[value_len] = '\0';
			return 1;
		}

		pos = eol + 1;
	}

	return 0;
}

/*
 * chunked_walk
 *
 * Description:
 * Walks a chunked transfer encoded body, optionally copying the decoded bytes.
 * A NULL destination just measures the body.
 *
 * Params:
 * const char *body: body bytes, starting at the first chunk size line.
 * size_t len: bytes available.
 * size_t *encoded_end: offset just past the terminating chunk, on success.
 * char *out: destination for the decoded body, may be NULL.
 * size_t *out_len: number of decoded bytes, may be NULL.
 *
 * Return:
 * 1 when the terminating chunk was reached, 0 when more data is needed,
 * -1 when the body is malformed.
 * */
static int chunked_walk(const char *body, size_t len, size_t *encoded_end,
			char *out, size_t *out_len)
{
	size_t pos = 0, decoded = 0;

	for (;;) {
		size_t eol = pos, i = 0;
		unsigned long chunk_size = 0;
		int digits = 0;

		while (eol < len && body[eol] != '\n')
			eol++;
		if (eol >= len)
			return 0;

		for (i = pos; i < eol; i++) {
			char c = body[i];
			int digit = 0;

			/* Chunk extensions are separated from the size by a semicolon */
			if (c == ';' || c == '\r')
				break;
			if (c >= '0' && c <= '9')
				digit = c - '0';
			else if (c >= 'a' && c <= 'f')
				digit = c - 'a' + 10;
			else if (c >= 'A' && c <= 'F')
				digit = c - 'A' + 10;
			else
				return -1;
			/* One more digit would overflow: no real body is that
			 * large, and a wrapped size would defeat the bounds
			 * check below */
			if (chunk_size > (ULONG_MAX >> 4))
				return -1;
			chunk_size = chunk_size * 16 + (unsigned long)digit;
			digits++;
		}

		if (!digits)
			return -1;

		pos = eol + 1;

		if (chunk_size == 0) {
			/* Trailer section, terminated by an empty line */
			for (;;) {
				size_t trailer_eol = pos;
				int empty = 0;

				while (trailer_eol < len && body[trailer_eol] != '\n')
					trailer_eol++;
				if (trailer_eol >= len)
					return 0;
				empty = (trailer_eol == pos) ||
					(trailer_eol == pos + 1 && body[pos] == '\r');
				pos = trailer_eol + 1;
				if (empty) {
					if (encoded_end)
						*encoded_end = pos;
					if (out_len)
						*out_len = decoded;
					return 1;
				}
			}
		}

		/* written as a subtraction: pos + chunk_size cannot wrap */
		if (pos > len || chunk_size > len - pos || len - pos - chunk_size < 2)
			return 0;

		if (out)
			memcpy(out + decoded, body + pos, chunk_size);
		decoded += chunk_size;
		pos += chunk_size + 2;
	}
}

/*
 * http1_frame
 *
 * Description:
 * Applies the HTTP/1.x message framing rules to tell where a buffered message
 * ends: Content-Length, chunked transfer encoding, responses without a body,
 * and bodies delimited by the end of the connection.
 *
 * Params:
 * const char *buf: buffered message.
 * size_t len: bytes buffered.
 * int head_request: the paired request used the HEAD method, so the response
 * carries no body whatever Content-Length says.
 * size_t *msg_len: total message length, when complete.
 * size_t *body_off: offset of the body inside the message.
 * int *chunked: set when the body uses the chunked transfer encoding.
 *
 * Return:
 * The framing state of the message.
 * */
static enum http_frame_state http1_frame(const char *buf, size_t len, int head_request,
					 size_t *msg_len, size_t *body_off, int *chunked)
{
	char value[64] = {0};
	ssize_t header_end = 0;
	size_t header_len = 0, body_start = 0, body_len = 0, encoded_end = 0;
	int is_response = 0, status = 0;

	*chunked = 0;

	header_end = memfind(buf, len, "\r\n\r\n", 4);
	if (header_end < 0) {
		/* Some servers and clients still emit bare LF line endings */
		header_end = memfind(buf, len, "\n\n", 2);
		if (header_end < 0)
			return len > 64 * 1024 ? HTTP_FRAME_INVALID : HTTP_FRAME_NEED_MORE;
		header_len = (size_t)header_end + 1;
		body_start = (size_t)header_end + 2;
	} else {
		header_len = (size_t)header_end + 2;
		body_start = (size_t)header_end + 4;
	}

	*body_off = body_start;
	is_response = len >= 5 && memcmp(buf, "HTTP/", 5) == 0;
	/* "HTTP/1.1 200": three digits, read in place — the buffer is not NUL
	 * terminated, so atoi() could run past its end */
	if (is_response && len >= 12) {
		for (size_t i = 9; i < 12 && buf[i] >= '0' && buf[i] <= '9'; i++)
			status = status * 10 + (buf[i] - '0');
	}

	/* Chunked wins over Content-Length when both are present */
	if (header_value(buf, header_len, "transfer-encoding", value, sizeof(value)) &&
	    contains_ci(value, "chunked")) {
		int walked = chunked_walk(buf + body_start, len - body_start, &encoded_end, NULL, NULL);

		if (walked < 0)
			return HTTP_FRAME_INVALID;
		if (walked == 0)
			return HTTP_FRAME_NEED_MORE;
		*chunked = 1;
		*msg_len = body_start + encoded_end;
		return HTTP_FRAME_COMPLETE;
	}

	/* Responses to HEAD, 1xx, 204 and 304 never carry a body */
	if (is_response && (head_request || status == 204 || status == 304 ||
			    (status >= 100 && status < 200))) {
		*msg_len = body_start;
		return HTTP_FRAME_COMPLETE;
	}

	if (header_value(buf, header_len, "content-length", value, sizeof(value))) {
		char *end = NULL;
		unsigned long long declared = 0;

		errno = 0;
		declared = strtoull(value, &end, 10);
		/* "-1" (strtoull would turn it into 2^64 - 1), "abc", or a
		 * length that does not fit: invalid, never a wrapped addition */
		if (value[0] < '0' || value[0] > '9' || end == value || errno ||
		    declared > SIZE_MAX)
			return HTTP_FRAME_INVALID;
		body_len = (size_t)declared;
		if (len - body_start < body_len)
			return HTTP_FRAME_NEED_MORE;
		*msg_len = body_start + body_len;
		return HTTP_FRAME_COMPLETE;
	}

	/* No framing header: a request has no body, a response runs until the
	 * peer closes the connection */
	if (!is_response) {
		*msg_len = body_start;
		return HTTP_FRAME_COMPLETE;
	}

	*msg_len = len;
	return HTTP_FRAME_UNTIL_CLOSE;
}

/*
 * inflate_body
 *
 * Description:
 * Decompresses a gzip or deflate encoded body, the way a proxy does before
 * showing it.
 *
 * Params:
 * const char *in: compressed bytes.
 * size_t in_len: compressed length.
 * size_t *out_len: decompressed length, on success.
 *
 * Return:
 * A newly allocated buffer holding the decompressed body, NULL on failure.
 * */
static char *inflate_body(const char *in, size_t in_len, size_t *out_len)
{
	z_stream stream;
	char *out = NULL, *bigger = NULL;
	size_t cap = in_len * 4 + 1024;
	int ret = 0;

	if (in_len == 0)
		return NULL;

	memset(&stream, 0, sizeof(stream));
	/* 47 = automatic gzip/zlib header detection */
	if (inflateInit2(&stream, 47) != Z_OK)
		return NULL;

	out = malloc(cap);
	if (!out) {
		inflateEnd(&stream);
		return NULL;
	}

	stream.next_in = (Bytef *)(uintptr_t)in;
	stream.avail_in = (uInt)in_len;
	stream.next_out = (Bytef *)out;
	stream.avail_out = (uInt)cap;

	for (;;) {
		ret = inflate(&stream, Z_NO_FLUSH);
		if (ret == Z_STREAM_END)
			break;

		/* Genuine corruption (Z_DATA_ERROR, Z_NEED_DICT, ...): stop, but keep
		 * whatever was decoded before it — a partial body still helps */
		if (ret != Z_OK && ret != Z_BUF_ERROR)
			break;

		/* Output buffer full: grow it and keep inflating */
		if (stream.avail_out == 0) {
			if (cap >= 64 * 1024 * 1024)
				break;   /* refuse to grow further, return what we have */
			bigger = realloc(out, cap * 2);
			if (!bigger) {
				free(out);
				inflateEnd(&stream);
				return NULL;
			}
			stream.next_out = (Bytef *)(bigger + cap);
			stream.avail_out = (uInt)cap;
			out = bigger;
			cap *= 2;
			continue;
		}

		/* Room left but the stream neither ended nor can make progress: the
		 * compressed body was captured truncated (a response ePtracer did not
		 * see the end of). Return the bytes decoded so far rather than nothing,
		 * which is what let the caller fall back to the raw compressed dump. */
		if (ret == Z_BUF_ERROR || stream.avail_in == 0)
			break;
	}

	*out_len = cap - stream.avail_out;
	inflateEnd(&stream);
	if (*out_len == 0) {
		free(out);
		return NULL;
	}
	return out;
}

/*
 * describe_message
 *
 * Description:
 * Builds the one line summary shown next to a message, the same information a
 * proxy puts in its history: method and absolute URL for a request, status
 * line for a response.
 *
 * Params:
 * const char *msg: raw message.
 * size_t len: message length.
 * int is_tls: the message travelled inside TLS, so the scheme is https.
 * char *out: destination buffer.
 * size_t out_size: destination buffer size.
 * */
static void describe_message(const char *msg, size_t len, int is_tls,
			     char *out, size_t out_size)
{
	char host[256] = {0};
	size_t line_len = 0, method_len = 0, target_len = 0;
	const char *target = NULL;
	ssize_t eol = memfind(msg, len, "\n", 1);

	line_len = eol < 0 ? len : (size_t)eol;
	if (line_len > 0 && msg[line_len - 1] == '\r')
		line_len--;

	/* Responses are already self describing */
	if (len >= 5 && memcmp(msg, "HTTP/", 5) == 0) {
		if (line_len >= out_size)
			line_len = out_size - 1;
		memcpy(out, msg, line_len);
		out[line_len] = '\0';
		return;
	}

	while (method_len < line_len && msg[method_len] != ' ')
		method_len++;
	target = msg + method_len + 1;
	while (method_len + 1 + target_len < line_len && target[target_len] != ' ')
		target_len++;

	header_value(msg, len, "host", host, sizeof(host));

	/* An absolute target already carries the scheme and the authority */
	if (target_len > 4 && strncasecmp(target, "http", 4) == 0)
		snprintf(out, out_size, "%.*s %.*s", (int)method_len, msg,
			 (int)target_len, target);
	else if (host[0])
		snprintf(out, out_size, "%.*s %s://%s%.*s", (int)method_len, msg,
			 is_tls ? "https" : "http", host, (int)target_len, target);
	else
		snprintf(out, out_size, "%.*s %.*s", (int)method_len, msg,
			 (int)target_len, target);
}

/*
 * find_conn_state
 *
 * Description:
 * Returns the per connection record holding the last request seen, creating it
 * when needed. The oldest slot is recycled when the table is full.
 *
 * Params:
 * __u64 stream_id: connection identifier carried by the events.
 *
 * Return:
 * The connection record, never NULL.
 * */
static struct http_conn_state *find_conn_state(__u64 stream_id)
{
	int i = 0, free_slot = -1, oldest = -1;

	for (i = 0; i < HTTP_MAX_CONNS; i++) {
		if (http_conns[i].in_use && http_conns[i].stream_id == stream_id) {
			http_conns[i].last_use = ++http_conn_tick;
			return &http_conns[i];
		}
		if (!http_conns[i].in_use && free_slot < 0)
			free_slot = i;
		if (http_conns[i].in_use &&
		    (oldest < 0 || http_conns[i].last_use < http_conns[oldest].last_use))
			oldest = i;
	}

	/* A full table evicts the least recently used connection, never an
	 * arbitrary one: overwriting an active connection would lose the request
	 * line — and the HEAD flag — the response about to arrive is paired with */
	if (free_slot < 0)
		free_slot = oldest >= 0 ? oldest : 0;

	memset(&http_conns[free_slot], 0, sizeof(http_conns[free_slot]));
	http_conns[free_slot].in_use = 1;
	http_conns[free_slot].stream_id = stream_id;
	http_conns[free_slot].last_use = ++http_conn_tick;
	return &http_conns[free_slot];
}

/*
 * header_line_is
 *
 * Description:
 * Tells whether a header line declares the given field.
 *
 * Params:
 * const char *line: header line, without its line ending.
 * size_t line_len: line length.
 * const char *name: field name, without the colon.
 *
 * Return:
 * 1 on a match, 0 otherwise.
 * */
static int header_line_is(const char *line, size_t line_len, const char *name)
{
	size_t name_len = strlen(name);

	return line_len > name_len && line[name_len] == ':' &&
	       strncasecmp(line, name, name_len) == 0;
}

/*
 * print_decoded_headers
 *
 * Description:
 * Prints the header block of a message whose body has been unchunked and/or
 * decompressed. The fields that no longer describe the body are dropped and
 * Content-Length is restated, so that what is printed is still a valid HTTP
 * message and not a mix of the original headers and a decoded body.
 *
 * Params:
 * const char *msg: raw message.
 * size_t body_off: offset of the body inside the message.
 * size_t content_length: length of the decoded body.
 * */
static void print_decoded_headers(const char *msg, size_t body_off, size_t content_length)
{
	size_t pos = 0;
	int start_line = 1;

	while (pos < body_off) {
		size_t eol = pos, line_end = 0;

		while (eol < body_off && msg[eol] != '\n')
			eol++;
		line_end = eol;
		if (line_end > pos && msg[line_end - 1] == '\r')
			line_end--;

		/* The empty line closes the header block */
		if (line_end == pos)
			break;

		if (start_line ||
		    (!header_line_is(msg + pos, line_end - pos, "transfer-encoding") &&
		     !header_line_is(msg + pos, line_end - pos, "content-encoding") &&
		     !header_line_is(msg + pos, line_end - pos, "content-length"))) {
			http_out_write(msg + pos, line_end - pos);
			fwrite("\r\n", 1, 2, stdout);
		}

		start_line = 0;
		pos = eol + 1;
	}

	printf("Content-Length: %zu\r\n\r\n", content_length);
}

/*
 * dump_message_to_file
 *
 * Description:
 * Writes a message to its own file, byte for byte, so that it can be replayed
 * or fed to another tool as is.
 *
 * Params:
 * unsigned int seq: message number, used to keep the pairs together.
 * int is_response: the message is a response.
 * const char *msg: raw message.
 * size_t len: message length.
 * */
static void dump_message_to_file(unsigned int seq, int is_response, const char *msg, size_t len)
{
	char path[PATH_MAX + 64];
	FILE *out = NULL;
	int fd = -1;

	if (!http_dump_dir[0])
		return;

	snprintf(path, sizeof(path), "%s/%04u-%s.http", http_dump_dir, seq,
		 is_response ? "response" : "request");

	/* ePtracer runs as root: never follow a symlink planted in the dump
	 * directory, which could otherwise point the write at any file */
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
	out = fd >= 0 ? fdopen(fd, "wb") : NULL;
	if (!out) {
		log_error("[!] Cannot write %s: %s", path, strerror(errno));
		if (fd >= 0)
			close(fd);
		return;
	}

	fwrite(msg, 1, len, out);
	fclose(out);
}

/*
 * print_message_banner
 *
 * Description:
 * Prints the two line header shown above every message: the metadata an
 * intercepting proxy keeps in its history. It is deliberately kept outside the
 * message itself, which is printed verbatim right after it.
 *
 * Params:
 * const struct http_stream *stream: context the message was captured in.
 * const char *summary: one line description of the message.
 * size_t len: message length.
 * int is_response: the message is a response.
 * int complete: the message was fully framed.
 * const char *reply_to: request this message answers, NULL when not applicable.
 * */
static void print_message_banner(const struct http_stream *stream, const char *summary,
				 size_t len, int is_response, int complete,
				 const char *reply_to)
{
	char peer[INET6_ADDRSTRLEN + 16] = {0};
	char timestamp[32] = {0};
	struct tm tm_buf;
	time_t seconds;
	__s64 wall_ns = (__s64)stream->first_ts + http_clock_offset_ns;

	seconds = (time_t)(wall_ns / 1000000000LL);
	localtime_r(&seconds, &tm_buf);
	strftime(timestamp, sizeof(timestamp), "%H:%M:%S", &tm_buf);
	format_peer(&stream->conn, peer, sizeof(peer));
	char safe_summary[HTTP_URL_MAX], safe_reply[HTTP_URL_MAX];
	snprintf(safe_summary, sizeof(safe_summary), "%s", summary);
	http_safe_text(safe_summary);
	summary = safe_summary;
	if (reply_to) {
		snprintf(safe_reply, sizeof(safe_reply), "%s", reply_to);
		reply_to = http_safe_text(safe_reply);
	}

	printf("\n═══════════════════════════════════════════════════════════════════════════\n");
	printf(" #%u  %s  %s\n", ++http_message_seq,
	       is_response ? "RESPONSE" : "REQUEST ", summary);
	printf("      %s.%06u  %s  %s  pid=%u tid=%u comm=%s  %zu bytes%s\n",
	       timestamp, (unsigned int)((wall_ns % 1000000000LL) / 1000),
	       stream->source == HTTP_SRC_TLS ? "TLS" : "cleartext", peer,
	       stream->pid, stream->tid, stream->comm, len,
	       complete ? "" : "  [incomplete]");
	if (reply_to && reply_to[0])
		printf("      in reply to: %s\n", reply_to);
	if (stream->lost_bytes)
		printf("      [some bytes were dropped by the capture, framing may be off]\n");
	printf("───────────────────────────────────────────────────────────────────────────\n");
}

/*
 * render_message
 *
 * Description:
 * Prints one reassembled message: a two line banner with the metadata a proxy
 * shows in its history, then the message itself. Headers are always rendered
 * verbatim; the body is decoded unless raw output was requested.
 *
 * Params:
 * struct http_stream *stream: stream the message belongs to.
 * const char *msg: raw message bytes.
 * size_t len: message length.
 * int complete: the message was fully framed, as opposed to flushed on idle.
 * */
static void render_message(struct http_stream *stream, const char *msg, size_t len,
			   int complete)
{
	struct http_conn_state *conn_state = find_conn_state(stream->stream_id);
	char summary[HTTP_URL_MAX] = {0};
	char encoding[64] = {0};
	char *decoded = NULL, *unchunked = NULL;
	const char *body = NULL;
	size_t body_off = 0, body_len = 0, msg_len = 0, decoded_len = 0;
	int is_response = len >= 5 && memcmp(msg, "HTTP/", 5) == 0;
	int is_tls = stream->source == HTTP_SRC_TLS;
	int chunked = 0;

	if (len == 0)
		return;

	describe_message(msg, len, is_tls, summary, sizeof(summary));
	print_message_banner(stream, summary, len, is_response, complete,
			     is_response ? conn_state->request_line : NULL);

	/* Remember the request so that the response can be paired with it */
	if (!is_response) {
		snprintf(conn_state->request_line, sizeof(conn_state->request_line), "%.*s",
			 (int)sizeof(conn_state->request_line) - 1, summary);
		conn_state->head_request = len >= 5 && strncasecmp(msg, "HEAD ", 5) == 0;
	}

	dump_message_to_file(http_message_seq, is_response, msg, len);

	/* The message is printed exactly as it was exchanged: same line endings,
	 * same bytes, nothing escaped and nothing inserted in it */
	if (!http_decode_bodies) {
		http_out_write(msg, len);
		if (msg[len - 1] != '\n')
			printf("\n");
		fflush(stdout);
		return;
	}

	if (http1_frame(msg, len, conn_state->head_request, &msg_len, &body_off, &chunked) ==
	    HTTP_FRAME_INVALID || body_off >= len) {
		http_out_write(msg, len);
		if (msg[len - 1] != '\n')
			printf("\n");
		fflush(stdout);
		return;
	}

	body = msg + body_off;
	body_len = len - body_off;

	if (chunked) {
		size_t encoded_end = 0, plain_len = 0;

		unchunked = malloc(body_len);
		if (unchunked &&
		    chunked_walk(body, body_len, &encoded_end, unchunked, &plain_len) == 1) {
			body = unchunked;
			body_len = plain_len;
		}
	}

	if (header_value(msg, body_off, "content-encoding", encoding, sizeof(encoding)) &&
	    (contains_ci(encoding, "gzip") || contains_ci(encoding, "deflate"))) {
		decoded = inflate_body(body, body_len, &decoded_len);
		if (decoded) {
			body = decoded;
			body_len = decoded_len;
		}
	}

	/* Nothing could be decoded: the original bytes are still the truth */
	if (body == msg + body_off) {
		http_out_write(msg, len);
		if (msg[len - 1] != '\n')
			printf("\n");
	} else {
		/* Dropping the encodings without restating the length would leave
		 * a message whose headers contradict its body */
		print_decoded_headers(msg, body_off, body_len);
		http_out_write(body, body_len);
		if (body_len == 0 || body[body_len - 1] != '\n')
			printf("\n");
	}

	free(unchunked);
	free(decoded);
	fflush(stdout);
}

/*
 * find_stream
 *
 * Description:
 * Returns the buffer holding one direction of one connection, creating it when
 * needed. When the table is full the least recently used entry is flushed and
 * recycled.
 *
 * Params:
 * const struct http_event_t *ev: event to be buffered.
 *
 * Return:
 * The stream buffer, or NULL when no slot could be allocated.
 * */
static void flush_stream(struct http_stream *stream, int complete);

static struct http_stream *find_stream(const struct http_event_t *ev)
{
	struct http_stream *oldest = NULL;
	int i = 0, free_slot = -1;

	for (i = 0; i < HTTP_MAX_STREAMS; i++) {
		struct http_stream *stream = &http_streams[i];

		if (stream->in_use && stream->stream_id == ev->stream_id &&
		    stream->direction == ev->direction && stream->source == ev->source)
			return stream;
		if (!stream->in_use && free_slot < 0)
			free_slot = i;
		if (stream->in_use && (!oldest || stream->last_ts < oldest->last_ts))
			oldest = stream;
	}

	if (free_slot < 0) {
		if (!oldest)
			return NULL;
		flush_stream(oldest, 0);
		oldest->in_use = 0;
		free_slot = (int)(oldest - http_streams);
	}

	http_streams[free_slot].in_use = 1;
	http_streams[free_slot].stream_id = ev->stream_id;
	http_streams[free_slot].direction = ev->direction;
	http_streams[free_slot].source = ev->source;
	http_streams[free_slot].len = 0;
	http_streams[free_slot].lost_bytes = 0;
	return &http_streams[free_slot];
}

/*
 * stream_append
 *
 * Description:
 * Appends a captured chunk to a stream buffer, growing it as needed.
 *
 * Params:
 * struct http_stream *stream: destination stream.
 * const char *data: chunk bytes.
 * size_t len: chunk length.
 *
 * Return:
 * 0 on success, -1 when the chunk could not be stored.
 * */
static int stream_append(struct http_stream *stream, const char *data, size_t len)
{
	size_t needed = stream->len + len;
	char *bigger = NULL;

	if (needed > stream->cap) {
		size_t cap = stream->cap ? stream->cap : MAX_HTTP_DATA_SIZE * 2;

		while (cap < needed)
			cap *= 2;
		bigger = realloc(stream->data, cap);
		if (!bigger)
			return -1;
		stream->data = bigger;
		stream->cap = cap;
	}

	memcpy(stream->data + stream->len, data, len);
	stream->len += len;
	return 0;
}

/*
 * flush_stream
 *
 * Description:
 * Renders whatever a stream holds and empties it. Used when a connection goes
 * idle, when a body was delimited by the end of the connection, and when a
 * slot has to be recycled.
 *
 * Params:
 * struct http_stream *stream: stream to flush.
 * int complete: the message was fully framed.
 * */
static void flush_stream(struct http_stream *stream, int complete)
{
	if (stream->len == 0)
		return;

	render_message(stream, stream->data, stream->len, complete);
	stream->len = 0;
}

/*
 * http_stream_push
 *
 * Description:
 * Feeds a captured chunk to the reassembler and renders every message that
 * became complete. Payloads that are not HTTP/1.x messages (HTTP/2 frames,
 * WebSocket traffic, anything else carried by TLS) are handed to the live
 * chunk view instead of being buffered.
 *
 * Params:
 * const struct http_event_t *ev: event delivered by the ring buffer.
 * */
static void http_stream_push(const struct http_event_t *ev)
{
	struct http_stream *stream = NULL;
	size_t consumed = 0;

	stream = find_stream(ev);
	if (!stream) {
		print_chunk_event(ev);
		return;
	}

	/* A chunk that starts a new message decides how the stream is handled */
	if (stream->len == 0) {
		if (ev->protocol != HTTP_PROTO_HTTP1_REQ && ev->protocol != HTTP_PROTO_HTTP1_RESP) {
			print_chunk_event(ev);
			return;
		}
		stream->pid = ev->pid;
		stream->tid = ev->tid;
		stream->conn = ev->conn;
		stream->first_ts = ev->timestamp_ns;
		stream->lost_bytes = 0;
		memcpy(stream->comm, ev->comm, sizeof(stream->comm));
	}

	stream->last_ts = ev->timestamp_ns;
	if (ev->truncated)
		stream->lost_bytes = 1;

	if (stream_append(stream, ev->data, ev->data_len) < 0) {
		log_error("[!] Out of memory while reassembling an HTTP message");
		stream->len = 0;
		return;
	}

	/* A keep-alive connection can deliver several messages in one chunk */
	for (;;) {
		struct http_conn_state *conn_state = find_conn_state(stream->stream_id);
		size_t msg_len = 0, body_off = 0;
		int chunked = 0;
		enum http_frame_state state;

		if (stream->len == 0)
			return;

		state = http1_frame(stream->data, stream->len, conn_state->head_request,
				    &msg_len, &body_off, &chunked);

		if (state == HTTP_FRAME_COMPLETE && msg_len <= stream->len) {
			render_message(stream, stream->data, msg_len, 1);
			consumed = msg_len;
			stream->len -= consumed;
			if (stream->len > 0) {
				memmove(stream->data, stream->data + consumed, stream->len);
				stream->first_ts = ev->timestamp_ns;
				continue;
			}
			return;
		}

		if (state == HTTP_FRAME_INVALID || stream->len > HTTP_MESSAGE_MAX_BYTES) {
			flush_stream(stream, 0);
			return;
		}

		/* NEED_MORE and UNTIL_CLOSE both wait: the first for the missing
		 * bytes, the second for the connection to fall idle */
		return;
	}
}

/*
 * http_stream_sweep
 *
 * Description:
 * Flushes the streams that stopped receiving data: responses whose body is
 * delimited by the end of the connection, and messages left incomplete by a
 * connection that went away. Called between two ring buffer polls.
 * */
static void http_stream_sweep()
{
	struct timespec now;
	__u64 now_ns = 0;
	int i = 0;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return;
	now_ns = (__u64)now.tv_sec * 1000000000ULL + (__u64)now.tv_nsec;

	for (i = 0; i < HTTP_MAX_STREAMS; i++) {
		struct http_stream *stream = &http_streams[i];
		struct http_conn_state *conn_state = NULL;
		size_t msg_len = 0, body_off = 0;
		int chunked = 0;

		if (!stream->in_use || stream->len == 0)
			continue;
		if (now_ns < stream->last_ts + HTTP_STREAM_IDLE_NS)
			continue;

		/* A body delimited by the connection end is complete as it is,
		 * anything else is a message the capture did not see the end of */
		conn_state = find_conn_state(stream->stream_id);
		flush_stream(stream,
			     http1_frame(stream->data, stream->len, conn_state->head_request,
					 &msg_len, &body_off, &chunked) == HTTP_FRAME_UNTIL_CLOSE);
	}
}
