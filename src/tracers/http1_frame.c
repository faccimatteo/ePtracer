/*
 * HTTP/1.1 message framing — see include/http1_frame.h.
 */

#include "http1_frame.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const char *h1_find(const char *buf, size_t len, const char *needle, size_t nlen)
{
	if (len < nlen)
		return NULL;
	for (size_t i = 0; i + nlen <= len; i++)
		if (buf[i] == needle[0] && memcmp(buf + i, needle, nlen) == 0)
			return buf + i;
	return NULL;
}

/* Does the comma separated list in [v, end) contain token (case-insensitive)? */
static int h1_list_has(const char *v, const char *end, const char *token)
{
	size_t tl = strlen(token);
	while (v < end) {
		while (v < end && (*v == ' ' || *v == '\t' || *v == ','))
			v++;
		const char *s = v;
		while (v < end && *v != ',')
			v++;
		const char *e = v;
		while (e > s && (e[-1] == ' ' || e[-1] == '\t'))
			e--;
		if ((size_t)(e - s) == tl && strncasecmp(s, token, tl) == 0)
			return 1;
	}
	return 0;
}

/* Walk the chunked body starting at pos. Returns H1_COMPLETE with *end set to
 * the first byte after the trailers, H1_INCOMPLETE, or H1_INVALID. */
static enum h1_result h1_chunked(const char *buf, size_t len, size_t pos, size_t *end)
{
	for (;;) {
		const char *eol = h1_find(buf + pos, len - pos, "\r\n", 2);
		if (!eol)
			return len - pos > 1024 ? H1_INVALID : H1_INCOMPLETE;

		/* strtoull would skip leading blanks and line ends, past eol */
		if (!isxdigit((unsigned char)buf[pos]))
			return H1_INVALID;
		char *stop;
		unsigned long long size = strtoull(buf + pos, &stop, 16);
		if (stop == buf + pos || (stop < eol && *stop != ';' && *stop != ' ' && *stop != '\t'))
			return H1_INVALID;
		pos = (size_t)(eol - buf) + 2;

		if (size == 0) {
			/* trailers, then the blank line */
			if (len - pos >= 2 && buf[pos] == '\r' && buf[pos + 1] == '\n') {
				*end = pos + 2;
				return H1_COMPLETE;
			}
			const char *t = h1_find(buf + pos, len - pos, "\r\n\r\n", 4);
			if (!t)
				return H1_INCOMPLETE;
			*end = (size_t)(t - buf) + 4;
			return H1_COMPLETE;
		}
		if (size > (unsigned long long)1 << 40)
			return H1_INVALID;
		if (len - pos < size + 2)
			return H1_INCOMPLETE;
		pos += (size_t)size;
		if (buf[pos] != '\r' || buf[pos + 1] != '\n')
			return H1_INVALID;
		pos += 2;
	}
}

enum h1_result h1_frame(const char *buf, size_t len, enum h1_kind kind,
			int request_was_head, struct h1_info *info)
{
	memset(info, 0, sizeof(*info));

	const char *hend = h1_find(buf, len, "\r\n\r\n", 4);
	if (!hend)
		return len > H1_MAX_HEAD ? H1_INVALID : H1_INCOMPLETE;
	info->head_len = (size_t)(hend - buf) + 4;

	const char *eol = h1_find(buf, info->head_len, "\r\n", 2);
	size_t line_len = (size_t)(eol - buf);

	if (kind == H1_RESPONSE) {
		/* HTTP/1.x SP 3DIGIT */
		if (line_len < 12 || strncmp(buf, "HTTP/1.", 7) != 0 || buf[8] != ' ' ||
		    !isdigit((unsigned char)buf[9]) || !isdigit((unsigned char)buf[10]) ||
		    !isdigit((unsigned char)buf[11]))
			return H1_INVALID;
		info->status = (buf[9] - '0') * 100 + (buf[10] - '0') * 10 + (buf[11] - '0');
	} else {
		/* METHOD SP target SP HTTP/1.x */
		size_t m = 0;
		while (m < line_len && m < sizeof(info->method) - 1 &&
		       isupper((unsigned char)buf[m]))
			m++;
		if (m == 0 || m >= line_len || buf[m] != ' ' || line_len < 14 ||
		    strncmp(eol - 8, "HTTP/1.", 7) != 0)
			return H1_INVALID;
		memcpy(info->method, buf, m);
		info->method[m] = '\0';
		info->is_head = strcmp(info->method, "HEAD") == 0;
	}

	/* headers */
	int chunked = 0, have_cl = 0;
	unsigned long long cl = 0;
	const char *p = eol + 2;
	while (p < hend) {
		const char *le = h1_find(p, (size_t)(hend + 2 - p), "\r\n", 2);
		const char *colon = memchr(p, ':', (size_t)(le - p));
		if (colon) {
			size_t nl = (size_t)(colon - p);
			const char *v = colon + 1;
			if (nl == 17 && strncasecmp(p, "Transfer-Encoding", 17) == 0 &&
			    h1_list_has(v, le, "chunked")) {
				chunked = 1;
			} else if (nl == 14 && strncasecmp(p, "Content-Length", 14) == 0) {
				while (v < le && (*v == ' ' || *v == '\t'))
					v++;
				if (v >= le || *v < '0' || *v > '9')
					return H1_INVALID;   /* "-1" would wrap */
				char *stop;
				unsigned long long n = strtoull(v, &stop, 10);
				if (stop == v)
					return H1_INVALID;
				/* two different lengths is a smuggling vector: refuse */
				if (have_cl && n != cl)
					return H1_INVALID;
				cl = n;
				have_cl = 1;
			}
		}
		p = le + 2;
	}

	if (kind == H1_RESPONSE &&
	    (request_was_head || info->status / 100 == 1 ||
	     info->status == 204 || info->status == 304)) {
		info->total = info->head_len;
		return H1_COMPLETE;
	}

	info->chunked = chunked;
	if (chunked) {
		size_t end;
		enum h1_result r = h1_chunked(buf, len, info->head_len, &end);
		if (r == H1_COMPLETE)
			info->total = end;
		return r;
	}
	if (have_cl) {
		if (cl > (unsigned long long)1 << 40)
			return H1_INVALID;
		info->total = info->head_len + (size_t)cl;
		return len >= info->total ? H1_COMPLETE : H1_INCOMPLETE;
	}
	if (kind == H1_REQUEST) {
		info->total = info->head_len;
		return H1_COMPLETE;
	}
	return H1_UNTIL_CLOSE;
}
