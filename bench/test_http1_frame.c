/*
 * Test for src/tracers/http1_frame.c. Build/run: bench/run_unit.sh
 */

#include "http1_frame.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0;

#define CHECK(cond, msg) do {                                           \
	if (cond) { printf("  ok   %s\n", msg); }                      \
	else      { printf("  FAIL %s\n", msg); g_fail++; }           \
} while (0)

static enum h1_result frame_req(const char *s, struct h1_info *i)
{
	return h1_frame(s, strlen(s), H1_REQUEST, 0, i);
}

int main(void)
{
	struct h1_info i;
	printf("[requests]\n");
	const char *get = "GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\n";
	CHECK(frame_req(get, &i) == H1_COMPLETE && i.total == 28 && !strcmp(i.method, "GET"),
	      "GET without body ends at the head (pipelined next one left alone)");

	const char *post = "POST /p HTTP/1.1\r\nContent-Length: 5\r\n\r\nhel";
	CHECK(frame_req(post, &i) == H1_INCOMPLETE, "Content-Length body not complete yet");
	const char *post2 = "POST /p HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
	CHECK(frame_req(post2, &i) == H1_COMPLETE && i.total == strlen(post2) - 5,
	      "Content-Length body complete, extra bytes excluded");

	const char *chunk = "POST /c HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n"
			    "Content-Length: 999\r\n\r\n4\r\nwiki\r\n5;ext=1\r\npedia\r\n0\r\nX-T: 1\r\n\r\n";
	CHECK(frame_req(chunk, &i) == H1_COMPLETE && i.total == strlen(chunk),
	      "chunked (wins over Content-Length) with extension and trailer");
	const char *chunk_part = "POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwi";
	CHECK(frame_req(chunk_part, &i) == H1_INCOMPLETE, "partial chunk");

	const char *dup_cl = "POST /x HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd";
	CHECK(frame_req(dup_cl, &i) == H1_INVALID, "conflicting Content-Length refused (smuggling)");
	CHECK(frame_req("POST /x HTTP/1.1\r\nContent-Length: -1\r\n\r\nab", &i) == H1_INVALID,
	      "negative Content-Length refused (strtoull would wrap it)");
	CHECK(frame_req("POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
			"ffffffffffffffff\r\nAAAA\r\n0\r\n\r\n", &i) == H1_INVALID,
	      "chunk size beyond any buffer refused");
	CHECK(frame_req("POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
			"\r\n   ", &i) == H1_INVALID,
	      "chunk size line without digits refused");
	CHECK(frame_req("POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", &i) ==
	      H1_COMPLETE && i.chunked, "chunked framing reported to the caller");
	CHECK(frame_req("POST /x HTTP/1.1\r\nTransfer-Encoding: xchunkedx\r\nContent-Length: 0\r\n\r\n",
			&i) == H1_COMPLETE && !i.chunked,
	      "a token merely containing 'chunked' is not chunked");
	CHECK(frame_req("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", &i) == H1_INVALID,
	      "HTTP/2 preface is not HTTP/1.x");
	CHECK(frame_req("\x16\x03\x01\x02\x00", &i) == H1_INCOMPLETE ||
	      frame_req("\x16\x03\x01\x02\x00\r\n\r\n", &i) == H1_INVALID,
	      "binary garbage is not a request");

	printf("[responses]\n");
	const char *r204 = "HTTP/1.1 204 No Content\r\nContent-Length: 10\r\n\r\n";
	CHECK(h1_frame(r204, strlen(r204), H1_RESPONSE, 0, &i) == H1_COMPLETE &&
	      i.total == strlen(r204) && i.status == 204, "204 has no body");
	const char *rhead = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n";
	CHECK(h1_frame(rhead, strlen(rhead), H1_RESPONSE, 1, &i) == H1_COMPLETE &&
	      i.total == strlen(rhead), "response to HEAD has no body");
	CHECK(h1_frame(rhead, strlen(rhead), H1_RESPONSE, 0, &i) == H1_INCOMPLETE,
	      "same response to GET waits for its 10 bytes");
	const char *rclose = "HTTP/1.0 200 OK\r\n\r\nbody...";
	CHECK(h1_frame(rclose, strlen(rclose), H1_RESPONSE, 0, &i) == H1_UNTIL_CLOSE,
	      "no length: delimited by close");

	printf("\n%s (%d failure%s)\n", g_fail ? "FAILED" : "PASSED",
	       g_fail, g_fail == 1 ? "" : "s");
	return g_fail ? 1 : 0;
}
