/*
 * Standalone test for src/tracers/tls_keys.c (key store + trial decryption).
 * Build/run: bench/run_unit.sh
 */

#include "tls_keys.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/rand.h>

static int g_fail = 0;

#define CHECK(cond, msg) do {                                           \
	if (cond) { printf("  ok   %s\n", msg); }                      \
	else      { printf("  FAIL %s\n", msg); g_fail++; }           \
} while (0)

static void to_hex(const uint8_t *b, size_t n, char *out)
{
	for (size_t i = 0; i < n; i++)
		sprintf(out + 2 * i, "%02x", b[i]);
}

/* Seal a record with `secret` at seq 0, the way the app would. */
static size_t make_record(enum tls_cipher c, const uint8_t *secret, size_t slen,
			  uint8_t *rec, size_t cap)
{
	struct tls_key_ctx ctx;
	tls_key_ctx_init(&ctx, c, TLS_VERSION_1_3, secret, slen);
	const char *msg = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
	size_t len = 0;
	tls_record_seal(&ctx, (const uint8_t *)msg, strlen(msg),
			TLS_CT_APPLICATION_DATA, rec, cap, &len);
	return len;
}

static void test_keylog_exact(void)
{
	printf("[exact match from an NSS keylog line]\n");
	tls_keys_reset();

	uint8_t cr[32], secret[32];
	RAND_bytes(cr, 32);
	RAND_bytes(secret, 32);
	char crh[65], sh[65], line[256];
	to_hex(cr, 32, crh);
	to_hex(secret, 32, sh);
	snprintf(line, sizeof(line), "CLIENT_TRAFFIC_SECRET_0 %s %s\n", crh, sh);

	CHECK(tls_keys_add_keylog_line(1234, line, KEYSRC_KEYLOG_LINE) == 0,
	      "keylog line parsed");
	CHECK(tls_keys_add_keylog_line(1234, "# comment", KEYSRC_KEYLOG_LINE) == 0,
	      "comment line ignored");
	CHECK(tls_keys_add_keylog_line(1234, "BOGUS_LABEL aa bb", KEYSRC_KEYLOG_LINE) == -1,
	      "unknown label rejected");
	CHECK(tls_keys_add_keylog_line(1234, "CLIENT_TRAFFIC_SECRET_0 zz 00", KEYSRC_KEYLOG_LINE) == -1,
	      "bad hex rejected");

	uint8_t rec[512];
	size_t rlen = make_record(TLS_AES_128_GCM_SHA256, secret, 32, rec, sizeof(rec));
	struct tls_key_ctx ctx;
	int r = tls_keys_resolve(1234, cr, TLS_LBL_CLIENT_TRAFFIC_0,
				 TLS_AES_128_GCM_SHA256, rec, rlen, 0, &ctx);
	CHECK(r == 0 && ctx.seq == 0, "resolved by (pid, client_random)");

	uint8_t other_cr[32];
	RAND_bytes(other_cr, 32);
	r = tls_keys_resolve(1234, other_cr, TLS_LBL_CLIENT_TRAFFIC_0,
			     TLS_AES_128_GCM_SHA256, rec, rlen, 0, &ctx);
	CHECK(r == 1, "a different client_random does not match");

	r = tls_keys_resolve(1234, cr, TLS_LBL_SERVER_TRAFFIC_0,
			     TLS_AES_128_GCM_SHA256, rec, rlen, 0, &ctx);
	CHECK(r == 1, "the other direction's label does not match");
}

static void test_candidates(void)
{
	printf("[candidates without client_random, resolved by trial decryption]\n");
	tls_keys_reset();

	/* nine decoys + the right secret, all for the same pid */
	uint8_t right[48];
	RAND_bytes(right, 48);
	for (int i = 0; i < 10; i++) {
		struct tls_secret_event_t ev;
		memset(&ev, 0, sizeof(ev));
		ev.pid = 77;
		ev.source = KEYSRC_ANCHOR;
		ev.label = TLS_LBL_SERVER_TRAFFIC_0;
		ev.secret_len = 48;
		if (i == 6)
			memcpy(ev.secret, right, 48);
		else
			RAND_bytes(ev.secret, 48);
		tls_keys_add(&ev);
	}
	CHECK(tls_keys_count() == 10, "ten candidates stored");

	uint8_t rec[512], cr[32];
	RAND_bytes(cr, 32);
	size_t rlen = make_record(TLS_AES_256_GCM_SHA384, right, 48, rec, sizeof(rec));

	struct tls_key_ctx ctx;
	int r = tls_keys_resolve(78, cr, TLS_LBL_SERVER_TRAFFIC_0,
				 TLS_AES_256_GCM_SHA384, rec, rlen, 0, &ctx);
	CHECK(r == 1, "another pid's candidates are never tried");

	r = tls_keys_resolve(77, cr, TLS_LBL_SERVER_TRAFFIC_0,
			     TLS_AES_128_GCM_SHA256, rec, rlen, 0, &ctx);
	CHECK(r == 1, "48-byte candidates are skipped for a SHA-256 suite");

	r = tls_keys_resolve(77, cr, TLS_LBL_SERVER_TRAFFIC_0,
			     TLS_AES_256_GCM_SHA384, rec, rlen, 0, &ctx);
	CHECK(r == 0 && memcmp(ctx.secret, right, 48) == 0,
	      "the one right secret among ten is found");

	uint8_t pt[512], it;
	size_t pl;
	CHECK(tls_record_open(&ctx, rec, rlen, pt, sizeof(pt), &pl, &it) == TLS_REC_OK,
	      "returned ctx opens the record at seq 0");

	/* bound: now an exact entry for this client_random */
	r = tls_keys_resolve(77, cr, TLS_LBL_SERVER_TRAFFIC_0,
			     TLS_AES_256_GCM_SHA384, rec, rlen, 0, &ctx);
	CHECK(r == 0, "after binding the lookup is exact");

	/* a handshake record (not openable with the app key) is not resolved */
	uint8_t hs_secret[48], hs_rec[512];
	RAND_bytes(hs_secret, 48);
	size_t hs_len = make_record(TLS_AES_256_GCM_SHA384, hs_secret, 48, hs_rec, sizeof(hs_rec));
	uint8_t cr2[32];
	RAND_bytes(cr2, 32);
	r = tls_keys_resolve(77, cr2, TLS_LBL_SERVER_TRAFFIC_0,
			     TLS_AES_256_GCM_SHA384, hs_rec, hs_len, 0, &ctx);
	CHECK(r == 1, "a record under an unknown key stays unresolved (handshake / not yet)");
}

static void test_dedup(void)
{
	printf("[the same secret reported twice is stored once]\n");
	tls_keys_reset();
	struct tls_secret_event_t ev;
	memset(&ev, 0, sizeof(ev));
	ev.pid = 5;
	ev.label = TLS_LBL_CLIENT_TRAFFIC_0;
	ev.secret_len = 32;
	RAND_bytes(ev.secret, 32);
	tls_keys_add(&ev);
	ev.has_client_random = 1;
	RAND_bytes(ev.client_random, 32);
	tls_keys_add(&ev);
	CHECK(tls_keys_count() == 1, "single entry, upgraded with the client random");
}

static void test_late_key(void)
{
	printf("[late key: earlier records were relayed opaque]\n");
	tls_keys_reset();

	uint8_t secret[32], cr[32];
	RAND_bytes(secret, 32);
	RAND_bytes(cr, 32);

	/* the app already sent records at seq 0 and 1 before the key showed up;
	 * this one is seq 2 */
	struct tls_key_ctx app;
	tls_key_ctx_init(&app, TLS_AES_128_GCM_SHA256, TLS_VERSION_1_3, secret, 32);
	app.seq = 2;
	uint8_t rec[512];
	size_t rlen;
	tls_record_seal(&app, (const uint8_t *)"late", 4, TLS_CT_APPLICATION_DATA,
			rec, sizeof(rec), &rlen);

	struct tls_secret_event_t ev;
	memset(&ev, 0, sizeof(ev));
	ev.pid = 9;
	ev.label = TLS_LBL_CLIENT_TRAFFIC_0;
	ev.secret_len = 32;
	memcpy(ev.secret, secret, 32);
	tls_keys_add(&ev);

	struct tls_key_ctx ctx;
	CHECK(tls_keys_resolve(9, cr, TLS_LBL_CLIENT_TRAFFIC_0, TLS_AES_128_GCM_SHA256,
			       rec, rlen, 0, &ctx) == 1,
	      "max_seq 0 does not find a seq-2 record");
	CHECK(tls_keys_resolve(9, cr, TLS_LBL_CLIENT_TRAFFIC_0, TLS_AES_128_GCM_SHA256,
			       rec, rlen, 3, &ctx) == 0 && ctx.seq == 2,
	      "max_seq 3 finds it and reports seq 2");
}

static void add_cand(__u32 pid, __u64 ssl, __u64 ts, enum tls_secret_label lbl,
		     const uint8_t *secret)
{
	struct tls_secret_event_t ev;
	memset(&ev, 0, sizeof(ev));
	ev.pid = pid;
	ev.ssl_ptr = ssl;
	ev.timestamp_ns = ts;
	ev.source = KEYSRC_ANCHOR;
	ev.label = (__u8)lbl;
	ev.secret_len = 32;
	memcpy(ev.secret, secret, 32);
	tls_keys_add(&ev);
}

static void test_sibling(void)
{
	printf("[sibling: the server key of a connection, with no record to try it on]\n");
	tls_keys_reset();

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	__u64 t0 = (__u64)now.tv_sec * 1000000000ULL + (__u64)now.tv_nsec;
	uint8_t c2s[32], s2c[32], decoy_late[32], decoy_other[32], cr[32];
	RAND_bytes(c2s, 32); RAND_bytes(s2c, 32);
	RAND_bytes(decoy_late, 32); RAND_bytes(decoy_other, 32); RAND_bytes(cr, 32);

	add_cand(42, 0xA000, t0,            TLS_LBL_CLIENT_TRAFFIC_0, c2s);
	add_cand(42, 0xA000, t0 + 20000,    TLS_LBL_SERVER_TRAFFIC_0, s2c);
	add_cand(42, 0xA000, t0 + 5000000000ULL, TLS_LBL_SERVER_TRAFFIC_0, decoy_late);
	add_cand(42, 0xB000, t0 + 10000,    TLS_LBL_SERVER_TRAFFIC_0, decoy_other);

	struct tls_key_ctx ctx;
	CHECK(tls_keys_sibling(42, cr, TLS_LBL_SERVER_TRAFFIC_0, TLS_AES_128_GCM_SHA256, &ctx) == 1,
	      "nothing bound to the connection yet: no sibling");

	uint8_t rec[512];
	size_t rlen = make_record(TLS_AES_128_GCM_SHA256, c2s, 32, rec, sizeof(rec));
	CHECK(tls_keys_resolve(42, cr, TLS_LBL_CLIENT_TRAFFIC_0, TLS_AES_128_GCM_SHA256,
			       rec, rlen, 0, &ctx) == 0, "client key resolved by trial");

	CHECK(tls_keys_sibling(42, cr, TLS_LBL_SERVER_TRAFFIC_0, TLS_AES_128_GCM_SHA256, &ctx) == 0 &&
	      memcmp(ctx.secret, s2c, 32) == 0,
	      "server key = same ssl_ptr, nearest in time (decoys: other handle, 5 s later)");

	CHECK(tls_keys_sibling(42, cr, TLS_LBL_SERVER_TRAFFIC_0, TLS_AES_128_GCM_SHA256, &ctx) == 0 &&
	      memcmp(ctx.secret, s2c, 32) == 0, "second lookup is exact (bound)");
}

int main(void)
{
	test_keylog_exact();
	test_candidates();
	test_dedup();
	test_late_key();
	test_sibling();
	printf("\n%s (%d failure%s)\n", g_fail ? "FAILED" : "PASSED",
	       g_fail, g_fail == 1 ? "" : "s");
	return g_fail ? 1 : 0;
}
