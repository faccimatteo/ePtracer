/*
 * Standalone test + microbench for src/tracers/tls_record.c.
 *
 * Builds without the rest of ePtracer:
 *   see bench/run_tls_record.sh (gcc test_tls_record.c tls_record.c -lcrypto)
 *
 * It proves correctness against two independent oracles and then measures the
 * per-byte cost that feeds the latency model (docs/design/latency-benchmarks.md):
 *
 *  1. HKDF-Expand-Label vs OpenSSL's own builtin "TLS13-KDF" EVP — byte-exact
 *     check of the RFC 8446 §7.1 label construction.
 *  2. AEAD interop: a record our seal() produced is opened by raw EVP, and a
 *     record raw EVP produced is opened by our open(). This catches any
 *     nonce / AAD / content-type-stripping mistake.
 *  3. Round-trip and sequence-number translation (the splice case: open on one
 *     leg's seq, seal on the other leg's seq, same key).
 *  4. A wrong key yields TLS_REC_BAD_TAG, never wrong plaintext.
 *  5. --bench: ns/byte for open and open+seal, per cipher suite.
 */

#include "tls_record.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>

static int g_fail = 0;

#define CHECK(cond, msg) do {                                           \
	if (cond) { printf("  ok   %s\n", msg); }                      \
	else      { printf("  FAIL %s\n", msg); g_fail++; }           \
} while (0)

static void hexdump(const char *tag, const uint8_t *b, size_t n)
{
	printf("    %s: ", tag);
	for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
	printf("\n");
}

/* ---- oracle 1: OpenSSL builtin TLS13-KDF ------------------------------- */

static int oracle_expand_label(const char *md, const uint8_t *secret, size_t slen,
			       const char *label, uint8_t *out, size_t out_len)
{
	EVP_KDF *kdf = EVP_KDF_fetch(NULL, "TLS13-KDF", NULL);
	if (!kdf) return -1;
	EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
	EVP_KDF_free(kdf);
	if (!kctx) return -1;

	int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
	OSSL_PARAM p[7], *pp = p;
	*pp++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
	*pp++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)md, 0);
	*pp++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)secret, slen);
	*pp++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PREFIX, "tls13 ", 6);
	*pp++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL,
						 (void *)label, strlen(label));
	*pp++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_DATA, "", 0);
	*pp = OSSL_PARAM_construct_end();

	int ok = EVP_KDF_derive(kctx, out, out_len, p) == 1;
	EVP_KDF_CTX_free(kctx);
	return ok ? 0 : -1;
}

/* ---- oracle 2: a raw-EVP TLS 1.3 record sealer ------------------------- */

static void raw_nonce(const uint8_t *iv, uint64_t seq, uint8_t *nonce)
{
	memcpy(nonce, iv, TLS_IV_LEN);
	for (int i = 0; i < 8; i++)
		nonce[TLS_IV_LEN - 1 - i] ^= (uint8_t)((seq >> (8 * i)) & 0xff);
}

/* Produce a full TLS 1.3 record exactly as the RFC dictates, with plain EVP,
 * to check our open() against something that does not share our code. */
static size_t raw_seal(const char *aead, const uint8_t *key,
		       const uint8_t *iv, uint64_t seq,
		       const uint8_t *pt, size_t pt_len, uint8_t inner_type,
		       uint8_t *out)
{
	size_t inner_len = pt_len + 1;
	size_t ct_len = inner_len + TLS_AEAD_TAG_LEN;
	out[0] = TLS_CT_APPLICATION_DATA; out[1] = 0x03; out[2] = 0x03;
	out[3] = (uint8_t)(ct_len >> 8); out[4] = (uint8_t)(ct_len & 0xff);

	uint8_t nonce[TLS_IV_LEN];
	raw_nonce(iv, seq, nonce);
	uint8_t *inner = malloc(inner_len);
	memcpy(inner, pt, pt_len);
	inner[pt_len] = inner_type;

	EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, aead, NULL);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int len;
	EVP_EncryptInit_ex2(ctx, c, key, nonce, NULL);
	EVP_EncryptUpdate(ctx, NULL, &len, out, TLS_RECORD_HEADER_LEN);
	EVP_EncryptUpdate(ctx, out + TLS_RECORD_HEADER_LEN, &len, inner, (int)inner_len);
	int fin; EVP_EncryptFinal_ex(ctx, out + TLS_RECORD_HEADER_LEN + len, &fin);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TLS_AEAD_TAG_LEN,
			    out + TLS_RECORD_HEADER_LEN + inner_len);
	EVP_CIPHER_CTX_free(ctx);
	EVP_CIPHER_free(c);
	free(inner);
	return TLS_RECORD_HEADER_LEN + ct_len;
}

/* ---- functional tests -------------------------------------------------- */

static void test_expand_label(void)
{
	printf("[HKDF-Expand-Label vs OpenSSL TLS13-KDF]\n");
	uint8_t secret[32];
	RAND_bytes(secret, sizeof(secret));

	const char *labels[] = { "key", "iv", "traffic upd", "derived" };
	for (size_t i = 0; i < sizeof(labels) / sizeof(*labels); i++) {
		uint8_t mine[16], theirs[16];
		int r = tls_hkdf_expand_label(TLS_AES_128_GCM_SHA256, secret, 32,
					      labels[i], NULL, 0, mine, sizeof(mine));
		int o = oracle_expand_label("SHA256", secret, 32, labels[i],
					    theirs, sizeof(theirs));
		char msg[64];
		snprintf(msg, sizeof(msg), "label \"%s\" matches builtin", labels[i]);
		CHECK(r == TLS_REC_OK && o == 0 &&
		      memcmp(mine, theirs, sizeof(mine)) == 0, msg);
		if (memcmp(mine, theirs, sizeof(mine)) != 0) {
			hexdump("ours ", mine, sizeof(mine));
			hexdump("their", theirs, sizeof(theirs));
		}
	}
}

static void test_interop(enum tls_cipher cipher, const char *name, const char *aead)
{
	printf("[AEAD interop + round-trip: %s]\n", name);
	uint8_t secret[48];
	size_t slen = (cipher == TLS_AES_256_GCM_SHA384) ? 48 : 32;
	RAND_bytes(secret, (int)slen);

	struct tls_key_ctx rx, tx;
	CHECK(tls_key_ctx_init(&rx, cipher, TLS_VERSION_1_3, secret, slen) == TLS_REC_OK,
	      "key ctx init (rx leg)");
	CHECK(tls_key_ctx_init(&tx, cipher, TLS_VERSION_1_3, secret, slen) == TLS_REC_OK,
	      "key ctx init (tx leg)");

	const char *payload = "GET /v1/login HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
	size_t plen = strlen(payload);

	/* 1. raw EVP seals at seq 0, 1, 2; our open() must recover each. */
	int all_ok = 1;
	for (uint64_t seq = 0; seq < 3; seq++) {
		uint8_t rec[512], pt[512], itype;
		size_t rlen = raw_seal(aead, rx.key, rx.iv, seq,
				       (const uint8_t *)payload, plen,
				       TLS_CT_APPLICATION_DATA, rec);
		size_t out_len;
		int r = tls_record_open(&rx, rec, rlen, pt, sizeof(pt), &out_len, &itype);
		if (r != TLS_REC_OK || out_len != plen ||
		    memcmp(pt, payload, plen) != 0 || itype != TLS_CT_APPLICATION_DATA)
			all_ok = 0;
	}
	CHECK(all_ok, "our open() recovers records sealed by raw EVP (seq 0..2)");

	/* 2. our seal() at the tx leg must be openable by raw EVP at the same seq. */
	uint8_t rec[512];
	size_t rlen;
	int sr = tls_record_seal(&tx, (const uint8_t *)payload, plen,
				 TLS_CT_APPLICATION_DATA, rec, sizeof(rec), &rlen);
	/* decrypt it independently */
	struct tls_record_hdr hdr; size_t total;
	tls_record_peek(rec, rlen, &hdr, &total);
	uint8_t nonce[TLS_IV_LEN]; raw_nonce(tx.iv, 0, nonce);
	EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, aead, NULL);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	uint8_t dec[512]; int len, fin;
	size_t ctlen = rlen - TLS_RECORD_HEADER_LEN - TLS_AEAD_TAG_LEN;
	int ev = 1;
	ev &= EVP_DecryptInit_ex2(ctx, c, tx.key, nonce, NULL);
	ev &= EVP_DecryptUpdate(ctx, NULL, &len, rec, TLS_RECORD_HEADER_LEN);
	ev &= EVP_DecryptUpdate(ctx, dec, &len, rec + TLS_RECORD_HEADER_LEN, (int)ctlen);
	ev &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TLS_AEAD_TAG_LEN,
				  rec + TLS_RECORD_HEADER_LEN + ctlen);
	ev &= EVP_DecryptFinal_ex(ctx, dec + len, &fin);
	EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
	/* the inner plaintext is payload || inner_type, so ctlen == plen + 1 */
	CHECK(sr == TLS_REC_OK && ev == 1 && ctlen == plen + 1 &&
	      memcmp(dec, payload, plen) == 0 && dec[plen] == TLS_CT_APPLICATION_DATA,
	      "raw EVP opens a record sealed by our seal()");

	/* 3. splice translation: open on rx seq, re-seal on tx seq, reopen. */
	struct tls_key_ctx rx2, tx2;
	tls_key_ctx_init(&rx2, cipher, TLS_VERSION_1_3, secret, slen);
	tls_key_ctx_init(&tx2, cipher, TLS_VERSION_1_3, secret, slen);
	rx2.seq = 7;        /* pretend we joined mid-stream on this leg */
	int splice_ok = 1;
	{
		uint8_t src[512], pt[512], itype, reenc[512], pt2[512], itype2;
		size_t rl = raw_seal(aead, rx2.key, rx2.iv, 7,
				     (const uint8_t *)payload, plen,
				     TLS_CT_APPLICATION_DATA, src);
		size_t ol;
		if (tls_record_open(&rx2, src, rl, pt, sizeof(pt), &ol, &itype) != TLS_REC_OK)
			splice_ok = 0;
		/* edit the plaintext, then seal on the (different) tx seq */
		memcpy(pt, "POST", 4);
		size_t rl2;
		if (tls_record_seal(&tx2, pt, ol, TLS_CT_APPLICATION_DATA,
				    reenc, sizeof(reenc), &rl2) != TLS_REC_OK)
			splice_ok = 0;
		struct tls_key_ctx verify;
		tls_key_ctx_init(&verify, cipher, TLS_VERSION_1_3, secret, slen);
		size_t ol2;
		if (tls_record_open(&verify, reenc, rl2, pt2, sizeof(pt2), &ol2, &itype2) != TLS_REC_OK)
			splice_ok = 0;
		if (ol2 != plen || memcmp(pt2, "POST", 4) != 0)
			splice_ok = 0;
	}
	CHECK(splice_ok, "open(rx seq=7) -> edit -> seal(tx seq=0) -> reopen");

	/* 4. wrong key -> BAD_TAG, never wrong plaintext */
	uint8_t bad_secret[48];
	RAND_bytes(bad_secret, (int)slen);
	struct tls_key_ctx wrong;
	tls_key_ctx_init(&wrong, cipher, TLS_VERSION_1_3, bad_secret, slen);
	uint8_t good[512]; size_t goodlen =
		raw_seal(aead, rx.key, rx.iv, 0, (const uint8_t *)payload, plen,
			 TLS_CT_APPLICATION_DATA, good);
	uint8_t pt[512], itype; size_t ol;
	int wr = tls_record_open(&wrong, good, goodlen, pt, sizeof(pt), &ol, &itype);
	CHECK(wr == TLS_REC_BAD_TAG, "wrong key -> TLS_REC_BAD_TAG (trial decryption is safe)");
}

/* ---- TLS 1.2 / 1.1 interop -------------------------------------------- */

/* Oracle: OpenSSL's own TLS1-PRF (validates our P_hash / 1.0-1.1 split PRF). */
static int oracle_tls_prf(const char *md, const uint8_t *secret, size_t slen,
			  const char *label, const uint8_t *sr, const uint8_t *cr,
			  uint8_t *out, size_t out_len)
{
	EVP_KDF *kdf = EVP_KDF_fetch(NULL, "TLS1-PRF", NULL);
	if (!kdf) return -1;
	EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
	EVP_KDF_free(kdf);
	if (!kctx) return -1;
	OSSL_PARAM p[6], *pp = p;
	*pp++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)md, 0);
	*pp++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, (void *)secret, slen);
	*pp++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, (void *)label, strlen(label));
	*pp++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, (void *)sr, 32);
	*pp++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, (void *)cr, 32);
	*pp = OSSL_PARAM_construct_end();
	int ok = EVP_KDF_derive(kctx, out, out_len, p) == 1;
	EVP_KDF_CTX_free(kctx);
	return ok ? 0 : -1;
}

/* Raw TLS 1.2 AEAD record (independent of our seal). */
static size_t raw_seal12_aead(const char *aead, const uint8_t *key,
			      const uint8_t *fixed_iv, size_t fixed_iv_len,
			      uint64_t seq, uint8_t type, uint16_t ver,
			      const uint8_t *pt, size_t pt_len, uint8_t *out)
{
	int gcm = fixed_iv_len == 4;
	size_t explicit_len = gcm ? 8 : 0;
	uint8_t nonce[TLS_IV_LEN];
	if (gcm) {
		memcpy(nonce, fixed_iv, 4);
		for (int i = 0; i < 8; i++) nonce[4 + i] = (uint8_t)(seq >> (56 - 8 * i));
	} else {
		memcpy(nonce, fixed_iv, 12);
		for (int i = 0; i < 8; i++) nonce[11 - i] ^= (uint8_t)(seq >> (8 * i));
	}
	uint8_t aad[13];
	for (int i = 0; i < 8; i++) aad[i] = (uint8_t)(seq >> (56 - 8 * i));
	aad[8] = type; aad[9] = (uint8_t)(ver >> 8); aad[10] = (uint8_t)ver;
	aad[11] = (uint8_t)(pt_len >> 8); aad[12] = (uint8_t)pt_len;

	uint8_t *frag = out + 5;
	if (gcm) memcpy(frag, nonce + 4, 8);
	uint8_t *ct = frag + explicit_len;
	EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, aead, NULL);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int len;
	EVP_EncryptInit_ex2(ctx, c, key, nonce, NULL);
	EVP_EncryptUpdate(ctx, NULL, &len, aad, sizeof(aad));
	EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len);
	int fin; EVP_EncryptFinal_ex(ctx, ct + len, &fin);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, ct + pt_len);
	EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(c);
	size_t frag_len = explicit_len + pt_len + 16;
	out[0] = type; out[1] = (uint8_t)(ver >> 8); out[2] = (uint8_t)ver;
	out[3] = (uint8_t)(frag_len >> 8); out[4] = (uint8_t)frag_len;
	return 5 + frag_len;
}

static void test_interop_tls12(enum tls_cipher cipher, const char *name,
			       const char *aead, int is_cbc, int etm)
{
	printf("[TLS 1.2 interop + round-trip: %s]\n", name);
	uint8_t ms[48], cr[32], sr[32];
	RAND_bytes(ms, sizeof(ms)); RAND_bytes(cr, sizeof(cr)); RAND_bytes(sr, sizeof(sr));
	const char *prf_md = (cipher == TLS_AES_256_GCM_SHA384) ? "SHA384" : "SHA256";

	/* key ctx for both directions */
	struct tls_key_ctx cli, srv;
	CHECK(tls12_key_ctx_init(&cli, cipher, TLS_VERSION_1_2, ms, sizeof(ms),
				 cr, sr, 0, etm) == TLS_REC_OK, "key ctx init (client_write)");
	CHECK(tls12_key_ctx_init(&srv, cipher, TLS_VERSION_1_2, ms, sizeof(ms),
				 cr, sr, 1, etm) == TLS_REC_OK, "key ctx init (server_write)");

	/* 1. our key block (client_write_key/iv) matches OpenSSL TLS1-PRF */
	if (!is_cbc) {
		uint8_t kb[200];
		size_t need = 2 * cli.key_len + 2 * cli.iv_len;  /* no MAC keys */
		int o = oracle_tls_prf(prf_md, ms, sizeof(ms), "key expansion", sr, cr, kb, need);
		int key_ok = o == 0 && memcmp(cli.key, kb, cli.key_len) == 0 &&
			     memcmp(cli.iv, kb + 2 * cli.key_len, cli.iv_len) == 0;
		CHECK(key_ok, "key block (client_write key+iv) matches OpenSSL TLS1-PRF");
	}

	const char *payload = "GET /v3/listings?q=silver+necklace HTTP/1.1\r\nHost: openapi.etsy.com\r\n\r\n";
	size_t plen = strlen(payload);

	/* 2. a record our seal() made is reopened by our open() (self round-trip) */
	int rt_ok = 1;
	{
		struct tls_key_ctx s = cli, o = cli;
		uint8_t rec[512], pt[512], it; size_t rl, ol;
		for (uint64_t seq = 0; seq < 3; seq++) {
			if (tls_record_seal(&s, (const uint8_t *)payload, plen,
					    TLS_CT_APPLICATION_DATA, rec, sizeof(rec), &rl) != TLS_REC_OK)
				rt_ok = 0;
			if (tls_record_open(&o, rec, rl, pt, sizeof(pt), &ol, &it) != TLS_REC_OK ||
			    ol != plen || memcmp(pt, payload, plen) != 0 ||
			    it != TLS_CT_APPLICATION_DATA)
				rt_ok = 0;
		}
	}
	CHECK(rt_ok, "seal(seq 0..2) -> open round-trips");

	/* 3. AEAD only: a raw-EVP record is opened by our open() (format check) */
	if (!is_cbc) {
		struct tls_key_ctx o = cli;
		uint8_t rec[512], pt[512], it; size_t ol;
		size_t rl = raw_seal12_aead(aead, cli.key, cli.iv, cli.iv_len, 0,
					    TLS_CT_APPLICATION_DATA, 0x0303,
					    (const uint8_t *)payload, plen, rec);
		int r = tls_record_open(&o, rec, rl, pt, sizeof(pt), &ol, &it);
		CHECK(r == TLS_REC_OK && ol == plen && memcmp(pt, payload, plen) == 0 &&
		      it == TLS_CT_APPLICATION_DATA,
		      "our open() recovers a raw-EVP TLS 1.2 record");
	}

	/* 4. splice translation across directions and seqs */
	{
		struct tls_key_ctx rx = srv, tx = srv, vfy = srv;
		rx.seq = 5;
		uint8_t rec[512], pt[512], it, re[512], pt2[512], it2; size_t rl, ol, rl2, ol2;
		int ok = 1;
		struct tls_key_ctx mk = srv; mk.seq = 5;
		ok &= tls_record_seal(&mk, (const uint8_t *)payload, plen,
				      TLS_CT_APPLICATION_DATA, rec, sizeof(rec), &rl) == TLS_REC_OK;
		ok &= tls_record_open(&rx, rec, rl, pt, sizeof(pt), &ol, &it) == TLS_REC_OK;
		memcpy(pt, "POST", 4);
		ok &= tls_record_seal(&tx, pt, ol, TLS_CT_APPLICATION_DATA, re, sizeof(re), &rl2) == TLS_REC_OK;
		ok &= tls_record_open(&vfy, re, rl2, pt2, sizeof(pt2), &ol2, &it2) == TLS_REC_OK;
		ok &= ol2 == plen && memcmp(pt2, "POST", 4) == 0;
		CHECK(ok, "open(rx seq=5) -> edit -> seal(tx seq=0) -> reopen");
	}

	/* 5. wrong master secret -> BAD_TAG, never wrong plaintext */
	{
		uint8_t bad[48]; RAND_bytes(bad, sizeof(bad));
		struct tls_key_ctx wrong;
		tls12_key_ctx_init(&wrong, cipher, TLS_VERSION_1_2, bad, sizeof(bad), cr, sr, 0, etm);
		struct tls_key_ctx s = cli;
		uint8_t rec[512], pt[512], it; size_t rl, ol;
		tls_record_seal(&s, (const uint8_t *)payload, plen,
				TLS_CT_APPLICATION_DATA, rec, sizeof(rec), &rl);
		int wr = tls_record_open(&wrong, rec, rl, pt, sizeof(pt), &ol, &it);
		CHECK(wr == TLS_REC_BAD_TAG, "wrong master secret -> TLS_REC_BAD_TAG");
	}
}

/* TLS 1.1 uses the legacy MD5+SHA1 PRF and CBC only. Validate the key block
 * against OpenSSL's TLS1-PRF (MD5-SHA1) and round-trip a CBC record. */
static void test_tls11(void)
{
	printf("[TLS 1.1 CBC + legacy PRF]\n");
	uint8_t ms[48], cr[32], sr[32];
	RAND_bytes(ms, sizeof(ms)); RAND_bytes(cr, sizeof(cr)); RAND_bytes(sr, sizeof(sr));

	struct tls_key_ctx cli;
	CHECK(tls12_key_ctx_init(&cli, TLS_AES_128_CBC_SHA, TLS_VERSION_1_1, ms, sizeof(ms),
				 cr, sr, 0, 0) == TLS_REC_OK, "key ctx init (TLS 1.1 client_write)");

	/* key block = MD5+SHA1 PRF("key expansion", sr+cr); mac(20)+key(16) first */
	uint8_t kb[200];
	size_t need = 2 * 20 + 2 * cli.key_len;   /* 2 MAC keys + 2 enc keys (no IV) */
	int o = oracle_tls_prf("MD5-SHA1", ms, sizeof(ms), "key expansion", sr, cr, kb, need);
	int key_ok = o == 0 && memcmp(cli.mac_key, kb, 20) == 0 &&
		     memcmp(cli.key, kb + 2 * 20, cli.key_len) == 0;
	CHECK(key_ok, "key block (mac+enc keys) matches OpenSSL TLS1-PRF (MD5-SHA1)");

	const char *payload = "GET / HTTP/1.1\r\nHost: legacy.example.com\r\n\r\n";
	size_t plen = strlen(payload);
	for (int etm = 0; etm <= 1; etm++) {
		struct tls_key_ctx s, d;
		tls12_key_ctx_init(&s, TLS_AES_128_CBC_SHA, TLS_VERSION_1_1, ms, sizeof(ms), cr, sr, 0, etm);
		tls12_key_ctx_init(&d, TLS_AES_128_CBC_SHA, TLS_VERSION_1_1, ms, sizeof(ms), cr, sr, 0, etm);
		uint8_t rec[512], pt[512], it; size_t rl, ol;
		int ok = tls_record_seal(&s, (const uint8_t *)payload, plen,
					 TLS_CT_APPLICATION_DATA, rec, sizeof(rec), &rl) == TLS_REC_OK &&
			 tls_record_open(&d, rec, rl, pt, sizeof(pt), &ol, &it) == TLS_REC_OK &&
			 ol == plen && memcmp(pt, payload, plen) == 0;
		CHECK(ok, etm ? "CBC EtM seal->open round-trips (TLS 1.1)"
			      : "CBC MtE seal->open round-trips (TLS 1.1)");
	}
}

/* ---- microbench -------------------------------------------------------- */

static double now_ns(void)
{
	struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static void bench(enum tls_cipher cipher, const char *name, const char *aead,
		  size_t payload_size)
{
	size_t slen = (cipher == TLS_AES_256_GCM_SHA384) ? 48 : 32;
	uint8_t secret[48]; RAND_bytes(secret, (int)slen);
	struct tls_key_ctx rx, tx;
	tls_key_ctx_init(&rx, cipher, TLS_VERSION_1_3, secret, slen);
	tls_key_ctx_init(&tx, cipher, TLS_VERSION_1_3, secret, slen);

	uint8_t *pt = malloc(payload_size);
	RAND_bytes(pt, (int)payload_size);
	uint8_t *rec = malloc(payload_size + 64);
	uint8_t *dec = malloc(payload_size + 64);
	uint8_t *reenc = malloc(payload_size + 64);

	/* one record carrying the whole payload (fragmentation is linear, so a
	 * single record is a faithful ns/byte probe) */
	size_t rlen = raw_seal(aead, rx.key, rx.iv, 0, pt, payload_size,
			       TLS_CT_APPLICATION_DATA, rec);

	const int iters = 2000;
	size_t ol; uint8_t itype;

	/* open only (1 pass) */
	double t0 = now_ns();
	for (int i = 0; i < iters; i++) {
		rx.seq = 0;
		tls_record_open(&rx, rec, rlen, dec, payload_size + 64, &ol, &itype);
	}
	double open_ns = (now_ns() - t0) / iters;

	/* open + seal (2 passes, the edit path) */
	t0 = now_ns();
	for (int i = 0; i < iters; i++) {
		rx.seq = 0; tx.seq = 0;
		size_t rl2;
		tls_record_open(&rx, rec, rlen, dec, payload_size + 64, &ol, &itype);
		tls_record_seal(&tx, dec, ol, TLS_CT_APPLICATION_DATA,
				reenc, payload_size + 64, &rl2);
	}
	double both_ns = (now_ns() - t0) / iters;

	printf("  %-24s %8zu B   open %7.2f ns/rec (%.3f ns/B)   open+seal %7.2f ns/rec (%.3f ns/B)\n",
	       name, payload_size, open_ns, open_ns / payload_size,
	       both_ns, both_ns / payload_size);

	free(pt); free(rec); free(dec); free(reenc);
}

int main(int argc, char **argv)
{
	int do_bench = (argc > 1 && strcmp(argv[1], "--bench") == 0);

	test_expand_label();
	test_interop(TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256", "AES-128-GCM");
	test_interop(TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384", "AES-256-GCM");
	test_interop(TLS_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256",
		     "ChaCha20-Poly1305");

	test_interop_tls12(TLS_AES_128_GCM_SHA256, "TLS 1.2 AES-128-GCM", "AES-128-GCM", 0, 0);
	test_interop_tls12(TLS_AES_256_GCM_SHA384, "TLS 1.2 AES-256-GCM", "AES-256-GCM", 0, 0);
	test_interop_tls12(TLS_CHACHA20_POLY1305_SHA256, "TLS 1.2 ChaCha20-Poly1305",
			   "ChaCha20-Poly1305", 0, 0);
	test_interop_tls12(TLS_AES_128_CBC_SHA, "TLS 1.2 AES-128-CBC-SHA (MtE)", "AES-128-CBC", 1, 0);
	test_interop_tls12(TLS_AES_128_CBC_SHA, "TLS 1.2 AES-128-CBC-SHA (EtM)", "AES-128-CBC", 1, 1);
	test_interop_tls12(TLS_AES_256_CBC_SHA256, "TLS 1.2 AES-256-CBC-SHA256 (EtM)", "AES-256-CBC", 1, 1);
	test_tls11();

	if (do_bench) {
		printf("\n[microbench] (ns/byte feeds docs/design/latency-benchmarks.md §6.1)\n");
		size_t sizes[] = { 1024, 16384, 65536, 1048576 };
		struct { enum tls_cipher c; const char *n; const char *a; } cs[] = {
			{ TLS_AES_128_GCM_SHA256,       "AES-128-GCM",       "AES-128-GCM" },
			{ TLS_AES_256_GCM_SHA384,       "AES-256-GCM",       "AES-256-GCM" },
			{ TLS_CHACHA20_POLY1305_SHA256, "ChaCha20-Poly1305", "ChaCha20-Poly1305" },
		};
		for (size_t i = 0; i < sizeof(cs)/sizeof(*cs); i++)
			for (size_t j = 0; j < sizeof(sizes)/sizeof(*sizes); j++)
				bench(cs[i].c, cs[i].n, cs[i].a, sizes[j]);
	}

	printf("\n%s (%d failure%s)\n", g_fail ? "FAILED" : "PASSED",
	       g_fail, g_fail == 1 ? "" : "s");
	return g_fail ? 1 : 0;
}
