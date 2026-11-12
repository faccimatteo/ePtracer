/*
 * TLS record layer — see include/tls_record.h for the contract.
 *
 * TLS 1.3 is the common case (BoringSSL, rustls, Go, modern OpenSSL negotiate
 * it). TLS 1.2 is also supported: the AEAD suites (AES-GCM, ChaCha20-Poly1305)
 * and the AES-CBC + HMAC suites, which old endpoints (and some mobile API hosts,
 * e.g. openapi.etsy.com) still negotiate. TLS 1.1/1.0 reuse the CBC path with
 * the legacy MD5+SHA-1 PRF. The key material differs by version: 1.3 derives
 * key/iv from a per-direction traffic secret (HKDF-Expand-Label); 1.2 and below
 * expand one master secret into a key block with the TLS PRF.
 */

#include "tls_record.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

static int tls13_record_open(struct tls_key_ctx *ctx,
			     const uint8_t *record, size_t record_len,
			     uint8_t *out, size_t out_cap, size_t *out_len,
			     uint8_t *inner_type);
static int tls13_record_seal(struct tls_key_ctx *ctx,
			     const uint8_t *plaintext, size_t plaintext_len,
			     uint8_t inner_type,
			     uint8_t *out, size_t out_cap, size_t *out_len);

/* API common to OpenSSL 1.1.1 (the eadb/Android chroot) and 3.0 (desktop):
 * EVP_PKEY_HKDF for the key schedule, EVP_get_cipherbyname + the legacy
 * EVP_*Init_ex for the AEAD/CBC, HMAC() for the PRF and CBC MAC. No EVP_KDF/
 * OSSL_PARAM, no *_ex2. */

/* ---- cipher suite parameters ------------------------------------------- */

struct rec_suite_params {
	const EVP_CIPHER *aead;      /* AEAD or CBC block cipher */
	const EVP_MD     *md;        /* PRF / HKDF hash */
	const EVP_MD     *mac_md;    /* CBC HMAC hash; NULL for AEAD */
	uint8_t           key_len;
	uint8_t           fixed_iv_len;  /* AEAD TLS1.2 fixed IV: GCM 4, ChaCha 12 */
	uint8_t           mac_len;       /* CBC MAC length; 0 for AEAD */
	uint8_t           block_len;     /* CBC block size; 0 for AEAD */
	int               is_aead;
};

static int rec_suite_lookup(enum tls_cipher cipher, struct rec_suite_params *p)
{
	memset(p, 0, sizeof(*p));
	switch (cipher) {
	case TLS_AES_128_GCM_SHA256:
		p->aead = EVP_get_cipherbyname("aes-128-gcm");
		p->md = EVP_sha256(); p->key_len = 16;
		p->fixed_iv_len = 4; p->is_aead = 1;
		break;
	case TLS_AES_256_GCM_SHA384:
		p->aead = EVP_get_cipherbyname("aes-256-gcm");
		p->md = EVP_sha384(); p->key_len = 32;
		p->fixed_iv_len = 4; p->is_aead = 1;
		break;
	case TLS_CHACHA20_POLY1305_SHA256:
		p->aead = EVP_get_cipherbyname("chacha20-poly1305");
		p->md = EVP_sha256(); p->key_len = 32;
		p->fixed_iv_len = 12; p->is_aead = 1;
		break;
	case TLS_AES_128_CBC_SHA:
		p->aead = EVP_get_cipherbyname("aes-128-cbc");
		p->md = EVP_sha256();  /* TLS 1.2 PRF hash for a SHA-1 MAC suite */
		p->mac_md = EVP_sha1(); p->key_len = 16;
		p->mac_len = 20; p->block_len = 16;
		break;
	case TLS_AES_256_CBC_SHA:
		p->aead = EVP_get_cipherbyname("aes-256-cbc");
		p->md = EVP_sha256();
		p->mac_md = EVP_sha1(); p->key_len = 32;
		p->mac_len = 20; p->block_len = 16;
		break;
	case TLS_AES_128_CBC_SHA256:
		p->aead = EVP_get_cipherbyname("aes-128-cbc");
		p->md = EVP_sha256();
		p->mac_md = EVP_sha256(); p->key_len = 16;
		p->mac_len = 32; p->block_len = 16;
		break;
	case TLS_AES_256_CBC_SHA256:
		p->aead = EVP_get_cipherbyname("aes-256-cbc");
		p->md = EVP_sha256();
		p->mac_md = EVP_sha256(); p->key_len = 32;
		p->mac_len = 32; p->block_len = 16;
		break;
	default:
		return TLS_REC_UNSUPPORTED;
	}
	if (!p->aead)
		return TLS_REC_INTERNAL;
	if (!p->is_aead && !p->mac_md)
		return TLS_REC_INTERNAL;
	return TLS_REC_OK;
}

int tls_cipher_is_aead(enum tls_cipher cipher)
{
	struct rec_suite_params sp;
	return rec_suite_lookup(cipher, &sp) == TLS_REC_OK && sp.is_aead;
}

enum tls_cipher tls_cipher_from_wire(uint16_t suite)
{
	switch (suite) {
	case 0x1301: return TLS_AES_128_GCM_SHA256;
	case 0x1302: return TLS_AES_256_GCM_SHA384;
	case 0x1303: return TLS_CHACHA20_POLY1305_SHA256;
	default:     return TLS_CIPHER_UNKNOWN;
	}
}

enum tls_cipher tls12_cipher_from_wire(uint16_t suite)
{
	switch (suite) {
	/* AES-128-GCM-SHA256 (ECDHE-RSA/ECDSA, DHE-RSA, RSA) */
	case 0xC02F: case 0xC02B: case 0x009E: case 0x009C:
		return TLS_AES_128_GCM_SHA256;
	/* AES-256-GCM-SHA384 */
	case 0xC030: case 0xC02C: case 0x009F: case 0x009D:
		return TLS_AES_256_GCM_SHA384;
	/* ChaCha20-Poly1305-SHA256 (RFC 7905) */
	case 0xCCA8: case 0xCCA9: case 0xCCAA:
		return TLS_CHACHA20_POLY1305_SHA256;
	/* AES-CBC with HMAC-SHA1 */
	case 0xC013: case 0xC009: case 0x002F: case 0x0033:
		return TLS_AES_128_CBC_SHA;
	case 0xC014: case 0xC00A: case 0x0035: case 0x0039:
		return TLS_AES_256_CBC_SHA;
	/* AES-CBC with HMAC-SHA256 */
	case 0xC027: case 0xC023: case 0x003C: case 0x0067:
		return TLS_AES_128_CBC_SHA256;
	case 0xC028: case 0xC024: case 0x003D: case 0x006B:
		return TLS_AES_256_CBC_SHA256;
	default:
		return TLS_CIPHER_UNKNOWN;
	}
}

static size_t rec_hash_len(enum tls_cipher cipher)
{
	return cipher == TLS_AES_256_GCM_SHA384 ? 48 : 32;
}

/* ---- HKDF-Expand-Label (RFC 8446 §7.1) --------------------------------- */

/*
 * HkdfLabel = struct {
 *     uint16 length;
 *     opaque label<7..255>   = "tls13 " + Label;
 *     opaque context<0..255> = Context;
 * }
 * then out = HKDF-Expand(secret, HkdfLabel, length).
 */
int tls_hkdf_expand_label(enum tls_cipher cipher,
			  const uint8_t *secret, size_t secret_len,
			  const char *label,
			  const uint8_t *context, size_t context_len,
			  uint8_t *out, size_t out_len)
{
	struct rec_suite_params sp;
	if (rec_suite_lookup(cipher, &sp) != TLS_REC_OK)
		return TLS_REC_UNSUPPORTED;

	uint8_t info[2 + 1 + 255 + 1 + 255];
	size_t pos = 0;
	size_t full_label_len = 6 + strlen(label);   /* "tls13 " + label */

	if (full_label_len > 255 || context_len > 255 || out_len > 0xffff)
		return TLS_REC_MALFORMED;

	info[pos++] = (uint8_t)(out_len >> 8);
	info[pos++] = (uint8_t)(out_len & 0xff);
	info[pos++] = (uint8_t)full_label_len;
	memcpy(info + pos, "tls13 ", 6); pos += 6;
	memcpy(info + pos, label, strlen(label)); pos += strlen(label);
	info[pos++] = (uint8_t)context_len;
	if (context_len) { memcpy(info + pos, context, context_len); pos += context_len; }

	EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!kctx)
		return TLS_REC_INTERNAL;

	size_t outlen = out_len;
	int ok = EVP_PKEY_derive_init(kctx) == 1 &&
		 EVP_PKEY_CTX_hkdf_mode(kctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) == 1 &&
		 EVP_PKEY_CTX_set_hkdf_md(kctx, sp.md) == 1 &&
		 EVP_PKEY_CTX_set1_hkdf_key(kctx, secret, (int)secret_len) == 1 &&
		 EVP_PKEY_CTX_add1_hkdf_info(kctx, info, (int)pos) == 1 &&
		 EVP_PKEY_derive(kctx, out, &outlen) == 1 && outlen == out_len;
	EVP_PKEY_CTX_free(kctx);
	return ok ? TLS_REC_OK : TLS_REC_INTERNAL;
}

/* ---- key schedule ------------------------------------------------------ */

static int rec_derive_key_iv(struct tls_key_ctx *ctx)
{
	struct rec_suite_params sp;
	if (rec_suite_lookup(ctx->cipher, &sp) != TLS_REC_OK)
		return TLS_REC_UNSUPPORTED;

	ctx->key_len = sp.key_len;
	ctx->iv_len = TLS_IV_LEN;   /* 1.3: the full 12-byte iv is derived */
	ctx->mac_key_len = 0;
	int r = tls_hkdf_expand_label(ctx->cipher, ctx->secret, ctx->secret_len,
				      "key", NULL, 0, ctx->key, ctx->key_len);
	if (r != TLS_REC_OK)
		return r;
	return tls_hkdf_expand_label(ctx->cipher, ctx->secret, ctx->secret_len,
				     "iv", NULL, 0, ctx->iv, TLS_IV_LEN);
}

int tls_key_ctx_init(struct tls_key_ctx *ctx,
		     enum tls_cipher cipher, enum tls_version version,
		     const uint8_t *secret, size_t secret_len)
{
	if (secret_len > TLS_MAX_SECRET_LEN)
		return TLS_REC_MALFORMED;
	if (version != TLS_VERSION_1_3)
		return TLS_REC_UNSUPPORTED;

	memset(ctx, 0, sizeof(*ctx));
	ctx->cipher = cipher;
	ctx->version = version;
	ctx->secret_len = (uint8_t)secret_len;
	memcpy(ctx->secret, secret, secret_len);
	ctx->seq = 0;
	return rec_derive_key_iv(ctx);
}

int tls_key_ctx_update(struct tls_key_ctx *ctx)
{
	uint8_t next[TLS_MAX_SECRET_LEN];
	size_t slen = rec_hash_len(ctx->cipher);
	int r = tls_hkdf_expand_label(ctx->cipher, ctx->secret, slen,
				      "traffic upd", NULL, 0, next, slen);
	if (r != TLS_REC_OK)
		return r;
	memcpy(ctx->secret, next, slen);
	ctx->secret_len = (uint8_t)slen;
	ctx->seq = 0;
	return rec_derive_key_iv(ctx);
}

/* ---- TLS 1.2 / 1.1 / 1.0 key schedule (RFC 5246 §5, RFC 2246 §5) -------- */

/*
 * P_hash(secret, seed) = HMAC(secret, A(1)+seed) || HMAC(secret, A(2)+seed) ...
 * with A(0)=seed, A(i)=HMAC(secret, A(i-1)). Fills out[0..out_len).
 */
static int rec_p_hash(const EVP_MD *md, const uint8_t *secret, size_t slen,
		      const uint8_t *seed, size_t seed_len,
		      uint8_t *out, size_t out_len)
{
	unsigned int mdlen = (unsigned int)EVP_MD_size(md);
	uint8_t a[EVP_MAX_MD_SIZE];        /* A(i) */
	uint8_t block[EVP_MAX_MD_SIZE];
	/* A(1) = HMAC(secret, seed) */
	if (!HMAC(md, secret, (int)slen, seed, seed_len, a, &mdlen))
		return TLS_REC_INTERNAL;

	size_t done = 0;
	while (done < out_len) {
		/* HMAC(secret, A(i) + seed) */
		HMAC_CTX *h = HMAC_CTX_new();
		unsigned int blen = (unsigned int)EVP_MD_size(md);
		int ok = h &&
			 HMAC_Init_ex(h, secret, (int)slen, md, NULL) == 1 &&
			 HMAC_Update(h, a, mdlen) == 1 &&
			 HMAC_Update(h, seed, seed_len) == 1 &&
			 HMAC_Final(h, block, &blen) == 1;
		if (h)
			HMAC_CTX_free(h);
		if (!ok)
			return TLS_REC_INTERNAL;
		size_t take = out_len - done < blen ? out_len - done : blen;
		memcpy(out + done, block, take);
		done += take;
		/* A(i+1) = HMAC(secret, A(i)) */
		if (done < out_len &&
		    !HMAC(md, secret, (int)slen, a, mdlen, a, &mdlen))
			return TLS_REC_INTERNAL;
	}
	return TLS_REC_OK;
}

/*
 * TLS PRF. For 1.2 it is P_<prf_md>(secret, label+seed). For 1.0/1.1 it is
 * P_MD5(S1, .) XOR P_SHA1(S2, .), the secret split into halves S1,S2 that
 * overlap by one byte when its length is odd (RFC 2246 §5).
 */
static int rec_tls_prf(enum tls_version version, const EVP_MD *prf_md,
		       const uint8_t *secret, size_t slen,
		       const char *label, const uint8_t *seed, size_t seed_len,
		       uint8_t *out, size_t out_len)
{
	uint8_t ls[64 + 64];   /* label + seed */
	size_t llen = strlen(label);
	if (llen + seed_len > sizeof(ls))
		return TLS_REC_MALFORMED;
	memcpy(ls, label, llen);
	memcpy(ls + llen, seed, seed_len);
	size_t ls_len = llen + seed_len;

	if (version >= TLS_VERSION_1_2)
		return rec_p_hash(prf_md, secret, slen, ls, ls_len, out, out_len);

	/* TLS 1.0/1.1: split secret, combine P_MD5 and P_SHA1. */
	size_t half = (slen + 1) / 2;
	const uint8_t *s1 = secret;
	const uint8_t *s2 = secret + (slen - half);
	uint8_t md5out[512], sha1out[512];
	if (out_len > sizeof(md5out))
		return TLS_REC_MALFORMED;
	int r = rec_p_hash(EVP_md5(), s1, half, ls, ls_len, md5out, out_len);
	if (r != TLS_REC_OK)
		return r;
	r = rec_p_hash(EVP_sha1(), s2, half, ls, ls_len, sha1out, out_len);
	if (r != TLS_REC_OK)
		return r;
	for (size_t i = 0; i < out_len; i++)
		out[i] = md5out[i] ^ sha1out[i];
	return TLS_REC_OK;
}

int tls12_key_ctx_init(struct tls_key_ctx *ctx,
		       enum tls_cipher cipher, enum tls_version version,
		       const uint8_t *master_secret, size_t ms_len,
		       const uint8_t client_random[TLS_RANDOM_LEN],
		       const uint8_t server_random[TLS_RANDOM_LEN],
		       int is_server, int etm)
{
	struct rec_suite_params sp;
	if (rec_suite_lookup(cipher, &sp) != TLS_REC_OK)
		return TLS_REC_UNSUPPORTED;
	if (ms_len == 0 || ms_len > TLS_MAX_SECRET_LEN)
		return TLS_REC_MALFORMED;
	if (version != TLS_VERSION_1_0 && version != TLS_VERSION_1_1 &&
	    version != TLS_VERSION_1_2)
		return TLS_REC_UNSUPPORTED;
	/* AEAD suites are TLS 1.2 only. */
	if (sp.is_aead && version != TLS_VERSION_1_2)
		return TLS_REC_UNSUPPORTED;

	/* key_block = PRF(master, "key expansion", server_random + client_random) */
	uint8_t seed[2 * TLS_RANDOM_LEN];
	memcpy(seed, server_random, TLS_RANDOM_LEN);
	memcpy(seed + TLS_RANDOM_LEN, client_random, TLS_RANDOM_LEN);

	size_t need = (size_t)2 * sp.mac_len + (size_t)2 * sp.key_len +
		      (size_t)2 * sp.fixed_iv_len;
	uint8_t kb[2 * (TLS_MAX_MAC_LEN + TLS_MAX_KEY_LEN + TLS_IV_LEN)];
	int r = rec_tls_prf(version, sp.md, master_secret, ms_len,
			    "key expansion", seed, sizeof(seed), kb, need);
	if (r != TLS_REC_OK)
		return r;

	memset(ctx, 0, sizeof(*ctx));
	ctx->cipher = cipher;
	ctx->version = version;
	ctx->key_len = sp.key_len;
	ctx->seq = 0;

	/* key_block order: MAC keys, write keys, fixed IVs; client then server. */
	size_t off = 0;
	const uint8_t *cli_mac = kb + off;              off += sp.mac_len;
	const uint8_t *srv_mac = kb + off;              off += sp.mac_len;
	const uint8_t *cli_key = kb + off;              off += sp.key_len;
	const uint8_t *srv_key = kb + off;              off += sp.key_len;
	const uint8_t *cli_iv  = kb + off;              off += sp.fixed_iv_len;
	const uint8_t *srv_iv  = kb + off;              off += sp.fixed_iv_len;

	const uint8_t *mac = is_server ? srv_mac : cli_mac;
	const uint8_t *key = is_server ? srv_key : cli_key;
	const uint8_t *iv  = is_server ? srv_iv  : cli_iv;

	memcpy(ctx->key, key, sp.key_len);
	if (sp.fixed_iv_len)
		memcpy(ctx->iv, iv, sp.fixed_iv_len);
	ctx->iv_len = sp.fixed_iv_len;
	if (sp.mac_len) {
		memcpy(ctx->mac_key, mac, sp.mac_len);
		ctx->mac_key_len = sp.mac_len;
		ctx->etm = etm ? 1 : 0;   /* EtM only applies to CBC/MAC suites */
	}
	return TLS_REC_OK;
}

/* ---- record framing ---------------------------------------------------- */

int tls_record_peek(const uint8_t *buf, size_t len,
		    struct tls_record_hdr *hdr, size_t *total)
{
	if (len < TLS_RECORD_HEADER_LEN)
		return TLS_REC_NEED_MORE;

	hdr->type    = buf[0];
	hdr->version = (uint16_t)((buf[1] << 8) | buf[2]);
	hdr->length  = (uint16_t)((buf[3] << 8) | buf[4]);

	if (hdr->length > TLS_MAX_FRAGMENT)
		return TLS_REC_MALFORMED;

	*total = TLS_RECORD_HEADER_LEN + hdr->length;
	if (len < *total)
		return TLS_REC_NEED_MORE;
	return TLS_REC_OK;
}

/* nonce = iv with the record sequence number XORed into its low 8 bytes */
static void rec_build_nonce(const uint8_t iv[TLS_IV_LEN], uint64_t seq,
			uint8_t nonce[TLS_IV_LEN])
{
	memcpy(nonce, iv, TLS_IV_LEN);
	for (int i = 0; i < 8; i++)
		nonce[TLS_IV_LEN - 1 - i] ^= (uint8_t)((seq >> (8 * i)) & 0xff);
}

/* ---- TLS 1.2 / 1.1 record protection ----------------------------------- */

/* additional_data = seq(8) || type(1) || version(2) || plaintext_len(2) */
static void rec12_aad(uint64_t seq, uint8_t type, const uint8_t ver[2],
		      uint16_t plen, uint8_t aad[13])
{
	for (int i = 0; i < 8; i++)
		aad[i] = (uint8_t)((seq >> (56 - 8 * i)) & 0xff);
	aad[8]  = type;
	aad[9]  = ver[0];
	aad[10] = ver[1];
	aad[11] = (uint8_t)(plen >> 8);
	aad[12] = (uint8_t)(plen & 0xff);
}

/* TLS 1.2 AEAD open. GCM carries an 8-byte explicit nonce at the front of the
 * fragment; ChaCha20-Poly1305 (RFC 7905) derives the nonce like 1.3. */
static int tls12_aead_open(struct tls_key_ctx *ctx, const struct rec_suite_params *sp,
			   const uint8_t *record, size_t record_len,
			   uint8_t *out, size_t out_cap, size_t *out_len,
			   uint8_t *inner_type)
{
	int gcm = sp->fixed_iv_len == 4;         /* GCM: explicit nonce on the wire */
	size_t explicit_len = gcm ? 8 : 0;
	const uint8_t *frag = record + TLS_RECORD_HEADER_LEN;
	size_t frag_len = record_len - TLS_RECORD_HEADER_LEN;
	if (frag_len < explicit_len + TLS_AEAD_TAG_LEN)
		return TLS_REC_MALFORMED;
	size_t pt_len = frag_len - explicit_len - TLS_AEAD_TAG_LEN;
	if (pt_len > out_cap)
		return TLS_REC_MALFORMED;

	uint8_t nonce[TLS_IV_LEN];
	if (gcm) {
		memcpy(nonce, ctx->iv, 4);
		memcpy(nonce + 4, frag, 8);
	} else {
		rec_build_nonce(ctx->iv, ctx->seq, nonce);
	}
	const uint8_t *ct  = frag + explicit_len;
	const uint8_t *tag = ct + pt_len;

	uint8_t aad[13];
	rec12_aad(ctx->seq, record[0], record + 1, (uint16_t)pt_len, aad);

	EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
	if (!c)
		return TLS_REC_INTERNAL;
	int rc = TLS_REC_INTERNAL, len = 0, final = 0;
	if (EVP_DecryptInit_ex(c, sp->aead, NULL, NULL, NULL) != 1 ||
	    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, TLS_IV_LEN, NULL) != 1 ||
	    EVP_DecryptInit_ex(c, NULL, NULL, ctx->key, nonce) != 1 ||
	    EVP_DecryptUpdate(c, NULL, &len, aad, sizeof(aad)) != 1 ||
	    EVP_DecryptUpdate(c, out, &len, ct, (int)pt_len) != 1)
		goto done;
	if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, TLS_AEAD_TAG_LEN,
				(void *)tag) != 1)
		goto done;
	if (EVP_DecryptFinal_ex(c, out + len, &final) != 1) {
		rc = TLS_REC_BAD_TAG;
		goto done;
	}
	*out_len = pt_len;
	*inner_type = record[0];
	ctx->seq++;
	rc = TLS_REC_OK;
done:
	EVP_CIPHER_CTX_free(c);
	return rc;
}

static int tls12_aead_seal(struct tls_key_ctx *ctx, const struct rec_suite_params *sp,
			   const uint8_t *plaintext, size_t plaintext_len,
			   uint8_t inner_type, uint8_t *out, size_t out_cap,
			   size_t *out_len)
{
	int gcm = sp->fixed_iv_len == 4;
	size_t explicit_len = gcm ? 8 : 0;
	size_t frag_len = explicit_len + plaintext_len + TLS_AEAD_TAG_LEN;
	size_t total = TLS_RECORD_HEADER_LEN + frag_len;
	if (total > out_cap || frag_len > TLS_MAX_FRAGMENT)
		return TLS_REC_MALFORMED;

	out[0] = inner_type;
	out[1] = (uint8_t)(ctx->version >> 8);
	out[2] = (uint8_t)(ctx->version & 0xff);
	out[3] = (uint8_t)(frag_len >> 8);
	out[4] = (uint8_t)(frag_len & 0xff);

	uint8_t *frag = out + TLS_RECORD_HEADER_LEN;
	uint8_t nonce[TLS_IV_LEN];
	if (gcm) {
		/* explicit nonce = the record sequence number, big-endian */
		memcpy(nonce, ctx->iv, 4);
		for (int i = 0; i < 8; i++)
			nonce[4 + i] = (uint8_t)((ctx->seq >> (56 - 8 * i)) & 0xff);
		memcpy(frag, nonce + 4, 8);
	} else {
		rec_build_nonce(ctx->iv, ctx->seq, nonce);
	}
	uint8_t *ct  = frag + explicit_len;
	uint8_t *tag = ct + plaintext_len;

	uint8_t aad[13];
	rec12_aad(ctx->seq, inner_type, out + 1, (uint16_t)plaintext_len, aad);

	EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
	if (!c)
		return TLS_REC_INTERNAL;
	int rc = TLS_REC_INTERNAL, len = 0, final = 0;
	if (EVP_EncryptInit_ex(c, sp->aead, NULL, NULL, NULL) != 1 ||
	    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, TLS_IV_LEN, NULL) != 1 ||
	    EVP_EncryptInit_ex(c, NULL, NULL, ctx->key, nonce) != 1 ||
	    EVP_EncryptUpdate(c, NULL, &len, aad, sizeof(aad)) != 1 ||
	    EVP_EncryptUpdate(c, ct, &len, plaintext, (int)plaintext_len) != 1 ||
	    EVP_EncryptFinal_ex(c, ct + len, &final) != 1 ||
	    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, TLS_AEAD_TAG_LEN, tag) != 1)
		goto done;
	*out_len = total;
	ctx->seq++;
	rc = TLS_REC_OK;
done:
	EVP_CIPHER_CTX_free(c);
	return rc;
}

/* CBC MAC = HMAC(mac_key, seq(8) || type(1) || version(2) || len(2) || content) */
static int rec_cbc_mac(const struct tls_key_ctx *ctx, const struct rec_suite_params *sp,
		       uint8_t type, const uint8_t ver[2],
		       const uint8_t *content, size_t content_len, uint8_t *mac)
{
	uint8_t hdr[13];
	rec12_aad(ctx->seq, type, ver, (uint16_t)content_len, hdr);
	HMAC_CTX *h = HMAC_CTX_new();
	unsigned int mlen = sp->mac_len;
	int ok = h &&
		 HMAC_Init_ex(h, ctx->mac_key, ctx->mac_key_len, sp->mac_md, NULL) == 1 &&
		 HMAC_Update(h, hdr, sizeof(hdr)) == 1 &&
		 HMAC_Update(h, content, content_len) == 1 &&
		 HMAC_Final(h, mac, &mlen) == 1;
	if (h)
		HMAC_CTX_free(h);
	return ok ? TLS_REC_OK : TLS_REC_INTERNAL;
}

/*
 * TLS 1.1/1.2 CBC open: explicit IV. Two layouts:
 *  - MAC-then-encrypt (classic): decrypt -> content || MAC || padding.
 *  - encrypt-then-MAC (RFC 7366): MAC over IV||ciphertext, then decrypt ->
 *    content || padding. OpenSSL negotiates EtM for CBC by default.
 */
static int tls_cbc_open(struct tls_key_ctx *ctx, const struct rec_suite_params *sp,
			const uint8_t *record, size_t record_len,
			uint8_t *out, size_t out_cap, size_t *out_len,
			uint8_t *inner_type)
{
	size_t iv_len = sp->block_len;      /* 1.1/1.2: explicit IV per record */
	const uint8_t *frag = record + TLS_RECORD_HEADER_LEN;
	size_t frag_len = record_len - TLS_RECORD_HEADER_LEN;

	if (ctx->etm) {
		/* frag = IV || ciphertext || MAC */
		if (frag_len < iv_len + sp->block_len + sp->mac_len)
			return TLS_REC_MALFORMED;
		size_t ct_len = frag_len - iv_len - sp->mac_len;
		if (ct_len % sp->block_len)
			return TLS_REC_MALFORMED;
		/* MAC covers seq||type||version||len(IV||ct) || IV||ct */
		uint8_t mac[TLS_MAX_MAC_LEN];
		if (rec_cbc_mac(ctx, sp, record[0], record + 1, frag, iv_len + ct_len, mac) != TLS_REC_OK)
			return TLS_REC_INTERNAL;
		if (CRYPTO_memcmp(mac, frag + iv_len + ct_len, sp->mac_len) != 0)
			return TLS_REC_BAD_TAG;
		uint8_t buf[TLS_MAX_FRAGMENT];
		if (ct_len > sizeof(buf))
			return TLS_REC_MALFORMED;
		EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
		if (!c)
			return TLS_REC_INTERNAL;
		int len = 0, final = 0, rc = TLS_REC_INTERNAL;
		if (EVP_DecryptInit_ex(c, sp->aead, NULL, ctx->key, frag) != 1 ||
		    EVP_CIPHER_CTX_set_padding(c, 0) != 1 ||
		    EVP_DecryptUpdate(c, buf, &len, frag + iv_len, (int)ct_len) != 1 ||
		    EVP_DecryptFinal_ex(c, buf + len, &final) != 1)
			goto etm_done;
		{
			uint8_t pad = buf[ct_len - 1];
			if ((size_t)pad + 1 > ct_len) { rc = TLS_REC_BAD_TAG; goto etm_done; }
			size_t content_len = ct_len - (size_t)pad - 1;
			if (content_len > out_cap) { rc = TLS_REC_MALFORMED; goto etm_done; }
			memcpy(out, buf, content_len);
			*out_len = content_len;
			*inner_type = record[0];
			ctx->seq++;
			rc = TLS_REC_OK;
		}
etm_done:
		EVP_CIPHER_CTX_free(c);
		return rc;
	}

	/* MAC-then-encrypt */
	if (frag_len < iv_len + sp->block_len || (frag_len - iv_len) % sp->block_len)
		return TLS_REC_MALFORMED;
	const uint8_t *iv = frag;
	const uint8_t *ct = frag + iv_len;
	size_t ct_len = frag_len - iv_len;

	uint8_t buf[TLS_MAX_FRAGMENT];
	if (ct_len > sizeof(buf))
		return TLS_REC_MALFORMED;

	EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
	if (!c)
		return TLS_REC_INTERNAL;
	int len = 0, final = 0, rc = TLS_REC_INTERNAL;
	if (EVP_DecryptInit_ex(c, sp->aead, NULL, ctx->key, iv) != 1 ||
	    EVP_CIPHER_CTX_set_padding(c, 0) != 1 ||
	    EVP_DecryptUpdate(c, buf, &len, ct, (int)ct_len) != 1 ||
	    EVP_DecryptFinal_ex(c, buf + len, &final) != 1)
		goto done;

	{
	size_t plen = ct_len;
	/* strip padding: last byte is pad_len, pad_len+1 trailing bytes removed */
	uint8_t pad = buf[plen - 1];
	if ((size_t)pad + 1 > plen) { rc = TLS_REC_BAD_TAG; goto done; }
	plen -= (size_t)pad + 1;
	if (plen < sp->mac_len) { rc = TLS_REC_BAD_TAG; goto done; }
	size_t content_len = plen - sp->mac_len;
	if (content_len > out_cap) { rc = TLS_REC_MALFORMED; goto done; }

	uint8_t mac[TLS_MAX_MAC_LEN];
	if (rec_cbc_mac(ctx, sp, record[0], record + 1, buf, content_len, mac) != TLS_REC_OK)
		goto done;
	if (CRYPTO_memcmp(mac, buf + content_len, sp->mac_len) != 0) {
		rc = TLS_REC_BAD_TAG;
		goto done;
	}
	memcpy(out, buf, content_len);
	*out_len = content_len;
	*inner_type = record[0];
	ctx->seq++;
	rc = TLS_REC_OK;
	}
done:
	EVP_CIPHER_CTX_free(c);
	return rc;
}

static int tls_cbc_seal(struct tls_key_ctx *ctx, const struct rec_suite_params *sp,
			const uint8_t *plaintext, size_t plaintext_len,
			uint8_t inner_type, uint8_t *out, size_t out_cap, size_t *out_len)
{
	size_t iv_len = sp->block_len;
	out[0] = inner_type;
	out[1] = (uint8_t)(ctx->version >> 8);
	out[2] = (uint8_t)(ctx->version & 0xff);

	if (ctx->etm) {
		/* encrypt(content || padding), then MAC over IV||ciphertext */
		size_t pad = sp->block_len - (plaintext_len % sp->block_len);  /* 1..block */
		size_t enc_len = plaintext_len + pad;
		size_t frag_len = iv_len + enc_len + sp->mac_len;
		size_t total = TLS_RECORD_HEADER_LEN + frag_len;
		if (total > out_cap || frag_len > TLS_MAX_FRAGMENT)
			return TLS_REC_MALFORMED;
		out[3] = (uint8_t)(frag_len >> 8);
		out[4] = (uint8_t)(frag_len & 0xff);
		uint8_t *frag = out + TLS_RECORD_HEADER_LEN;
		if (RAND_bytes(frag, (int)iv_len) != 1)
			return TLS_REC_INTERNAL;
		uint8_t buf[TLS_MAX_FRAGMENT];
		if (enc_len > sizeof(buf))
			return TLS_REC_MALFORMED;
		memcpy(buf, plaintext, plaintext_len);
		for (size_t i = 0; i < pad; i++)
			buf[plaintext_len + i] = (uint8_t)(pad - 1);
		EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
		if (!c)
			return TLS_REC_INTERNAL;
		int len = 0, final = 0, rc = TLS_REC_INTERNAL;
		if (EVP_EncryptInit_ex(c, sp->aead, NULL, ctx->key, frag) != 1 ||
		    EVP_CIPHER_CTX_set_padding(c, 0) != 1 ||
		    EVP_EncryptUpdate(c, frag + iv_len, &len, buf, (int)enc_len) != 1 ||
		    EVP_EncryptFinal_ex(c, frag + iv_len + len, &final) != 1)
			goto etm_sdone;
		if (rec_cbc_mac(ctx, sp, inner_type, out + 1, frag, iv_len + enc_len,
				frag + iv_len + enc_len) != TLS_REC_OK)
			goto etm_sdone;
		*out_len = total;
		ctx->seq++;
		rc = TLS_REC_OK;
etm_sdone:
		EVP_CIPHER_CTX_free(c);
		return rc;
	}

	uint8_t mac[TLS_MAX_MAC_LEN];
	if (rec_cbc_mac(ctx, sp, inner_type, out + 1, plaintext, plaintext_len, mac) != TLS_REC_OK)
		return TLS_REC_INTERNAL;

	/* body = content || mac || padding; padding brings it to a block multiple */
	size_t body = plaintext_len + sp->mac_len;
	size_t pad = sp->block_len - (body % sp->block_len);   /* 1..block_len */
	size_t enc_len = body + pad;
	size_t frag_len = iv_len + enc_len;
	size_t total = TLS_RECORD_HEADER_LEN + frag_len;
	if (total > out_cap || frag_len > TLS_MAX_FRAGMENT)
		return TLS_REC_MALFORMED;
	out[3] = (uint8_t)(frag_len >> 8);
	out[4] = (uint8_t)(frag_len & 0xff);

	uint8_t *frag = out + TLS_RECORD_HEADER_LEN;
	if (RAND_bytes(frag, (int)iv_len) != 1)
		return TLS_REC_INTERNAL;

	uint8_t buf[TLS_MAX_FRAGMENT];
	if (enc_len > sizeof(buf))
		return TLS_REC_MALFORMED;
	memcpy(buf, plaintext, plaintext_len);
	memcpy(buf + plaintext_len, mac, sp->mac_len);
	for (size_t i = 0; i < pad; i++)
		buf[body + i] = (uint8_t)(pad - 1);   /* padding bytes = pad_len */

	EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
	if (!c)
		return TLS_REC_INTERNAL;
	int len = 0, final = 0, rc = TLS_REC_INTERNAL;
	if (EVP_EncryptInit_ex(c, sp->aead, NULL, ctx->key, frag) != 1 ||
	    EVP_CIPHER_CTX_set_padding(c, 0) != 1 ||
	    EVP_EncryptUpdate(c, frag + iv_len, &len, buf, (int)enc_len) != 1 ||
	    EVP_EncryptFinal_ex(c, frag + iv_len + len, &final) != 1)
		goto done2;
	*out_len = total;
	ctx->seq++;
	rc = TLS_REC_OK;
done2:
	EVP_CIPHER_CTX_free(c);
	return rc;
}

/* ---- AEAD open --------------------------------------------------------- */

int tls_record_open(struct tls_key_ctx *ctx,
		    const uint8_t *record, size_t record_len,
		    uint8_t *out, size_t out_cap, size_t *out_len,
		    uint8_t *inner_type)
{
	if (ctx->version != TLS_VERSION_1_3) {
		struct rec_suite_params sp;
		if (rec_suite_lookup(ctx->cipher, &sp) != TLS_REC_OK)
			return TLS_REC_UNSUPPORTED;
		if (record_len < TLS_RECORD_HEADER_LEN)
			return TLS_REC_MALFORMED;
		return sp.is_aead ?
		       tls12_aead_open(ctx, &sp, record, record_len, out, out_cap, out_len, inner_type) :
		       tls_cbc_open(ctx, &sp, record, record_len, out, out_cap, out_len, inner_type);
	}
	return tls13_record_open(ctx, record, record_len, out, out_cap, out_len, inner_type);
}

static int tls13_record_open(struct tls_key_ctx *ctx,
		    const uint8_t *record, size_t record_len,
		    uint8_t *out, size_t out_cap, size_t *out_len,
		    uint8_t *inner_type)
{
	struct rec_suite_params sp;
	if (rec_suite_lookup(ctx->cipher, &sp) != TLS_REC_OK)
		return TLS_REC_UNSUPPORTED;
	if (record_len < TLS_RECORD_HEADER_LEN + TLS_AEAD_TAG_LEN)
		return TLS_REC_MALFORMED;

	const uint8_t *aad = record;                        /* the 5-byte header */
	const uint8_t *ct  = record + TLS_RECORD_HEADER_LEN;
	size_t ct_len = record_len - TLS_RECORD_HEADER_LEN; /* ciphertext + tag */
	size_t pt_len = ct_len - TLS_AEAD_TAG_LEN;
	if (pt_len > out_cap)
		return TLS_REC_MALFORMED;

	uint8_t nonce[TLS_IV_LEN];
	rec_build_nonce(ctx->iv, ctx->seq, nonce);

	EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
	if (!c)
		return TLS_REC_INTERNAL;

	int rc = TLS_REC_INTERNAL, len = 0;
	uint8_t *inner = NULL;

	if (EVP_DecryptInit_ex(c, sp.aead, NULL, NULL, NULL) != 1 ||
	    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, TLS_IV_LEN, NULL) != 1 ||
	    EVP_DecryptInit_ex(c, NULL, NULL, ctx->key, nonce) != 1)
		goto done;
	if (EVP_DecryptUpdate(c, NULL, &len, aad, (int)TLS_RECORD_HEADER_LEN) != 1)
		goto done;

	/* Decrypt into a scratch buffer: the inner plaintext is content ||
	 * inner_type(1) || zero-padding, and we must strip the trailing bytes
	 * before handing it up, so we cannot write straight into `out`. */
	inner = OPENSSL_malloc(pt_len ? pt_len : 1);
	if (!inner)
		goto done;
	if (EVP_DecryptUpdate(c, inner, &len, ct, (int)pt_len) != 1)
		goto done;

	if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, TLS_AEAD_TAG_LEN,
				(void *)(ct + pt_len)) != 1)
		goto done;

	int final = 0;
	if (EVP_DecryptFinal_ex(c, inner + len, &final) != 1) {
		rc = TLS_REC_BAD_TAG;   /* wrong key, or the record was tampered */
		goto done;
	}

	/* Strip inner padding: the last non-zero byte is the real content type. */
	size_t n = pt_len;
	while (n > 0 && inner[n - 1] == 0)
		n--;
	if (n == 0) { rc = TLS_REC_MALFORMED; goto done; }   /* all padding */

	*inner_type = inner[n - 1];
	*out_len = n - 1;
	memcpy(out, inner, *out_len);
	ctx->seq++;
	rc = TLS_REC_OK;

done:
	if (inner) OPENSSL_free(inner);
	EVP_CIPHER_CTX_free(c);
	return rc;
}

/* ---- AEAD seal --------------------------------------------------------- */

int tls_record_seal(struct tls_key_ctx *ctx,
		    const uint8_t *plaintext, size_t plaintext_len,
		    uint8_t inner_type,
		    uint8_t *out, size_t out_cap, size_t *out_len)
{
	if (ctx->version != TLS_VERSION_1_3) {
		struct rec_suite_params sp;
		if (rec_suite_lookup(ctx->cipher, &sp) != TLS_REC_OK)
			return TLS_REC_UNSUPPORTED;
		return sp.is_aead ?
		       tls12_aead_seal(ctx, &sp, plaintext, plaintext_len, inner_type,
				       out, out_cap, out_len) :
		       tls_cbc_seal(ctx, &sp, plaintext, plaintext_len, inner_type,
				    out, out_cap, out_len);
	}
	return tls13_record_seal(ctx, plaintext, plaintext_len, inner_type,
				 out, out_cap, out_len);
}

static int tls13_record_seal(struct tls_key_ctx *ctx,
		    const uint8_t *plaintext, size_t plaintext_len,
		    uint8_t inner_type,
		    uint8_t *out, size_t out_cap, size_t *out_len)
{
	struct rec_suite_params sp;
	if (rec_suite_lookup(ctx->cipher, &sp) != TLS_REC_OK)
		return TLS_REC_UNSUPPORTED;

	/* inner = plaintext || inner_type(1); no extra padding added. */
	size_t inner_len = plaintext_len + 1;
	size_t ct_len = inner_len + TLS_AEAD_TAG_LEN;
	size_t total = TLS_RECORD_HEADER_LEN + ct_len;
	if (total > out_cap || ct_len > TLS_MAX_FRAGMENT)
		return TLS_REC_MALFORMED;

	/* Record header: application_data, legacy version 0x0303, fragment len.
	 * This is the AEAD additional data, so it must be laid down first. */
	out[0] = TLS_CT_APPLICATION_DATA;
	out[1] = 0x03;
	out[2] = 0x03;
	out[3] = (uint8_t)(ct_len >> 8);
	out[4] = (uint8_t)(ct_len & 0xff);

	uint8_t nonce[TLS_IV_LEN];
	rec_build_nonce(ctx->iv, ctx->seq, nonce);

	EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
	if (!c)
		return TLS_REC_INTERNAL;

	int rc = TLS_REC_INTERNAL, len = 0;
	uint8_t *inner = NULL;
	uint8_t *ct = out + TLS_RECORD_HEADER_LEN;

	if (EVP_EncryptInit_ex(c, sp.aead, NULL, NULL, NULL) != 1 ||
	    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, TLS_IV_LEN, NULL) != 1 ||
	    EVP_EncryptInit_ex(c, NULL, NULL, ctx->key, nonce) != 1)
		goto done;
	if (EVP_EncryptUpdate(c, NULL, &len, out, (int)TLS_RECORD_HEADER_LEN) != 1)
		goto done;

	inner = OPENSSL_malloc(inner_len);
	if (!inner)
		goto done;
	memcpy(inner, plaintext, plaintext_len);
	inner[plaintext_len] = inner_type;

	if (EVP_EncryptUpdate(c, ct, &len, inner, (int)inner_len) != 1)
		goto done;
	int final = 0;
	if (EVP_EncryptFinal_ex(c, ct + len, &final) != 1)
		goto done;
	if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, TLS_AEAD_TAG_LEN,
				ct + inner_len) != 1)
		goto done;

	*out_len = total;
	ctx->seq++;
	rc = TLS_REC_OK;

done:
	if (inner) OPENSSL_free(inner);
	EVP_CIPHER_CTX_free(c);
	return rc;
}

const char *tls_rec_strerror(int code)
{
	switch (code) {
	case TLS_REC_OK:          return "ok";
	case TLS_REC_NEED_MORE:   return "need more data";
	case TLS_REC_BAD_TAG:     return "AEAD tag verification failed";
	case TLS_REC_UNSUPPORTED: return "unsupported cipher or version";
	case TLS_REC_MALFORMED:   return "malformed record";
	case TLS_REC_INTERNAL:    return "internal error";
	default:                  return "unknown";
	}
}
