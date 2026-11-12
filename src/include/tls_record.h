/*
 * TLS record layer — userspace decrypt/re-encrypt with session secrets.
 *
 * The splice design (docs/design/tls-splice-proxy.md) never does a MITM: the
 * handshake passes untouched between the app and the real server, and ePtracer
 * decrypts the application records using the traffic secrets captured from
 * inside the process (include/tls_keys.h). This module owns everything below
 * the HTTP layer: parsing TLS records off the wire, deriving per-record
 * key/iv/nonce from a secret (HKDF-Expand-Label), opening the AEAD, and
 * sealing a (possibly modified) plaintext back towards the other leg with a
 * translated sequence number.
 *
 * A wrong secret cannot produce wrong output: the AEAD tag verification fails
 * and tls_record_open() returns TLS_REC_BAD_TAG, which is exactly what makes
 * the heuristic key sources of include/tls_keys.h safe (trial decryption).
 *
 * This file is userspace-only and depends on nothing but OpenSSL EVP, so it
 * builds and is tested standalone (bench/test_tls_record.c).
 */

#ifndef EPTRACER_TLS_RECORD_H
#define EPTRACER_TLS_RECORD_H

#include <stddef.h>
#include <stdint.h>

/* TLS record content types (RFC 8446 / 5246) */
#define TLS_CT_CHANGE_CIPHER_SPEC 20
#define TLS_CT_ALERT              21
#define TLS_CT_HANDSHAKE          22
#define TLS_CT_APPLICATION_DATA   23

/* TLS record header is a fixed 5 bytes: type(1) version(2) length(2) */
#define TLS_RECORD_HEADER_LEN 5
/* A TLSCiphertext fragment is capped at 2^14 + 256 by the RFC */
#define TLS_MAX_FRAGMENT      (16384 + 256)
#define TLS_AEAD_TAG_LEN      16
#define TLS_MAX_KEY_LEN       32
#define TLS_IV_LEN            12
#define TLS_MAX_SECRET_LEN    64
#define TLS_MAX_MAC_LEN       32   /* HMAC-SHA256 output (CBC suites) */
#define TLS_RANDOM_LEN        32   /* client_random / server_random */

/*
 * Cipher suites we handle, as an AEAD/MAC + hash identity (not a wire value).
 * The TLS 1.3 values match the IANA numbers so a 1.3 ServerHello maps straight
 * onto one; the same three AEADs serve TLS 1.2 (tls12_cipher_from_wire() maps
 * the 1.2 suite numbers onto them). The CBC entries are TLS 1.0/1.1/1.2 block
 * ciphers with an HMAC, needed because old endpoints still negotiate them.
 */
enum tls_cipher {
	TLS_CIPHER_UNKNOWN            = 0,
	TLS_AES_128_GCM_SHA256       = 0x1301,
	TLS_AES_256_GCM_SHA384       = 0x1302,
	TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
	/* CBC suites (private ids, not wire numbers): AES-CBC + HMAC-SHA1/256 */
	TLS_AES_128_CBC_SHA          = 0xF001,
	TLS_AES_256_CBC_SHA          = 0xF002,
	TLS_AES_128_CBC_SHA256       = 0xF003,
	TLS_AES_256_CBC_SHA256       = 0xF004,
};

/* TLS protocol version carried in the record / negotiated */
enum tls_version {
	TLS_VERSION_UNKNOWN = 0,
	TLS_VERSION_1_0     = 0x0301,
	TLS_VERSION_1_1     = 0x0302,
	TLS_VERSION_1_2     = 0x0303,
	TLS_VERSION_1_3     = 0x0304,
};

/* Result codes shared by the record calls */
enum tls_rec_result {
	TLS_REC_OK          =  0,
	TLS_REC_NEED_MORE   =  1,  /* a full record is not buffered yet */
	TLS_REC_BAD_TAG     = -1,  /* AEAD verification failed (wrong key or tamper) */
	TLS_REC_UNSUPPORTED = -2,  /* cipher/version not handled */
	TLS_REC_MALFORMED   = -3,  /* not a well-formed TLS record */
	TLS_REC_INTERNAL    = -4,  /* OpenSSL / allocation failure */
};

/*
 * A directional key context: the traffic secret for one side (client->server
 * or server->client) expanded into the key and iv, plus the running record
 * sequence number. TLS 1.3 derives key and iv from the secret once; the nonce
 * is iv XOR seq for every record, and seq increments per record.
 */
struct tls_key_ctx {
	enum tls_cipher cipher;
	enum tls_version version;
	uint8_t secret[TLS_MAX_SECRET_LEN];
	uint8_t secret_len;
	uint8_t key[TLS_MAX_KEY_LEN];
	uint8_t key_len;
	uint8_t iv[TLS_IV_LEN];   /* 1.3/ChaCha: 12-byte iv; GCM 1.2: 4-byte salt */
	uint8_t iv_len;           /* fixed-IV length: 12 (1.3/ChaCha) or 4 (GCM 1.2) */
	uint8_t mac_key[TLS_MAX_MAC_LEN]; /* CBC suites only */
	uint8_t mac_key_len;      /* 0 for AEAD */
	uint8_t etm;              /* CBC: encrypt-then-MAC (RFC 7366) negotiated */
	uint64_t seq;             /* next record sequence number on this leg */
};

/* A parsed record header, filled by tls_record_peek(). */
struct tls_record_hdr {
	uint8_t  type;           /* outer content type (23 for app data in 1.3) */
	uint16_t version;        /* legacy record version (usually 0x0303) */
	uint16_t length;         /* fragment length that follows the 5-byte header */
};

/*
 * Derive key and iv from the traffic secret already stored in ctx->secret
 * (ctx->cipher and ctx->version must be set). Resets seq to 0.
 * Returns TLS_REC_OK or a negative code.
 */
int tls_key_ctx_init(struct tls_key_ctx *ctx,
		     enum tls_cipher cipher, enum tls_version version,
		     const uint8_t *secret, size_t secret_len);

/*
 * Set up one direction's key context for TLS 1.2 / 1.1 / 1.0 from the session
 * master secret. Unlike 1.3 there is a single secret for the whole connection:
 * the key block is PRF(master, "key expansion", server_random + client_random)
 * and this picks the client_write_* material when is_server is 0, the
 * server_write_* material when it is 1. `version` selects the record format
 * (AEAD for 1.2 AEAD suites; CBC+HMAC for the CBC suites on 1.0/1.1/1.2).
 * Resets seq to 0. Returns TLS_REC_OK or a negative code.
 */
int tls12_key_ctx_init(struct tls_key_ctx *ctx,
		       enum tls_cipher cipher, enum tls_version version,
		       const uint8_t *master_secret, size_t ms_len,
		       const uint8_t client_random[TLS_RANDOM_LEN],
		       const uint8_t server_random[TLS_RANDOM_LEN],
		       int is_server, int etm);

/* Map a TLS 1.2 (RFC 5246/5288/7905 and the CBC) wire cipher-suite value onto
 * our enum, TLS_CIPHER_UNKNOWN if unhandled. */
enum tls_cipher tls12_cipher_from_wire(uint16_t suite);

/* Is this one of the AEAD suites (GCM / ChaCha20-Poly1305)? The CBC suites and
 * UNKNOWN are not. */
int tls_cipher_is_aead(enum tls_cipher cipher);

/*
 * HKDF-Expand-Label as defined by RFC 8446 §7.1. Exposed because
 * tls_keys.c reuses it for KeyUpdate ("traffic upd") and exporters.
 */
int tls_hkdf_expand_label(enum tls_cipher cipher,
			  const uint8_t *secret, size_t secret_len,
			  const char *label,
			  const uint8_t *context, size_t context_len,
			  uint8_t *out, size_t out_len);

/*
 * Rotate the traffic secret in place per RFC 8446 §7.2 (application traffic
 * secret N -> N+1), re-derives key/iv and resets seq. Used when a KeyUpdate
 * crosses the encrypted channel.
 */
int tls_key_ctx_update(struct tls_key_ctx *ctx);

/*
 * Peek the 5-byte header of the record at the front of buf. Returns TLS_REC_OK
 * with *hdr filled and *total set to the full record size (header + fragment),
 * TLS_REC_NEED_MORE if fewer than 5 bytes are present, or TLS_REC_MALFORMED.
 */
int tls_record_peek(const uint8_t *buf, size_t len,
		    struct tls_record_hdr *hdr, size_t *total);

/*
 * Open one TLS 1.3 record. `record` points at the full record (5-byte header
 * included) of `record_len` bytes; the AEAD is computed over the real record
 * header as additional data, exactly as the RFC requires. The recovered inner
 * plaintext (content only, padding and inner content-type stripped) is written
 * to out (capacity out_cap); *out_len receives its length and *inner_type the
 * TLS content type that was hidden inside. ctx->seq is consumed and advanced.
 *
 * Returns TLS_REC_OK, TLS_REC_BAD_TAG (wrong key / tampered), or negative.
 */
int tls_record_open(struct tls_key_ctx *ctx,
		    const uint8_t *record, size_t record_len,
		    uint8_t *out, size_t out_cap, size_t *out_len,
		    uint8_t *inner_type);

/*
 * Seal one TLS 1.3 record towards the opposite leg. `plaintext`/`plaintext_len`
 * is the content, `inner_type` the content type to hide (usually
 * TLS_CT_APPLICATION_DATA). The full record (header + ciphertext + tag) is
 * written to out (capacity out_cap) and *out_len set. ctx->seq is consumed and
 * advanced — this is the leg's own sequence, which is why re-encryption with
 * the same key but a different seq produces a valid record for the other side.
 */
int tls_record_seal(struct tls_key_ctx *ctx,
		    const uint8_t *plaintext, size_t plaintext_len,
		    uint8_t inner_type,
		    uint8_t *out, size_t out_cap, size_t *out_len);

/* Human-readable form of a result code, for logs. */
const char *tls_rec_strerror(int code);

/* Map a wire cipher-suite value onto our enum, TLS_CIPHER_UNKNOWN if unhandled. */
enum tls_cipher tls_cipher_from_wire(uint16_t suite);

#endif /* EPTRACER_TLS_RECORD_H */
