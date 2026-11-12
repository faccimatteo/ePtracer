/*
 * TLS splice — one connection, relayed between the app and the real server,
 * decrypted and re-encrypted with the app's own session keys.
 *
 * The handshake passes untouched (the server's real certificate reaches the
 * app, so pinning holds), then every encrypted record is opened with the
 * traffic secret captured inside the process (include/tls_keys.h) and either:
 *
 *  - relayed as is (passthrough: the plaintext is only reported), or
 *  - handed to the owner (intercept), who sends back whatever plaintext the
 *    proxy released with tls_splice_send(); it is sealed towards the other
 *    side with the same key and that side's own sequence number.
 *
 * The two legs share key and iv and differ only in the record sequence number:
 * as long as nothing was changed in a direction its counters stay equal and the
 * original ciphertext is forwarded untouched (fast path). The first change makes
 * them diverge, and from then on records of that direction are re-sealed.
 *
 * The module owns no socket: bytes come in through tls_splice_feed() and go
 * out through the hooks, which keeps it testable and lets the proxy bridge
 * drive it asynchronously (a request can sit in Burp's Intercept for minutes).
 *
 * TLS 1.3 and TLS 1.2 (AEAD and AES-CBC+HMAC, with or without encrypt-then-MAC)
 * are decrypted, and TLS 1.1/1.0 over CBC; what it still cannot understand (an
 * unknown cipher suite, SSLv3, or a key that never shows up) never breaks the
 * connection: it degrades to OPAQUE, where bytes are relayed verbatim.
 */

#ifndef EPTRACER_TLS_SPLICE_H
#define EPTRACER_TLS_SPLICE_H

#include <stddef.h>
#include <stdint.h>

#include "tls_record.h"

enum splice_dir {
	SPLICE_C2S = 0,   /* app -> server */
	SPLICE_S2C = 1,   /* server -> app */
};

enum splice_state {
	SPLICE_HANDSHAKE = 0,  /* before ServerHello: everything relayed verbatim */
	SPLICE_ACTIVE,         /* TLS 1.3 negotiated: records opened once keys resolve */
	SPLICE_OPAQUE,         /* not decryptable: relayed verbatim for good */
	SPLICE_FAILED,         /* inconsistent after divergence: the owner must close */
};

struct tls_splice;

struct tls_splice_hooks {
	/* Bytes to put on the wire towards `to` (SPLICE_C2S: the server side). */
	int  (*forward)(void *user, enum splice_dir to, const uint8_t *buf, size_t len);

	/* Decrypted content of one record of direction `dir`. inner_type is the TLS
	 * content type hidden in the record (23 application data, 22 post-handshake
	 * messages, 21 alerts). In intercept mode the owner must eventually call
	 * tls_splice_send() with it (possibly modified), in order; in passthrough
	 * mode the record has already been forwarded and this is a notification.
	 * May be NULL in passthrough mode. */
	void (*plaintext)(void *user, enum splice_dir dir, uint8_t inner_type,
			  const uint8_t *buf, size_t len);

	/* Called right before keys are looked up, so the owner can drain pending
	 * key events (ring buffer, keylog file) into the key store. May be NULL. */
	void (*need_keys)(void *user);

	void *user;
};

/*
 * pid: process the connection belongs to (keys are looked up for it).
 * intercept_mask: bit SPLICE_C2S / SPLICE_S2C set => that direction goes through
 * the owner (intercept); clear => passthrough.
 */
struct tls_splice *tls_splice_new(uint32_t pid, unsigned intercept_mask,
				  const struct tls_splice_hooks *hooks);
void tls_splice_free(struct tls_splice *s);

/*
 * Feed bytes received on the wire from the side that originates `dir`
 * (SPLICE_C2S: bytes the app sent). Partial records are buffered. Returns 0, or
 * -1 when the connection entered SPLICE_FAILED.
 */
int tls_splice_feed(struct tls_splice *s, enum splice_dir dir,
		    const uint8_t *buf, size_t len);

/*
 * Seal plaintext as records of `inner_type` in direction `dir` and forward them
 * (fragmented at 2^14). Only valid once that direction's key is known.
 * Returns 0 or -1.
 */
int tls_splice_send(struct tls_splice *s, enum splice_dir dir, uint8_t inner_type,
		    const uint8_t *buf, size_t len);

/*
 * strict: a client record that no captured key opens is never relayed: the
 * connection fails instead (and so does a session that cannot be decrypted at
 * all, TLS 1.2 or an unknown suite). Off, such records go through untouched.
 * hold_ms: how long such a client record waits for its key to show up first,
 * since the probe and the record race each other by microseconds.
 */
void tls_splice_set_policy(struct tls_splice *s, int strict, int hold_ms);

/*
 * Make `dir` usable for tls_splice_send() before any record of it was seen,
 * using the secret captured from the same library handle as an already
 * resolved one (tls_keys_sibling()). This is how the proxy's answer can be
 * sealed towards the app when the server has sent nothing under its key yet.
 * Returns 0 when keyed, 1 when the secret is not known, -1 if not ACTIVE.
 */
int tls_splice_prime(struct tls_splice *s, enum splice_dir dir);

enum splice_state tls_splice_state(const struct tls_splice *s);
/* 1 once the key of `dir` has been resolved and records are being opened */
int tls_splice_keyed(const struct tls_splice *s, enum splice_dir dir);
/* Server name / suite as seen in the handshake, for logs */
const char *tls_splice_sni(const struct tls_splice *s);
enum tls_cipher tls_splice_cipher(const struct tls_splice *s);

/* Counters, for tests and the latency bench */
struct tls_splice_stats {
	uint64_t records_verbatim[2];   /* forwarded as received (fast path / opaque) */
	uint64_t records_resealed[2];   /* re-encrypted with the translated seq */
	uint64_t records_opened[2];
	uint64_t key_updates[2];
};
void tls_splice_get_stats(const struct tls_splice *s, struct tls_splice_stats *out);

/*
 * Parse helpers, exposed for the interceptor (which peeks the ClientHello before
 * deciding the mode) and for tests. Both take a full handshake record.
 * Return 0 on success.
 */
int tls_parse_client_hello(const uint8_t *rec, size_t len,
			   uint8_t client_random[32], char *sni, size_t sni_cap);
int tls_parse_server_hello(const uint8_t *rec, size_t len, uint8_t server_random[32],
			   uint16_t *cipher_suite, uint16_t *version, int *is_hrr,
			   int *etm);

#endif /* EPTRACER_TLS_SPLICE_H */
