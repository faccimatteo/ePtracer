/*
 * TLS splice — see include/tls_splice.h.
 */

#include "tls_splice.h"
#include "tls_keys.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

/* How many records may have been relayed opaque before the key showed up and
 * still be accounted for by trying each sequence number. Past that the
 * direction stays opaque: a key that late is not worth the trial cost. */
#define SPLICE_MAX_LATE_RECORDS 64

/* TLS 1.3 handshake message types we look at */
#define HS_CLIENT_HELLO 1
#define HS_SERVER_HELLO 2
#define HS_KEY_UPDATE   24

/* ServerHello.random of a HelloRetryRequest: SHA-256("HelloRetryRequest") */
static const uint8_t splice_hrr_random[32] = {
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02,
	0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
	0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
};

struct splice_dir_state {
	uint8_t *buf;            /* bytes of a record not complete yet */
	size_t   len, cap;
	struct tls_key_ctx rx;   /* opens records coming from this direction's origin */
	struct tls_key_ctx tx;   /* seals records towards this direction's destination */
	int      keyed;
	uint64_t unresolved;     /* encrypted records relayed before the key resolved */
	uint64_t hs_records;     /* records recognized under the handshake key */
	int      hold_spent;     /* waited once for a key that never came */
	int      ccs_seen;       /* TLS<=1.2: ChangeCipherSpec passed, next records encrypted */
};

struct tls_splice {
	uint32_t pid;
	unsigned intercept_mask;
	struct tls_splice_hooks h;
	enum splice_state state;
	uint8_t  client_random[32];
	int      have_client_random;
	uint8_t  server_random[32];      /* TLS<=1.2: needed to expand the key block */
	char     sni[256];
	enum tls_cipher cipher;
	enum tls_version version;        /* negotiated record version */
	uint8_t  master[TLS_MAX_SECRET_LEN]; /* TLS<=1.2 master secret, once resolved */
	uint8_t  master_len;
	int      have_master;
	int      etm;                    /* TLS<=1.2 CBC: encrypt-then-MAC negotiated */
	struct splice_dir_state d[2];
	struct tls_splice_stats st;
	int      strict;         /* never relay client data that could not be opened */
	int      hold_ms;        /* how long a client record waits for its key */
};

/* ---- handshake parsing ------------------------------------------------- */

static uint16_t splice_rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }

int tls_parse_client_hello(const uint8_t *rec, size_t len,
			   uint8_t client_random[32], char *sni, size_t sni_cap)
{
	/* record hdr(5) | hs type(1) len(3) | legacy_version(2) random(32) ... */
	if (len < 5 + 4 + 2 + 32 + 1 || rec[0] != TLS_CT_HANDSHAKE ||
	    rec[5] != HS_CLIENT_HELLO)
		return -1;
	memcpy(client_random, rec + 11, 32);
	if (sni && sni_cap)
		sni[0] = '\0';

	size_t p = 43;
	size_t end = len;
	if (p + 1 > end) return 0;
	p += 1 + rec[p];                                  /* session id */
	if (p + 2 > end) return 0;
	p += 2 + splice_rd16(rec + p);                           /* cipher suites */
	if (p + 1 > end) return 0;
	p += 1 + rec[p];                                  /* compression */
	if (p + 2 > end) return 0;
	size_t ext_end = p + 2 + splice_rd16(rec + p);
	p += 2;
	if (ext_end > end) ext_end = end;

	while (p + 4 <= ext_end) {
		uint16_t type = splice_rd16(rec + p), elen = splice_rd16(rec + p + 2);
		p += 4;
		if (p + elen > ext_end)
			break;
		/* server_name: list len(2) | name type(1)=0 | name len(2) | name */
		if (type == 0 && elen >= 5 && rec[p + 2] == 0 && sni && sni_cap) {
			size_t nlen = splice_rd16(rec + p + 3);
			if (5 + nlen <= elen) {
				if (nlen >= sni_cap) nlen = sni_cap - 1;
				memcpy(sni, rec + p + 5, nlen);
				sni[nlen] = '\0';
			}
		}
		p += elen;
	}
	return 0;
}

int tls_parse_server_hello(const uint8_t *rec, size_t len, uint8_t server_random[32],
			   uint16_t *cipher_suite, uint16_t *version, int *is_hrr, int *etm)
{
	if (etm)
		*etm = 0;
	if (len < 5 + 4 + 2 + 32 + 1 || rec[0] != TLS_CT_HANDSHAKE ||
	    rec[5] != HS_SERVER_HELLO)
		return -1;
	*version = splice_rd16(rec + 9);                         /* legacy_version */
	memcpy(server_random, rec + 11, 32);
	*is_hrr = memcmp(server_random, splice_hrr_random, 32) == 0;

	size_t p = 43;
	if (p + 1 > len) return -1;
	p += 1 + rec[p];                                  /* session id echo */
	if (p + 3 > len) return -1;
	*cipher_suite = splice_rd16(rec + p);
	p += 3;                                           /* suite + compression */
	if (p + 2 > len) return 0;                        /* no extensions: TLS 1.2 */
	size_t ext_end = p + 2 + splice_rd16(rec + p);
	p += 2;
	if (ext_end > len) ext_end = len;

	while (p + 4 <= ext_end) {
		uint16_t type = splice_rd16(rec + p), elen = splice_rd16(rec + p + 2);
		p += 4;
		if (p + elen > ext_end)
			break;
		if (type == 0x002b && elen == 2)          /* supported_versions */
			*version = splice_rd16(rec + p);
		if (type == 0x0016 && etm)                /* encrypt_then_mac (RFC 7366) */
			*etm = 1;
		p += elen;
	}
	return 0;
}

/* Does a plaintext handshake payload carry a KeyUpdate? Messages may be
 * coalesced, so walk them. */
static int splice_has_key_update(const uint8_t *buf, size_t len)
{
	size_t off = 0;
	while (off + 4 <= len) {
		size_t mlen = (size_t)buf[off + 1] << 16 | (size_t)buf[off + 2] << 8 | buf[off + 3];
		if (buf[off] == HS_KEY_UPDATE)
			return 1;
		off += 4 + mlen;
	}
	return 0;
}

/* ---- plumbing ---------------------------------------------------------- */

static int splice_fwd(struct tls_splice *s, enum splice_dir dir, const uint8_t *b, size_t n)
{
	/* a record of direction dir travels to the side dir points at */
	return s->h.forward ? s->h.forward(s->h.user, dir, b, n) : 0;
}

static int splice_intercepted(const struct tls_splice *s, enum splice_dir dir)
{
	return (s->intercept_mask >> dir) & 1;
}

static enum tls_secret_label splice_label_for(enum splice_dir dir)
{
	return dir == SPLICE_C2S ? TLS_LBL_CLIENT_TRAFFIC_0 : TLS_LBL_SERVER_TRAFFIC_0;
}

/* Give up on decrypting: relay everything verbatim from now on. Only safe while
 * no direction has diverged, otherwise the peers would see sequence gaps. */
static int splice_go_opaque(struct tls_splice *s)
{
	/* strict: what cannot be read must not reach the server */
	if (s->strict) {
		s->state = SPLICE_FAILED;
		return -1;
	}
	for (int i = 0; i < 2; i++)
		if (s->d[i].keyed && s->d[i].tx.seq != s->d[i].rx.seq) {
			s->state = SPLICE_FAILED;
			return -1;
		}
	s->state = SPLICE_OPAQUE;
	return 0;
}

struct tls_splice *tls_splice_new(uint32_t pid, unsigned intercept_mask,
				  const struct tls_splice_hooks *hooks)
{
	struct tls_splice *s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;
	s->pid = pid;
	s->intercept_mask = intercept_mask;
	if (hooks)
		s->h = *hooks;
	s->state = SPLICE_HANDSHAKE;
	return s;
}

void tls_splice_free(struct tls_splice *s)
{
	if (!s)
		return;
	free(s->d[0].buf);
	free(s->d[1].buf);
	free(s);
}

enum splice_state tls_splice_state(const struct tls_splice *s) { return s->state; }
int tls_splice_keyed(const struct tls_splice *s, enum splice_dir dir) { return s->d[dir].keyed; }
const char *tls_splice_sni(const struct tls_splice *s) { return s->sni; }
enum tls_cipher tls_splice_cipher(const struct tls_splice *s) { return s->cipher; }
void tls_splice_get_stats(const struct tls_splice *s, struct tls_splice_stats *out) { *out = s->st; }

/* ---- sealing towards a destination ------------------------------------- */

static int splice_seal_and_forward(struct tls_splice *s, enum splice_dir dir, uint8_t inner_type,
			    const uint8_t *buf, size_t len)
{
	struct splice_dir_state *d = &s->d[dir];
	static __thread uint8_t out[TLS_RECORD_HEADER_LEN + TLS_MAX_FRAGMENT];
	size_t off = 0;

	do {
		size_t chunk = len - off > 16384 ? 16384 : len - off;
		size_t out_len;
		if (tls_record_seal(&d->tx, buf + off, chunk, inner_type,
				    out, sizeof(out), &out_len) != TLS_REC_OK)
			return -1;
		if (splice_fwd(s, dir, out, out_len) < 0)
			return -1;
		s->st.records_resealed[dir]++;
		off += chunk;
	} while (off < len);

	if (inner_type == TLS_CT_HANDSHAKE && splice_has_key_update(buf, len)) {
		if (tls_key_ctx_update(&d->tx) != TLS_REC_OK)
			return -1;
	}
	return 0;
}

int tls_splice_send(struct tls_splice *s, enum splice_dir dir, uint8_t inner_type,
		    const uint8_t *buf, size_t len)
{
	if (s->state != SPLICE_ACTIVE || !s->d[dir].keyed)
		return -1;
	if (len == 0)
		return 0;
	return splice_seal_and_forward(s, dir, inner_type, buf, len);
}

/* ---- one complete record ----------------------------------------------- */

static int splice_handle_handshake(struct tls_splice *s, enum splice_dir dir,
				  const uint8_t *rec, size_t len)
{
	if (rec[0] == TLS_CT_HANDSHAKE && dir == SPLICE_C2S) {
		uint8_t cr[32];
		/* a second ClientHello (after HRR) keeps the same random, and the
		 * SNI is the same: parsing it again is harmless */
		if (tls_parse_client_hello(rec, len, cr, s->sni, sizeof(s->sni)) == 0) {
			memcpy(s->client_random, cr, 32);
			s->have_client_random = 1;
		}
	} else if (rec[0] == TLS_CT_HANDSHAKE && dir == SPLICE_S2C) {
		uint8_t sr[32];
		uint16_t suite = 0, version = 0;
		int hrr = 0, etm = 0;
		if (tls_parse_server_hello(rec, len, sr, &suite, &version, &hrr, &etm) == 0 && !hrr) {
			if (version == TLS_VERSION_1_3) {
				s->cipher = tls_cipher_from_wire(suite);
				s->version = TLS_VERSION_1_3;
				if (s->cipher != TLS_CIPHER_UNKNOWN)
					s->state = SPLICE_ACTIVE;
				else if (splice_go_opaque(s) != 0)   /* unknown 1.3 suite */
					return -1;
			} else if (version == TLS_VERSION_1_2 || version == TLS_VERSION_1_1 ||
				   version == TLS_VERSION_1_0) {
				/* TLS 1.2/1.1/1.0: one master secret, key block expanded
				 * with server_random; encryption starts at ChangeCipherSpec,
				 * handled per direction in splice_handle_active_tls12(). */
				s->cipher = tls12_cipher_from_wire(suite);
				s->version = (enum tls_version)version;
				s->etm = etm;
				memcpy(s->server_random, sr, 32);
				if (s->cipher != TLS_CIPHER_UNKNOWN)
					s->state = SPLICE_ACTIVE;
				else if (splice_go_opaque(s) != 0)   /* unknown suite */
					return -1;
			} else if (splice_go_opaque(s) != 0) {   /* SSLv3 / unknown version */
				return -1;
			}
		}
	}
	s->st.records_verbatim[dir]++;
	return splice_fwd(s, dir, rec, len);
}

/* ---- records the key store cannot open yet ---------------------------- */

enum splice_class {
	SPLICE_CLASS_UNKNOWN   = 0,   /* no key opens it (yet) */
	SPLICE_CLASS_APP       = 1,   /* application key resolved: d->keyed now set */
	SPLICE_CLASS_HANDSHAKE = 2,   /* opened by the handshake key: Finished & co */
};

static enum tls_secret_label splice_hs_label_for(enum splice_dir dir)
{
	return dir == SPLICE_C2S ? TLS_LBL_CLIENT_HS : TLS_LBL_SERVER_HS;
}

static enum splice_class splice_classify(struct tls_splice *s, enum splice_dir dir,
					 const uint8_t *rec, size_t len)
{
	struct splice_dir_state *d = &s->d[dir];
	struct tls_key_ctx ctx;

	if (s->h.need_keys)
		s->h.need_keys(s->h.user);

	uint64_t max_seq = d->unresolved < SPLICE_MAX_LATE_RECORDS ?
			   d->unresolved : SPLICE_MAX_LATE_RECORDS;
	if (tls_keys_resolve(s->pid, s->client_random, splice_label_for(dir), s->cipher,
			     rec, len, max_seq, &ctx) == 0) {
		/* records before this one went through verbatim, so the destination
		 * counted them: both legs are at the same sequence number */
		d->rx = ctx;
		d->tx = ctx;
		d->keyed = 1;
		return SPLICE_CLASS_APP;
	}

	/* The same probe captures the handshake secrets: a record they open is
	 * the Finished (or the client certificate flight), which carries no
	 * application data and has to reach the peer for the handshake to end. */
	max_seq = d->hs_records < SPLICE_MAX_LATE_RECORDS ? d->hs_records : SPLICE_MAX_LATE_RECORDS;
	if (tls_keys_resolve(s->pid, s->client_random, splice_hs_label_for(dir), s->cipher,
			     rec, len, max_seq, &ctx) == 0) {
		d->hs_records = ctx.seq + 1;
		return SPLICE_CLASS_HANDSHAKE;
	}
	return SPLICE_CLASS_UNKNOWN;
}

static uint64_t splice_now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static int splice_handle_active(struct tls_splice *s, enum splice_dir dir,
			 const uint8_t *rec, size_t len)
{
	struct splice_dir_state *d = &s->d[dir];

	/* change_cipher_spec compatibility records and cleartext alerts are not
	 * protected and do not consume a sequence number */
	if (rec[0] != TLS_CT_APPLICATION_DATA) {
		s->st.records_verbatim[dir]++;
		return splice_fwd(s, dir, rec, len);
	}

	if (!d->keyed) {
		enum splice_class c = splice_classify(s, dir, rec, len);

		/* A record nobody can open yet may well be application data whose
		 * key is still on its way: wait for it rather than relay it unseen.
		 * Client side, so that a request never reaches the server unseen.
		 * Server side too: a TLS 1.3 server may send application data right
		 * after its Finished (HTTP/2 SETTINGS, in 0.5-RTT), before the client
		 * even received the Finished it needs to derive that key; relayed
		 * as is, the server's own frames would reach the app behind the
		 * bridge's back. The Finished itself was recognized above and has
		 * already gone out, so the client is not kept waiting for it.
		 * A direction waits once: if its key never comes, its next records
		 * are not delayed again. */
		if (c == SPLICE_CLASS_UNKNOWN && s->hold_ms > 0 && !d->hold_spent) {
			uint64_t deadline = splice_now_ms() + (uint64_t)s->hold_ms;
			struct timespec tick = { 0, 1000000 };
			while (c == SPLICE_CLASS_UNKNOWN && splice_now_ms() < deadline) {
				nanosleep(&tick, NULL);
				c = splice_classify(s, dir, rec, len);
			}
			if (c == SPLICE_CLASS_UNKNOWN)
				d->hold_spent = 1;
		}

		if (c == SPLICE_CLASS_HANDSHAKE) {
			s->st.records_verbatim[dir]++;
			return splice_fwd(s, dir, rec, len);
		}
		if (c == SPLICE_CLASS_UNKNOWN) {
			if (s->strict && dir == SPLICE_C2S) {
				s->state = SPLICE_FAILED;
				return -1;
			}
			/* not strict: relay it untouched, the connection keeps working
			 * but this record was not inspectable */
			d->unresolved++;
			s->st.records_verbatim[dir]++;
			return splice_fwd(s, dir, rec, len);
		}
	}

	static __thread uint8_t pt[TLS_MAX_FRAGMENT];
	size_t pt_len;
	uint8_t inner;
	uint64_t rec_seq = d->rx.seq;

	if (tls_record_open(&d->rx, rec, len, pt, sizeof(pt), &pt_len, &inner) != TLS_REC_OK) {
		/* the key stopped matching: relay verbatim if that is still safe */
		if (splice_go_opaque(s) != 0)
			return -1;
		s->st.records_verbatim[dir]++;
		return splice_fwd(s, dir, rec, len);
	}
	s->st.records_opened[dir]++;

	int key_update = inner == TLS_CT_HANDSHAKE && splice_has_key_update(pt, pt_len);

	if (splice_intercepted(s, dir)) {
		/* the owner sends it back (edited or not) through tls_splice_send(),
		 * which also rotates the tx key on the KeyUpdate it carries */
		if (s->h.plaintext)
			s->h.plaintext(s->h.user, dir, inner, pt, pt_len);
	} else {
		int rc;
		if (d->tx.seq == rec_seq) {
			/* fast path: nothing changed so far in this direction, the
			 * original ciphertext is valid for the destination as is */
			d->tx.seq++;
			s->st.records_verbatim[dir]++;
			rc = splice_fwd(s, dir, rec, len);
			if (rc >= 0 && key_update && tls_key_ctx_update(&d->tx) != TLS_REC_OK)
				rc = -1;
		} else {
			rc = splice_seal_and_forward(s, dir, inner, pt, pt_len);
		}
		if (rc < 0)
			return -1;
		if (s->h.plaintext)
			s->h.plaintext(s->h.user, dir, inner, pt, pt_len);
	}

	if (key_update) {
		s->st.key_updates[dir]++;
		if (tls_key_ctx_update(&d->rx) != TLS_REC_OK)
			return -1;
	}
	return 0;
}

/* ---- TLS 1.2 / 1.1 / 1.0 active path ----------------------------------- */

/* Resolve the master secret for this connection and key the direction. */
static enum splice_class splice_classify_tls12(struct tls_splice *s, enum splice_dir dir,
					       const uint8_t *rec, size_t len)
{
	struct splice_dir_state *d = &s->d[dir];
	struct tls_key_ctx ctx;
	uint8_t master[TLS_MAX_SECRET_LEN];
	uint8_t master_len = 0;
	int is_server = dir == SPLICE_S2C;

	if (s->h.need_keys)
		s->h.need_keys(s->h.user);

	uint64_t max_seq = d->unresolved < SPLICE_MAX_LATE_RECORDS ?
			   d->unresolved : SPLICE_MAX_LATE_RECORDS;
	if (tls_keys_resolve_tls12(s->pid, s->client_random, s->server_random,
				   s->cipher, s->version, is_server, s->etm, rec, len,
				   max_seq, &ctx, master, &master_len) == 0) {
		d->rx = ctx;
		d->tx = ctx;
		d->keyed = 1;
		if (!s->have_master) {
			memcpy(s->master, master, master_len);
			s->master_len = master_len;
			s->have_master = 1;
		}
		return SPLICE_CLASS_APP;
	}
	return SPLICE_CLASS_UNKNOWN;
}

static int splice_handle_active_tls12(struct tls_splice *s, enum splice_dir dir,
				      const uint8_t *rec, size_t len)
{
	struct splice_dir_state *d = &s->d[dir];

	/* Before this direction's ChangeCipherSpec everything is in the clear:
	 * the rest of the handshake (Certificate, *KeyExchange, NewSessionTicket)
	 * and the CCS record itself. Relay verbatim; the CCS flips the epoch. */
	if (!d->ccs_seen) {
		if (rec[0] == TLS_CT_CHANGE_CIPHER_SPEC)
			d->ccs_seen = 1;
		s->st.records_verbatim[dir]++;
		return splice_fwd(s, dir, rec, len);
	}

	/* Encrypted epoch: the first record is the Finished (content type 22),
	 * then application data (23). The record content type is in the clear in
	 * the header but the body is encrypted. */
	if (!d->keyed) {
		enum splice_class c = splice_classify_tls12(s, dir, rec, len);

		if (c == SPLICE_CLASS_UNKNOWN && s->hold_ms > 0 && !d->hold_spent) {
			uint64_t deadline = splice_now_ms() + (uint64_t)s->hold_ms;
			struct timespec tick = { 0, 1000000 };
			while (c == SPLICE_CLASS_UNKNOWN && splice_now_ms() < deadline) {
				nanosleep(&tick, NULL);
				c = splice_classify_tls12(s, dir, rec, len);
			}
			if (c == SPLICE_CLASS_UNKNOWN)
				d->hold_spent = 1;
		}

		if (c == SPLICE_CLASS_UNKNOWN) {
			if (s->strict && dir == SPLICE_C2S) {
				s->state = SPLICE_FAILED;
				return -1;
			}
			/* relay untouched: the connection works, this record is not seen */
			d->unresolved++;
			s->st.records_verbatim[dir]++;
			return splice_fwd(s, dir, rec, len);
		}
	}

	static __thread uint8_t pt[TLS_MAX_FRAGMENT];
	size_t pt_len;
	uint8_t inner;
	uint64_t rec_seq = d->rx.seq;

	if (tls_record_open(&d->rx, rec, len, pt, sizeof(pt), &pt_len, &inner) != TLS_REC_OK) {
		if (splice_go_opaque(s) != 0)
			return -1;
		s->st.records_verbatim[dir]++;
		return splice_fwd(s, dir, rec, len);
	}
	s->st.records_opened[dir]++;

	/* The encrypted Finished (22), an encrypted alert (21), or any non-data
	 * record is never edited: relay it, keeping the destination's seq in step. */
	if (inner != TLS_CT_APPLICATION_DATA) {
		if (d->tx.seq == rec_seq) {
			d->tx.seq++;
			s->st.records_verbatim[dir]++;
			return splice_fwd(s, dir, rec, len);
		}
		return splice_seal_and_forward(s, dir, inner, pt, pt_len);
	}

	if (splice_intercepted(s, dir)) {
		if (s->h.plaintext)
			s->h.plaintext(s->h.user, dir, inner, pt, pt_len);
	} else {
		int rc;
		if (d->tx.seq == rec_seq) {
			d->tx.seq++;
			s->st.records_verbatim[dir]++;
			rc = splice_fwd(s, dir, rec, len);
		} else {
			rc = splice_seal_and_forward(s, dir, inner, pt, pt_len);
		}
		if (rc < 0)
			return -1;
		if (s->h.plaintext)
			s->h.plaintext(s->h.user, dir, inner, pt, pt_len);
	}
	return 0;
}

/* ---- input ------------------------------------------------------------- */

static int splice_buf_append(struct splice_dir_state *d, const uint8_t *b, size_t n)
{
	if (d->len + n > d->cap) {
		size_t cap = d->cap ? d->cap : 8192;
		while (cap < d->len + n)
			cap *= 2;
		uint8_t *nb = realloc(d->buf, cap);
		if (!nb)
			return -1;
		d->buf = nb;
		d->cap = cap;
	}
	memcpy(d->buf + d->len, b, n);
	d->len += n;
	return 0;
}

int tls_splice_feed(struct tls_splice *s, enum splice_dir dir,
		    const uint8_t *buf, size_t len)
{
	struct splice_dir_state *d = &s->d[dir];

	if (s->state == SPLICE_FAILED)
		return -1;

	if (splice_buf_append(d, buf, len) != 0) {
		s->state = SPLICE_FAILED;
		return -1;
	}

	size_t off = 0;
	while (s->state != SPLICE_OPAQUE && s->state != SPLICE_FAILED) {
		struct tls_record_hdr hdr;
		size_t total;
		int r = tls_record_peek(d->buf + off, d->len - off, &hdr, &total);
		if (r == TLS_REC_NEED_MORE)
			break;
		if (r != TLS_REC_OK) {
			/* not TLS (or not anymore): stop interpreting */
			if (splice_go_opaque(s) != 0)
				return -1;
			break;
		}

		int rc;
		if (s->state == SPLICE_HANDSHAKE)
			rc = splice_handle_handshake(s, dir, d->buf + off, total);
		else if (s->version == TLS_VERSION_1_3)
			rc = splice_handle_active(s, dir, d->buf + off, total);
		else
			rc = splice_handle_active_tls12(s, dir, d->buf + off, total);
		if (rc < 0) {
			s->state = SPLICE_FAILED;
			return -1;
		}
		off += total;
	}

	if (s->state == SPLICE_OPAQUE && off < d->len) {
		/* everything left, partial records included, goes out verbatim */
		if (splice_fwd(s, dir, d->buf + off, d->len - off) < 0)
			return -1;
		off = d->len;
	}

	memmove(d->buf, d->buf + off, d->len - off);
	d->len -= off;
	return s->state == SPLICE_FAILED ? -1 : 0;
}

void tls_splice_set_policy(struct tls_splice *s, int strict, int hold_ms)
{
	s->strict = strict;
	s->hold_ms = hold_ms < 0 ? 0 : hold_ms;
}

int tls_splice_prime(struct tls_splice *s, enum splice_dir dir)
{
	struct splice_dir_state *d = &s->d[dir];
	struct tls_key_ctx ctx;

	if (d->keyed)
		return 0;
	if (s->state != SPLICE_ACTIVE)
		return -1;
	if (s->h.need_keys)
		s->h.need_keys(s->h.user);

	/* TLS 1.2 and below: one master secret for the whole connection. Once it
	 * is known (a direction resolved it against a record), the per-direction
	 * key is a deterministic expansion with server_random. */
	if (s->version != TLS_VERSION_1_3) {
		if (!s->have_master)
			return 1;   /* no record decrypted yet, master not validated */
		if (tls12_key_ctx_init(&ctx, s->cipher, s->version, s->master, s->master_len,
				       s->client_random, s->server_random,
				       dir == SPLICE_S2C, s->etm) != TLS_REC_OK)
			return 1;
		d->rx = ctx;
		d->tx = ctx;
		d->keyed = 1;
		return 0;
	}

	if (tls_keys_sibling(s->pid, s->client_random, splice_label_for(dir),
			     s->cipher, &ctx) != 0)
		return 1;
	d->rx = ctx;
	d->tx = ctx;
	d->keyed = 1;
	return 0;
}
