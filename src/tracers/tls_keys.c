/*
 * TLS key store — see include/tls_keys.h.
 */

#include "tls_keys.h"

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

struct key_entry {
	int   in_use;
	__u32 pid;
	__u64 timestamp_ns;
	__u64 ssl_ptr;           /* library handle: the secrets of one handshake share it */
	__u8  source;
	__u8  label;
	__u8  has_client_random;
	__u8  secret_len;
	__u8  client_random[TLS_KEYS_RANDOM_LEN];
	__u8  secret[TLS_KEYS_SECRET_LEN];
};

static struct key_entry key_store[TLS_KEYS_CAPACITY];
static size_t key_store_next;     /* ring cursor: the slot the next add overwrites */
static pthread_mutex_t key_store_lock = PTHREAD_MUTEX_INITIALIZER;

static __u64 keys_now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

void tls_keys_reset(void)
{
	pthread_mutex_lock(&key_store_lock);
	memset(key_store, 0, sizeof(key_store));
	key_store_next = 0;
	pthread_mutex_unlock(&key_store_lock);
}

size_t tls_keys_count(void)
{
	size_t n = 0;
	pthread_mutex_lock(&key_store_lock);
	for (size_t i = 0; i < TLS_KEYS_CAPACITY; i++)
		n += key_store[i].in_use ? 1 : 0;
	pthread_mutex_unlock(&key_store_lock);
	return n;
}

int tls_keys_add(const struct tls_secret_event_t *ev)
{
	__u8 label;

	if (!ev || ev->secret_len == 0 || ev->secret_len > TLS_KEYS_SECRET_LEN)
		return -1;

	label = ev->label;
	if (label == TLS_LBL_UNKNOWN && ev->label_name[0]) {
		label = (__u8)tls_keys_label_from_name(ev->label_name,
						       strnlen(ev->label_name,
							       sizeof(ev->label_name)));
		if (label == TLS_LBL_UNKNOWN)
			return -1;
	}

	pthread_mutex_lock(&key_store_lock);
	/* The same secret can be reported twice (two probes on one stack, or a
	 * keylog file plus a probe): keep a single entry, upgraded with the client
	 * random if the new report has it. */
	for (size_t i = 0; i < TLS_KEYS_CAPACITY; i++) {
		struct key_entry *e = &key_store[i];
		if (e->in_use && e->pid == ev->pid && e->label == label &&
		    e->secret_len == ev->secret_len &&
		    memcmp(e->secret, ev->secret, ev->secret_len) == 0) {
			if (!e->has_client_random && ev->has_client_random) {
				e->has_client_random = 1;
				memcpy(e->client_random, ev->client_random, TLS_KEYS_RANDOM_LEN);
			}
			pthread_mutex_unlock(&key_store_lock);
			return 0;
		}
	}

	struct key_entry *e = &key_store[key_store_next];
	key_store_next = (key_store_next + 1) % TLS_KEYS_CAPACITY;
	memset(e, 0, sizeof(*e));
	e->in_use = 1;
	e->pid = ev->pid;
	e->timestamp_ns = ev->timestamp_ns ? ev->timestamp_ns : keys_now_ns();
	e->ssl_ptr = ev->ssl_ptr;
	e->source = ev->source;
	e->label = label;
	e->has_client_random = ev->has_client_random;
	e->secret_len = ev->secret_len;
	memcpy(e->client_random, ev->client_random, TLS_KEYS_RANDOM_LEN);
	memcpy(e->secret, ev->secret, ev->secret_len);
	pthread_mutex_unlock(&key_store_lock);
	return 0;
}

/* ---- NSS keylog format ------------------------------------------------- */

static const struct { const char *name; enum tls_secret_label label; } key_label_names[] = {
	{ "CLIENT_HANDSHAKE_TRAFFIC_SECRET", TLS_LBL_CLIENT_HS },
	{ "SERVER_HANDSHAKE_TRAFFIC_SECRET", TLS_LBL_SERVER_HS },
	{ "CLIENT_TRAFFIC_SECRET_0",         TLS_LBL_CLIENT_TRAFFIC_0 },
	{ "SERVER_TRAFFIC_SECRET_0",         TLS_LBL_SERVER_TRAFFIC_0 },
	{ "EXPORTER_SECRET",                 TLS_LBL_EXPORTER },
	{ "CLIENT_EARLY_TRAFFIC_SECRET",     TLS_LBL_CLIENT_EARLY },
	{ "CLIENT_RANDOM",                   TLS_LBL_TLS12_MASTER },
};

enum tls_secret_label tls_keys_label_from_name(const char *name, size_t len)
{
	for (size_t i = 0; i < sizeof(key_label_names) / sizeof(*key_label_names); i++)
		if (strlen(key_label_names[i].name) == len &&
		    memcmp(key_label_names[i].name, name, len) == 0)
			return key_label_names[i].label;
	return TLS_LBL_UNKNOWN;
}

static int keys_hexval(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* Decode a hex token of exactly `len` chars into out; returns bytes or -1. */
static int keys_unhex(const char *s, size_t len, __u8 *out, size_t cap)
{
	if (len % 2 || len / 2 > cap)
		return -1;
	for (size_t i = 0; i < len / 2; i++) {
		int hi = keys_hexval(s[2 * i]), lo = keys_hexval(s[2 * i + 1]);
		if (hi < 0 || lo < 0)
			return -1;
		out[i] = (__u8)(hi << 4 | lo);
	}
	return (int)(len / 2);
}

/* Split the next whitespace-delimited token; returns its length, 0 at end. */
static size_t keys_next_token(const char **p, const char **tok)
{
	while (**p && isspace((unsigned char)**p))
		(*p)++;
	*tok = *p;
	while (**p && !isspace((unsigned char)**p))
		(*p)++;
	return (size_t)(*p - *tok);
}

int tls_keys_add_keylog_line(__u32 pid, const char *line, enum tls_key_source src)
{
	const char *p = line, *tok;
	size_t n = keys_next_token(&p, &tok);
	if (n == 0 || tok[0] == '#')
		return 0;

	enum tls_secret_label label = tls_keys_label_from_name(tok, n);
	if (label == TLS_LBL_UNKNOWN)
		return -1;

	struct tls_secret_event_t ev;
	memset(&ev, 0, sizeof(ev));
	ev.pid = pid;
	ev.source = (__u8)src;
	ev.label = (__u8)label;

	n = keys_next_token(&p, &tok);
	if (keys_unhex(tok, n, ev.client_random, sizeof(ev.client_random)) != TLS_KEYS_RANDOM_LEN)
		return -1;
	ev.has_client_random = 1;

	n = keys_next_token(&p, &tok);
	int slen = keys_unhex(tok, n, ev.secret, sizeof(ev.secret));
	if (slen <= 0)
		return -1;
	ev.secret_len = (__u8)slen;

	return tls_keys_add(&ev);
}

int tls_keys_load_keylog_file(__u32 pid, const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;
	char line[512];
	int added = 0;
	while (fgets(line, sizeof(line), f)) {
		const char *p = line, *tok;
		size_t n = keys_next_token(&p, &tok);
		if (n == 0 || tok[0] == '#')
			continue;
		if (tls_keys_add_keylog_line(pid, line, KEYSRC_KEYLOG_FILE) == 0)
			added++;
	}
	fclose(f);
	return added;
}

/* ---- resolution -------------------------------------------------------- */

static size_t keys_secret_len_for(enum tls_cipher cipher)
{
	return cipher == TLS_AES_256_GCM_SHA384 ? 48 : 32;
}

/* Handshake messages only sent under a handshake key: EncryptedExtensions,
 * Certificate, CertificateRequest, CertificateVerify, Finished. Under an
 * application key the handshake messages are NewSessionTicket and KeyUpdate. */
static int keys_handshake_flight(uint8_t inner, const uint8_t *pt, size_t len)
{
	return inner == TLS_CT_HANDSHAKE && len &&
	       (pt[0] == 8 || pt[0] == 11 || pt[0] == 13 || pt[0] == 15 || pt[0] == 20);
}

/* What a record must turn out to be for a secret of this label to be the
 * right one: 1 the handshake flight, 0 anything else, -1 no constraint. An
 * unlabeled secret (the HMAC probe) opens handshake and application records
 * alike if it is the handshake secret: the content tells which it is. */
static int keys_flight_of(enum tls_secret_label label)
{
	if (label == TLS_LBL_CLIENT_HS || label == TLS_LBL_SERVER_HS)
		return 1;
	if (label == TLS_LBL_CLIENT_TRAFFIC_0 || label == TLS_LBL_SERVER_TRAFFIC_0)
		return 0;
	return -1;
}

/* Does this secret open the record at some seq in [0, max_seq], as a record of
 * the expected flight? On success *ctx is left at that seq, ready to open the
 * record for real. */
static int keys_trial_open(const struct key_entry *e, enum tls_cipher cipher,
		      const uint8_t *record, size_t record_len,
		      uint64_t max_seq, int flight, struct tls_key_ctx *ctx)
{
	if (tls_key_ctx_init(ctx, cipher, TLS_VERSION_1_3,
			     e->secret, e->secret_len) != TLS_REC_OK)
		return 0;

	static __thread uint8_t scratch[TLS_MAX_FRAGMENT];
	for (uint64_t seq = 0; seq <= max_seq; seq++) {
		struct tls_key_ctx probe = *ctx;
		size_t out_len;
		uint8_t inner_type;
		probe.seq = seq;
		if (tls_record_open(&probe, record, record_len, scratch, sizeof(scratch),
				    &out_len, &inner_type) == TLS_REC_OK) {
			if (flight >= 0 &&
			    keys_handshake_flight(inner_type, scratch, out_len) != flight)
				return 0;   /* the right key for another label */
			ctx->seq = seq;
			return 1;
		}
	}
	return 0;
}

int tls_keys_resolve(__u32 pid, const __u8 client_random[TLS_KEYS_RANDOM_LEN],
		     enum tls_secret_label label, enum tls_cipher cipher,
		     const uint8_t *record, size_t record_len,
		     uint64_t max_seq, struct tls_key_ctx *out)
{
	if (!record || !out || cipher == TLS_CIPHER_UNKNOWN)
		return -1;

	size_t want_len = keys_secret_len_for(cipher);
	int flight = keys_flight_of(label);
	__u64 now = keys_now_ns();
	struct key_entry snapshot;
	int found = 1;

	pthread_mutex_lock(&key_store_lock);

	/* 1. exact match: the source told us which connection the secret is for.
	 *    Still validated by trial, so a stale or colliding entry is ignored. */
	for (size_t i = 0; i < TLS_KEYS_CAPACITY && found; i++) {
		struct key_entry *e = &key_store[i];
		if (!e->in_use || e->label != label || !e->has_client_random ||
		    (e->pid != pid && e->pid != 0) ||
		    memcmp(e->client_random, client_random, TLS_KEYS_RANDOM_LEN) != 0)
			continue;
		snapshot = *e;
		if (keys_trial_open(&snapshot, cipher, record, record_len, max_seq, flight, out))
			found = 0;
	}

	/* 2. candidates: secrets of this pid with no client random, recent
	 *    enough, of the right size for the negotiated hash. */
	for (size_t i = 0; i < TLS_KEYS_CAPACITY && found; i++) {
		struct key_entry *e = &key_store[i];
		if (!e->in_use || e->has_client_random || e->pid != pid ||
		    e->secret_len != want_len ||
		    (e->label != label && e->label != TLS_LBL_UNKNOWN))
			continue;
		if (now > e->timestamp_ns &&
		    now - e->timestamp_ns > TLS_KEYS_CANDIDATE_WINDOW_NS)
			continue;
		snapshot = *e;
		if (keys_trial_open(&snapshot, cipher, record, record_len, max_seq, flight, out)) {
			/* bind it: from now on this secret belongs to this connection */
			e->has_client_random = 1;
			memcpy(e->client_random, client_random, TLS_KEYS_RANDOM_LEN);
			if (e->label == TLS_LBL_UNKNOWN)
				e->label = (__u8)label;
			found = 0;
		}
	}

	pthread_mutex_unlock(&key_store_lock);
	return found;
}

/* ---- TLS 1.2 / 1.1 resolution (one master secret per connection) ------- */

/* Does this master secret, expanded for the given direction, open the record
 * at some seq in [0, max_seq]? On success *ctx is left at that seq. */
static int keys_trial_open_tls12(const struct key_entry *e,
				 const __u8 cr[TLS_KEYS_RANDOM_LEN],
				 const __u8 sr[TLS_KEYS_RANDOM_LEN],
				 enum tls_cipher cipher, enum tls_version version,
				 int is_server, int etm,
				 const uint8_t *record, size_t record_len,
				 uint64_t max_seq, struct tls_key_ctx *ctx)
{
	if (tls12_key_ctx_init(ctx, cipher, version, e->secret, e->secret_len,
			       cr, sr, is_server, etm) != TLS_REC_OK)
		return 0;

	static __thread uint8_t scratch[TLS_MAX_FRAGMENT];
	for (uint64_t seq = 0; seq <= max_seq; seq++) {
		struct tls_key_ctx probe = *ctx;
		size_t out_len;
		uint8_t inner_type;
		probe.seq = seq;
		if (tls_record_open(&probe, record, record_len, scratch, sizeof(scratch),
				    &out_len, &inner_type) == TLS_REC_OK) {
			ctx->seq = seq;
			return 1;
		}
	}
	return 0;
}

int tls_keys_resolve_tls12(__u32 pid, const __u8 client_random[TLS_KEYS_RANDOM_LEN],
			   const __u8 server_random[TLS_KEYS_RANDOM_LEN],
			   enum tls_cipher cipher, enum tls_version version,
			   int is_server, int etm, const uint8_t *record, size_t record_len,
			   uint64_t max_seq, struct tls_key_ctx *out,
			   __u8 *master_out, __u8 *master_len_out)
{
	if (!record || !out || cipher == TLS_CIPHER_UNKNOWN)
		return -1;

	__u64 now = keys_now_ns();
	struct key_entry snapshot;
	int found = 1;

	pthread_mutex_lock(&key_store_lock);

	/* 1. exact: a CLIENT_RANDOM keylog entry names this connection. */
	for (size_t i = 0; i < TLS_KEYS_CAPACITY && found; i++) {
		struct key_entry *e = &key_store[i];
		if (!e->in_use || e->label != TLS_LBL_TLS12_MASTER || !e->has_client_random ||
		    (e->pid != pid && e->pid != 0) ||
		    memcmp(e->client_random, client_random, TLS_KEYS_RANDOM_LEN) != 0)
			continue;
		snapshot = *e;
		if (keys_trial_open_tls12(&snapshot, client_random, server_random, cipher,
					  version, is_server, etm, record, record_len, max_seq, out)) {
			if (master_out) memcpy(master_out, e->secret, e->secret_len);
			if (master_len_out) *master_len_out = e->secret_len;
			found = 0;
		}
	}

	/* 2. candidates: a master captured without a client random, same pid, recent. */
	for (size_t i = 0; i < TLS_KEYS_CAPACITY && found; i++) {
		struct key_entry *e = &key_store[i];
		if (!e->in_use || e->has_client_random || e->pid != pid ||
		    e->label != TLS_LBL_TLS12_MASTER)
			continue;
		if (now > e->timestamp_ns &&
		    now - e->timestamp_ns > TLS_KEYS_CANDIDATE_WINDOW_NS)
			continue;
		snapshot = *e;
		if (keys_trial_open_tls12(&snapshot, client_random, server_random, cipher,
					  version, is_server, etm, record, record_len, max_seq, out)) {
			e->has_client_random = 1;
			memcpy(e->client_random, client_random, TLS_KEYS_RANDOM_LEN);
			if (master_out) memcpy(master_out, e->secret, e->secret_len);
			if (master_len_out) *master_len_out = e->secret_len;
			found = 0;
		}
	}

	pthread_mutex_unlock(&key_store_lock);
	return found;
}

/* Two secrets from one handshake are derived microseconds apart */
#define TLS_KEYS_SIBLING_WINDOW_NS (1000ULL * 1000 * 1000)

int tls_keys_sibling(__u32 pid, const __u8 client_random[TLS_KEYS_RANDOM_LEN],
		     enum tls_secret_label label, enum tls_cipher cipher,
		     struct tls_key_ctx *out)
{
	const struct key_entry *anchor = NULL, *best = NULL;
	__u64 best_dt = ~0ULL;
	size_t want_len;
	int rc = 1;

	if (!out || cipher == TLS_CIPHER_UNKNOWN)
		return -1;
	want_len = keys_secret_len_for(cipher);

	pthread_mutex_lock(&key_store_lock);

	for (size_t i = 0; i < TLS_KEYS_CAPACITY; i++) {
		const struct key_entry *e = &key_store[i];
		if (!e->in_use || !e->has_client_random ||
		    (e->pid != pid && e->pid != 0) ||
		    memcmp(e->client_random, client_random, TLS_KEYS_RANDOM_LEN) != 0)
			continue;
		/* already known for this connection: a keylog line, or bound earlier */
		if (e->label == label && e->secret_len == want_len) {
			best = e;
			break;
		}
		/* any secret of this connection that came with a library handle
		 * can introduce its siblings */
		if (!anchor && e->ssl_ptr)
			anchor = e;
	}

	if (!best && anchor) {
		for (size_t i = 0; i < TLS_KEYS_CAPACITY; i++) {
			const struct key_entry *e = &key_store[i];
			if (!e->in_use || e->pid != anchor->pid || e->ssl_ptr != anchor->ssl_ptr ||
			    e->label != label || e->secret_len != want_len)
				continue;
			/* bound to another connection: the handle was reused */
			if (e->has_client_random &&
			    memcmp(e->client_random, client_random, TLS_KEYS_RANDOM_LEN) != 0)
				continue;
			__u64 dt = e->timestamp_ns > anchor->timestamp_ns ?
				   e->timestamp_ns - anchor->timestamp_ns :
				   anchor->timestamp_ns - e->timestamp_ns;
			if (dt < best_dt && dt <= TLS_KEYS_SIBLING_WINDOW_NS) {
				best = e;
				best_dt = dt;
			}
		}
	}

	if (best && tls_key_ctx_init(out, cipher, TLS_VERSION_1_3,
				     best->secret, best->secret_len) == TLS_REC_OK) {
		struct key_entry *w = (struct key_entry *)best;
		w->has_client_random = 1;
		memcpy(w->client_random, client_random, TLS_KEYS_RANDOM_LEN);
		rc = 0;
	}

	pthread_mutex_unlock(&key_store_lock);
	return rc;
}
