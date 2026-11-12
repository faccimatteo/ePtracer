/*
 * TLS key store — session secrets captured inside the traced process.
 *
 * The splice (include/tls_splice.h) needs, for every connection it relays, the
 * traffic secrets the app's TLS library derived during the handshake. They
 * arrive from two kinds of sources:
 *
 *  - sources that know the connection: an NSS keylog line ("LABEL <client_random>
 *    <secret>", from a keylog callback, Go's writeKeyLog, a rustls call-site
 *    probe, or simply an SSLKEYLOGFILE written by the app), indexed by
 *    (pid, client_random) and matched exactly against the ClientHello seen on
 *    the wire;
 *  - sources that only know the secret (an entry probe on BoringSSL's
 *    ssl_log_secret, where the client random is behind a struct we do not want
 *    to depend on): kept as *candidates* for that pid, in a time window around
 *    the handshake.
 *
 * Candidates are resolved by trial decryption: the first application record of
 * the connection is opened with each one, and only a candidate whose AEAD tag
 * verifies is bound to the connection. A wrong candidate cannot produce wrong
 * plaintext, so the heuristic is safe by construction.
 *
 * Thread safe: the ring buffer consumer adds, the splice sessions resolve.
 */

#ifndef EPTRACER_TLS_KEYS_H
#define EPTRACER_TLS_KEYS_H

#ifdef __bpf__
/* vmlinux.h provides __u8/__u32/__u64 */
#else
#include <linux/types.h>
#include <stddef.h>
#include <stdint.h>
#include "tls_record.h"
#endif

#define TLS_KEYS_RANDOM_LEN 32
#define TLS_KEYS_SECRET_LEN 64
/* Longest NSS keylog label is CLIENT_HANDSHAKE_TRAFFIC_SECRET (31) */
#define TLS_KEYS_LABEL_LEN  40

/* Which secret of the TLS 1.3 key schedule (or the TLS 1.2 master secret) */
enum tls_secret_label {
	TLS_LBL_UNKNOWN          = 0,
	TLS_LBL_CLIENT_HS        = 1,   /* CLIENT_HANDSHAKE_TRAFFIC_SECRET */
	TLS_LBL_SERVER_HS        = 2,   /* SERVER_HANDSHAKE_TRAFFIC_SECRET */
	TLS_LBL_CLIENT_TRAFFIC_0 = 3,   /* CLIENT_TRAFFIC_SECRET_0 */
	TLS_LBL_SERVER_TRAFFIC_0 = 4,   /* SERVER_TRAFFIC_SECRET_0 */
	TLS_LBL_EXPORTER         = 5,   /* EXPORTER_SECRET */
	TLS_LBL_CLIENT_EARLY     = 6,   /* CLIENT_EARLY_TRAFFIC_SECRET */
	TLS_LBL_TLS12_MASTER     = 7,   /* CLIENT_RANDOM (TLS 1.2 master secret) */
};

/* Where a secret came from, for diagnostics */
enum tls_key_source {
	KEYSRC_KEYLOG_FILE      = 1,    /* SSLKEYLOGFILE / --keylog */
	KEYSRC_ANCHOR           = 2,    /* uprobe on the keylog function (tls_anchor.h) */
	KEYSRC_GO               = 3,    /* crypto/tls setTrafficSecret / writeKeyLog */
	KEYSRC_KEYLOG_LINE      = 4,    /* a full keylog line read from the process */
	KEYSRC_CALLSITE         = 5,    /* call-site probe (rustls dyn KeyLog) */
	KEYSRC_HMAC             = 6,    /* HMAC key setup seen in SHA-2 (tls_anchor.h) */
};

/* Event pushed by the eBPF key-capture probes on tls_secret_rb. */
struct tls_secret_event_t {
	__u64 timestamp_ns;             /* bpf_ktime_get_ns(), CLOCK_MONOTONIC */
	__u32 pid;
	__u32 tid;
	__u64 ssl_ptr;                  /* library connection handle, 0 if unknown */
	__u8  source;                   /* enum tls_key_source */
	__u8  label;                    /* enum tls_secret_label */
	__u8  has_client_random;
	__u8  secret_len;
	__u8  client_random[TLS_KEYS_RANDOM_LEN];
	__u8  secret[TLS_KEYS_SECRET_LEN];
	/* Raw label string as the library passed it, when `label` is
	 * TLS_LBL_UNKNOWN: mapping strings in BPF is not worth the
	 * instructions, userspace does it with tls_keys_label_from_name(). */
	char  label_name[TLS_KEYS_LABEL_LEN];
};

#ifndef __bpf__

/* Candidates older than this (relative to the record being resolved) are not
 * tried: a handshake and its first record are milliseconds apart. */
#define TLS_KEYS_CANDIDATE_WINDOW_NS (30ULL * 1000 * 1000 * 1000)
/* Capacity of the store; the oldest entries are overwritten first. */
#define TLS_KEYS_CAPACITY 4096

void tls_keys_reset(void);

/* Add a captured secret. A label given by name is mapped here; a name that is
 * not an NSS keylog label rejects the event. Returns 0, or -1 if the event is
 * malformed. */
int tls_keys_add(const struct tls_secret_event_t *ev);

/*
 * Parse one NSS keylog line ("LABEL <client_random hex> <secret hex>") and add
 * it for `pid` (0 = any process, used for a keylog file not tied to a pid).
 * Comment and blank lines are accepted and ignored (return 0).
 * Returns 0, or -1 if the line is malformed or the label unknown.
 */
int tls_keys_add_keylog_line(__u32 pid, const char *line, enum tls_key_source src);

/* Load a whole keylog file. Returns the number of secrets added, -1 on I/O error. */
int tls_keys_load_keylog_file(__u32 pid, const char *path);

/* Map an NSS keylog label string onto the enum. */
enum tls_secret_label tls_keys_label_from_name(const char *name, size_t len);

/*
 * Find the key context for one direction of a connection.
 *
 *  pid, client_random: what the splice saw (ClientHello on the wire).
 *  label:  TLS_LBL_CLIENT_TRAFFIC_0 for client->server records,
 *          TLS_LBL_SERVER_TRAFFIC_0 for server->client.
 *  cipher: from the ServerHello.
 *  record/record_len: a complete encrypted record of that direction, used to
 *          validate the secret by trial decryption.
 *  max_seq: highest sequence number the record may carry. Normally 0 (the first
 *          application record), but when the key arrived late and earlier
 *          records of this direction were relayed opaque, the record is at
 *          seq k <= max_seq and every value is tried.
 *
 * On success fills *out (with out->seq set to the record's sequence number,
 * ready to open `record`), binds a resolved candidate to client_random so later
 * lookups are exact, and returns 0. Returns 1 when no stored secret opens the
 * record (it may be a handshake record still, or the key has not arrived yet),
 * -1 on bad arguments.
 */
int tls_keys_resolve(__u32 pid, const __u8 client_random[TLS_KEYS_RANDOM_LEN],
		     enum tls_secret_label label, enum tls_cipher cipher,
		     const uint8_t *record, size_t record_len,
		     uint64_t max_seq, struct tls_key_ctx *out);

/*
 * Find the secret of `label` for a connection without a record to validate it
 * against: the key the splice needs to seal what the proxy answers towards the
 * app, when the server has not sent anything under that key yet.
 *
 * The connection must already have one secret bound to client_random (resolved
 * by tls_keys_resolve(), or exact from a keylog line). An exact entry for
 * `label` wins; otherwise the candidate captured from the same library handle
 * (ssl_ptr) closest in time is taken — every secret of a handshake comes from
 * one SSL object, within microseconds. Binds it and returns 0 with *out at
 * seq 0; returns 1 when there is no such secret, -1 on bad arguments.
 */
int tls_keys_sibling(__u32 pid, const __u8 client_random[TLS_KEYS_RANDOM_LEN],
		     enum tls_secret_label label, enum tls_cipher cipher,
		     struct tls_key_ctx *out);

/*
 * TLS 1.2 / 1.1 / 1.0 resolution. There is one master secret per connection
 * (captured as the CLIENT_RANDOM keylog entry), from which both directions'
 * keys are derived with server_random. Finds the master for the connection
 * (exact by client_random, or a recent candidate of `pid` validated by trial),
 * derives the client_write (is_server 0) or server_write (is_server 1) key for
 * `cipher`/`version`, and trial-opens `record` at a seq in [0, max_seq]. On
 * success fills *out ready to open the record, copies the validated master to
 * master_out and master_len_out when they are non-NULL, binds the master to
 * client_random, and returns 0. Returns 1 if no master opens it, -1 on bad args.
 */
int tls_keys_resolve_tls12(__u32 pid, const __u8 client_random[TLS_KEYS_RANDOM_LEN],
			   const __u8 server_random[TLS_KEYS_RANDOM_LEN],
			   enum tls_cipher cipher, enum tls_version version,
			   int is_server, int etm, const uint8_t *record, size_t record_len,
			   uint64_t max_seq, struct tls_key_ctx *out,
			   __u8 *master_out, __u8 *master_len_out);

/* Number of stored entries (tests, stats). */
size_t tls_keys_count(void);

#endif /* !__bpf__ */

#endif /* EPTRACER_TLS_KEYS_H */
