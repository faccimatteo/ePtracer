/*
 * Trust-store detection, and targeted CA import for the classes that allow it.
 *
 * include/http_ca.h trusts the proxy CA through the environment, which only a
 * *spawned* process inherits and which NSS ignores entirely. This module answers
 * the question that comes before that one: *how* does a given binary decide what
 * to trust? It watches the files the traced process (and its children, when they
 * are followed) open with openat(2)/open(2) and classifies the trust mechanism
 * from what it reaches for during the handshake:
 *
 *   - an on-disk PEM bundle (/etc/ssl/certs/ca-certificates.crt and friends):
 *     OpenSSL, GnuTLS, Go, Python, curl — the SSL_CERT_FILE/env approach of
 *     http_ca.c covers these when the process was spawned.
 *
 *   - an NSS database (cert9.db, the legacy cert8.db, secmod.db, pkcs11.txt):
 *     Firefox, Thunderbird, Chromium, Evolution and the rest of the NSS world.
 *     These ignore the environment and trust only the database in their profile.
 *
 * The second one is the only class where a *non-invasive* import is possible:
 * the database is a file in the user's own profile, and `certutil -A` adds the
 * proxy CA to it without touching anything machine-wide. So the import is done
 * only for that class, on the exact database the process was seen opening — no
 * assumption about where Thunderbird, Chromium or anything else keeps it. A
 * process that reaches for a system p11-kit anchor instead is reported and left
 * alone: trusting it would mean installing on the machine, which this tool does
 * not do.
 *
 * Detection reads nothing but paths, so it costs a string per cert-store open
 * and nothing otherwise; it is only enabled while interception is active, the
 * one case where the trust store matters.
 */

#ifndef EPTRACER_HTTP_CA_DETECT_H
#define EPTRACER_HTTP_CA_DETECT_H

/* Bytes of the opened path carried to userspace */
#define CA_PATH_LEN     256
#define CA_COMM_LEN     16
/* Ring buffer for the cert-store open events, small: these are rare */
#define CA_RINGBUF_SIZE (256 * 1024)

/* Which trust store an opened file belongs to, decided in kernel space from the
 * file name so that userspace only sees the opens that matter. */
enum ca_store_kind {
	CA_STORE_UNKNOWN = 0,
	CA_STORE_PEM_BUNDLE = 1,  /* on-disk PEM bundle, env/SSL_CERT_FILE applies */
	CA_STORE_NSS_DB     = 2,  /* NSS database, needs certutil into the profile */
};

/* Event pushed through ca_rb_map when a traced process opens a trust-store file */
struct ca_open_event_t {
	__u32 pid;
	__u8  kind;                 /* enum ca_store_kind */
	char  comm[CA_COMM_LEN];
	char  path[CA_PATH_LEN];    /* the file as passed to openat(2) */
};

/* Runtime switch, pushed in ca_detect_config_map: the openat probes do nothing
 * until userspace turns detection on, so they cost nothing when -I is not used */
struct ca_detect_config_t {
	__u8 enabled;
};

/* Arguments handed to the ca_detect_tracer thread */
struct ca_detect_args {
	struct eptracer_bpf *skel;
	const char *intercept;    /* --intercept value, to obtain the proxy CA */
	const char *proxy_ca;     /* --proxy-ca value, may be NULL/empty */
	int   import;             /* attempt the NSS import, off for 'direct' */
};

void *ca_detect_tracer(void *ca_detect_arguments);

/*
 * Imports the proxy CA into the invoking user's Chromium/Electron NSS database
 * (~/.pki/nssdb, or ~/snap/<name>/current/.pki/nssdb for a snap) before a
 * spawned process starts, so the first TLS handshake
 * already trusts the proxy — the reactive detection cannot win that race. A
 * no-op when that database does not exist. Safe to call once, before the child
 * is released.
 */
void ca_preseed_nss(const char *intercept, const char *proxy_ca, const char *program);

/*
 * Returns a file holding the proxy CA in PEM form, obtaining it if necessary
 * (from --proxy-ca, or fetched from the proxy), so the NSS import has something
 * to feed certutil. Reuses the file http_ca.c already wrote for a spawned
 * process. Returns NULL for 'direct' interception or when the CA is unavailable.
 */
const char *http_ca_proxy_ca_file(const char *intercept_endpoint, const char *ca_path);

#endif /* EPTRACER_HTTP_CA_DETECT_H */
