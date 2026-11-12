/*
 * Proxy bridge, FRONT side — see include/proxy_bridge.h.
 *
 * Userspace-only (sockets + OpenSSL), so it builds and is tested standalone
 * against bench/burp_style_proxy.py, a Burp-style CONNECT + MITM proxy.
 */

#include "proxy_bridge.h"
#include <ctype.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/obj_mac.h>

struct proxy_front {
	int      fd;
	SSL_CTX *ctx;
	SSL     *ssl;
	int      nonblocking;
};

static __thread char pb_err[256];

static void pb_set_err(const char *fmt, ...)
{
	va_list ap;
	__builtin_va_start(ap, fmt);
	vsnprintf(pb_err, sizeof(pb_err), fmt, ap);
	__builtin_va_end(ap);
}

const char *proxy_bridge_last_error(void) { return pb_err; }

/* ---- plain TCP dial to the proxy --------------------------------------- */

static int pb_dial(const char *host, int port)
{
	char portstr[16];
	snprintf(portstr, sizeof(portstr), "%d", port);

	struct addrinfo hints, *res = NULL, *rp;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	int gai = getaddrinfo(host, portstr, &hints, &res);
	if (gai != 0) {
		pb_set_err("resolve %s:%d: %s", host, port, gai_strerror(gai));
		return -1;
	}

	int fd = -1;
	for (rp = res; rp; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd < 0)
			continue;
		if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd < 0)
		pb_set_err("connect %s:%d: %s", host, port, strerror(errno));
	return fd;
}

static int pb_write_all(int fd, const char *buf, size_t len)
{
	size_t off = 0;
	while (off < len) {
		ssize_t n = write(fd, buf + off, len - off);
		if (n <= 0) {
			if (n < 0 && errno == EINTR)
				continue;
			return -1;
		}
		off += (size_t)n;
	}
	return 0;
}

/* ---- the CONNECT request to the proxy ---------------------------------- */

/*
 * Send `CONNECT authority:port` and read the reply up to the blank line. A
 * Burp-style proxy answers "HTTP/1.1 200 Connection established". We insist on
 * a 2xx status and consume exactly the header block, leaving the socket at the
 * first TLS byte.
 */
static int pb_do_connect(int fd, const char *authority, int port)
{
	/* The authority comes from the intercepted traffic (Host header, SNI):
	 * only host-name characters may reach the CONNECT line, so a crafted
	 * name cannot inject headers or a second request into the proxy */
	for (const char *c = authority; *c; c++) {
		if (!isalnum((unsigned char)*c) && !strchr(".-_[]:", *c)) {
			pb_set_err("refusing CONNECT to an invalid host name");
			return -1;
		}
	}
	if (!authority[0] || port <= 0 || port > 65535) {
		pb_set_err("refusing CONNECT without a valid host and port");
		return -1;
	}

	char req[512];
	int n = snprintf(req, sizeof(req),
			 "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n"
			 "Proxy-Connection: keep-alive\r\n\r\n",
			 authority, port, authority, port);
	if (n <= 0 || pb_write_all(fd, req, (size_t)n) != 0) {
		pb_set_err("sending CONNECT: %s", strerror(errno));
		return -1;
	}

	char reply[1024];
	size_t used = 0;
	for (;;) {
		if (used >= sizeof(reply) - 1) {
			pb_set_err("CONNECT reply too large");
			return -1;
		}
		ssize_t r = read(fd, reply + used, sizeof(reply) - 1 - used);
		if (r <= 0) {
			pb_set_err("reading CONNECT reply: %s",
				r == 0 ? "proxy closed" : strerror(errno));
			return -1;
		}
		used += (size_t)r;
		reply[used] = '\0';
		if (strstr(reply, "\r\n\r\n"))
			break;
	}

	/* "HTTP/1.1 200 ..." — accept any 2xx */
	if (strncmp(reply, "HTTP/1.", 7) != 0 || reply[9] != '2') {
		char *eol = strpbrk(reply, "\r\n");
		if (eol) *eol = '\0';
		pb_set_err("proxy refused CONNECT: %.120s", reply);
		return -1;
	}
	return 0;
}

/* ---- TLS towards the proxy (client) ------------------------------------ */

static int pb_tls_handshake(struct proxy_front *pf, const struct proxy_bridge_cfg *cfg,
			 const char *authority)
{
	pf->ctx = SSL_CTX_new(TLS_client_method());
	if (!pf->ctx) {
		pb_set_err("SSL_CTX_new failed");
		return -1;
	}
	SSL_CTX_set_min_proto_version(pf->ctx, TLS1_2_VERSION);

	int verify = cfg->ca_file[0] != '\0';
	if (verify) {
		if (SSL_CTX_load_verify_locations(pf->ctx, cfg->ca_file, NULL) != 1) {
			pb_set_err("loading proxy CA %s failed", cfg->ca_file);
			return -1;
		}
		SSL_CTX_set_verify(pf->ctx, SSL_VERIFY_PEER, NULL);
	}

	pf->ssl = SSL_new(pf->ctx);
	if (!pf->ssl) {
		pb_set_err("SSL_new failed");
		return -1;
	}
	SSL_set_fd(pf->ssl, pf->fd);
	/* SNI: the proxy mints its leaf certificate for this authority */
	SSL_set_tlsext_host_name(pf->ssl, authority);
	if (verify) {
		SSL_set_hostflags(pf->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		if (SSL_set1_host(pf->ssl, authority) != 1) {
			pb_set_err("SSL_set1_host failed");
			return -1;
		}
	}

	if (SSL_connect(pf->ssl) != 1) {
		long vr = SSL_get_verify_result(pf->ssl);
		if (vr != X509_V_OK)
			pb_set_err("TLS to proxy failed: cert verify: %s",
				X509_verify_cert_error_string(vr));
		else
			pb_set_err("TLS handshake to proxy failed");
		return -1;
	}
	return 0;
}

/* ---- public API -------------------------------------------------------- */

int proxy_front_open(const struct proxy_bridge_cfg *cfg,
		     const char *authority, int port,
		     struct proxy_front **out)
{
	*out = NULL;
	struct proxy_front *pf = calloc(1, sizeof(*pf));
	if (!pf) {
		pb_set_err("out of memory");
		return -1;
	}
	pf->fd = -1;

	pf->fd = pb_dial(cfg->proxy_host, cfg->proxy_port);
	if (pf->fd < 0)
		goto fail;
	if (pb_do_connect(pf->fd, authority, port) != 0)
		goto fail;
	if (pb_tls_handshake(pf, cfg, authority) != 0)
		goto fail;

	*out = pf;
	return 0;

fail:
	proxy_front_close(pf);
	return -1;
}

long proxy_front_write(struct proxy_front *pf, const void *buf, size_t len)
{
	for (;;) {
		/* without partial writes SSL_write sends it all or nothing, and a
		 * retry must pass the same buffer */
		int n = SSL_write(pf->ssl, buf, (int)len);
		if (n > 0)
			return n;
		int e = SSL_get_error(pf->ssl, n);
		if (pf->nonblocking && (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ)) {
			struct pollfd p = { pf->fd, e == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN, 0 };
			if (poll(&p, 1, 10000) > 0)
				continue;
		}
		pb_set_err("SSL_write: %d", e);
		return -1;
	}
}

long proxy_front_read(struct proxy_front *pf, void *buf, size_t cap)
{
	int n = SSL_read(pf->ssl, buf, (int)cap);
	if (n > 0)
		return n;
	int e = SSL_get_error(pf->ssl, n);
	if (e == SSL_ERROR_ZERO_RETURN)
		return 0;   /* clean TLS close */
	if (pf->nonblocking && (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE))
		return PROXY_FRONT_AGAIN;
	pb_set_err("SSL_read: %d", e);
	return -1;
}

int proxy_front_set_nonblocking(struct proxy_front *pf)
{
	int fl = fcntl(pf->fd, F_GETFL);
	if (fl < 0 || fcntl(pf->fd, F_SETFL, fl | O_NONBLOCK) < 0)
		return -1;
	pf->nonblocking = 1;
	return 0;
}

void proxy_front_close(struct proxy_front *pf)
{
	if (!pf)
		return;
	if (pf->ssl) {
		SSL_shutdown(pf->ssl);
		SSL_free(pf->ssl);
	}
	if (pf->ctx)
		SSL_CTX_free(pf->ctx);
	if (pf->fd >= 0)
		close(pf->fd);
	free(pf);
}

int proxy_front_fd(const struct proxy_front *pf) { return pf->fd; }

int proxy_front_pending(const struct proxy_front *pf) { return SSL_pending(pf->ssl); }

/* A throwaway self-signed certificate for the UPSTREAM listener */
static int pb_self_signed(SSL_CTX *ctx)
{
	int ok = 0;
	/* P-256 key, with the API common to OpenSSL 1.1.1 and 3.0 */
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	X509 *x = X509_new();
	if (pctx && EVP_PKEY_keygen_init(pctx) == 1 &&
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) == 1)
		EVP_PKEY_keygen(pctx, &pkey);
	EVP_PKEY_CTX_free(pctx);
	if (!pkey || !x)
		goto out;

	X509_set_version(x, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x), (long)time(NULL));
	X509_gmtime_adj(X509_getm_notBefore(x), -3600);
	X509_gmtime_adj(X509_getm_notAfter(x), 365L * 24 * 3600);
	X509_set_pubkey(x, pkey);
	X509_NAME *name = X509_get_subject_name(x);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				   (const unsigned char *)"ePtracer upstream", -1, -1, 0);
	X509_set_issuer_name(x, name);
	if (X509_sign(x, pkey, EVP_sha256()) <= 0)
		goto out;
	ok = SSL_CTX_use_certificate(ctx, x) == 1 && SSL_CTX_use_PrivateKey(ctx, pkey) == 1;
out:
	X509_free(x);
	EVP_PKEY_free(pkey);
	return ok;
}

struct ssl_ctx_st *proxy_upstream_ctx(const char *cert_file, const char *key_file)
{
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx) {
		pb_set_err("SSL_CTX_new failed");
		return NULL;
	}
	int ok;
	if (cert_file && *cert_file && key_file && *key_file)
		ok = SSL_CTX_use_certificate_chain_file(ctx, cert_file) == 1 &&
		     SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) == 1;
	else
		ok = pb_self_signed(ctx);
	if (!ok) {
		pb_set_err("cannot set up the upstream certificate");
		SSL_CTX_free(ctx);
		return NULL;
	}
	/* no ALPN callback: a proxy offering h2 falls back to HTTP/1.1, which is
	 * what the bridge frames */
	return ctx;
}
