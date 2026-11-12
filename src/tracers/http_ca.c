/*
 * Automatic trust of the intercepting proxy's CA.
 *
 * The rationale is in include/http_ca.h. This file does the work: it obtains the
 * proxy CA (from a file, or fetched from the proxy over the proxy's own cert
 * endpoint), normalizes it to PEM, merges it with the system trust store into a
 * temporary bundle, and exports the environment variables the TLS stacks read,
 * so that the spawned process trusts the proxy with no manual step.
 */

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/*
 * This file is #included into the eptracer.c translation unit, which has already
 * pulled in include/http_ca.h, include/http_intercept.h and include/log.h, the
 * same way the other tracers rely on their parent TU. It is never compiled on
 * its own.
 */

/* How long the CA fetch waits on the proxy before giving up */
#define HTTP_CA_IO_TIMEOUT_S   5
/* Upper bound on the fetched cert response, a CA certificate is a few KB */
#define HTTP_CA_MAX_RESPONSE   (256 * 1024)

/* Where the well known proxies serve their CA. The request goes to the proxy as
 * an ordinary (cleartext) proxied GET, which is how a browser downloads it. */
struct ca_endpoint {
	const char *host;   /* value of the Host header and of the absolute URL */
	const char *path;   /* path of the cert on that pseudo host */
	const char *proxy;  /* which proxy this is, for logging */
};

static const struct ca_endpoint ca_endpoints[] = {
	{ "burp",    "/cert",     "Burp Suite" },
	{ "mitm.it", "/cert/pem", "mitmproxy"  },
};

/* System trust stores, distribution dependent; the first that exists is used */
static const char *const ca_system_bundles[] = {
	"/etc/ssl/certs/ca-certificates.crt",       /* Debian, Ubuntu, Alpine */
	"/etc/pki/tls/certs/ca-bundle.crt",         /* Fedora, RHEL, CentOS */
	"/etc/ssl/ca-bundle.pem",                   /* openSUSE */
	"/etc/ssl/cert.pem",                        /* generic, macOS-like */
	NULL,
};

/* Temporary files exported to the child, unlinked on cleanup */
static char ca_bundle_path[256] = {0};
static char ca_proxy_only_path[256] = {0};

/*
 * ca_parse_endpoint
 *
 * Description:
 * Reads the proxy host and port out of the --intercept value, so that the CA
 * can be fetched from the same proxy the connections are tunnelled to.
 *
 * Params:
 * const char *spec: the --intercept value.
 * char *host: buffer receiving the host.
 * size_t host_size: its size.
 * int *port: receives the port.
 * int *is_direct: set when interception has no proxy behind it.
 *
 * Return:
 * 0 on success, -1 when the endpoint cannot be understood.
 * */
static int ca_parse_endpoint(const char *spec, char *host, size_t host_size,
			     int *port, int *is_direct)
{
	const char *colon = NULL;
	char *end = NULL;
	long value = 0;
	size_t host_len = 0;

	*is_direct = 0;
	snprintf(host, host_size, "%s", INTERCEPT_DEFAULT_UPSTREAM_HOST);
	*port = INTERCEPT_DEFAULT_UPSTREAM_PORT;

	if (!spec || !spec[0])
		return 0;

	if (strcasecmp(spec, INTERCEPT_UPSTREAM_DIRECT) == 0) {
		*is_direct = 1;
		return 0;
	}

	/* A bare number keeps the loopback default and sets the port */
	value = strtol(spec, &end, 10);
	if (end && *end == '\0' && value > 0 && value < 65536) {
		*port = (int)value;
		return 0;
	}

	colon = strrchr(spec, ':');
	if (!colon) {
		snprintf(host, host_size, "%s", spec);
		return 0;
	}

	host_len = (size_t)(colon - spec);
	if (host_len == 0 || host_len >= host_size)
		return -1;

	value = strtol(colon + 1, &end, 10);
	if (!end || *end != '\0' || value <= 0 || value >= 65536)
		return -1;

	memcpy(host, spec, host_len);
	host[host_len] = '\0';
	*port = (int)value;
	return 0;
}

/*
 * ca_dial
 *
 * Description:
 * Opens a TCP connection to the proxy, with a receive and send timeout so the
 * fetch cannot hang ePtracer's startup.
 *
 * Params:
 * const char *host: proxy host.
 * int port: proxy port.
 *
 * Return:
 * A connected socket, -1 on failure.
 * */
static int ca_dial(const char *host, int port)
{
	struct addrinfo hints = {0}, *res = NULL, *it = NULL;
	struct timeval timeout = { HTTP_CA_IO_TIMEOUT_S, 0 };
	char service[16];
	int fd = -1;

	snprintf(service, sizeof(service), "%d", port);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(host, service, &hints, &res) != 0)
		return -1;

	for (it = res; it; it = it->ai_next) {
		fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
		if (fd < 0)
			continue;
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
		if (connect(fd, it->ai_addr, it->ai_addrlen) == 0)
			break;
		close(fd);
		fd = -1;
	}

	freeaddrinfo(res);
	return fd;
}

/*
 * ca_http_get_body
 *
 * Description:
 * Sends a proxied GET for a proxy's own cert endpoint and returns the response
 * body. The proxy serves this without contacting any real server, which is what
 * lets the CA be fetched with a plain cleartext request.
 *
 * Params:
 * const char *proxy_host: proxy to connect to.
 * int proxy_port: its port.
 * const struct ca_endpoint *ep: which pseudo host and path to ask for.
 * size_t *out_len: receives the body length.
 *
 * Return:
 * A newly allocated body, to be freed by the caller, or NULL on failure.
 * */
static unsigned char *ca_http_get_body(const char *proxy_host, int proxy_port,
				       const struct ca_endpoint *ep, size_t *out_len)
{
	char request[512];
	unsigned char *buf = NULL, *body = NULL;
	size_t cap = 8192, len = 0, body_len = 0;
	ssize_t header_end = 0;
	int fd = -1, status = 0;
	ssize_t got = 0;

	fd = ca_dial(proxy_host, proxy_port);
	if (fd < 0)
		return NULL;

	snprintf(request, sizeof(request),
		 "GET http://%s%s HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\n"
		 "Connection: close\r\n\r\n", ep->host, ep->path, ep->host);

	if (write(fd, request, strlen(request)) < 0) {
		close(fd);
		return NULL;
	}

	buf = malloc(cap);
	if (!buf) {
		close(fd);
		return NULL;
	}

	while ((got = read(fd, buf + len, cap - len)) > 0) {
		len += (size_t)got;
		if (len > HTTP_CA_MAX_RESPONSE)
			break;
		if (len == cap) {
			unsigned char *bigger = realloc(buf, cap * 2);

			if (!bigger) {
				free(buf);
				close(fd);
				return NULL;
			}
			buf = bigger;
			cap *= 2;
		}
	}
	close(fd);

	/* Split the status line and headers from the body */
	header_end = memfind((const char *)buf, len, "\r\n\r\n", 4);
	if (header_end < 0 || len < 12 || memcmp(buf, "HTTP/1.", 7) != 0) {
		free(buf);
		return NULL;
	}

	status = atoi((const char *)buf + 9);
	if (status != 200) {
		free(buf);
		return NULL;
	}

	body = buf + (size_t)header_end + 4;
	body_len = len - (size_t)(body - buf);
	if (body_len == 0) {
		free(buf);
		return NULL;
	}

	/* Hand back just the body, in its own allocation */
	{
		unsigned char *copy = malloc(body_len);

		if (!copy) {
			free(buf);
			return NULL;
		}
		memcpy(copy, body, body_len);
		free(buf);
		*out_len = body_len;
		return copy;
	}
}

/*
 * ca_to_pem
 *
 * Description:
 * Turns a certificate — PEM or DER, however the proxy or the operator gave it —
 * into a PEM string, and validates it as an X.509 certificate along the way, so
 * that a proxy error page or a truncated download is rejected rather than
 * written into the trust bundle.
 *
 * Params:
 * const unsigned char *data: certificate bytes.
 * size_t len: their length.
 * size_t *pem_len: receives the PEM length.
 *
 * Return:
 * A newly allocated PEM string, to be freed by the caller, or NULL on failure.
 * */
static char *ca_to_pem(const unsigned char *data, size_t len, size_t *pem_len)
{
	X509 *cert = NULL;
	BIO *in = NULL, *out = NULL;
	char *pem = NULL, *result = NULL;
	long pem_bytes = 0;

	/* PEM already, when it starts with the armour */
	if (len > 27 && memfind((const char *)data, len < 64 ? len : 64,
				"-----BEGIN CERTIFICATE-----", 27) >= 0) {
		in = BIO_new_mem_buf(data, (int)len);
		if (in)
			cert = PEM_read_bio_X509(in, NULL, NULL, NULL);
	} else {
		/* DER: what Burp's /cert serves */
		const unsigned char *p = data;

		cert = d2i_X509(NULL, &p, (long)len);
	}

	BIO_free(in);
	if (!cert)
		return NULL;

	out = BIO_new(BIO_s_mem());
	if (!out || PEM_write_bio_X509(out, cert) != 1) {
		X509_free(cert);
		BIO_free(out);
		return NULL;
	}

	pem_bytes = BIO_get_mem_data(out, &pem);
	if (pem_bytes > 0) {
		result = malloc((size_t)pem_bytes + 1);
		if (result) {
			memcpy(result, pem, (size_t)pem_bytes);
			result[pem_bytes] = '\0';
			*pem_len = (size_t)pem_bytes;
		}
	}

	X509_free(cert);
	BIO_free(out);
	return result;
}

/*
 * ca_read_file
 *
 * Description:
 * Reads a certificate file the operator supplied.
 *
 * Params:
 * const char *path: file to read.
 * size_t *len: receives the length.
 *
 * Return:
 * A newly allocated buffer, or NULL on failure.
 * */
static unsigned char *ca_read_file(const char *path, size_t *len)
{
	FILE *fp = fopen(path, "rb");
	unsigned char *buf = NULL;
	long size = 0;

	if (!fp)
		return NULL;

	if (fseek(fp, 0, SEEK_END) != 0 || (size = ftell(fp)) <= 0 ||
	    size > HTTP_CA_MAX_RESPONSE || fseek(fp, 0, SEEK_SET) != 0) {
		fclose(fp);
		return NULL;
	}

	buf = malloc((size_t)size);
	if (!buf) {
		fclose(fp);
		return NULL;
	}

	if (fread(buf, 1, (size_t)size, fp) != (size_t)size) {
		free(buf);
		fclose(fp);
		return NULL;
	}

	fclose(fp);
	*len = (size_t)size;
	return buf;
}

/*
 * ca_obtain_pem
 *
 * Description:
 * Gets the proxy CA as PEM: from the file the operator pointed at when given,
 * otherwise fetched from the proxy over the well known cert endpoints.
 *
 * Params:
 * const char *proxy_host: proxy host.
 * int proxy_port: proxy port.
 * const char *ca_path: operator supplied certificate, may be NULL/empty.
 * size_t *pem_len: receives the PEM length.
 *
 * Return:
 * A newly allocated PEM string, or NULL when no CA could be obtained.
 * */
static char *ca_obtain_pem(const char *proxy_host, int proxy_port,
			   const char *ca_path, size_t *pem_len)
{
	char *pem = NULL;
	size_t i = 0;

	if (ca_path && ca_path[0]) {
		size_t raw_len = 0;
		unsigned char *raw = ca_read_file(ca_path, &raw_len);

		if (!raw) {
			log_error("[!] Cannot read the proxy CA at %s: %s", ca_path,
				  strerror(errno));
			return NULL;
		}
		pem = ca_to_pem(raw, raw_len, pem_len);
		free(raw);
		if (!pem)
			log_error("[!] %s is not a valid certificate (PEM or DER)", ca_path);
		return pem;
	}

	for (i = 0; i < sizeof(ca_endpoints) / sizeof(ca_endpoints[0]); i++) {
		size_t raw_len = 0;
		unsigned char *raw = ca_http_get_body(proxy_host, proxy_port,
						      &ca_endpoints[i], &raw_len);

		if (!raw)
			continue;
		pem = ca_to_pem(raw, raw_len, pem_len);
		free(raw);
		if (pem) {
			log_info("[+] Fetched the %s CA from the proxy at %s:%d",
				 ca_endpoints[i].proxy, proxy_host, proxy_port);
			return pem;
		}
	}

	log_error("[!] Could not fetch the proxy CA from %s:%d. Pass it with "
		  "--proxy-ca <file> if the proxy is not Burp or mitmproxy",
		  proxy_host, proxy_port);
	return NULL;
}

/*
 * ca_write_temp
 *
 * Description:
 * Writes a buffer to a fresh temporary file, world readable — a CA certificate
 * is public, and the spawned process has to be able to read it even if it drops
 * privileges after start.
 *
 * Params:
 * const char *content: bytes to write.
 * size_t len: their length.
 * char *path_out: buffer receiving the created path.
 * size_t path_size: its size.
 *
 * Return:
 * 0 on success, -1 otherwise.
 * */
static int ca_write_temp(const char *content, size_t len, char *path_out, size_t path_size)
{
	/* /tmp does not exist on Android: /data/local/tmp is its equivalent */
	const char *dir = getenv("TMPDIR");
	char template[PATH_MAX];
	int fd = -1;

	if (!dir || dir[0] != '/' || access(dir, W_OK) != 0)
		dir = access("/tmp", W_OK) == 0 ? "/tmp" : "/data/local/tmp";
	snprintf(template, sizeof(template), "%s/eptracer-ca-XXXXXX", dir);
	fd = mkstemp(template);
	ssize_t written = 0;

	if (fd < 0) {
		log_error("[!] Cannot create a temporary CA file: %s", strerror(errno));
		return -1;
	}

	written = write(fd, content, len);
	close(fd);

	if (written < 0 || (size_t)written != len) {
		unlink(template);
		return -1;
	}

	if (chmod(template, 0644) < 0)
		log_debug("[?] Could not relax the permissions of %s", template);

	snprintf(path_out, path_size, "%s", template);
	return 0;
}

/*
 * ca_build_bundle
 *
 * Description:
 * Builds the trust bundle exported to the child: the system trust store with
 * the proxy CA appended, so that the process trusts the proxy on top of — not
 * instead of — the real world, and connections that are not intercepted keep
 * validating normally.
 *
 * Params:
 * const char *proxy_pem: the proxy CA in PEM form.
 * size_t proxy_len: its length.
 *
 * Return:
 * 0 on success, -1 otherwise.
 * */
static int ca_build_bundle(const char *proxy_pem, size_t proxy_len)
{
	const char *system_bundle = NULL;
	unsigned char *system_pem = NULL;
	size_t system_len = 0, total = 0;
	char *combined = NULL;
	int i = 0, ret = -1;

	for (i = 0; ca_system_bundles[i]; i++) {
		if (access(ca_system_bundles[i], R_OK) == 0) {
			system_bundle = ca_system_bundles[i];
			break;
		}
	}

	if (system_bundle)
		system_pem = ca_read_file(system_bundle, &system_len);
	else
		log_error("[!] No system trust store found: the spawned process will "
			  "trust the proxy CA only, non-intercepted TLS may fail");

	total = system_len + proxy_len + 1;
	combined = malloc(total);
	if (!combined) {
		free(system_pem);
		return -1;
	}

	if (system_pem)
		memcpy(combined, system_pem, system_len);
	memcpy(combined + system_len, proxy_pem, proxy_len);
	combined[system_len + proxy_len] = '\0';

	if (ca_write_temp(combined, system_len + proxy_len, ca_bundle_path,
			  sizeof(ca_bundle_path)) == 0 &&
	    ca_write_temp(proxy_pem, proxy_len, ca_proxy_only_path,
			  sizeof(ca_proxy_only_path)) == 0)
		ret = 0;

	free(combined);
	free(system_pem);
	return ret;
}

/*
 * ca_export_env
 *
 * Description:
 * Exports the environment variables the common TLS stacks read for their trust
 * store. Set before the fork, they are inherited by the spawned process.
 * */
static void ca_export_env(void)
{
	/* OpenSSL/BoringSSL, Go crypto/tls and Python ssl honour SSL_CERT_FILE;
	 * the *_CA_BUNDLE and *_CAINFO names cover the tools that read their own */
	setenv("SSL_CERT_FILE", ca_bundle_path, 1);
	setenv("CURL_CA_BUNDLE", ca_bundle_path, 1);
	setenv("REQUESTS_CA_BUNDLE", ca_bundle_path, 1);
	setenv("GIT_SSL_CAINFO", ca_bundle_path, 1);
	setenv("AWS_CA_BUNDLE", ca_bundle_path, 1);
	/* Node adds NODE_EXTRA_CA_CERTS to its built-in store, so it gets the
	 * proxy CA on its own rather than a replacement bundle */
	setenv("NODE_EXTRA_CA_CERTS", ca_proxy_only_path, 1);
}

int http_ca_autotrust(const char *intercept_endpoint, const char *ca_path)
{
	char proxy_host[256] = {0};
	char *proxy_pem = NULL;
	size_t proxy_len = 0;
	int proxy_port = 0, is_direct = 0;

	if (ca_parse_endpoint(intercept_endpoint, proxy_host, sizeof(proxy_host),
			      &proxy_port, &is_direct) < 0) {
		log_error("[!] Cannot parse the interception endpoint '%s' for CA trust",
			  intercept_endpoint);
		return -1;
	}

	/* Direct interception has no proxy, so no CA to trust */
	if (is_direct)
		return 0;

	proxy_pem = ca_obtain_pem(proxy_host, proxy_port, ca_path, &proxy_len);
	if (!proxy_pem)
		return -1;

	if (ca_build_bundle(proxy_pem, proxy_len) < 0) {
		free(proxy_pem);
		http_ca_cleanup();
		return -1;
	}
	free(proxy_pem);

	ca_export_env();
	log_info("[+] Proxy CA trusted automatically for the spawned process "
		 "(no manual certificate install needed)");
	return 0;
}

const char *http_ca_proxy_ca_file(const char *intercept_endpoint, const char *ca_path)
{
	char proxy_host[256] = {0};
	char *proxy_pem = NULL;
	size_t proxy_len = 0;
	int proxy_port = 0, is_direct = 0;

	/* http_ca_autotrust() already wrote this for a spawned process */
	if (ca_proxy_only_path[0])
		return ca_proxy_only_path;

	if (ca_parse_endpoint(intercept_endpoint, proxy_host, sizeof(proxy_host),
			      &proxy_port, &is_direct) < 0 || is_direct)
		return NULL;

	proxy_pem = ca_obtain_pem(proxy_host, proxy_port, ca_path, &proxy_len);
	if (!proxy_pem)
		return NULL;

	if (ca_write_temp(proxy_pem, proxy_len, ca_proxy_only_path,
			  sizeof(ca_proxy_only_path)) < 0) {
		free(proxy_pem);
		return NULL;
	}
	free(proxy_pem);
	return ca_proxy_only_path;
}

void http_ca_cleanup(void)
{
	if (ca_bundle_path[0]) {
		unlink(ca_bundle_path);
		ca_bundle_path[0] = '\0';
	}
	if (ca_proxy_only_path[0]) {
		unlink(ca_proxy_only_path);
		ca_proxy_only_path[0] = '\0';
	}
}
