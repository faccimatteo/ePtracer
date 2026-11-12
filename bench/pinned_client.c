/*
 * pinned_client — an HTTPS client with OpenSSL linked in statically and the
 * server's public key pinned, for the live splice test (bench/run_live_splice.sh).
 *
 * Statically linked on purpose: its TLS is in no shared library ePtracer probes
 * at start, so the key probe can only reach it through trace_exec, when a
 * followed launcher script executes it — the Discord case.
 *
 *   pinned_client HOST PORT SNI CA_FILE PIN_SHA256_B64 OUT_PREFIX PATH...
 *
 * Each PATH is requested on one keep-alive connection; the answer is written to
 * OUT_PREFIX<n>. Exit 0 if the pin matched and every answer was received.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

/* base64(sha256(SubjectPublicKeyInfo)), as curl --pinnedpubkey */
static int pin_matches(SSL *ssl, const char *want)
{
	X509 *cert = SSL_get1_peer_certificate(ssl);
	unsigned char *der = NULL, md[32], b64[64];
	int len, ok = 0;

	if (!cert)
		return 0;
	len = i2d_PUBKEY(X509_get0_pubkey(cert), &der);
	if (len > 0 && EVP_Digest(der, (size_t)len, md, NULL, EVP_sha256(), NULL)) {
		EVP_EncodeBlock(b64, md, 32);
		ok = strcmp((char *)b64, want) == 0;
	}
	OPENSSL_free(der);
	X509_free(cert);
	return ok;
}

/* Read one HTTP/1.1 answer with a Content-Length into out (NUL terminated). */
static long read_answer(SSL *ssl, char *out, size_t cap)
{
	size_t used = 0;
	long want = -1;

	while (used < cap - 1) {
		int n = SSL_read(ssl, out + used, (int)(cap - 1 - used));
		if (n <= 0)
			break;
		used += (size_t)n;
		out[used] = '\0';
		char *end = strstr(out, "\r\n\r\n");
		if (end && want < 0) {
			char *cl = strcasestr(out, "content-length:");
			want = (long)(end + 4 - out) + (cl && cl < end ? atol(cl + 15) : 0);
		}
		if (want >= 0 && (long)used >= want)
			return (long)used;
	}
	return -1;
}

int main(int argc, char **argv)
{
	if (argc < 8) {
		fprintf(stderr, "usage: %s HOST PORT SNI CA PIN OUT_PREFIX PATH...\n", argv[0]);
		return 2;
	}
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons((uint16_t)atoi(argv[2])) };
	inet_pton(AF_INET, argv[1], &sa.sin_addr);
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		perror("connect");
		return 1;
	}

	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_load_verify_locations(ctx, argv[4], NULL);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, fd);
	SSL_set_tlsext_host_name(ssl, argv[3]);
	SSL_set1_host(ssl, argv[3]);
	if (SSL_connect(ssl) != 1) {
		fprintf(stderr, "handshake refused: %s\n",
			X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
		return 3;
	}
	if (!pin_matches(ssl, argv[5])) {
		fprintf(stderr, "pinned key mismatch\n");
		return 4;
	}

	static char buf[1 << 16];
	for (int i = 7; i < argc; i++) {
		int n = snprintf(buf, sizeof(buf), "GET %s HTTP/1.1\r\nHost: %s\r\n"
				 "User-Agent: pinned-client\r\n\r\n", argv[i], argv[3]);
		if (SSL_write(ssl, buf, n) != n || read_answer(ssl, buf, sizeof(buf)) < 0) {
			fprintf(stderr, "no answer for %s\n", argv[i]);
			return 5;
		}
		char name[512];
		snprintf(name, sizeof(name), "%s%d", argv[6], i - 6);
		FILE *f = fopen(name, "w");
		if (f) {
			fputs(buf, f);
			fclose(f);
		}
	}
	SSL_shutdown(ssl);
	return 0;
}
