/*
 * Standalone FRONT-side test for src/tracers/proxy_bridge.c against a Burp-style
 * proxy (bench/burp_style_proxy.py). Driven by bench/run_proxy_bridge.sh, which
 * generates the test CA, starts the mock proxy and passes its port + CA here.
 *
 * It proves the ePtracer -> Burp-style-proxy leg end to end:
 *   - CONNECT tunnel is opened,
 *   - TLS to the proxy completes and the proxy's CA verifies (pinning-style
 *     hostname match against the authority),
 *   - a decrypted request flows to the proxy and the (match/replaced) bytes come
 *     back, i.e. the proxy really sees and can modify the plaintext.
 *
 * Usage: test_proxy_bridge <proxy_port> <ca_file> <authority>
 */

#include "proxy_bridge.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>

int main(int argc, char **argv)
{
	if (argc != 4) {
		fprintf(stderr, "usage: %s <proxy_port> <ca_file> <authority>\n", argv[0]);
		return 2;
	}
	int port = atoi(argv[1]);
	const char *ca = argv[2];
	const char *authority = argv[3];

	SSL_library_init();

	struct proxy_bridge_cfg cfg;
	memset(&cfg, 0, sizeof(cfg));
	snprintf(cfg.proxy_host, sizeof(cfg.proxy_host), "127.0.0.1");
	cfg.proxy_port = port;
	snprintf(cfg.ca_file, sizeof(cfg.ca_file), "%s", ca);

	int fail = 0;

	/* 1. open the CONNECT + TLS tunnel, verifying the proxy CA */
	struct proxy_front *pf = NULL;
	if (proxy_front_open(&cfg, authority, 443, &pf) != 0) {
		printf("  FAIL open tunnel: %s\n", proxy_bridge_last_error());
		return 1;
	}
	printf("  ok   CONNECT + TLS to Burp-style proxy (CA verified, host %s)\n",
	       authority);

	/* 2. send a decrypted request carrying a token the proxy will replace */
	const char *body = "{\"user\":\"admin\",\"password\":\"hunter2\"}";
	char req[512];
	int req_len = snprintf(req, sizeof(req),
			       "POST /v1/login HTTP/1.1\r\n"
			       "Host: %s\r\n"
			       "Content-Type: application/json\r\n"
			       "Content-Length: %zu\r\n"
			       "\r\n"
			       "%s", authority, strlen(body), body);
	if (proxy_front_write(pf, req, (size_t)req_len) < 0) {
		printf("  FAIL write request: %s\n", proxy_bridge_last_error());
		proxy_front_close(pf);
		return 1;
	}
	printf("  ok   decrypted request written through the proxy\n");

	/* 3. read the response and confirm the proxy saw + modified the plaintext */
	char buf[8192];
	size_t total = 0;
	long n;
	while (total < sizeof(buf) - 1 &&
	       (n = proxy_front_read(pf, buf + total, sizeof(buf) - 1 - total)) > 0)
		total += (size_t)n;
	buf[total] = '\0';
	proxy_front_close(pf);

	if (total == 0) {
		printf("  FAIL no response from proxy\n");
		return 1;
	}

	if (strstr(buf, "X-Burp-Mock-Authority:") &&
	    strstr(buf, authority))
		printf("  ok   proxy minted its cert for the right authority (%s)\n", authority);
	else
		{ printf("  FAIL authority not echoed by proxy\n"); fail++; }

	/* the proxy was told to replace hunter2 -> REDACTED; the echoed request
	 * body must reflect the edit, proving it can modify spliced traffic */
	if (strstr(buf, "X-Burp-Mock-Replaced: 1") && strstr(buf, "REDACTED") &&
	    !strstr(buf, "hunter2"))
		printf("  ok   proxy modified the plaintext (hunter2 -> REDACTED)\n");
	else
		{ printf("  FAIL match&replace not observed in round-trip\n"); fail++; }

	printf("\n%s\n", fail ? "FAILED" : "PASSED");
	return fail ? 1 : 0;
}
