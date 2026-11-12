#!/usr/bin/env bash
# End-to-end test of the proxy sandwich and its at-most-once guarantee.
# Usage: bench/run_e2e_sandwich.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/eptracer_sandwich.XXXXXX")"
trap 'rm -rf "$work"' EXIT
authority="api.example.com"

mkcert() {   # $1 prefix, $2 CA name
	openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/$1-ca.key" -out "$work/$1-ca.crt" \
		-days 1 -subj "/CN=$2" >/dev/null 2>&1
	openssl req -newkey rsa:2048 -nodes -keyout "$work/$1.key" -out "$work/$1.csr" \
		-subj "/CN=$authority" >/dev/null 2>&1
	# cloudflare-ech.com too: the outer SNI of an Encrypted Client Hello
	printf 'subjectAltName = DNS:%s,DNS:cloudflare-ech.com\n' "$authority" > "$work/$1.ext"
	openssl x509 -req -in "$work/$1.csr" -CA "$work/$1-ca.crt" -CAkey "$work/$1-ca.key" \
		-CAcreateserial -days 1 -sha256 -extfile "$work/$1.ext" -out "$work/$1.crt" >/dev/null 2>&1
}
mkcert origin "E2E Origin CA"     # the real server; only the client trusts it
mkcert proxy  "E2E Burp-style CA" # the proxy's MITM leaf; only ePtracer talks to it

t="$root/src/tracers"
gcc -O2 -Wall -Wextra -I"$root/src/include" \
	"$here/sandwich_relay.c" "$t/splice_bridge.c" "$t/http1_frame.c" "$t/proxy_bridge.c" \
	"$t/tls_splice.c" "$t/tls_keys.c" "$t/tls_record.c" \
	-lssl -lcrypto -lnghttp2 -lpthread -o "$work/sandwich_relay"

timeout 300 python3 "$here/e2e_sandwich.py" --relay "$work/sandwich_relay" \
	--ca "$work/origin-ca.crt" --cert "$work/origin.crt" --key "$work/origin.key" \
	--proxy-cert "$work/proxy.crt" --proxy-key "$work/proxy.key"

# HTTP/2 through the same sandwich, with node's h2 client and server
if command -v node >/dev/null; then
	echo
	echo "== HTTP/2 =="
	timeout 300 node "$here/e2e_h2.mjs" --relay "$work/sandwich_relay" \
		--ca "$work/origin-ca.crt" --cert "$work/origin.crt" --key "$work/origin.key" \
		--proxy-cert "$work/proxy.crt" --proxy-key "$work/proxy.key"
else
	echo "[!] node not found: HTTP/2 scenarios skipped"
fi
