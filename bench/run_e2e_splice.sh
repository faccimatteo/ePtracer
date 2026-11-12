#!/usr/bin/env bash
# End-to-end TLS splice test: real TLS 1.3 client and server, the splice relay in
# between, keys from the client's SSLKEYLOGFILE (stand-in for eBPF capture).
# Usage: bench/run_e2e_splice.sh [--bench N]
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/eptracer_e2e.XXXXXX")"
trap 'rm -rf "$work"' EXIT
authority="api.example.com"

# the *server's* certificate, from a CA only the client trusts: the relay never
# sees a private key, which is the whole point
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/ca.key" -out "$work/ca.crt" \
	-days 1 -subj "/CN=ePtracer E2E Origin CA" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$work/srv.key" -out "$work/srv.csr" \
	-subj "/CN=$authority" >/dev/null 2>&1
printf 'subjectAltName = DNS:%s\n' "$authority" > "$work/srv.ext"
openssl x509 -req -in "$work/srv.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" \
	-CAcreateserial -days 1 -sha256 -extfile "$work/srv.ext" -out "$work/srv.crt" >/dev/null 2>&1

t="$root/src/tracers"
gcc -O2 -Wall -Wextra -I"$root/src/include" \
	"$here/splice_relay.c" "$t/tls_splice.c" "$t/tls_keys.c" "$t/tls_record.c" \
	-lcrypto -lpthread -o "$work/splice_relay"

timeout 300 python3 "$here/e2e_splice.py" --relay "$work/splice_relay" \
	--ca "$work/ca.crt" --cert "$work/srv.crt" --key "$work/srv.key" "$@"
