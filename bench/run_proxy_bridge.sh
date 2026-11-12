#!/usr/bin/env bash
# First integration test of the proxy bridge against a Burp-style HTTP proxy.
#
# It generates a throwaway CA and a leaf certificate for the test authority
# (exactly how Burp mints a per-host cert from its own CA), starts
# bench/burp_style_proxy.py with a Match&Replace rule, then runs the C FRONT
# test (bench/test_proxy_bridge.c) through it.
#
# Everything is on loopback and torn down on exit. No root, no eBPF needed:
# this validates the userspace proxy leg in isolation.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/eptracer_proxytest.XXXXXX")"
authority="api.example.com"
proxy_pid=""

cleanup() {
	[ -n "$proxy_pid" ] && kill "$proxy_pid" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT

echo "[*] generating test CA + leaf for $authority"
openssl genrsa -out "$work/ca.key" 2048 >/dev/null 2>&1
openssl req -x509 -new -nodes -key "$work/ca.key" -sha256 -days 1 \
	-subj "/CN=ePtracer Test CA" -out "$work/ca.crt" >/dev/null 2>&1

openssl genrsa -out "$work/leaf.key" 2048 >/dev/null 2>&1
openssl req -new -key "$work/leaf.key" -subj "/CN=$authority" -out "$work/leaf.csr" >/dev/null 2>&1
cat > "$work/leaf.ext" <<EOF
subjectAltName = DNS:$authority
EOF
openssl x509 -req -in "$work/leaf.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" \
	-CAcreateserial -days 1 -sha256 -extfile "$work/leaf.ext" \
	-out "$work/leaf.crt" >/dev/null 2>&1

echo "[*] starting Burp-style mock proxy (match&replace: hunter2 -> REDACTED)"
python3 "$here/burp_style_proxy.py" \
	--port 0 --cert "$work/leaf.crt" --key "$work/leaf.key" \
	--replace hunter2 --replace-to REDACTED > "$work/proxy.out" 2>"$work/proxy.err" &
proxy_pid=$!

# wait for the proxy to print its ephemeral port
port=""
for _ in $(seq 1 50); do
	if grep -q '^PORT ' "$work/proxy.out" 2>/dev/null; then
		port="$(awk '/^PORT /{print $2; exit}' "$work/proxy.out")"
		break
	fi
	sleep 0.1
done
if [ -z "$port" ]; then
	echo "[!] proxy did not start"; cat "$work/proxy.err" >&2; exit 1
fi
echo "[*] proxy on 127.0.0.1:$port"

echo "[*] building FRONT test"
gcc -O2 -Wall -Wextra \
	-I"$root/src/include" \
	"$here/test_proxy_bridge.c" "$root/src/tracers/proxy_bridge.c" \
	-lssl -lcrypto -o "$work/test_proxy_bridge"

echo "[*] running FRONT test against the Burp-style proxy"
# map the authority to loopback so SNI/CONNECT use the name but the socket lands
# on the local mock (the real splice uses the kernel redirect for this)
timeout 20 "$work/test_proxy_bridge" "$port" "$work/ca.crt" "$authority"
