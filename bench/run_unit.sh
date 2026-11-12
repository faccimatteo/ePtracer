#!/bin/sh
# Build and run the standalone unit tests of the splice userspace modules.
# Usage: bench/run_unit.sh
set -e
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
out="$(mktemp -d "${TMPDIR:-/tmp}/eptracer_unit.XXXXXX")"
trap 'rm -rf "$out"' EXIT

cc="gcc -O2 -Wall -Wextra -I$root/src/include"
t="$root/src/tracers"

$cc "$here/test_tls_keys.c" "$t/tls_keys.c" "$t/tls_record.c" \
	-lcrypto -lpthread -o "$out/test_tls_keys"
echo "== tls_keys =="
"$out/test_tls_keys"

$cc "$here/test_tls_anchor.c" "$t/tls_anchor.c" -lelf -o "$out/test_tls_anchor"
echo "== tls_anchor =="
"$out/test_tls_anchor"

$cc "$here/test_http1_frame.c" "$t/http1_frame.c" -o "$out/test_http1_frame"
echo "== http1_frame =="
"$out/test_http1_frame"
