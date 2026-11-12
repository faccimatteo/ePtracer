#!/bin/sh
# Build and run the standalone record-layer test + microbench.
# Usage: bench/run_tls_record.sh [--bench]
set -e
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
out="${TMPDIR:-/tmp}/eptracer_test_tls_record"

gcc -O2 -Wall -Wextra \
    -I"$root/src/include" \
    "$here/test_tls_record.c" "$root/src/tracers/tls_record.c" \
    -lcrypto -o "$out"

exec "$out" "$@"
