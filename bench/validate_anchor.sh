#!/usr/bin/env bash
# Dynamic validation of tls_anchor on the system libssl: does the function it
# resolves really receive every keylog label and the right secrets, in a client
# that never installed a keylog callback?
#
#   1. tls_anchor resolves the keylog function in libssl.so.3 (static scan);
#   2. openssl s_server runs TLS 1.3 *with* -keylogfile: the reference secrets;
#   3. openssl s_client runs under gdb, *without* -keylogfile, with a breakpoint
#      on the resolved function; each hit dumps (label=rsi, secret=rdx[rcx]),
#      the registers the eBPF uprobe reads;
#   4. every TLS 1.3 secret of the session must match the server's keylog.
#
# No root needed (gdb debugs its own child). Usage: bench/validate_anchor.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/eptracer_anchor.XXXXXX")"
srv_pid=""
cleanup() {
	# s_server -naccept 1 has usually exited already
	[ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT

lib="$(ldd "$(command -v openssl)" | awk '/libssl\.so/{print $3; exit}')"
lib="$(readlink -f "$lib")"
echo "[*] openssl links $lib"

gcc -O2 -Wall -I"$root/src/include" "$here/test_tls_anchor.c" "$root/src/tracers/tls_anchor.c" \
	-lelf -o "$work/anchor"
read -r anchor_vaddr anchor_off < <("$work/anchor" --find "$lib")
sym_vaddr="0x$(nm -D --defined-only "$lib" | awk '$3 ~ /^SSL_new(@|$)/{print $1; exit}')"
echo "[*] static scan: keylog function at $anchor_vaddr (file offset $anchor_off), SSL_new at $sym_vaddr"

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/k.pem" -out "$work/c.pem" \
	-days 1 -subj "/CN=api.example.com" >/dev/null 2>&1
port="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"
openssl s_server -accept "127.0.0.1:$port" -cert "$work/c.pem" -key "$work/k.pem" \
	-tls1_3 -keylogfile "$work/server.keys" -quiet -naccept 1 >/dev/null 2>&1 < /dev/null &
srv_pid=$!
sleep 0.5

timeout 60 gdb -q -batch -nx \
	-ex "set \$anchor_off = $anchor_vaddr" \
	-ex "set \$sym_vaddr = $sym_vaddr" \
	-ex "set \$run_args = \"s_client -connect 127.0.0.1:$port -tls1_3 -servername api.example.com < /dev/null > /dev/null 2>&1\"" \
	-x "$here/validate_anchor_gdb.py" \
	--args "$(command -v openssl)" > "$work/gdb.out" 2>&1 || true

grep '^ANCHOR' "$work/gdb.out" || { echo "[!] no hit"; tail -20 "$work/gdb.out"; exit 1; }
echo "[*] server keylog (reference):"
sed 's/^/    /' "$work/server.keys"

python3 - "$work/gdb.out" "$work/server.keys" <<'EOF'
import sys
hits = {}
for l in open(sys.argv[1]):
    p = l.split()
    if len(p) == 3 and p[0] == "ANCHOR":
        hits[p[1]] = p[2]
ref = {}
for l in open(sys.argv[2]):
    p = l.split()
    if len(p) == 3:
        ref[p[0]] = p[2]
fail = 0
for label, secret in ref.items():
    got = hits.get(label)
    ok = got == secret
    fail += not ok
    print(("  ok   " if ok else "  FAIL ") + f"{label}: " +
          ("probe secret == server keylog" if ok else f"probe={got} ref={secret}"))
print("\n" + ("FAILED" if fail or not ref else "PASSED") +
      " (client had no keylog callback; the entry probe saw every secret)")
sys.exit(1 if fail or not ref else 0)
EOF
