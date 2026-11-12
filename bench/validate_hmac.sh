#!/usr/bin/env bash
# Dynamic validation of the HMAC key setup fallback (tls_anchor_find_hmac):
# do the SHA-2 block functions it finds really see every TLS 1.3 secret as an
# HMAC key, in a program whose TLS has no keylog function to probe?
#
#   1. tls_anchor finds the SHA-2 block functions of the node executable
#      (OpenSSL linked in statically, where the keylog anchor finds nothing);
#   2. openssl s_server runs TLS 1.3;
#   3. a node https client connects under gdb, with breakpoints on those
#      functions printing every single-block call padded with 0x36 (the
#      candidates the eBPF probe would send), and logs its real secrets through
#      the 'keylog' event;
#   4. every TLS 1.3 traffic secret must be among the candidates (the
#      exporter secret only becomes an HMAC key if keying material is exported,
#      which the splice never needs).
#
# No root needed. Usage: bench/validate_hmac.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/eptracer_hmac.XXXXXX")"
srv_pid=""
cleanup() {
	[ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT

node="$(readlink -f "$(command -v node)")"
gcc -O2 -I"$root/src/include" "$here/test_tls_anchor.c" "$root/src/tracers/tls_anchor.c" \
	-lelf -o "$work/anchor"

# file offsets -> addresses relative to the first loaded segment, which gdb
# adds to where that segment is mapped (works with and without PIE)
"$work/anchor" --hmac "$node" > "$work/offsets"
python3 - "$node" "$work/offsets" > "$work/funcs" <<'EOF'
import struct, sys
d = open(sys.argv[1], "rb").read(1 << 16)
phoff, = struct.unpack_from("<Q", d, 0x20); phnum, = struct.unpack_from("<H", d, 0x38)
loads = []
for i in range(phnum):
    p_type, _, off, vaddr, _, filesz = struct.unpack_from("<IIQQQQ", d, phoff + i * 56)
    if p_type == 1:
        loads.append((off, vaddr, filesz))
for line in open(sys.argv[2]):
    off, bits = line.split(); off = int(off, 16)
    for o, v, sz in loads:
        if o <= off < o + sz:
            print("0x%x %s" % (off - o + v - loads[0][1], bits[3:])); break
EOF
echo "[*] $(wc -l < "$work/funcs") SHA-2 block functions found in $node"

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/k.pem" -out "$work/c.pem" \
	-days 1 -subj "/CN=api.example.com" -addext "subjectAltName=DNS:api.example.com" >/dev/null 2>&1
port="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"
openssl s_server -accept "127.0.0.1:$port" -cert "$work/c.pem" -key "$work/k.pem" \
	-tls1_3 -www -quiet -naccept 1 >/dev/null 2>&1 < /dev/null &
srv_pid=$!
sleep 0.5

cat > "$work/client.js" <<EOF
const https = require('https'), fs = require('fs');
const req = https.get({ host: '127.0.0.1', port: $port, servername: 'api.example.com', path: '/',
                        ca: fs.readFileSync('$work/c.pem'), agent: false }, res => {
  res.resume(); res.on('end', () => process.exit(0)); });
req.on('socket', s => s.on('keylog', l => fs.appendFileSync('$work/keylog', l)));
req.on('error', e => { console.error(e.message); process.exit(1); });
EOF

timeout 120 gdb -q -batch -nx \
	-ex "set \$funcs_file = \"$work/funcs\"" \
	-ex "set \$run_args = \"$work/client.js > /dev/null 2>&1\"" \
	-x "$here/validate_hmac_gdb.py" --args "$node" > "$work/gdb.out" 2>&1 || true

grep -m1 '^HMAC-BASE' "$work/gdb.out" || { echo "[!] no run"; tail -20 "$work/gdb.out"; exit 1; }
echo "[*] $(grep -c '^CANDIDATE' "$work/gdb.out") candidates seen"
python3 - "$work/gdb.out" "$work/keylog" <<'EOF'
import sys
cands = {l.split()[1] for l in open(sys.argv[1]) if l.startswith("CANDIDATE")}
ref = {}
for l in open(sys.argv[2]):
    p = l.split()
    if len(p) == 3:
        ref[p[0]] = p[2]
fail = 0
for label, secret in ref.items():
    if "EXPORTER" in label:
        continue
    ok = secret in cands
    fail += not ok
    print(("  ok   " if ok else "  FAIL ") + f"{label}: " +
          ("seen as an HMAC key" if ok else "not among the candidates"))
print("\n" + ("FAILED" if fail or not ref else "PASSED") +
      " (no keylog function in this TLS: the secrets were recognized inside SHA-2)")
sys.exit(1 if fail or not ref else 0)
EOF
