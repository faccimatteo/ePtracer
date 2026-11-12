#!/usr/bin/env bash
# Live test of --tls-mode splice with the real eBPF key probe. Needs root:
#
#   sudo NODE="$(command -v node)" bench/run_live_splice.sh
#
# (NODE because sudo resets PATH, and node often lives in the user's nvm.)
#
# The "app" is curl with certificate pinning (--pinnedpubkey) against a local
# HTTPS origin (node, HTTP/1.1 and HTTP/2), spawned by ePtracer through a
# wrapper script (-F follows it). The proxy is the Burp-style mock, configured
# with ePtracer as its upstream, editing responses and replaying /replay.
#
#   1. splice, HTTP/1.1   expect: pin accepted, edits applied, each request once
#   2. splice, HTTP/2     same over h2
#   3. mitm (control)     expect: pinning refuses the proxy certificate
#   4. exec-follow        a launcher script runs a client with OpenSSL linked in
#                         statically, outside every known path, and no --ssl-lib:
#                         the key probe can only reach it through trace_exec
#   5. hmac-node          a launcher script runs node, whose static OpenSSL has no
#                         keylog function to anchor: the secrets can only come
#                         from the HMAC key setup inside its SHA-2 functions
#
# Everything lives in /tmp/eptracer-live (left in place, world-readable) so the
# logs can be inspected afterwards. Ports 18080-18082/18443. The origin listens
# on this machine's own non-loopback address: ePtracer never redirects
# connections to 127.0.0.0/8 (they would make its slot encoding ambiguous).
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
W=/tmp/eptracer-live
PORT=18443 PROXY=18080 LISTEN=18081 BRIDGE=18082
AUTH=api.example.com

if [ "$(id -u)" != 0 ]; then
	echo "run it with sudo: sudo $0"; exit 2
fi
for t in python3 curl openssl; do
	command -v "$t" >/dev/null || { echo "[!] $t is needed"; exit 2; }
done
NODE="${NODE:-$(command -v node)}"
[ -x "$NODE" ] || { echo "[!] node not found: pass NODE=/path/to/node"; exit 2; }
[ -x "$root/eptracer" ] || { echo "[!] build ePtracer first (make)"; exit 2; }
ORIGIN_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}')"
[ -n "$ORIGIN_IP" ] || { echo "[!] no non-loopback IPv4 address to run the origin on"; exit 2; }
# a port taken by something else would silently turn every run into a direct
# connection: refuse to start instead
for p in $PORT $PROXY $LISTEN $BRIDGE; do
	if ss -ltnH "sport = :$p" | grep -q .; then
		echo "[!] port $p is already in use (sudo ss -ltnp 'sport = :$p'): free it first"
		exit 2
	fi
done

rm -rf "$W"
mkdir -p "$W"
chmod 1777 "$W"
pids=()
cleanup() {
	for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
	chmod -R a+rX "$W" 2>/dev/null || true
}
trap cleanup EXIT

echo "[*] certificates"
mk() {   # $1 name
	openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/$1-ca.key" -out "$W/$1-ca.crt" \
		-days 1 -subj "/CN=$1 test CA" >/dev/null 2>&1
	openssl req -newkey rsa:2048 -nodes -keyout "$W/$1.key" -out "$W/$1.csr" \
		-subj "/CN=$AUTH" >/dev/null 2>&1
	printf 'subjectAltName = DNS:%s\n' "$AUTH" > "$W/$1.ext"
	openssl x509 -req -in "$W/$1.csr" -CA "$W/$1-ca.crt" -CAkey "$W/$1-ca.key" -CAcreateserial \
		-days 1 -sha256 -extfile "$W/$1.ext" -out "$W/$1.crt" >/dev/null 2>&1
}
mk origin
mk proxy
PIN="$(openssl x509 -in "$W/origin.crt" -pubkey -noout | openssl pkey -pubin -outform der |
	openssl dgst -sha256 -binary | base64)"

echo "[*] origin (node, h1 + h2) on $ORIGIN_IP:$PORT"
cat > "$W/origin.mjs" <<EOF
import http2 from 'node:http2'; import fs from 'node:fs';
const log = fs.createWriteStream('$W/origin.log', { flags: 'a' });
const s = http2.createSecureServer({ key: fs.readFileSync('$W/origin.key'),
  cert: fs.readFileSync('$W/origin.crt'), allowHTTP1: true }, (req, res) => {
  log.write(\`REQ \${req.method} \${req.url} \${req.httpVersion}\n\`);
  let n = 0; req.on('data', c => n += c.length);
  req.on('end', () => { res.writeHead(200, { 'x-token': 'SERVER_TOKEN', 'content-type': 'text/plain' });
    res.end(\`hello from the real server, \${req.url} over HTTP/\${req.httpVersion}\n\`); });
});
s.listen($PORT, '$ORIGIN_IP');
EOF
"$NODE" "$W/origin.mjs" & pids+=($!)

echo "[*] Burp-style proxy on 127.0.0.1:$PROXY (upstream: ePtracer on $BRIDGE)"
python3 "$here/burp_style_proxy.py" --port "$PROXY" --cert "$W/proxy.crt" --key "$W/proxy.key" \
	--upstream "127.0.0.1:$BRIDGE" --replace-resp SERVER_TOKEN=EDITED_BY_PROXY \
	--repeat-path /replay-h1 --repeat-path /replay-h2 --repeat-path /replay-exec \
	--repeat-path /replay-node \
	> "$W/proxy.out" 2> "$W/proxy.log" & pids+=($!)
sleep 1

run() {   # $1 run name, $2 curl protocol flag, $3 tls mode
	local R="$W/$1"
	mkdir -p "$R"; chmod 1777 "$R"
	cat > "$R/app.sh" <<EOF
#!/bin/sh
curl -sS -i $2 --cacert $W/origin-ca.crt --pinnedpubkey sha256//$PIN \\
  --resolve $AUTH:$PORT:$ORIGIN_IP \\
  -o $R/out1 https://$AUTH:$PORT/hello-${1%%-*} \\
  -o $R/out2 https://$AUTH:$PORT/replay-${1%%-*} 2> $R/curl.err
echo \$? > $R/curl.rc
EOF
	chmod 755 "$R/app.sh"
	echo "[*] run '$1': eptracer -p app.sh -F -I 127.0.0.1:$PROXY --tls-mode $3"
	"$root/eptracer" -p "$R/app.sh" -F -v -I "127.0.0.1:$PROXY" --tls-mode "$3" \
		--bridge-port "$BRIDGE" --intercept-port "$LISTEN" --intercept-ports "$PORT" \
		> "$R/eptracer.log" 2>&1 &
	local epid=$!
	for _ in $(seq 1 60); do [ -f "$R/curl.rc" ] && break; sleep 0.5; done
	sleep 1
	kill -INT "$epid" 2>/dev/null; wait "$epid" 2>/dev/null
	echo "    curl exit code: $(cat "$R/curl.rc" 2>/dev/null || echo 'none (timeout)')"
}

run h1-splice --http1.1 splice
run h2-splice --http2 splice
run mitm-control --http1.1 mitm

echo "[*] building the statically linked pinned client"
mkdir -p "$W/bin"
gcc -O2 -o "$W/bin/pinned_client" "$here/pinned_client.c" \
	/usr/lib/x86_64-linux-gnu/libssl.a /usr/lib/x86_64-linux-gnu/libcrypto.a -lpthread -ldl 2>/dev/null ||
	echo "[!] cannot build it (libssl-dev with static libraries needed)"
chmod 755 "$W/bin" "$W/bin/pinned_client" 2>/dev/null
R="$W/exec-follow"
mkdir -p "$R"; chmod 1777 "$R"
cat > "$R/app.sh" <<EOF
#!/bin/sh
# the launcher: the program with TLS in it is only known once executed
$W/bin/pinned_client $ORIGIN_IP $PORT $AUTH $W/origin-ca.crt $PIN $R/out /hello-exec /replay-exec 2> $R/client.err
echo \$? > $R/client.rc
EOF
chmod 755 "$R/app.sh"
echo "[*] run 'exec-follow': eptracer -p app.sh -F -I 127.0.0.1:$PROXY --tls-mode splice (no --ssl-lib)"
"$root/eptracer" -p "$R/app.sh" -F -v -I "127.0.0.1:$PROXY" --tls-mode splice \
	--bridge-port "$BRIDGE" --intercept-port "$LISTEN" --intercept-ports "$PORT" \
	> "$R/eptracer.log" 2>&1 &
epid=$!
for _ in $(seq 1 60); do [ -f "$R/client.rc" ] && break; sleep 0.5; done
sleep 1
kill -INT "$epid" 2>/dev/null; wait "$epid" 2>/dev/null
echo "    client exit code: $(cat "$R/client.rc" 2>/dev/null || echo 'none (timeout)')"

R="$W/hmac-node"
mkdir -p "$R"; chmod 1777 "$R"
cat > "$R/client.js" <<EOF
const https = require('https'), fs = require('fs');
const agent = new https.Agent({ keepAlive: true, maxSockets: 1 });
const get = (path) => new Promise((ok, ko) => https.get({ host: '$ORIGIN_IP', port: $PORT,
  servername: '$AUTH', headers: { host: '$AUTH' }, path, agent,
  ca: fs.readFileSync('$W/origin-ca.crt') }, res => {
    let b = ''; res.on('data', d => b += d);
    res.on('end', () => ok('HTTP/1.1 ' + res.statusCode + '\n' +
      Object.entries(res.headers).map(([k, v]) => k + ': ' + v).join('\n') + '\n\n' + b));
  }).on('error', ko));
(async () => {
  fs.writeFileSync('$R/out1', await get('/hello-node'));
  fs.writeFileSync('$R/out2', await get('/replay-node'));
  process.exit(0);
})().catch(e => { console.error(e.message); process.exit(1); });
EOF
cat > "$R/app.sh" <<EOF
#!/bin/sh
$NODE $R/client.js 2> $R/client.err
echo \$? > $R/client.rc
EOF
chmod 755 "$R/app.sh"
echo "[*] run 'hmac-node': eptracer -p app.sh -F -I 127.0.0.1:$PROXY --tls-mode splice (no --ssl-lib)"
"$root/eptracer" -p "$R/app.sh" -F -v -I "127.0.0.1:$PROXY" --tls-mode splice \
	--bridge-port "$BRIDGE" --intercept-port "$LISTEN" --intercept-ports "$PORT" \
	> "$R/eptracer.log" 2>&1 &
epid=$!
for _ in $(seq 1 60); do [ -f "$R/client.rc" ] && break; sleep 0.5; done
sleep 1
kill -INT "$epid" 2>/dev/null; wait "$epid" 2>/dev/null
echo "    node exit code: $(cat "$R/client.rc" 2>/dev/null || echo 'none (timeout)')"

R="$W/quic"
mkdir -p "$R"; chmod 1777 "$R"
cat > "$R/app.sh" <<EOF
#!/bin/sh
python3 - > $R/out 2>&1 <<'PY'
import socket
for port in (443, 53):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", port)); s.send(b"x"); print(f"UDP{port} ALLOWED")
    except OSError as e:
        print(f"UDP{port} BLOCKED {e.errno}")
PY
echo done > $R/rc
EOF
chmod 755 "$R/app.sh"
echo "[*] run 'quic': UDP/443 must be refused, UDP/53 must pass"
"$root/eptracer" -p "$R/app.sh" -F -v -I "127.0.0.1:$PROXY" --tls-mode splice \
	--bridge-port "$BRIDGE" --intercept-port "$LISTEN" --intercept-ports "$PORT" \
	> "$R/eptracer.log" 2>&1 &
epid=$!
for _ in $(seq 1 40); do [ -f "$R/rc" ] && break; sleep 0.5; done
sleep 1
kill -INT "$epid" 2>/dev/null; wait "$epid" 2>/dev/null

chmod -R a+rX "$W"
python3 - "$W" <<'EOF'
import collections, os, re, sys
W = sys.argv[1]
fail = 0
def check(c, m):
    global fail
    print(("  ok   " if c else "  FAIL ") + m); fail += not c
def read(p):
    try: return open(os.path.join(W, p), errors="replace").read()
    except OSError: return ""
origin = collections.Counter(l.split()[2] for l in read("origin.log").splitlines() if l.startswith("REQ"))
proxy = read("proxy.log")
for run, proto in (("h1", "HTTP/1.1"), ("h2", "HTTP/2")):
    R = f"{run}-splice"
    print(f"[{R}]")
    log = read(f"{R}/eptracer.log")
    out1, out2 = read(f"{R}/out1"), read(f"{R}/out2")
    check(re.search(r"Keylog function of .*libssl", log) is not None, "key probe placed on libssl by the string anchor")
    check(read(f"{R}/curl.rc").strip() == "0", f"curl succeeded with pinning on ({read(f'{R}/curl.err').strip() or 'no error'})")
    check(re.search(r"x-token: EDITED_BY_PROXY", out1, re.I) is not None, "response edited in the proxy reached the app")
    check(re.search(r"x-burp-mock: forwarded", out1, re.I) is not None, "request went through the proxy")
    check(origin[f"/hello-{run}"] == 1, f"/hello-{run} reached the real server once ({origin[f'/hello-{run}']})")
    check(origin[f"/replay-{run}"] == 1, f"/replay-{run} reached the real server once despite the replay ({origin[f'/replay-{run}']})")
    check("already delivered (duplicate)" in log, "the replay was refused by ePtracer")
    if run == "h2":
        check("HTTP/2, terminated on both legs" in log, "HTTP/2 negotiated with the real server and terminated")
print("[mitm-control]")
rc = read("mitm-control/curl.rc").strip()
check(rc not in ("", "0"), f"plain MITM is refused by pinning, as expected (curl exit {rc or 'none'})")
check(origin["/hello-mitm"] == 0, "and nothing reached the server")
print("[exec-follow]")
log = read("exec-follow/eptracer.log")
out1 = read("exec-follow/out1")
check(re.search(r"Keylog function of .*/bin/pinned_client", log) is not None,
      "key probe placed on the executed binary, found through trace_exec")
check(read("exec-follow/client.rc").strip() == "0",
      f"static client succeeded with its pin ({read('exec-follow/client.err').strip() or 'no error'})")
check(re.search(r"x-token: EDITED_BY_PROXY", out1, re.I) is not None, "response edited in the proxy reached it")
check(origin["/hello-exec"] == 1 and origin["/replay-exec"] == 1,
      f"each request reached the server once ({origin['/hello-exec']}, {origin['/replay-exec']})")
print("[hmac-node]")
log = read("hmac-node/eptracer.log")
check(re.search(r"Keys of .*/node from its HMAC key setup", log) is not None,
      "SHA-2 functions of node probed (no keylog function to anchor)")
check(read("hmac-node/client.rc").strip() == "0",
      f"node succeeded ({read('hmac-node/client.err').strip() or 'no error'})")
check(re.search(r"x-token: EDITED_BY_PROXY", read("hmac-node/out1"), re.I) is not None,
      "decrypted with keys from HMAC: the edited response reached it")
check(origin["/hello-node"] == 1 and origin["/replay-node"] == 1,
      f"each request reached the server once ({origin['/hello-node']}, {origin['/replay-node']})")
print("[quic]")
q = read("quic/out")
check("UDP443 BLOCKED" in q, f"UDP/443 refused so QUIC falls back to TCP ({q.split(chr(10))[0] if q else 'no output'})")
check("UDP53 ALLOWED" in q, "UDP/53 (DNS) left alone")
print("\n" + ("FAILED" if fail else "PASSED") + f" ({fail} failure{'s' if fail != 1 else ''})  —  logs in {W}")
sys.exit(1 if fail else 0)
EOF
