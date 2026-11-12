#!/usr/bin/env bash
# End-to-end suite: runs the real ePtracer binary, as root, against real TLS
# stacks, on whatever kernel and userland it is started on. The same script
# backs the kernel matrix (little-vm-helper VMs) and the distribution matrix
# (privileged containers); the Android emulator has its own driver.
#
#   sudo tests/e2e/run.sh [--expect-unsupported] [--only a,b] [--out DIR]
#
# Environment:
#   EPTRACER   binary under test (default: dist/eptracer-$(uname -m), then ./eptracer)
#   GO_CLIENT  static Go HTTPS client (tests/e2e/goclient); the Go scenario is
#              skipped without it
#
# Scenarios print PASS / FAIL / SKIP; a tool a scenario needs (curl, gnutls-cli)
# being absent is a SKIP, not a failure. Results also go to $OUT/results.tsv,
# from which the compatibility table is built. Exit status: 0 when nothing
# failed.
#
# --expect-unsupported is for kernels below the support floor (5.4): the only
# scenario run is `check`, and it passes when ePtracer refuses to run there.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
EXPECT_UNSUPPORTED=0
ONLY=""
OUT="${OUT:-/tmp/eptracer-e2e}"

while [ $# -gt 0 ]; do
	case "$1" in
	--expect-unsupported) EXPECT_UNSUPPORTED=1 ;;
	--only) ONLY="$2"; shift ;;
	--out) OUT="$2"; shift ;;
	*) echo "unknown option $1"; exit 2 ;;
	esac
	shift
done

if [ -z "${EPTRACER:-}" ]; then
	for c in "$root/dist/eptracer-$(uname -m)" "$root/eptracer"; do
		[ -x "$c" ] && { EPTRACER="$c"; break; }
	done
fi
[ -x "${EPTRACER:-}" ] || { echo "[!] no ePtracer binary: set EPTRACER"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "[!] run as root"; exit 2; }

PORT_HTTP=18000 PORT_HTTPS=18443 PORT_PROXY=18080 PORT_LISTEN=18081 PORT_BRIDGE=18082
AUTH=api.example.com

# emptied rather than removed: it may be a bind mount
mkdir -p "$OUT"
rm -rf "${OUT:?}"/* 2>/dev/null
chmod 1777 "$OUT"
RESULTS="$OUT/results.tsv"
: > "$RESULTS"
FAILED=0
pids=()
cleanup() {
	for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
	chmod -R a+rX "$OUT" 2>/dev/null || true
}
trap cleanup EXIT

have() { command -v "$1" >/dev/null 2>&1; }
want() { [ -z "$ONLY" ] || [[ ",$ONLY," == *",$1,"* ]]; }

result() {   # $1 scenario, $2 PASS|FAIL|SKIP, $3 detail
	printf '%-18s %-5s %s\n' "$1" "$2" "$3"
	printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$RESULTS"
	if [ "$2" = FAIL ]; then
		FAILED=1
		# the tail of the log is what a CI reader needs to see
		[ -f "$OUT/$1/eptracer.log" ] && tail -n 25 "$OUT/$1/eptracer.log" | sed 's/^/    | /'
	fi
}

uname -a
echo "eptracer: $EPTRACER"
echo

# ---------------------------------------------------------------- check
"$EPTRACER" --check > "$OUT/check.log" 2>&1
rc=$?
cat "$OUT/check.log"
echo
if [ "$EXPECT_UNSUPPORTED" = 1 ]; then
	if [ $rc -ne 0 ] && grep -q 'NOT SUPPORTED' "$OUT/check.log"; then
		result check PASS "refused as expected on an unsupported kernel"
	else
		result check FAIL "--check accepted a kernel below the support floor (rc=$rc)"
	fi
	exit $FAILED
fi
if [ $rc -eq 0 ]; then
	result check PASS "$(tail -n 1 "$OUT/check.log")"
else
	result check FAIL "$(tail -n 1 "$OUT/check.log")"
	echo "[!] preflight failed: the remaining scenarios cannot work"
	exit 1
fi

# ---------------------------------------------------------------- fixtures
have python3 || { result fixtures SKIP "python3 missing: no origin server, nothing else to run"; exit $FAILED; }
have openssl || { result fixtures SKIP "openssl CLI missing: cannot mint certificates"; exit $FAILED; }

# a non-loopback address: ePtracer never redirects 127.0.0.0/8 (the slot
# encoding of -I lives there), so the origin must not listen on it
IP="$(python3 -c 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect(("10.255.255.255",1));print(s.getsockname()[0])' 2>/dev/null || true)"
[ -n "$IP" ] && [ "${IP#127.}" = "$IP" ] || IP=""
ORIGIN_IP="${IP:-127.0.0.1}"

mk_cert() {   # $1 name
	openssl req -x509 -newkey rsa:2048 -nodes -keyout "$OUT/$1-ca.key" -out "$OUT/$1-ca.crt" \
		-days 1 -subj "/CN=$1 test CA" >/dev/null 2>&1
	openssl req -newkey rsa:2048 -nodes -keyout "$OUT/$1.key" -out "$OUT/$1.csr" \
		-subj "/CN=$AUTH" >/dev/null 2>&1
	printf 'subjectAltName = DNS:%s\n' "$AUTH" > "$OUT/$1.ext"
	openssl x509 -req -in "$OUT/$1.csr" -CA "$OUT/$1-ca.crt" -CAkey "$OUT/$1-ca.key" \
		-CAcreateserial -days 1 -sha256 -extfile "$OUT/$1.ext" -out "$OUT/$1.crt" >/dev/null 2>&1
}
mk_cert origin
mk_cert proxy
chmod a+r "$OUT"/*

python3 "$here/origin.py" --host "$ORIGIN_IP" --http-port $PORT_HTTP --https-port $PORT_HTTPS \
	--cert "$OUT/origin.crt" --key "$OUT/origin.key" --log "$OUT/origin.log" \
	> "$OUT/origin.out" 2>&1 & pids+=($!)
for _ in $(seq 1 50); do grep -q READY "$OUT/origin.out" 2>/dev/null && break; sleep 0.1; done
grep -q READY "$OUT/origin.out" || { result fixtures FAIL "origin did not start: $(cat "$OUT/origin.out")"; exit 1; }

# ePtracer spawns the app through this wrapper (-p splits on spaces only), and
# is stopped once the app wrote its exit code. $1 scenario, $2 shell command,
# rest: ePtracer options.
ep_run() {
	local name="$1" cmd="$2"; shift 2
	local R="$OUT/$name"
	mkdir -p "$R"; chmod 1777 "$R"
	# printf, not a heredoc: $cmd must reach the file literally
	printf '#!/bin/sh\n( %s ) > %s/app.out 2> %s/app.err\necho $? > %s/app.rc\n' \
		"$cmd" "$R" "$R" "$R" > "$R/app.sh"
	chmod 755 "$R/app.sh"
	"$EPTRACER" -p "$R/app.sh" "$@" > "$R/eptracer.log" 2>&1 &
	local epid=$!
	for _ in $(seq 1 120); do
		[ -f "$R/app.rc" ] && break
		kill -0 "$epid" 2>/dev/null || break
		sleep 0.25
	done
	# let the last events drain from the ring buffers
	sleep 1
	kill -INT "$epid" 2>/dev/null
	for _ in $(seq 1 40); do kill -0 "$epid" 2>/dev/null || break; sleep 0.25; done
	kill -KILL "$epid" 2>/dev/null
	wait "$epid" 2>/dev/null
	APP_RC="$(cat "$R/app.rc" 2>/dev/null || echo none)"
}

# Like ep_run, for a program spawned as is (-p "PROGRAM ARGS", no spaces in
# them): its exit is not observable from here, so it counts as done, and
# successful, once the origin logged the request. $2 path the origin must see.
ep_run_direct() {
	local name="$1" path="$2" cmd="$3"; shift 3
	local R="$OUT/$name"
	mkdir -p "$R"
	"$EPTRACER" -p "$cmd" "$@" > "$R/eptracer.log" 2>&1 &
	local epid=$!
	APP_RC=none
	for _ in $(seq 1 120); do
		grep -q "REQ GET $path\$" "$OUT/origin.log" 2>/dev/null && { APP_RC=0; break; }
		kill -0 "$epid" 2>/dev/null || break
		sleep 0.25
	done
	sleep 1
	kill -INT "$epid" 2>/dev/null
	for _ in $(seq 1 40); do kill -0 "$epid" 2>/dev/null || break; sleep 0.25; done
	kill -KILL "$epid" 2>/dev/null
	wait "$epid" 2>/dev/null
}

# PASS when the app succeeded and $3 (an ERE) shows up in the ePtracer log
expect_log() {   # $1 scenario, $2 description, $3 pattern
	local R="$OUT/$1"
	if [ "$APP_RC" != 0 ]; then
		result "$1" FAIL "app exit code $APP_RC: $(head -c 200 "$R/app.err" 2>/dev/null)"
	elif grep -qE "$3" "$R/eptracer.log"; then
		result "$1" PASS "$2"
	else
		result "$1" FAIL "$2: /$3/ not in the ePtracer output"
	fi
}

CURL_TLS="curl -sS --http1.1 -k --resolve $AUTH:$PORT_HTTPS:$ORIGIN_IP"

# ---------------------------------------------------------------- syscalls
if want syscall; then
	ep_run syscall "cat /proc/self/status" -S -F
	expect_log syscall "syscalls decoded" 'syscall="(execve|openat|read)"'
fi

# ---------------------------------------------------------------- stack
if want stack; then
	ep_run stack "e=\$((\$(date +%s) + 3)); while [ \$(date +%s) -lt \$e ]; do :; done" -s -F
	expect_log stack "stack samples captured" '^(User|Kernel) stack size -> [0-9]+'
fi

# ---------------------------------------------------------------- cleartext
if want http-clear; then
	if have curl; then
		ep_run http-clear "curl -sS http://$ORIGIN_IP:$PORT_HTTP/ep-clear" -H -F
	else
		ep_run http-clear "python3 -c 'import urllib.request as u;u.urlopen(\"http://$ORIGIN_IP:$PORT_HTTP/ep-clear\").read()'" -H -F
	fi
	expect_log http-clear "cleartext HTTP over syscalls" 'GET .*/ep-clear'
fi

# ---------------------------------------------------------------- OpenSSL (curl)
if want tls-curl; then
	if have curl && curl -V | grep -qiE 'openssl|boringssl'; then
		ep_run tls-curl "$CURL_TLS https://$AUTH:$PORT_HTTPS/ep-curl" -H -F -t
		expect_log tls-curl "curl ($(curl -V | head -1 | grep -oiE '(openssl|boringssl)/[^ ]+' | head -1))" 'GET .*/ep-curl'
	else
		result tls-curl SKIP "no curl linked against OpenSSL"
	fi
fi

# ---------------------------------------------------------------- OpenSSL (python)
if want tls-python; then
	ver="$(python3 -c 'import ssl;print(ssl.OPENSSL_VERSION)')"
	ep_run tls-python "python3 -c '
import socket, ssl
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
s = c.wrap_socket(socket.create_connection((\"$ORIGIN_IP\", $PORT_HTTPS)), server_hostname=\"$AUTH\")
s.sendall(b\"GET /ep-python HTTP/1.1\\r\\nHost: $AUTH\\r\\nConnection: close\\r\\n\\r\\n\")
while s.recv(4096): pass
'" -H -F -t
	expect_log tls-python "python ($ver)" 'GET .*/ep-python'
fi

# ---------------------------------------------------------------- GnuTLS
if want tls-gnutls; then
	if have gnutls-cli; then
		ep_run tls-gnutls "printf 'GET /ep-gnutls HTTP/1.1\r\nHost: $AUTH\r\nConnection: close\r\n\r\n' | gnutls-cli --insecure --logfile=/dev/null -p $PORT_HTTPS $ORIGIN_IP" -H -F -t
		expect_log tls-gnutls "gnutls-cli ($(gnutls-cli --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+'))" 'GET .*/ep-gnutls'
	else
		result tls-gnutls SKIP "gnutls-cli missing"
	fi
fi

# ---------------------------------------------------------------- Go
if want tls-go; then
	if [ -x "${GO_CLIENT:-}" ]; then
		# spawned directly, not through the wrapper: the Go probes go on the
		# traced executable before it runs (a child would only be found by the
		# -F rescan, a second later, after this short-lived client is gone)
		ep_run_direct tls-go /ep-go "$GO_CLIENT https://$ORIGIN_IP:$PORT_HTTPS/ep-go" -H -t
		expect_log tls-go "Go crypto/tls (static, $(uname -m))" 'GET .*/ep-go'
	else
		result tls-go SKIP "GO_CLIENT not set"
	fi
fi

# ---------------------------------------------------------------- -I (mitm)
proxy_start() {   # $1 log name, rest: extra proxy options
	local log="$1"; shift
	python3 "$root/bench/burp_style_proxy.py" --port $PORT_PROXY \
		--cert "$OUT/proxy.crt" --key "$OUT/proxy.key" "$@" \
		> "$OUT/$log.out" 2> "$OUT/$log.log" & PROXY_PID=$!
	pids+=($PROXY_PID)
	for _ in $(seq 1 50); do grep -q PORT "$OUT/$log.out" 2>/dev/null && break; sleep 0.1; done
}
proxy_stop() { kill "$PROXY_PID" 2>/dev/null; wait "$PROXY_PID" 2>/dev/null; }

if want intercept; then
	if [ -z "$IP" ]; then
		result intercept SKIP "no non-loopback IPv4 address"
	elif ! have curl; then
		result intercept SKIP "curl missing"
	else
		proxy_start proxy-mitm
		# no -k: the proxy CA is trusted only because ePtracer exports it to
		# the spawned process
		ep_run intercept "curl -sS --http1.1 --resolve $AUTH:$PORT_HTTPS:$ORIGIN_IP https://$AUTH:$PORT_HTTPS/ep-mitm" \
			-I 127.0.0.1:$PORT_PROXY --proxy-ca "$OUT/proxy-ca.crt" \
			--intercept-port $PORT_LISTEN --intercept-ports $PORT_HTTPS -F
		proxy_stop
		if [ "$APP_RC" != 0 ]; then
			result intercept FAIL "curl exit code $APP_RC: $(head -c 200 "$OUT/intercept/app.err")"
		elif grep -q 'request GET /ep-mitm' "$OUT/proxy-mitm.log"; then
			result intercept PASS "connection diverted to the proxy, CA trusted for the child"
		else
			result intercept FAIL "the proxy never saw the request"
		fi
	fi
fi

# ---------------------------------------------------------------- -I splice
if want splice; then
	if [ -z "$IP" ]; then
		result splice SKIP "no non-loopback IPv4 address"
	elif ! have curl; then
		result splice SKIP "curl missing"
	else
		PIN="$(openssl x509 -in "$OUT/origin.crt" -pubkey -noout | openssl pkey -pubin -outform der |
			openssl dgst -sha256 -binary | base64)"
		proxy_start proxy-splice --upstream 127.0.0.1:$PORT_BRIDGE --replace-resp SERVER_TOKEN=EDITED_BY_PROXY
		# pinned to the origin's own key: a MITM would be refused, only the
		# splice can put the proxy in the path
		ep_run splice "curl -sS -i --http1.1 --cacert $OUT/origin-ca.crt --pinnedpubkey sha256//$PIN --resolve $AUTH:$PORT_HTTPS:$ORIGIN_IP https://$AUTH:$PORT_HTTPS/ep-splice" \
			-I 127.0.0.1:$PORT_PROXY --tls-mode splice --bridge-port $PORT_BRIDGE \
			--intercept-port $PORT_LISTEN --intercept-ports $PORT_HTTPS -F
		proxy_stop
		if [ "$APP_RC" != 0 ]; then
			result splice FAIL "curl exit code $APP_RC: $(head -c 200 "$OUT/splice/app.err")"
		elif ! grep -q EDITED_BY_PROXY "$OUT/splice/app.out"; then
			result splice FAIL "pin held but the proxy edit did not reach the app"
		elif [ "$(grep -c 'REQ GET /ep-splice' "$OUT/origin.log")" != 1 ]; then
			result splice FAIL "the origin saw the request $(grep -c 'REQ GET /ep-splice' "$OUT/origin.log") times"
		else
			result splice PASS "pinned session kept, proxy edit applied, request sent once"
		fi
	fi
fi

echo
echo "results: $RESULTS"
exit $FAILED
