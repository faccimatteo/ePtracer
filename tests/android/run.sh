#!/usr/bin/env bash
# Android e2e suite, host side. Drives a rooted device or emulator over adb:
# pushes the static ePtracer binary, the fixtures and device.sh, serves the
# origin (and the proxy) from the host, and checks what ePtracer captured.
#
#   tests/android/run.sh [-s SERIAL] [--expect-unsupported] [--only a,b] [--out DIR]
#
# Environment:
#   EPTRACER_DIR  directory with eptracer-x86_64 / eptracer-aarch64 (default: dist/)
#   ORIGIN_HOST   address the device reaches the host at (default: 10.0.2.2,
#                 the emulator's alias for the host loopback)
#
# Root: `adb root` where the build allows it (emulator default/google_apis
# images), `su` otherwise (Magisk). Scenarios print PASS/FAIL/SKIP and go to
# $OUT/results.tsv, as in tests/e2e/run.sh.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
EXPECT_UNSUPPORTED=0
ONLY=""
OUT="${OUT:-/tmp/eptracer-android-e2e}"
SERIAL="${ANDROID_SERIAL:-}"
EPTRACER_DIR="${EPTRACER_DIR:-$root/dist}"
ORIGIN_HOST="${ORIGIN_HOST:-10.0.2.2}"
PORT_HTTP=18000 PORT_HTTPS=18443 PORT_PROXY=18080 PORT_BRIDGE=18082
D=/data/local/tmp/e2e

while [ $# -gt 0 ]; do
	case "$1" in
	-s) SERIAL="$2"; shift ;;
	--expect-unsupported) EXPECT_UNSUPPORTED=1 ;;
	--only) ONLY="$2"; shift ;;
	--out) OUT="$2"; shift ;;
	*) echo "unknown option $1"; exit 2 ;;
	esac
	shift
done

ADB=(adb ${SERIAL:+-s "$SERIAL"})
rm -rf "$OUT"; mkdir -p "$OUT"
RESULTS="$OUT/results.tsv"; : > "$RESULTS"
FAILED=0
pids=()
cleanup() {
	for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
	"${ADB[@]}" reverse --remove-all >/dev/null 2>&1
	"${ADB[@]}" forward --remove-all >/dev/null 2>&1
}
trap cleanup EXIT

want() { [ -z "$ONLY" ] || [[ ",$ONLY," == *",$1,"* ]]; }
result() {
	printf '%-18s %-5s %s\n' "$1" "$2" "$3"
	printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$RESULTS"
	if [ "$2" = FAIL ]; then
		FAILED=1
		[ -f "$OUT/$1/eptracer.log" ] && tail -n 25 "$OUT/$1/eptracer.log" | sed 's/^/    | /'
	fi
}

# ---------------------------------------------------------------- device
"${ADB[@]}" wait-for-device
for _ in $(seq 1 180); do
	[ "$("${ADB[@]}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] && break
	sleep 2
done
"${ADB[@]}" root >/dev/null 2>&1 && sleep 2 && "${ADB[@]}" wait-for-device
if [ "$("${ADB[@]}" shell id -u | tr -d '\r')" = 0 ]; then
	ROOT_SH=(sh)
elif "${ADB[@]}" shell su -c id 2>/dev/null | grep -q 'uid=0'; then
	ROOT_SH=(su -c sh)
else
	echo "[!] no root on the device: neither adb root nor su"; exit 2
fi
# run a command as root on the device: shipped as a script, so that no quoting
# has to survive adb shell and su on the way
dsh() {
	printf '%s\n' "$1" > "$OUT/.cmd.sh"
	"${ADB[@]}" push "$OUT/.cmd.sh" /data/local/tmp/e2e-cmd.sh >/dev/null
	"${ADB[@]}" shell "${ROOT_SH[@]}" /data/local/tmp/e2e-cmd.sh
}
prop() { "${ADB[@]}" shell getprop "$1" | tr -d '\r'; }

abi="$(prop ro.product.cpu.abi)"
case "$abi" in
x86_64) arch=x86_64 ;;
arm64-v8a) arch=aarch64 ;;
*) echo "[!] unsupported ABI $abi"; exit 2 ;;
esac
[ -x "$EPTRACER_DIR/eptracer-$arch" ] || { echo "[!] missing $EPTRACER_DIR/eptracer-$arch"; exit 2; }

echo "device: $(prop ro.product.model), Android $(prop ro.build.version.release) (API $(prop ro.build.version.sdk)), $abi"
echo "kernel: $("${ADB[@]}" shell uname -r | tr -d '\r')"
echo

dsh "rm -rf $D; mkdir -p $D" >/dev/null
"${ADB[@]}" push "$EPTRACER_DIR/eptracer-$arch" "$D/eptracer" >/dev/null
"${ADB[@]}" push "$here/device.sh" "$D/device.sh" >/dev/null
dsh "chmod 755 $D/eptracer $D/device.sh"

fetch() {   # $1 scenario: bring its files back to $OUT/$1
	mkdir -p "$OUT/$1"
	for f in eptracer.log app.out app.err app.rc; do
		dsh "cat $D/$1/$f 2>/dev/null" | tr -d '\r' > "$OUT/$1/$f"
	done
	APP_RC="$(cat "$OUT/$1/app.rc")"; APP_RC="${APP_RC:-none}"
}
expect_log() {   # $1 scenario, $2 description, $3 ERE
	if [ "$APP_RC" != 0 ]; then
		result "$1" FAIL "app exit code $APP_RC: $(head -c 300 "$OUT/$1/app.err" "$OUT/$1/app.out" 2>/dev/null)"
	elif grep -qE "$3" "$OUT/$1/eptracer.log"; then
		result "$1" PASS "$2"
	else
		result "$1" FAIL "$2: /$3/ not in the ePtracer output"
	fi
}

# ---------------------------------------------------------------- check
dsh "$D/eptracer --check" | tr -d '\r' > "$OUT/check.log"
cat "$OUT/check.log"; echo
if [ "$EXPECT_UNSUPPORTED" = 1 ]; then
	if grep -q 'NOT SUPPORTED' "$OUT/check.log"; then
		result check PASS "refused as expected on an unsupported kernel"
	else
		result check FAIL "--check accepted a kernel below the support floor"
	fi
	exit $FAILED
fi
if grep -q '^SUPPORTED' "$OUT/check.log"; then
	result check PASS "$(tail -n 1 "$OUT/check.log")"
else
	result check FAIL "$(tail -n 1 "$OUT/check.log")"
	exit 1
fi

# ---------------------------------------------------------------- fixtures
if [ ! -f "$here/fixture/out/e2e.apk" ]; then
	"$here/fixture/build.sh" >/dev/null || { result fixtures FAIL "cannot build the fixture app"; exit 1; }
fi
"${ADB[@]}" push "$here/fixture/out/e2e.dex" "$D/e2e.dex" >/dev/null
dsh "chmod 644 $D/e2e.dex"
"${ADB[@]}" install -r -g "$here/fixture/out/e2e.apk" >/dev/null 2>&1 ||
	"${ADB[@]}" install -r "$here/fixture/out/e2e.apk" >/dev/null

(cd "$OUT" &&
	openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 1 -subj "/CN=e2e CA" &&
	openssl req -newkey rsa:2048 -nodes -keyout origin.key -out origin.csr -subj "/CN=api.example.com" &&
	printf 'subjectAltName = DNS:api.example.com\n' > origin.ext &&
	openssl x509 -req -in origin.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 1 \
		-extfile origin.ext -out origin.crt &&
	openssl req -x509 -newkey rsa:2048 -nodes -keyout proxy.key -out proxy.crt -days 1 -subj "/CN=e2e proxy CA"
) >/dev/null 2>&1

# 0.0.0.0: an emulator reaches the host loopback as 10.0.2.2, a physical
# device needs ORIGIN_HOST set to the host's LAN address
python3 "$root/tests/e2e/origin.py" --host 0.0.0.0 --http-port $PORT_HTTP --https-port $PORT_HTTPS \
	--cert "$OUT/origin.crt" --key "$OUT/origin.key" --log "$OUT/origin.log" \
	> "$OUT/origin.out" 2>&1 & pids+=($!)
for _ in $(seq 1 50); do grep -q READY "$OUT/origin.out" 2>/dev/null && break; sleep 0.1; done

CLIENT="CLASSPATH=$D/e2e.dex app_process /system/bin com.eptracer.e2e.E2EClient"
URL_TLS="https://$ORIGIN_HOST:$PORT_HTTPS"
URL_CLEAR="http://$ORIGIN_HOST:$PORT_HTTP"

# ---------------------------------------------------------------- syscalls
if want syscall; then
	dsh "sh $D/device.sh spawn syscall 'cat /proc/self/status' -S -F" >/dev/null
	fetch syscall
	expect_log syscall "syscalls decoded" 'syscall="(execve|openat|read)"'
fi

# ---------------------------------------------------------------- stack
if want stack; then
	dsh "sh $D/device.sh spawn stack 'e=\$((\$(date +%s) + 3)); while [ \$(date +%s) -lt \$e ]; do :; done' -s -F" >/dev/null
	fetch stack
	expect_log stack "stack samples captured" '^(User|Kernel) stack size -> [0-9]+'
fi

# ---------------------------------------------------------------- cleartext
if want http-clear; then
	dsh "sh $D/device.sh spawn http-clear '$CLIENT $URL_CLEAR/ep-clear' -H -F" >/dev/null
	fetch http-clear
	expect_log http-clear "cleartext HTTP from the framework stack" 'GET .*/ep-clear'
fi

# ---------------------------------------------------------------- Conscrypt
if want tls-conscrypt; then
	dsh "sh $D/device.sh spawn tls-conscrypt '$CLIENT $URL_TLS/ep-conscrypt' -H -F -t" >/dev/null
	fetch tls-conscrypt
	expect_log tls-conscrypt "HttpsURLConnection over Conscrypt (BoringSSL)" 'GET .*/ep-conscrypt'
fi

# ---------------------------------------------------------------- --package
if want package; then
	dsh "sh $D/device.sh package package '$URL_TLS/ep-package' -H -t" >/dev/null
	fetch package
	expect_log package "app found by package name (zygote fork)" 'GET .*/ep-package'
fi

# ---------------------------------------------------------------- splice
if want splice; then
	# device 127.0.0.1:PROXY -> host proxy; the proxy's upstream (ePtracer's
	# bridge on the device) is host 127.0.0.1:BRIDGE -> device
	"${ADB[@]}" reverse tcp:$PORT_PROXY tcp:$PORT_PROXY >/dev/null
	"${ADB[@]}" forward tcp:$PORT_BRIDGE tcp:$PORT_BRIDGE >/dev/null
	python3 "$root/bench/burp_style_proxy.py" --port $PORT_PROXY \
		--cert "$OUT/proxy.crt" --key "$OUT/proxy.key" \
		--upstream 127.0.0.1:$PORT_BRIDGE --replace-resp SERVER_TOKEN=EDITED_BY_PROXY \
		> "$OUT/proxy.out" 2> "$OUT/proxy.log" & ppid=$!
	pids+=($ppid)
	sleep 1
	dsh "sh $D/device.sh spawn splice '$CLIENT $URL_TLS/ep-splice' -I 127.0.0.1:$PORT_PROXY --tls-mode splice --bridge-port $PORT_BRIDGE --intercept-ports $PORT_HTTPS -F" >/dev/null
	fetch splice
	kill $ppid 2>/dev/null
	n="$(grep -c 'REQ GET /ep-splice' "$OUT/origin.log" 2>/dev/null)"
	if [ "$APP_RC" != 0 ]; then
		result splice FAIL "app exit code $APP_RC: $(head -c 300 "$OUT/splice/app.err")"
	elif ! grep -qi 'EDITED_BY_PROXY' "$OUT/splice/app.out"; then
		result splice FAIL "the proxy edit did not reach the app"
	elif [ "$n" != 1 ]; then
		result splice FAIL "the origin saw the request $n times"
	else
		result splice PASS "Conscrypt session kept, proxy edit applied, request sent once"
	fi
fi

echo
echo "results: $RESULTS"
exit $FAILED
