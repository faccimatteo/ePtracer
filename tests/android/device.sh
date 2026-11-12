#!/system/bin/sh
# Device side of the Android e2e suite, run as root by tests/android/run.sh:
#
#   device.sh spawn   NAME "COMMAND" [eptracer options]   ePtracer spawns COMMAND (-p)
#   device.sh package NAME URL [eptracer options]         the fixture app, by --package
#
# Leaves in /data/local/tmp/e2e/NAME: eptracer.log, app.out, app.err, app.rc.
# Plain POSIX sh: it runs under Android's mksh, without any userland of ours.
D=/data/local/tmp/e2e
EP=$D/eptracer
PKG=com.eptracer.e2e

mode=$1 name=$2
shift 2
R=$D/$name
rm -rf "$R"
mkdir -p "$R"

stop_eptracer() {
	# let the last events drain from the ring buffers, then stop it the way
	# a user would (Ctrl-C), so the redirect and the probes come down
	sleep 1
	kill -INT "$1" 2>/dev/null
	i=0
	while [ $i -lt 40 ] && kill -0 "$1" 2>/dev/null; do sleep 0.25; i=$((i + 1)); done
	kill -KILL "$1" 2>/dev/null
	wait "$1" 2>/dev/null
}

case "$mode" in
spawn)
	cmd=$1
	shift
	printf '#!/system/bin/sh\n( %s ) > %s/app.out 2> %s/app.err\necho $? > %s/app.rc\n' \
		"$cmd" "$R" "$R" "$R" > "$R/app.sh"
	chmod 755 "$R/app.sh"
	"$EP" -p "$R/app.sh" "$@" > "$R/eptracer.log" 2>&1 &
	epid=$!
	i=0
	while [ $i -lt 160 ] && [ ! -f "$R/app.rc" ] && kill -0 $epid 2>/dev/null; do
		sleep 0.25
		i=$((i + 1))
	done
	stop_eptracer $epid
	;;
package)
	url=$1
	shift
	am force-stop $PKG
	logcat -c
	"$EP" --package $PKG "$@" > "$R/eptracer.log" 2>&1 &
	epid=$!
	# the probes go in before the app exists: give the attach time to finish
	sleep 4
	am start -n $PKG/.E2EActivity --es url "$url" > /dev/null 2>&1
	i=0
	while [ $i -lt 80 ]; do
		logcat -d -s ePtracerE2E:I 2>/dev/null | grep -q 'E2E ' && break
		sleep 0.25
		i=$((i + 1))
	done
	logcat -d -s ePtracerE2E:I > "$R/app.out" 2>&1
	if grep -q 'E2E OK' "$R/app.out"; then echo 0; else echo 1; fi > "$R/app.rc"
	stop_eptracer $epid
	am force-stop $PKG
	;;
*)
	echo "unknown mode $mode" >&2
	exit 2
	;;
esac
chmod -R a+r "$R"
