#!/usr/bin/env bash
# Distribution matrix: the static binary against the TLS libraries a given
# distribution ships (OpenSSL 1.1/3.x, GnuTLS, their paths), on the host kernel.
#
#   tests/distro/run.sh IMAGE [run.sh options]     e.g. tests/distro/run.sh debian:12
#
# The container is privileged and shares the host PID and cgroup namespaces:
# ePtracer filters by the PIDs the kernel sees, which are the host's, and -I
# attaches to the cgroup hierarchy the kernel uses. Results land in
# ${OUT:-/tmp/eptracer-distro}/<image>/results.tsv.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
image="$1"; shift
tag="$(echo "$image" | tr '/:' '__')"
out="${OUT:-/tmp/eptracer-distro}/$tag"
mkdir -p "$out"

install='
if command -v apt-get >/dev/null; then
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq && apt-get install -y -qq --no-install-recommends \
		bash python3 openssl curl gnutls-bin ca-certificates procps >/dev/null
elif command -v dnf >/dev/null; then
	dnf install -y -q --allowerasing bash python3 openssl curl gnutls-utils procps-ng >/dev/null
elif command -v apk >/dev/null; then
	apk add -q bash python3 openssl curl gnutls-utils procps
elif command -v pacman >/dev/null; then
	pacman -Sy --noconfirm --needed bash python openssl curl gnutls procps-ng >/dev/null
elif command -v zypper >/dev/null; then
	zypper -n -q in bash python3 openssl curl gnutls procps >/dev/null
fi
mountpoint -q /sys/kernel/tracing 2>/dev/null || mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || true
mountpoint -q /sys/kernel/debug 2>/dev/null || mount -t debugfs nodev /sys/kernel/debug 2>/dev/null || true
. /etc/os-release 2>/dev/null && echo "userland: $PRETTY_NAME"
'

# the image for this machine's architecture, always: a tag once pulled for
# another one would otherwise run emulated, where uprobes cannot work
case "$(uname -m)" in
aarch64 | arm64) platform=linux/arm64 ;;
*) platform=linux/amd64 ;;
esac

docker run --rm --platform "$platform" --privileged --pid=host --cgroupns=host \
	-v "$root:/src:ro" -v "$out:/out" \
	-e EPTRACER="/src/dist/eptracer-$(uname -m)" -e GO_CLIENT="${GO_CLIENT:+/src/${GO_CLIENT#$root/}}" \
	"$image" sh -c "$install
exec bash /src/tests/e2e/run.sh --out /out $*"
