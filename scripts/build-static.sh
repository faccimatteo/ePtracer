#!/bin/sh
# Builds a fully static (musl) eptracer for the architecture of the machine it
# runs on. The same binary runs on any Linux distribution and directly on
# Android (adb push + su): CO-RE/BTF makes the BPF side portable across
# kernels, musl + -static makes the userspace side portable across userlands.
#
#   scripts/build-static.sh            # runs the build inside an Alpine container
#   scripts/build-static.sh --inside   # (used by the above / by CI) build in place
#
# Output: dist/eptracer-<arch>
set -eu

# pinned by digest (multi-arch index): the release binaries are built in it
ALPINE_IMAGE=${ALPINE_IMAGE:-alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f}
ROOT=$(cd "$(dirname "$0")/.." && pwd)

if [ "${1:-}" != "--inside" ]; then
	# explicit, or a tag pulled once for another architecture would be reused
	case "$(uname -m)" in
	aarch64 | arm64) DOCKER_PLATFORM=${DOCKER_PLATFORM:-linux/arm64} ;;
	*) DOCKER_PLATFORM=${DOCKER_PLATFORM:-linux/amd64} ;;
	esac
	exec docker run --rm --platform "$DOCKER_PLATFORM" \
		-v "$ROOT:/src" -w /src \
		-e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
		"$ALPINE_IMAGE" /src/scripts/build-static.sh --inside
fi

apk add --no-cache \
	bash make clang llvm lld gcc musl-dev linux-headers pkgconf git \
	elfutils-dev zlib-dev zlib-static zstd-dev zstd-static \
	openssl-dev openssl-libs-static nghttp2-dev nghttp2-static \
	libcap-dev cargo rust >/dev/null

git config --global --add safe.directory '*'
cd "$ROOT"
[ -f bpftool/src/Makefile ] || git submodule update --init --recursive

# Build in a private copy: objects already in the tree were built against the
# host libc and must not leak in, and the host tree must not be clobbered
BUILD=${BUILD_DIR:-/tmp/eptracer-build}
rm -rf "$BUILD" && mkdir -p "$BUILD"
tar -C "$ROOT" --exclude=./.output --exclude=./blazesym/target --exclude=./dist \
	--exclude=./eptracer --exclude='*.o' --exclude='*.a' -cf - . | tar -C "$BUILD" -xf -
cd "$BUILD"
ln -sfn bpftool/libbpf libbpf

make -j"$(nproc)" STATIC=1 CC=gcc

arch=$(uname -m)
mkdir -p "$ROOT/dist"
strip -o "$ROOT/dist/eptracer-$arch" eptracer
out="$ROOT/dist/eptracer-$arch"
"$out" --help >/dev/null
echo "[+] dist/eptracer-$arch ($(du -h "$out" | cut -f1))"

[ -n "${HOST_UID:-}" ] && chown -R "$HOST_UID:${HOST_GID:-$HOST_UID}" "$ROOT/dist" || true
