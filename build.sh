#!/usr/bin/env bash
# One-shot build script for ePtracer.
# Installs missing toolchains, fetches submodules and runs the Makefile build.
set -euo pipefail

cd "$(dirname "$0")"

# Build dependencies (clang, llvm, libelf, make, ...) via apt
if ! command -v clang >/dev/null || ! command -v make >/dev/null; then
	echo "[*] Installing build dependencies (requires root)"
	if [ "$(id -u)" -eq 0 ]; then
		./install_deps.sh
	else
		sudo ./install_deps.sh
	fi
fi

# Rust toolchain, needed to build blazesym
if [ -f "$HOME/.cargo/env" ]; then
	. "$HOME/.cargo/env"
fi
if ! command -v cargo >/dev/null; then
	echo "[*] Installing Rust toolchain"
	curl https://sh.rustup.rs -sSf | sh -s -- -y
	. "$HOME/.cargo/env"
fi

# Vendored dependencies (bpftool/libbpf, blazesym, argparse, log.c)
git submodule update --init

# Builds libbpf, bpftool, blazesym, the BPF program + skeleton and the
# userspace binary
make

echo "[+] Build complete: $(pwd)/eptracer"
