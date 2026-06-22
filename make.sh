#!/usr/bin/bash
# Run the following to setup and compile ePtracer within a clean environment
apt update && \
apt upgrade -y && \
apt install -y \
    libbpf-dev \
    binutils-dev \
    libcap-dev \
    libelf-dev \
    libc6 \
    build-essential \
    clang \
    llvm \
    clang-format \
    clang-tidy \
    clang-tools \
    clangd \
    libc++-dev \
    libc++1 \
    libc++abi-dev \
    libc++abi1 \
    libclang-dev \
    libclang1 \
    liblldb-dev \
    libllvm-ocaml-dev \
    libomp-dev \
    libomp5 \
    lld \
    lldb \
    llvm-dev \
    llvm-runtime \
    python3-clang \
    curl