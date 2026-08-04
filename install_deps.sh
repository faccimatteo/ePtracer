#!/usr/bin/bash
# Run the following to setup and compile ePtracer within a clean environment
apt update && \
apt upgrade -y && \
apt install -y \
    git \
    make \
    pkg-config \
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
    curl \
    libcurl4-openssl-dev \
    libnghttp2-dev \
    libidn2-dev \
    librtmp-dev \
    libssh-dev \
    libpsl-dev \
    libssl-dev \
    libzstd-dev \
    zlib1g-dev \
    libgnutls28-dev \
    libsasl2-dev \
    libtasn1-6-dev \
    libffi-dev \
    libbrotli-dev \
    libldap-dev \
    libkrb5-dev