#!/usr/bin/bash
# flags needed by blazesym if linked statically
# BLAZESYM_FLAGS="-lrt -ldl -lpthread -lm"
ROOT_DIR=$(pwd)

# Creates build directory if not already present
mkdir -p build

# initialize essential external repositories
git submodule init
git submodule update

cd ${ROOT_DIR}

# Compile external dependencies

# Blazesym
cd blazesym/capi
cargo build 
cd $ROOT_DIR

# Libbpf
cd libbpf/src
mkdir -p build root
BUILD_STATIC_ONLY=y OBJDIR=build DESTDIR=root make install
cd $ROOT_DIR

# Argparse
cd argparse
make 
cd $ROOT_DIR

# Compile user land and BPF programs using CMake
cd build && cmake ..
make
