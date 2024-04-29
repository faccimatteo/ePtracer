#!/usr/bin/bash
# flags needed by blazesym if linked statically
BLAZESYM_FLAGS="-lrt -ldl -lpthread -lm"
ROOT_DIR=$(pwd)

# initialize essential external repositories
git submodule init

# creating file necessary for BPF relocation
bpftool gen skeleton eptracer.bpf.o > ./lib/bpf/eptracer.skeleton.h

# Dynamically compile external dependencies

# Blazesym
cd blazesym/capi
cargo build 
cd $ROOT_DIR

#Libbpf
cd libbpf/src
mkdir build root
BUILD_STATIC_ONLY=y OBJDIR=build DESTDIR=root make install
cd $ROOT_DIR

# Argparse
cd argparse
make 
cd $ROOT_DIR

# Log
clang -shared -undefined dynamic_lookup -o log/src/log.so log/src/log.c

clang -Wall -Wextra -Wshadow \
	-O2 -g3 \
	-I . \
	-c eptracer.c \
	-o eptracer.o
# libbpf is statically liked to use not exported function parse_cpu_mask_file
clang -Wall -Wextra -Wshadow \
	-O2 -g3 \
	eptracer.o \
	libbpf/src/build/libbpf.a \
	argparse/libargparse.so \
	log/src/log.so \
	blazesym/target/debug/libblazesym_c.so \
	-lelf \
	-lz \
	-o eptracer
