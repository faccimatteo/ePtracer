#!/usr/bin/bash
# flags needed by blazesym
BLAZESYM_FLAGS="-lrt -ldl -lpthread -lm"

bpftool gen skeleton eptracer.bpf.o > ./lib/bpf/eptracer.skeleton.h
clang -Wall -Wextra -Wshadow \
	-O2 -g3 \
	-I . \
	-c eptracer.c \
	-o eptracer.o
clang -Wall -Wextra -Wshadow \
	-O2 -g3 \
	eptracer.o \
	libbpf/build/libbpf/libbpf.a \
	log/src/log.a \
	argparse/libargparse.a \
	blazesym/target/debug/libblazesym_c.a \
	$BLAZESYM_FLAGS \
	-lelf \
	-lz \
	-o eptracer
