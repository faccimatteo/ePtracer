#!/usr/bin/bash
# flags needed by blazesym
BLAZESYM_FLAGS="-lrt -ldl -lpthread -lm"

bpftool gen skeleton eptracer.bpf.o > eptracer.skeleton.h
clang -Wall -O2 -g \
	-I . \
	-c eptracer.c \
	-o eptracer.o
clang -Wall -O2 -g \
	eptracer.o \
	libbpf/build/libbpf/libbpf.a \
	log/src/log.a \
	argparse/libargparse.a \
	blazesym/target/debug/libblazesym_c.a \
	$BLAZESYM_FLAGS \
	-lelf \
	-lz \
	-o eptracer
