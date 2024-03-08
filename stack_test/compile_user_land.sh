#!/usr/bin/bash
bpftool gen skeleton get_stacktrace.bpf.o > get_stacktrace.skeleton.h
clang -g -O2 -Wall -I . -c get_stacktrace.c -o get_stacktrace.o
clang -Wall -O2 -g get_stacktrace.o libbpf/build/libbpf/libbpf.a log/src/log.a -lelf -lz -o get_stacktrace
