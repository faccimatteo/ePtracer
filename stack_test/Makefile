get_stacktrace.bpf.o: %.o: %.c
	clang \
		-target bpf \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g \
		-O2 -c $< -o $@

# ------------------------------------------------

get_stacktrace.o: %.o: %.c
	clang \
		-Wall \
		-I . \
		-g \
		-O2 -c $< -o $@

