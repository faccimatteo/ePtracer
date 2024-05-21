# Use clang to compile bpf program
eptracer.bpf.o: %.o: %.c
	clang \
		-target bpf \
		-I /usr/include/$(shell uname -m)-linux-gnu \
		-g \
		-O2 -c $< -o $@

# ------------------------------------------------

# Use clang to compile userspace program
eptracer.o: %.o: %.c
	clang \
		-Wall \
		-I . \
		-g \
		-O2 -c $< -o $@

