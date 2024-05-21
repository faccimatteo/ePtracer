# Use clang to compile bpf program
eptracer.bpf.o: ./build/%.o: ./src/eptracer.bpf.c
	clang \
		-target bpf \
		-I /usr/include/$(shell uname -m)-linux-gnu \
		-g \
		-O2 -c $< -o $@

# Use clang to compile userspace program
eptracer.o: ./build/%.o: ./src/%.c
	clang \
		-Wall \
		-I . \
		-g \
		-O2 -c $< -o $@

# Create build directory if it doesn't exist
.PHONY: prepare_build
prepare_build:
	mkdir -p build

# Clean up build directory
clean:
	rm -rf ./build/*

