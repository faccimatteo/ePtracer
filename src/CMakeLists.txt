cmake_minimum_required(VERSION 3.10)

project(ePtracer)

# Set the C compiler to clang
set(CMAKE_C_COMPILER clang)

# Defining useful variables
set(PROJECT_SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(PROJECT_BUILD_DIR ${CMAKE_SOURCE_DIR}/build)
set(LOG_SRC_DIR ${CMAKE_SOURCE_DIR}/log/src)

# Add the libraries source directory 
include_directories(${CMAKE_SOURCE_DIR}/lib)

# Building shared library from log repository
add_library(log.so SHARED EXCLUDE_FROM_ALL ${LOG_SRC_DIR}/log.c)

# Building BPF 
add_custom_target(eptracer_bpf_o ALL		        
	COMMAND ${CMAKE_C_COMPILER} -target bpf -I /usr/include/${CMAKE_SYSTEM_PROCESSOR}-linux-gnu -g -O2 -c ${PROJECT_SRC_DIR}/eptracer.bpf.c -o ${CMAKE_BINARY_DIR}/eptracer.bpf.o
	COMMENT "Building BPF program"
)

# Building user space 
add_custom_target(eptracer_o ALL		        
	COMMAND ${CMAKE_C_COMPILER} -g3 -O2 -c ${PROJECT_SRC_DIR}/eptracer.c -o ${CMAKE_BINARY_DIR}/eptracer.o
	DEPENDS bpf_skeleton
	COMMENT "Building user space program"
)

# Generating BPF skeleton header file, containing useful boilerplate functions
add_custom_target(bpf_skeleton ALL
	COMMAND bpftool gen skeleton ${CMAKE_SOURCE_DIR}/build/eptracer.bpf.o > ${PROJECT_SRC_DIR}/lib/bpf/eptracer.skeleton.h
	DEPENDS eptracer_bpf_o
	COMMENT "Building BPF skeleton"
)

# Finally compiling eptracer
add_custom_target(eptracer ALL 
	COMMAND ${CMAKE_C_COMPILER} -Wall -Wextra -Wshadow -O2 -g3 ${PROJECT_BUILD_DIR}/eptracer.o ${CMAKE_SOURCE_DIR}/libbpf/src/build/libbpf.a ${CMAKE_SOURCE_DIR}/argparse/libargparse.so ${CMAKE_SOURCE_DIR}/log/src/log.so ${CMAKE_SOURCE_DIR}/blazesym/target/debug/libblazesym_c.a -lrt -ldl -lpthread -lm -lelf -lz -o ${PROJECT_BUILD_DIR}/eptracer
	DEPENDS eptracer_o
	COMMENT "Building eptracer"
)
