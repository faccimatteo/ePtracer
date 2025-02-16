# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT 				:= .output
CLANG 				?= clang
OUTPUT_BIN			:= release 
SRC 				:= $(abspath ./src)
HEADERS_SRC 		:= $(abspath ./src/include)
LIBBLAZESYM_SRC 	:= $(abspath ./blazesym)
LIBBLAZESYM_HEADER 	:= $(abspath $(LIBBLAZESYM_SRC)/capi/include)
LIBBLAZESYM_OBJ 	:= $(abspath ./blazesym/target/release/libblazesym_c.a)
LIBBPF_SRC 			:= $(abspath ./libbpf/src)
LIBARGPARSE_SRC		:= $(abspath ./argparse)
LIBARGPARSE_OBJ		:= $(abspath $(LIBARGPARSE_SRC)/libargparse.a)
LIBLOG_SRC 			:= $(abspath ./log.c/src)
LIBLOG_OBJ			:= $(LIBLOG_SRC)/log.a
BPFTOOL_SRC 		:= $(abspath ./bpftool/src)
LIBBPF_OBJ 			:= $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT 		?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL 			?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
# CROSS_COMPILE		?= "" 
ARCH 				?= $(shell uname -m | sed 's/x86_64/x86/' \
	 				   	 | sed 's/arm.*/arm/' \
	 				   	 | sed 's/aarch64/arm64/' \
	 				   	 | sed 's/ppc64le/powerpc/' \
	 				   	 | sed 's/mips.*/mips/' \
	 				   	 | sed 's/riscv64/riscv/' \
	 				   	 | sed 's/loongarch64/loongarch/')
VMLINUX 			:= ./vmlinux/$(ARCH)/vmlinux.h
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES 			:= -I$(OUTPUT) -I./libbpf/include/uapi \
					   -I$(dir $(VMLINUX)) -I$(HEADERS_SRC)

CFLAGS 				:= -O2 -Wall -Wformat -Wformat=2 -Wconversion -Wimplicit-fallthrough \
						-Werror=format-security \
						-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 \
						-D_GLIBCXX_ASSERTIONS \
						-fstrict-flex-arrays=3 \
						-fstack-clash-protection -fstack-protector-strong \
						-Wl,-z,nodlopen -Wl,-z,noexecstack \
						-Wl,-z,relro -Wl,-z,now \
						-Wl,--as-needed -Wl,--no-copy-dt-needed-entries
ALL_LDFLAGS 		:= $(LDFLAGS) $(EXTRA_LDFLAGS) -static

APPS 				= eptracer 

CARGO 				?= $(shell which cargo)

ALL_LDFLAGS 		+= -lzstd -lutil -lrt -lpthread -lm -ldl -lc

ifeq ($(strip $(CARGO)),)
BZS_APPS :=
else
BZS_APPS 			:= # profile
APPS 				+= $(BZS_APPS)
# Required by libblazesym when linking statically
endif

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)
	$(MAKE) -C $(LIBARGPARSE_SRC) clean
	$(shell rm libbpf)

# Build output dirs 
$(OUTPUT) $(OUTPUT)/libbpf $(OUTPUT)/log $(OUTPUT)/argparse $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build log
LIBLOG_FLAGS 		:= -fPIC -DLOG_USE_COLOR
$(LIBLOG_OBJ): $(LIBLOG_SRC)/log.c
	$(call msg,LIB,$@)
	$(Q)$(CLANG) -o $(LIBLOG_SRC)/log.o -c $(LIBLOG_FLAGS) $^
	$(Q)$(AR) rcs $(LIBLOG_OBJ) $(LIBLOG_SRC)/log.o

# Build argparse
$(LIBARGPARSE_OBJ): $(LIBARGPARSE_SRC)
	$(Q)$(MAKE) -C $^ BUILD_STATIC_ONLY=1 OBJDIR=$(dir $@)
	$(call msg,LIB,$@)
	$(Q)cp $(LIBARGPARSE_OBJ) $(OUTPUT)
	
# Create libbpf symlink from bpftool if it does not exists
LIBBPF_PATH := ./libbpf
ifeq (,$(wildcard $(LIBBPF_PATH)))
$(shell ln -s $(abspath ./bpftool/libbpf) libbpf)
endif

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		\
		OBJDIR=$(dir $@)libbpf DESTDIR=$(dir $@)			\
		INCLUDEDIR= LIBDIR= UAPIDIR= ARCH=arm64				\
		install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# Building blazesym
$(LIBBLAZESYM_OBJ): 
	$(Q)cd $(LIBBLAZESYM_SRC)/capi && $(CARGO) build --release
	$(call msg,LIB,$@)
	$(Q)cp $@ $(OUTPUT)

# Copying blazesym headers
$(LIBBLAZESYM_HEADER):
	$(call msg,LIB,$@)
	$(Q)cp $(LIBBLAZESYM_SRC)/target/release/blazesym.h $@

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@
	$(Q) cp $@ $(abspath ./src/include/bpf)

# Build BPF code
$(OUTPUT)/%.bpf.o: $(SRC)/%.bpf.c $(LIBBPF_OBJ) $(wildcard $(OUTPUT)/%.skel.h) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -Xlinker --export-dynamic -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# Build userspace code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: $(SRC)/%.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(patsubst %,$(OUTPUT)/%.o,$(BZS_APPS)): $(LIBBLAZESYM_HEADER)

$(BZS_APPS): $(LIBBLAZESYM_OBJ)

# Build application binary
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) $(LIBBLAZESYM_OBJ) $(LIBARGPARSE_OBJ) $(LIBLOG_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $^ $(ALL_LDFLAGS) -lelf -lz -o $@ 
