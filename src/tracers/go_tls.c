/*
 * Reading the plaintext out of a Go program.
 *
 * Go is the one stack where covering another ABI is not enough. It links its
 * TLS in statically, so there is no shared object to hook; it passes arguments
 * in registers of its own choosing rather than following the C ABI; and a
 * uretprobe on Go code is not merely awkward but unsafe — the kernel builds
 * one by replacing the return address on the stack with a trampoline, and the
 * Go runtime walks its own frames by return address every time it grows,
 * shrinks or copies a goroutine stack. It finds an address belonging to no
 * function it knows, and panics. Attaching one is a way of crashing the
 * process being observed.
 *
 * So the return is probed where it actually is: on the RET instructions of
 * crypto/tls.(*Conn).Read. Finding them means decoding the function, because
 * scanning for the byte 0xC3 is not the same thing as finding a RET — in
 * Docker's own Conn.Read there are nine of those bytes and seven returns, and
 * a uprobe placed on one of the two impostors would write a breakpoint into
 * the middle of an instruction and take the process down with it.
 *
 * Hence the length decoder below. It walks the function from its first byte,
 * and everything it produces is checked before anything is attached: if the
 * walk does not land exactly on the last byte of the function, or meets an
 * opcode it cannot size, the read probes are not installed at all. Writes are
 * captured either way — they need no return probe, since the plaintext is
 * already in the buffer when the call is made.
 */

#include <fcntl.h>
#include <elf.h>
#include <gelf.h>
#include <libelf.h>

/* Most RET instructions a single function is expected to have */
#define GO_MAX_RETS         64
/* Refuse to decode anything bigger: a Conn.Read is a few kilobytes at most */
#define GO_MAX_FUNC_SIZE    (256 * 1024)
/* Symbols carrying the plaintext */
#define GO_TLS_WRITE_SYM    "crypto/tls.(*Conn).Write"
#define GO_TLS_READ_SYM     "crypto/tls.(*Conn).Read"
/* Section holding the version stamp, and the magic that opens it */
#define GO_BUILDINFO_SEC    ".go.buildinfo"
#define GO_BUILDINFO_MAGIC  "\xff Go buildinf:"
#define GO_BUILDINFO_MAGIC_LEN 14
/* Bit set in the buildinfo flags when the strings are stored inline */
#define GO_BUILDINFO_INLINE 0x02
#define GO_BUILDINFO_STRINGS_OFF 32

/* Where a symbol lives, both in memory and in the file */
struct go_symbol {
	__u64 vaddr;
	__u64 size;
	__u64 file_off;
};

#include "x86_insn.h"

/*
 * go_find_rets
 *
 * Description:
 * Walks a function instruction by instruction and records the offset of every
 * return. The walk is the whole point: a byte equal to 0xC3 inside a
 * displacement or an immediate is not a RET, and a probe placed on one would
 * write a breakpoint into the middle of an instruction.
 *
 * On architectures with fixed width instructions there is nothing to decode:
 * arm64 returns are a single aligned word.
 *
 * Params:
 * const unsigned char *code: function body.
 * size_t size: its length, from the symbol table.
 * __u64 *rets: array receiving the offsets.
 * int max_rets: its capacity.
 *
 * Return:
 * Number of returns found, -1 when the function could not be decoded end to
 * end — in which case nothing may be attached to it.
 * */
static int go_find_rets(const unsigned char *code, size_t size, __u64 *rets, int max_rets)
{
	size_t pos = 0;
	int found = 0;

#if defined(__x86_64__) || defined(__i386__)
	while (pos < size) {
		size_t len = x86_insn_len(code + pos, size - pos);

		if (len == 0)
			return -1;
		/* RET, and RET imm16 */
		if (code[pos] == 0xc3 || code[pos] == 0xc2) {
			if (found >= max_rets)
				return -1;
			rets[found++] = pos;
		}
		pos += len;
	}

	/* Landing anywhere but exactly on the end means the walk went off the
	 * rails somewhere, and every offset it produced is suspect */
	if (pos != size)
		return -1;
#elif defined(__aarch64__)
	if (size % 4)
		return -1;
	for (pos = 0; pos < size; pos += 4) {
		__u32 insn = (__u32)code[pos] | ((__u32)code[pos + 1] << 8) |
			     ((__u32)code[pos + 2] << 16) | ((__u32)code[pos + 3] << 24);

		/* RET {x30}, and RET with any other register in Rn */
		if ((insn & 0xfffffc1fu) == 0xd65f0000u) {
			if (found >= max_rets)
				return -1;
			rets[found++] = pos;
		}
	}
#else
	(void)code;
	(void)size;
	(void)rets;
	(void)max_rets;
	return -1;
#endif

	return found;
}

/*
 * go_lookup_symbol
 *
 * Description:
 * Finds a symbol in an ELF file and works out where its body sits in the file,
 * so that it can be read and decoded. Both symbol tables are searched: a Go
 * binary keeps its own in .symtab, which survives as long as it was not
 * stripped.
 *
 * Params:
 * Elf *elf: open ELF handle.
 * const char *name: symbol to find.
 * struct go_symbol *out: filled on success.
 *
 * Return:
 * 0 on success, -1 when the symbol is not there.
 * */
static int go_lookup_symbol(Elf *elf, const char *name, struct go_symbol *out)
{
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
	int found = 0;

	while (!found && (scn = elf_nextscn(elf, scn)) != NULL) {
		Elf_Data *data = NULL;
		size_t i = 0, count = 0;

		if (!gelf_getshdr(scn, &shdr))
			continue;
		if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM)
			continue;

		data = elf_getdata(scn, NULL);
		if (!data || shdr.sh_entsize == 0)
			continue;

		count = shdr.sh_size / shdr.sh_entsize;
		for (i = 0; i < count; i++) {
			GElf_Sym sym;
			const char *sym_name = NULL;

			if (!gelf_getsym(data, (int)i, &sym))
				continue;
			if (GELF_ST_TYPE(sym.st_info) != STT_FUNC || sym.st_size == 0)
				continue;
			sym_name = elf_strptr(elf, shdr.sh_link, sym.st_name);
			if (!sym_name || strcmp(sym_name, name) != 0)
				continue;

			out->vaddr = sym.st_value;
			out->size  = sym.st_size;
			found = 1;
			break;
		}
	}

	if (!found)
		return -1;

	/* Turn the virtual address into a file offset through the section that
	 * contains it: a function always lives in an allocated, mapped one */
	scn = NULL;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		if (!gelf_getshdr(scn, &shdr))
			continue;
		if (!(shdr.sh_flags & SHF_ALLOC) || shdr.sh_type == SHT_NOBITS)
			continue;
		if (out->vaddr < shdr.sh_addr || out->vaddr >= shdr.sh_addr + shdr.sh_size)
			continue;
		out->file_off = shdr.sh_offset + (out->vaddr - shdr.sh_addr);
		return 0;
	}

	return -1;
}

/*
 * go_read_version
 *
 * Description:
 * Reads the toolchain stamp out of .go.buildinfo. Only the register ABI, in
 * use since Go 1.17, puts the arguments where the probes look for them, so a
 * binary older than that is worth a word of warning.
 *
 * Params:
 * Elf *elf: open ELF handle.
 * char *out: buffer receiving the version, e.g. "go1.26.8".
 * size_t out_size: its size.
 *
 * Return:
 * 0 when a version was read, -1 otherwise.
 * */
static int go_read_version(Elf *elf, char *out, size_t out_size)
{
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
	size_t shstrndx = 0;

	if (elf_getshdrstrndx(elf, &shstrndx) != 0)
		return -1;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		Elf_Data *data = NULL;
		const unsigned char *blob = NULL;
		const char *sec_name = NULL;
		size_t len = 0;

		if (!gelf_getshdr(scn, &shdr))
			continue;
		sec_name = elf_strptr(elf, shstrndx, shdr.sh_name);
		if (!sec_name || strcmp(sec_name, GO_BUILDINFO_SEC) != 0)
			continue;

		data = elf_getdata(scn, NULL);
		if (!data || data->d_size < GO_BUILDINFO_STRINGS_OFF + 2)
			return -1;

		blob = (const unsigned char *)data->d_buf;
		if (memcmp(blob, GO_BUILDINFO_MAGIC, GO_BUILDINFO_MAGIC_LEN) != 0)
			return -1;
		/* Only the inline form is read: the older one stores pointers
		 * into the data segment, and the version is a nicety anyway */
		if (!(blob[15] & GO_BUILDINFO_INLINE))
			return -1;

		/* A varint length, which for any plausible version is one byte */
		len = blob[GO_BUILDINFO_STRINGS_OFF];
		if (len == 0 || len >= out_size || len & 0x80)
			return -1;
		if (GO_BUILDINFO_STRINGS_OFF + 1 + len > data->d_size)
			return -1;

		memcpy(out, blob + GO_BUILDINFO_STRINGS_OFF + 1, len);
		out[len] = '\0';
		return 0;
	}

	return -1;
}

/*
 * go_version_has_register_abi
 *
 * Description:
 * Tells whether a version stamp is Go 1.17 or later, which is when arguments
 * moved from the stack into registers.
 *
 * Params:
 * const char *version: stamp as read from the binary, e.g. "go1.26.8".
 *
 * Return:
 * 1 when the register ABI applies, 0 when it does not.
 * */
static int go_version_has_register_abi(const char *version)
{
	int major = 0, minor = 0;

	if (!version || sscanf(version, "go%d.%d", &major, &minor) != 2)
		return 1;   /* unreadable: assume a modern toolchain */
	if (major > 1)
		return 1;
	return minor >= 17;
}

/*
 * attach_go_tls
 *
 * Description:
 * Installs the Go plaintext probes on one executable. Writes are hooked at the
 * entry of crypto/tls.(*Conn).Write, where the buffer already holds what the
 * caller wants sent. Reads need the return, which is probed on the RET
 * instructions of crypto/tls.(*Conn).Read rather than with a uretprobe, since
 * the Go runtime walks its own stack by return address and a trampoline in
 * there makes it panic.
 *
 * Nothing is attached to the read path unless the function decoded cleanly
 * from its first byte to its last: an offset that is not an instruction
 * boundary would put a breakpoint inside an instruction.
 *
 * Params:
 * struct eptracer_bpf *skel: loaded BPF skeleton.
 * const char *path: executable to hook.
 *
 * Return:
 * Number of probes installed.
 * */
static int attach_go_tls(struct eptracer_bpf *skel, const char *path)
{
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
	struct go_symbol write_sym = {0}, read_sym = {0};
	struct bpf_link *link = NULL;
	unsigned char *body = NULL;
	__u64 rets[GO_MAX_RETS];
	char version[64] = {0};
	Elf *elf = NULL;
	FILE *file = NULL;
	int fd = -1, attached = 0, ret_count = 0, i = 0, have_version = 0;

	if (elf_version(EV_CURRENT) == EV_NONE)
		return 0;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf) {
		close(fd);
		return 0;
	}

	/* Neither symbol means this is not a Go program linking crypto/tls, or
	 * that it was stripped of the symbol table it would take to find them */
	if (go_lookup_symbol(elf, GO_TLS_WRITE_SYM, &write_sym) < 0 &&
	    go_lookup_symbol(elf, GO_TLS_READ_SYM, &read_sym) < 0)
		goto out;

	have_version = go_read_version(elf, version, sizeof(version)) == 0;
	if (have_version && !go_version_has_register_abi(version)) {
		log_error("[!] %s was built with %s, which still passes arguments on "
			  "the stack: its TLS cannot be read this way", path, version);
		goto out;
	}

	/* Write: the plaintext is in the buffer when the call is made, so the
	 * entry probe alone is enough and no return has to be caught */
	if (write_sym.size || go_lookup_symbol(elf, GO_TLS_WRITE_SYM, &write_sym) == 0) {
		if (http_link_count + 1 <= MAX_HTTP_LINKS) {
			uprobe_opts.func_name = GO_TLS_WRITE_SYM;
			uprobe_opts.retprobe = false;
			link = bpf_program__attach_uprobe_opts(skel->progs.probe_go_tls_write,
							       -1, path, 0, &uprobe_opts);
			if (link) {
				http_links[http_link_count++] = link;
				attached++;
			} else {
				log_debug("[?] %s not hooked in %s: %s", GO_TLS_WRITE_SYM,
					  path, strerror(errno));
			}
		}
	}

	if (!read_sym.size && go_lookup_symbol(elf, GO_TLS_READ_SYM, &read_sym) < 0)
		goto done;

	if (read_sym.size > GO_MAX_FUNC_SIZE) {
		log_error("[!] %s is %llu bytes in %s, refusing to decode it",
			  GO_TLS_READ_SYM, (unsigned long long)read_sym.size, path);
		goto done;
	}

	body = malloc(read_sym.size);
	if (!body)
		goto done;

	file = fopen(path, "rb");
	if (!file)
		goto done;
	if (fseek(file, (long)read_sym.file_off, SEEK_SET) != 0 ||
	    fread(body, 1, read_sym.size, file) != read_sym.size)
		goto done;

	ret_count = go_find_rets(body, read_sym.size, rets, GO_MAX_RETS);
	if (ret_count <= 0) {
		/* Deliberately conservative: a partial decode is not a partial
		 * result, it is a set of offsets that may not be instruction
		 * boundaries, and attaching to one of those crashes the target */
		log_error("[!] Could not decode %s in %s: its responses will not be "
			  "captured (requests still are)", GO_TLS_READ_SYM, path);
		goto done;
	}

	if (http_link_count + 1 > MAX_HTTP_LINKS)
		goto done;

	uprobe_opts.func_name = GO_TLS_READ_SYM;
	uprobe_opts.retprobe = false;
	link = bpf_program__attach_uprobe_opts(skel->progs.probe_go_tls_read_enter,
					       -1, path, 0, &uprobe_opts);
	if (!link) {
		log_debug("[?] %s not hooked in %s: %s", GO_TLS_READ_SYM, path,
			  strerror(errno));
		goto done;
	}
	http_links[http_link_count++] = link;
	attached++;

	for (i = 0; i < ret_count; i++) {
		if (http_link_count + 1 > MAX_HTTP_LINKS)
			break;
		uprobe_opts.func_name = GO_TLS_READ_SYM;
		uprobe_opts.retprobe = false;
		link = bpf_program__attach_uprobe_opts(skel->progs.probe_go_tls_read_ret,
						       -1, path, (size_t)rets[i], &uprobe_opts);
		if (!link) {
			log_error("[!] Cannot probe the return at +0x%llx of %s: %s",
				  (unsigned long long)rets[i], GO_TLS_READ_SYM,
				  strerror(errno));
			continue;
		}
		http_links[http_link_count++] = link;
		attached++;
	}

	log_debug("[+] %s decoded: %d returns probed", GO_TLS_READ_SYM, ret_count);

done:
	if (attached > 0)
		log_info("[+] Go crypto/tls plaintext hooked in %s%s%s", path,
			 have_version ? ", built with " : "", have_version ? version : "");
out:
	free(body);
	if (file)
		fclose(file);
	elf_end(elf);
	close(fd);
	return attached;
}
