/*
 * String-anchor resolution of a TLS stack's keylog function — see
 * include/tls_anchor.h.
 */

#include "tls_anchor.h"
#include "x86_insn.h"

#include <fcntl.h>
#include <gelf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <libelf.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* NSS keylog labels. EXPORTER_SECRET is also the tail of EARLY_EXPORTER_SECRET,
 * and a linker merging string tails makes both addresses real references. */
static const char *const anchor_labels[] = {
	"CLIENT_RANDOM",
	"CLIENT_EARLY_TRAFFIC_SECRET",
	"CLIENT_HANDSHAKE_TRAFFIC_SECRET",
	"SERVER_HANDSHAKE_TRAFFIC_SECRET",
	"CLIENT_TRAFFIC_SECRET_0",
	"SERVER_TRAFFIC_SECRET_0",
	"EXPORTER_SECRET",
	"EARLY_EXPORTER_SECRET",
};
#define ANCHOR_NLABELS (sizeof(anchor_labels) / sizeof(*anchor_labels))

/* A label can be found at several addresses (duplicated rodata, tail merges) */
#define ANCHOR_MAX_LABEL_ADDRS 64
/* Distinct call targets tallied */
#define ANCHOR_MAX_TARGETS     256
/* How far past the label load the call is looked for */
#define ANCHOR_MAX_WALK        32

unsigned tls_anchor_label_count(void) { return ANCHOR_NLABELS; }

const char *tls_anchor_label_name(unsigned i)
{
	return i < ANCHOR_NLABELS ? anchor_labels[i] : NULL;
}

/* ---- vote tally -------------------------------------------------------- */

/* A target is tallied per ABI: the same function voted for with the label in
 * two different registers would be two different readings of its arguments */
struct anchor_votes {
	struct { uint64_t target; unsigned abi; unsigned mask; unsigned count; } t[ANCHOR_MAX_TARGETS];
	size_t n;
};

static void anchor_vote(struct anchor_votes *v, uint64_t target, unsigned abi,
			unsigned label_index)
{
	for (size_t i = 0; i < v->n; i++)
		if (v->t[i].target == target && v->t[i].abi == abi) {
			v->t[i].mask |= 1u << label_index;
			v->t[i].count++;
			return;
		}
	if (v->n == ANCHOR_MAX_TARGETS)
		return;
	v->t[v->n].target = target;
	v->t[v->n].abi = abi;
	v->t[v->n].mask = 1u << label_index;
	v->t[v->n].count = 1;
	v->n++;
}

static int anchor_pick_best(const struct anchor_votes *v, struct tls_anchor_hit *out)
{
	int best = -1;
	unsigned best_labels = 0, best_count = 0;

	for (size_t i = 0; i < v->n; i++) {
		unsigned labels = (unsigned)__builtin_popcount(v->t[i].mask);
		if (labels > best_labels ||
		    (labels == best_labels && v->t[i].count > best_count)) {
			best = (int)i;
			best_labels = labels;
			best_count = v->t[i].count;
		}
	}
	if (best < 0 || best_labels < TLS_ANCHOR_MIN_LABELS)
		return 1;

	memset(out, 0, sizeof(*out));
	out->vaddr = v->t[best].target;
	out->abi = (enum tls_keylog_abi)v->t[best].abi;
	out->label_mask = v->t[best].mask;
	out->labels = best_labels;
	out->votes = best_count;
	return 0;
}

static int anchor_label_at(const struct tls_anchor_label *labels, size_t n, uint64_t addr)
{
	for (size_t i = 0; i < n; i++)
		if (labels[i].vaddr == addr)
			return (int)labels[i].index;
	return -1;
}

static uint32_t anchor_rd32le(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/* ---- x86-64 ------------------------------------------------------------ */

/* Does this instruction (no REX.B/REX.R, so the plain encodings) write
 * register `r` (6 rsi, 7 rdi)? A label loaded into the argument register and
 * then overwritten is not the argument of the call that follows. Only the
 * common forms are recognized; missing one can at worst add a stray vote, which
 * the distinct-label rule absorbs. */
static int anchor_x86_writes_reg(const uint8_t *p, size_t n, unsigned r)
{
	size_t i = 0;
	int rex_rb = 0;
	if (n && p[0] >= 0x40 && p[0] <= 0x4f) {
		rex_rb = p[0] & 0x05;   /* REX.R | REX.B: an extended register */
		i = 1;
	}
	if (i + 1 >= n || rex_rb)
		return 0;
	uint8_t op = p[i], modrm = p[i + 1];
	unsigned mod = modrm >> 6, reg = (modrm >> 3) & 7, rm = modrm & 7;

	if ((op == 0x8b || op == 0x8d) && reg == r)          /* mov/lea r, ... */
		return 1;
	if ((op == 0x89 || op == 0x31 || op == 0x33) && mod == 3 &&
	    (op == 0x33 ? reg : rm) == r)                      /* mov/xor r as dest */
		return 1;
	if (op == 0xb8 + r)                                   /* mov r32, imm32 */
		return 1;
	return 0;
}

static void anchor_scan_x86(const uint8_t *code, size_t len, uint64_t vaddr,
		     const struct tls_anchor_label *labels, size_t nlabels,
		     struct anchor_votes *v)
{
	for (size_t i = 0; i + 7 <= len; i++) {
		/* lea r64, [rip + disp32]: REX.W (0x48, or 0x4c with REX.R), 8d,
		 * ModR/M with mod 00 and rm 101 */
		if ((code[i] != 0x48 && code[i] != 0x4c) || code[i + 1] != 0x8d ||
		    (code[i + 2] & 0xc7) != 0x05)
			continue;
		unsigned reg = ((code[i + 2] >> 3) & 7) | (code[i] == 0x4c ? 8u : 0u);
		int32_t disp = (int32_t)anchor_rd32le(code + i + 3);
		uint64_t target = vaddr + i + 7 + (uint64_t)(int64_t)disp;

		int li = anchor_label_at(labels, nlabels, target);
		/* rsi: the label is the second argument (ssl_log_secret); rdi:
		 * the first (nss_keylog_int, ssl_log_secret inlined) */
		if (li < 0 || (reg != 6 && reg != 7))
			continue;
		unsigned abi = reg == 6 ? TLS_KEYLOG_ABI_LOG_SECRET : TLS_KEYLOG_ABI_NSS_INT;

		size_t pos = i + 7;
		for (int k = 0; k < ANCHOR_MAX_WALK && pos < len; k++) {
			uint8_t op = code[pos];
			/* `addr32 call rel32`: the linker relaxes a call through the
			 * GOT to a local function into this 6-byte form (Alpine) */
			size_t pfx = op == 0x67 && pos + 1 < len && code[pos + 1] == 0xe8;
			if (pfx)
				op = 0xe8;
			if ((op == 0xe8 || op == 0xe9) && pos + pfx + 5 <= len) {
				/* call rel32, or jmp rel32 as a tail call */
				int32_t rel = (int32_t)anchor_rd32le(code + pos + pfx + 1);
				uint64_t dst = vaddr + pos + pfx + 5 + (uint64_t)(int64_t)rel;
				if (dst >= vaddr && dst < vaddr + len)
					anchor_vote(v, dst, abi, (unsigned)li);
				break;
			}
			if (op == 0xc3 || op == 0xeb)    /* ret, short jmp: path ends */
				break;
			size_t n = x86_insn_len(code + pos, len - pos);
			if (n == 0 || anchor_x86_writes_reg(code + pos, n, reg))
				break;
			pos += n;
		}
	}
}

/* ---- arm64 ------------------------------------------------------------- */

static int64_t anchor_sext(uint64_t v, unsigned bits)
{
	uint64_t m = 1ULL << (bits - 1);
	return (int64_t)((v ^ m) - m);
}

static void anchor_scan_arm64(const uint8_t *code, size_t len, uint64_t vaddr,
		       const struct tls_anchor_label *labels, size_t nlabels,
		       struct anchor_votes *v)
{
	for (size_t i = 0; i + 4 <= len; i += 4) {
		uint32_t insn = anchor_rd32le(code + i);
		if ((insn & 0x9f000000) != 0x90000000)          /* adrp */
			continue;
		unsigned rd = insn & 0x1f;
		uint64_t imm = (uint64_t)((insn >> 5) & 0x7ffff) << 2 | ((insn >> 29) & 3);
		uint64_t pc = vaddr + i;
		uint64_t page = (pc & ~0xfffULL) + (uint64_t)(anchor_sext(imm, 21) * 4096);

		/* the matching add usually follows at once, sometimes a few later */
		for (size_t j = i + 4; j < i + 20 && j + 4 <= len; j += 4) {
			uint32_t a = anchor_rd32le(code + j);
			if ((a & 0xff800000) != 0x91000000)       /* add xd, xn, #imm12 */
				continue;
			if (((a >> 5) & 0x1f) != rd)
				continue;
			uint64_t addr = page + ((a >> 10) & 0xfff);
			int li = anchor_label_at(labels, nlabels, addr);
			/* x1: second argument (ssl_log_secret); x0: first
			 * (nss_keylog_int) */
			if (li < 0 || (a & 0x1f) > 1)
				break;
			unsigned abi = (a & 0x1f) == 1 ? TLS_KEYLOG_ABI_LOG_SECRET
						       : TLS_KEYLOG_ABI_NSS_INT;

			for (size_t k = j + 4, w = 0; w < ANCHOR_MAX_WALK && k + 4 <= len;
			     k += 4, w++) {
				uint32_t b = anchor_rd32le(code + k);
				if ((b & 0x7c000000) == 0x14000000) {   /* bl / b imm26 */
					int64_t off = anchor_sext(b & 0x3ffffff, 26) * 4;
					uint64_t dst = vaddr + k + (uint64_t)off;
					if (dst >= vaddr && dst < vaddr + len)
						anchor_vote(v, dst, abi, (unsigned)li);
					break;
				}
				if (b == 0xd65f03c0)                   /* ret */
					break;
			}
			break;
		}
	}
}

int tls_anchor_scan_code(enum tls_anchor_arch arch,
			 const uint8_t *code, size_t len, uint64_t code_vaddr,
			 const struct tls_anchor_label *labels, size_t nlabels,
			 struct tls_anchor_hit *out)
{
	struct anchor_votes *v = calloc(1, sizeof(*v));
	if (!v)
		return -1;
	if (arch == TLS_ANCHOR_X86_64)
		anchor_scan_x86(code, len, code_vaddr, labels, nlabels, v);
	else
		anchor_scan_arm64(code, len, code_vaddr, labels, nlabels, v);
	int r = anchor_pick_best(v, out);
	free(v);
	return r;
}

/* ---- ELF --------------------------------------------------------------- */

static size_t anchor_find_labels(Elf *elf, struct tls_anchor_label *out, size_t cap)
{
	size_t n = 0;
	Elf_Scn *scn = NULL;
	GElf_Shdr sh;

	while ((scn = elf_nextscn(elf, scn)) && n < cap) {
		if (!gelf_getshdr(scn, &sh) || sh.sh_type != SHT_PROGBITS ||
		    !(sh.sh_flags & SHF_ALLOC) || (sh.sh_flags & SHF_EXECINSTR))
			continue;
		Elf_Data *d = elf_getdata(scn, NULL);
		if (!d || !d->d_buf)
			continue;
		const char *buf = d->d_buf;

		for (unsigned li = 0; li < ANCHOR_NLABELS; li++) {
			size_t llen = strlen(anchor_labels[li]) + 1;   /* with the NUL */
			const char *p = buf, *end = buf + d->d_size;
			while (n < cap && (p = memmem(p, (size_t)(end - p),
						      anchor_labels[li], llen))) {
				out[n].index = li;
				out[n].vaddr = sh.sh_addr + (uint64_t)(p - buf);
				n++;
				p += llen;
			}
		}
	}
	return n;
}

static int anchor_vaddr_to_off(Elf *elf, uint64_t vaddr, uint64_t *off)
{
	size_t phnum;
	if (elf_getphdrnum(elf, &phnum) != 0)
		return -1;
	for (size_t i = 0; i < phnum; i++) {
		GElf_Phdr ph;
		if (!gelf_getphdr(elf, (int)i, &ph) || ph.p_type != PT_LOAD)
			continue;
		if (vaddr >= ph.p_vaddr && vaddr < ph.p_vaddr + ph.p_filesz) {
			*off = vaddr - ph.p_vaddr + ph.p_offset;
			return 0;
		}
	}
	return -1;
}

/* An ELF image starting at elf_off in a file: a plain library at 0, or a
 * library stored uncompressed inside an APK at its entry's offset */
struct anchor_image {
	void  *map;
	size_t size;
	Elf   *elf;
};

static Elf *anchor_open(const char *path, uint64_t elf_off, struct anchor_image *img)
{
	struct stat st;
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	memset(img, 0, sizeof(*img));
	if (fd < 0)
		return NULL;
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || (uint64_t)st.st_size <= elf_off ||
	    elf_version(EV_CURRENT) == EV_NONE) {
		close(fd);
		return NULL;
	}
	/* private and writable: libelf may touch the image, never the file */
	img->map = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	close(fd);
	if (img->map == MAP_FAILED) {
		img->map = NULL;
		return NULL;
	}
	img->size = (size_t)st.st_size;
	img->elf = elf_memory((char *)img->map + elf_off, img->size - (size_t)elf_off);
	return img->elf;
}

static void anchor_close(struct anchor_image *img)
{
	if (img->elf)
		elf_end(img->elf);
	if (img->map)
		munmap(img->map, img->size);
}

int tls_anchor_find(const char *path, struct tls_anchor_hit *out)
{
	return tls_anchor_find_at(path, 0, out);
}

int tls_anchor_find_at(const char *path, uint64_t elf_off, struct tls_anchor_hit *out)
{
	int rc = -1;
	struct anchor_image img;
	Elf *elf = anchor_open(path, elf_off, &img);
	GElf_Ehdr eh;
	struct anchor_votes *v = NULL;
	struct tls_anchor_label labels[ANCHOR_MAX_LABEL_ADDRS];

	if (!elf || !gelf_getehdr(elf, &eh))
		goto out;
	enum tls_anchor_arch arch;
	if (eh.e_machine == EM_X86_64)
		arch = TLS_ANCHOR_X86_64;
	else if (eh.e_machine == EM_AARCH64)
		arch = TLS_ANCHOR_ARM64;
	else
		goto out;

	size_t nlabels = anchor_find_labels(elf, labels, ANCHOR_MAX_LABEL_ADDRS);
	if (nlabels == 0) {
		rc = 1;
		goto out;
	}

	v = calloc(1, sizeof(*v));
	if (!v)
		goto out;

	Elf_Scn *scn = NULL;
	GElf_Shdr sh;
	while ((scn = elf_nextscn(elf, scn))) {
		if (!gelf_getshdr(scn, &sh) || sh.sh_type != SHT_PROGBITS ||
		    !(sh.sh_flags & SHF_EXECINSTR))
			continue;
		Elf_Data *d = elf_getdata(scn, NULL);
		if (!d || !d->d_buf)
			continue;
		if (arch == TLS_ANCHOR_X86_64)
			anchor_scan_x86(d->d_buf, d->d_size, sh.sh_addr, labels, nlabels, v);
		else
			anchor_scan_arm64(d->d_buf, d->d_size, sh.sh_addr, labels, nlabels, v);
	}

	rc = anchor_pick_best(v, out);
	if (rc == 0 && anchor_vaddr_to_off(elf, out->vaddr, &out->file_off) != 0)
		rc = -1;
out:
	free(v);
	anchor_close(&img);
	return rc;
}

/* ---- HMAC key setup fallback ------------------------------------------- */

/* First round constants: identical in every SHA-2 implementation */
static const uint32_t anchor_k256[4] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5 };
static const uint64_t anchor_k512[2] = { 0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL };
/* An implementation loads its table at an offset as well (K256+0x80) */
#define ANCHOR_TABLE_SPAN 0x400
#define ANCHOR_MAX_TABLES 8
#define ANCHOR_MAX_FUNCS  32

struct anchor_table { uint64_t vaddr; unsigned bits; };

struct anchor_hdr {
	const uint8_t *data;   /* .eh_frame_hdr */
	uint64_t vaddr;
	size_t size;
	const uint8_t *frame;  /* .eh_frame */
	uint64_t frame_vaddr;
	size_t frame_size;
};

static int anchor_has_tls13_labels(Elf *elf)
{
	Elf_Scn *scn = NULL;
	GElf_Shdr sh;
	while ((scn = elf_nextscn(elf, scn))) {
		if (!gelf_getshdr(scn, &sh) || sh.sh_type != SHT_PROGBITS || !(sh.sh_flags & SHF_ALLOC))
			continue;
		Elf_Data *d = elf_getdata(scn, NULL);
		if (d && d->d_buf && memmem(d->d_buf, d->d_size, "c ap traffic", 12))
			return 1;
	}
	return 0;
}

/* The tables may be in .rodata or, for perlasm, in .text itself */
static size_t anchor_find_tables(Elf *elf, struct anchor_table *t, size_t cap)
{
	size_t n = 0;
	Elf_Scn *scn = NULL;
	GElf_Shdr sh;
	while ((scn = elf_nextscn(elf, scn)) && n < cap) {
		if (!gelf_getshdr(scn, &sh) || sh.sh_type != SHT_PROGBITS || !(sh.sh_flags & SHF_ALLOC))
			continue;
		Elf_Data *d = elf_getdata(scn, NULL);
		if (!d || !d->d_buf)
			continue;
		const struct { const void *k; size_t len; unsigned bits; } pat[] = {
			{ anchor_k256, sizeof(anchor_k256), 256 },
			{ anchor_k512, sizeof(anchor_k512), 512 },
		};
		for (size_t k = 0; k < 2; k++) {
			const char *b = d->d_buf, *end = b + d->d_size, *p = b;
			while (n < cap && (p = memmem(p, (size_t)(end - p), pat[k].k, pat[k].len))) {
				t[n].vaddr = sh.sh_addr + (uint64_t)(p - b);
				t[n].bits = pat[k].bits;
				n++;
				p += pat[k].len;
			}
		}
	}
	return n;
}

/* The table an address points into: the closest one starting at or before it
 * (K256 and K512 often sit next to each other) */
static const struct anchor_table *anchor_table_at(const struct anchor_table *t, size_t n, uint64_t a)
{
	const struct anchor_table *best = NULL;
	for (size_t i = 0; i < n; i++)
		if (a >= t[i].vaddr && a < t[i].vaddr + ANCHOR_TABLE_SPAN &&
		    (!best || t[i].vaddr > best->vaddr))
			best = &t[i];
	return best;
}

static int anchor_load_hdr(Elf *elf, struct anchor_hdr *h)
{
	size_t shstrndx;
	Elf_Scn *scn = NULL;
	GElf_Shdr sh;
	memset(h, 0, sizeof(*h));
	if (elf_getshdrstrndx(elf, &shstrndx) != 0)
		return -1;
	while ((scn = elf_nextscn(elf, scn))) {
		if (!gelf_getshdr(scn, &sh))
			continue;
		const char *name = elf_strptr(elf, shstrndx, sh.sh_name);
		Elf_Data *d = elf_getdata(scn, NULL);
		if (!name || !d || !d->d_buf)
			continue;
		if (!strcmp(name, ".eh_frame_hdr")) {
			h->data = d->d_buf; h->vaddr = sh.sh_addr; h->size = d->d_size;
		} else if (!strcmp(name, ".eh_frame")) {
			h->frame = d->d_buf; h->frame_vaddr = sh.sh_addr; h->frame_size = d->d_size;
		}
	}
	/* the usual encodings: eh_frame_ptr pcrel|sdata4, count udata4, table datarel|sdata4 */
	if (!h->data || !h->frame || h->size < 12 || h->data[0] != 1 ||
	    h->data[2] != 0x03 || h->data[3] != 0x3b)
		return -1;
	return 0;
}

/* The function containing vaddr, from the unwind table: its start, 0 if none */
static uint64_t anchor_function_of(const struct anchor_hdr *h, uint64_t vaddr)
{
	uint32_t count = anchor_rd32le(h->data + 8);
	const uint8_t *tab = h->data + 12;
	if (12 + (uint64_t)count * 8 > h->size || !count)
		return 0;

	/* largest initial location <= vaddr */
	int64_t lo = 0, hi = (int64_t)count - 1, best = -1;
	while (lo <= hi) {
		int64_t mid = (lo + hi) / 2;
		uint64_t loc = h->vaddr + (uint64_t)(int64_t)(int32_t)anchor_rd32le(tab + mid * 8);
		if (loc <= vaddr) { best = mid; lo = mid + 1; } else hi = mid - 1;
	}
	if (best < 0)
		return 0;
	uint64_t start = h->vaddr + (uint64_t)(int64_t)(int32_t)anchor_rd32le(tab + best * 8);
	uint64_t fde = h->vaddr + (uint64_t)(int64_t)(int32_t)anchor_rd32le(tab + best * 8 + 4);

	/* the FDE says how far the function goes: length, CIE id, pc_begin, pc_range */
	if (fde < h->frame_vaddr || fde + 16 > h->frame_vaddr + h->frame_size)
		return 0;
	const uint8_t *f = h->frame + (fde - h->frame_vaddr);
	uint32_t range = anchor_rd32le(f + 12);
	return vaddr < start + range ? start : 0;
}

/* Instructions loading an address within a table: lea reg,[rip+d32] / adrp+add */
static size_t anchor_table_refs(enum tls_anchor_arch arch, const uint8_t *code, size_t len,
				uint64_t vaddr, const struct anchor_table *t, size_t nt,
				uint64_t *refs, unsigned *bits, size_t cap)
{
	size_t n = 0;
	if (arch == TLS_ANCHOR_X86_64) {
		for (size_t i = 0; i + 7 <= len && n < cap; i++) {
			if ((code[i] & 0xf0) != 0x40 || code[i + 1] != 0x8d || (code[i + 2] & 0xc7) != 0x05)
				continue;
			uint64_t target = vaddr + i + 7 + (uint64_t)(int64_t)(int32_t)anchor_rd32le(code + i + 3);
			const struct anchor_table *hit = anchor_table_at(t, nt, target);
			if (hit) { refs[n] = vaddr + i; bits[n] = hit->bits; n++; }
		}
	} else {
		for (size_t i = 0; i + 8 <= len && n < cap; i += 4) {
			uint32_t insn = anchor_rd32le(code + i), a = anchor_rd32le(code + i + 4);
			if ((insn & 0x9f000000) != 0x90000000 || (a & 0xff800000) != 0x91000000 ||
			    ((a >> 5) & 0x1f) != (insn & 0x1f))
				continue;
			uint64_t imm = (uint64_t)((insn >> 5) & 0x7ffff) << 2 | ((insn >> 29) & 3);
			uint64_t page = ((vaddr + i) & ~0xfffULL) + (uint64_t)(anchor_sext(imm, 21) * 4096);
			const struct anchor_table *hit = anchor_table_at(t, nt, page + ((a >> 10) & 0xfff));
			if (hit) { refs[n] = vaddr + i; bits[n] = hit->bits; n++; }
		}
		/* OpenSSL's hand-written arm64 SHA-2 (sha256-armv8.S, ...) keeps
		 * the constants next to the code and reaches them with a single
		 * adr: only one landing exactly on a table start counts, an adr
		 * into the middle of one is something else */
		for (size_t i = 0; i + 4 <= len && n < cap; i += 4) {
			uint32_t insn = anchor_rd32le(code + i);
			if ((insn & 0x9f000000) != 0x10000000)
				continue;
			uint64_t imm = (uint64_t)((insn >> 5) & 0x7ffff) << 2 | ((insn >> 29) & 3);
			uint64_t target = vaddr + i + (uint64_t)anchor_sext(imm, 21);
			const struct anchor_table *hit = anchor_table_at(t, nt, target);
			if (hit && hit->vaddr == target) { refs[n] = vaddr + i; bits[n] = hit->bits; n++; }
		}
	}
	return n;
}

/*
 * The entry of the arm64 function holding ref, for code without unwind
 * information (OpenSSL's perlasm emits no CFI on arm64): the closest
 * "stp x29, x30, [sp, #-N]!" above it, the frame setup every one of those
 * functions starts with — or the branch target its dispatcher jumps to, with
 * the arguments untouched either way. A ret met first means ref is not in a
 * function that sets up a frame: 0.
 */
static uint64_t anchor_arm64_entry_before(const uint8_t *code, uint64_t vaddr, uint64_t ref)
{
	for (uint64_t back = 0; back <= 512 && ref - back >= vaddr; back += 4) {
		uint32_t insn = anchor_rd32le(code + (ref - back - vaddr));
		if (back && (insn == 0xd65f03c0 || insn == 0xd65f0bff || insn == 0xd65f0fff))
			return 0;   /* ret, retaa, retab: the previous function */
		if ((insn & 0xffc07fff) == 0xa9807bfd)
			return ref - back;   /* stp x29, x30, [sp, #imm]! */
		if (ref - back == vaddr)
			break;
	}
	return 0;
}

int tls_anchor_find_hmac(const char *path, struct tls_sha_hit *out, size_t cap)
{
	return tls_anchor_find_hmac_at(path, 0, out, cap);
}

static int anchor_find_hmac(const char *path, uint64_t elf_off, struct tls_sha_hit *out,
			    size_t cap, int need_labels);

int tls_anchor_find_hmac_at(const char *path, uint64_t elf_off, struct tls_sha_hit *out, size_t cap)
{
	return anchor_find_hmac(path, elf_off, out, cap, 1);
}

int tls_anchor_find_hmac_crypto(const char *path, struct tls_sha_hit *out, size_t cap)
{
	return anchor_find_hmac(path, 0, out, cap, 0);
}

static int anchor_find_hmac(const char *path, uint64_t elf_off, struct tls_sha_hit *out,
			    size_t cap, int need_labels)
{
	int found = -1;
	struct anchor_image img;
	Elf *elf = anchor_open(path, elf_off, &img);
	GElf_Ehdr eh;
	if (!elf || !gelf_getehdr(elf, &eh) ||
	    (eh.e_machine != EM_X86_64 && eh.e_machine != EM_AARCH64))
		goto out;
	found = 0;
	enum tls_anchor_arch arch = eh.e_machine == EM_X86_64 ? TLS_ANCHOR_X86_64 : TLS_ANCHOR_ARM64;

	struct anchor_table tables[ANCHOR_MAX_TABLES];
	struct anchor_hdr hdr;
	size_t nt;
	if ((need_labels && !anchor_has_tls13_labels(elf)) ||
	    !(nt = anchor_find_tables(elf, tables, ANCHOR_MAX_TABLES)) ||
	    anchor_load_hdr(elf, &hdr) != 0)
		goto out;

	Elf_Scn *scn = NULL;
	GElf_Shdr sh;
	while ((scn = elf_nextscn(elf, scn))) {
		if (!gelf_getshdr(scn, &sh) || sh.sh_type != SHT_PROGBITS || !(sh.sh_flags & SHF_EXECINSTR))
			continue;
		Elf_Data *d = elf_getdata(scn, NULL);
		if (!d || !d->d_buf)
			continue;
		uint64_t refs[ANCHOR_MAX_FUNCS * 4];
		unsigned bits[ANCHOR_MAX_FUNCS * 4];
		size_t nr = anchor_table_refs(arch, d->d_buf, d->d_size, sh.sh_addr, tables, nt,
					      refs, bits, ANCHOR_MAX_FUNCS * 4);
		for (size_t i = 0; i < nr && (size_t)found < cap; i++) {
			uint64_t fn = anchor_function_of(&hdr, refs[i]), off;
			if (!fn && arch == TLS_ANCHOR_ARM64)
				fn = anchor_arm64_entry_before(d->d_buf, sh.sh_addr, refs[i]);
			if (!fn || anchor_vaddr_to_off(elf, fn, &off) != 0)
				continue;
			int dup = 0;
			for (int j = 0; j < found; j++)
				dup |= out[j].file_off == off;
			if (dup)
				continue;
			out[found].file_off = off;
			out[found].bits = bits[i];
			found++;
		}
	}
out:
	anchor_close(&img);
	return found;
}
