/*
 * Test for src/tracers/tls_anchor.c.
 *
 *   test_tls_anchor              synthetic x86-64 / arm64 code + system libs
 *   test_tls_anchor --find ELF   print the resolved keylog function of ELF
 *                                (used by bench/validate_anchor.sh)
 *   test_tls_anchor --hmac ELF   print the SHA-2 block functions of ELF
 *                                (used by bench/validate_hmac.sh)
 */

#include "tls_anchor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_fail = 0;

#define CHECK(cond, msg) do {                                           \
	if (cond) { printf("  ok   %s\n", msg); }                      \
	else      { printf("  FAIL %s\n", msg); g_fail++; }           \
} while (0)

/* ---- x86-64 synthetic code -------------------------------------------- */

static size_t emit(uint8_t *buf, size_t pos, const uint8_t *b, size_t n)
{
	memcpy(buf + pos, b, n);
	return pos + n;
}

/* lea r, [rip + (target - end_of_insn)] ; reg 6 = rsi, 0 = rax */
static size_t lea_rip(uint8_t *buf, size_t pos, uint64_t base, unsigned reg, uint64_t target)
{
	int32_t disp = (int32_t)(target - (base + pos + 7));
	uint8_t insn[7] = { 0x48, 0x8d, (uint8_t)(0x05 | reg << 3) };
	memcpy(insn + 3, &disp, 4);
	return emit(buf, pos, insn, 7);
}

static size_t call_rel(uint8_t *buf, size_t pos, uint64_t base, uint64_t target)
{
	int32_t rel = (int32_t)(target - (base + pos + 5));
	uint8_t insn[5] = { 0xe8 };
	memcpy(insn + 1, &rel, 4);
	return emit(buf, pos, insn, 5);
}

static void test_x86(void)
{
	printf("[x86-64 synthetic]\n");
	const uint64_t base = 0x10000;
	const uint64_t keylog_fn = base + 0x800, other_fn = base + 0x900;
	struct tls_anchor_label labels[] = {
		{ 0, 0x50000 },   /* CLIENT_RANDOM */
		{ 4, 0x50100 },   /* CLIENT_TRAFFIC_SECRET_0 */
		{ 5, 0x50200 },   /* SERVER_TRAFFIC_SECRET_0 */
	};
	uint8_t code[0x1000];
	memset(code, 0x90, sizeof(code));   /* nops */
	size_t p = 0;
	static const uint8_t mov_rdi_r14[] = { 0x4c, 0x89, 0xf7 };
	static const uint8_t mov_rsi_r15[] = { 0x4c, 0x89, 0xfe };

	/* site 1: lea rsi, CLIENT_RANDOM ; mov rdi, r14 ; call keylog */
	p = lea_rip(code, p, base, 6, 0x50000);
	p = emit(code, p, mov_rdi_r14, 3);
	p = call_rel(code, p, base, keylog_fn);
	/* site 2: lea rsi, CLIENT_TRAFFIC_SECRET_0 ; call keylog */
	p = lea_rip(code, p, base, 6, 0x50100);
	p = call_rel(code, p, base, keylog_fn);
	/* decoy 1: label into rax (stack-slot style), then an unrelated call,
	 * reached from two labels: must not vote */
	p = lea_rip(code, p, base, 0, 0x50100);
	p = call_rel(code, p, base, other_fn);
	p = lea_rip(code, p, base, 0, 0x50200);
	p = call_rel(code, p, base, other_fn);
	/* decoy 2: rsi loaded, then overwritten before the call */
	p = lea_rip(code, p, base, 6, 0x50200);
	p = emit(code, p, mov_rsi_r15, 3);
	p = call_rel(code, p, base, other_fn);
	code[0x800] = 0xc3;
	code[0x900] = 0xc3;

	struct tls_anchor_hit hit;
	int r = tls_anchor_scan_code(TLS_ANCHOR_X86_64, code, sizeof(code), base,
				     labels, 3, &hit);
	CHECK(r == 0 && hit.vaddr == keylog_fn, "keylog function found");
	CHECK(r == 0 && hit.labels == 2 && hit.label_mask == ((1u << 0) | (1u << 4)),
	      "voted by CLIENT_RANDOM and CLIENT_TRAFFIC_SECRET_0 only");

	/* a single label is not enough */
	struct tls_anchor_label one[] = { { 0, 0x50000 } };
	r = tls_anchor_scan_code(TLS_ANCHOR_X86_64, code, sizeof(code), base, one, 1, &hit);
	CHECK(r == 1, "one label alone does not resolve (needs two)");
}

/* ssl_log_secret() inlined (Ubuntu 22.04's OpenSSL 3.0.2): the call sites hand
 * the label to nss_keylog_int() as its *first* argument */
static void test_x86_nss_int(void)
{
	printf("[x86-64 synthetic, label in rdi]\n");
	const uint64_t base = 0x10000;
	const uint64_t nss_fn = base + 0x800;
	struct tls_anchor_label labels[] = {
		{ 0, 0x50000 },   /* CLIENT_RANDOM */
		{ 7, 0x50100 },   /* EARLY_EXPORTER_SECRET */
	};
	uint8_t code[0x1000];
	memset(code, 0x90, sizeof(code));
	size_t p = 0;
	static const uint8_t mov_rsi_rbp[] = { 0x48, 0x89, 0xee };
	static const uint8_t mov_rdi_r12[] = { 0x4c, 0x89, 0xe7 };

	/* mov rsi, rbp ; lea rdi, CLIENT_RANDOM ; call nss_keylog_int */
	p = emit(code, p, mov_rsi_rbp, 3);
	p = lea_rip(code, p, base, 7, 0x50000);
	p = call_rel(code, p, base, nss_fn);
	/* lea rdi, EARLY_EXPORTER_SECRET ; call nss_keylog_int */
	p = lea_rip(code, p, base, 7, 0x50100);
	p = call_rel(code, p, base, nss_fn);
	/* decoy: rdi loaded, then overwritten before the call */
	p = lea_rip(code, p, base, 7, 0x50100);
	p = emit(code, p, mov_rdi_r12, 3);
	p = call_rel(code, p, base, base + 0x900);
	code[0x800] = 0xc3;
	code[0x900] = 0xc3;

	struct tls_anchor_hit hit;
	int r = tls_anchor_scan_code(TLS_ANCHOR_X86_64, code, sizeof(code), base,
				     labels, 2, &hit);
	CHECK(r == 0 && hit.vaddr == nss_fn, "nss_keylog_int found");
	CHECK(r == 0 && hit.abi == TLS_KEYLOG_ABI_NSS_INT, "with its own argument layout");
	CHECK(r == 0 && hit.labels == 2, "voted by both labels, not by the decoy");
}

/* ---- arm64 synthetic code --------------------------------------------- */

static void put32(uint8_t *b, size_t pos, uint32_t v) { memcpy(b + pos, &v, 4); }

static uint32_t adrp(unsigned rd, uint64_t pc, uint64_t addr)
{
	int64_t pages = (int64_t)((addr & ~0xfffULL) - (pc & ~0xfffULL)) >> 12;
	uint32_t imm = (uint32_t)pages & 0x1fffff;
	return 0x90000000u | (imm & 3) << 29 | (imm >> 2) << 5 | rd;
}

static uint32_t add_imm(unsigned rd, unsigned rn, uint64_t addr)
{
	return 0x91000000u | (uint32_t)(addr & 0xfff) << 10 | rn << 5 | rd;
}

static uint32_t bl(uint64_t pc, uint64_t target)
{
	return 0x94000000u | ((uint32_t)((int64_t)(target - pc) >> 2) & 0x3ffffff);
}

static void test_arm64(void)
{
	printf("[arm64 synthetic]\n");
	const uint64_t base = 0x400000, fn = base + 0x800;
	struct tls_anchor_label labels[] = {
		{ 2, 0x7a1230 },  /* CLIENT_HANDSHAKE_TRAFFIC_SECRET */
		{ 3, 0x7a1260 },  /* SERVER_HANDSHAKE_TRAFFIC_SECRET */
	};
	uint8_t code[0x1000];
	for (size_t i = 0; i < sizeof(code); i += 4)
		put32(code, i, 0xd503201f);   /* nop */
	size_t p = 0;
	for (int s = 0; s < 2; s++) {
		uint64_t lab = labels[s].vaddr;
		put32(code, p, adrp(1, base + p, lab));        p += 4;
		put32(code, p, add_imm(1, 1, lab));           p += 4;
		put32(code, p, 0xaa1303e0);  /* mov x0, x19 */ p += 4;
		put32(code, p, bl(base + p, fn));             p += 4;
	}
	/* decoy: label into x8, then bl elsewhere */
	put32(code, p, adrp(8, base + p, 0x7a1230)); p += 4;
	put32(code, p, add_imm(8, 8, 0x7a1230));     p += 4;
	put32(code, p, bl(base + p, base + 0x900));  p += 4;
	put32(code, 0x800, 0xd65f03c0);

	struct tls_anchor_hit hit;
	int r = tls_anchor_scan_code(TLS_ANCHOR_ARM64, code, sizeof(code), base,
				     labels, 2, &hit);
	CHECK(r == 0 && hit.vaddr == fn && hit.labels == 2,
	      "adrp x1 + add x1 + bl resolves the keylog function");
}

/* ---- real images ------------------------------------------------------- */

static void print_hit(const char *path, const struct tls_anchor_hit *h)
{
	printf("    %s\n    keylog fn vaddr=0x%llx file_off=0x%llx labels=%u votes=%u (",
	       path, (unsigned long long)h->vaddr, (unsigned long long)h->file_off,
	       h->labels, h->votes);
	for (unsigned i = 0, first = 1; i < tls_anchor_label_count(); i++)
		if (h->label_mask & (1u << i)) {
			printf("%s%s", first ? "" : ", ", tls_anchor_label_name(i));
			first = 0;
		}
	printf(")\n");
}

static void test_real(void)
{
	printf("[real images]\n");
#if defined(__aarch64__)
	const char *ssl = "/usr/lib/aarch64-linux-gnu/libssl.so.3";
#else
	const char *ssl = "/usr/lib/x86_64-linux-gnu/libssl.so.3";
#endif
	struct tls_anchor_hit hit;
	int r = tls_anchor_find(ssl, &hit);
	CHECK(r == 0 && hit.labels >= 2, "system libssl.so.3 (stripped) resolves");
	if (r == 0)
		print_hit(ssl, &hit);

	/* the same library stored at an offset inside a bigger file, as an
	 * uncompressed .so inside an APK */
	{
		struct tls_anchor_hit plain, inner;
		char tmp[] = "/tmp/eptracer-anchor-apk-XXXXXX";
		int fd = mkstemp(tmp);
		FILE *in = fopen(ssl, "rb");
		static char buf[1 << 16];
		size_t n;
		memset(buf, 'Z', 8192);
		if (fd >= 0 && in && write(fd, buf, 8192) == 8192) {
			while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
				if (write(fd, buf, n) != (ssize_t)n)
					break;
		}
		if (in)
			fclose(in);
		if (fd >= 0)
			close(fd);
		int a1 = tls_anchor_find(ssl, &plain), a2 = tls_anchor_find_at(tmp, 8192, &inner);
		CHECK(a1 == 0 && a2 == 0 && plain.file_off == inner.file_off,
		      "the same library at offset 8192 in another file resolves the same");
		unlink(tmp);
	}

	r = tls_anchor_find("/usr/lib/x86_64-linux-gnu/libc.so.6", &hit);
	CHECK(r == 1, "libc has no keylog labels: not resolved");

	r = tls_anchor_find("/nonexistent", &hit);
	CHECK(r == -1, "missing file is an error");
}

int main(int argc, char **argv)
{
	if (argc == 3 && strcmp(argv[1], "--hmac") == 0) {
		struct tls_sha_hit h[32];
		int n = tls_anchor_find_hmac(argv[2], h, 32);
		for (int i = 0; i < n; i++)
			printf("0x%llx sha%u\n", (unsigned long long)h[i].file_off, h[i].bits);
		return n > 0 ? 0 : 1;
	}
	if (argc == 3 && strcmp(argv[1], "--find") == 0) {
		struct tls_anchor_hit hit;
		int r = tls_anchor_find(argv[2], &hit);
		if (r != 0) {
			fprintf(stderr, "not resolved (%d)\n", r);
			return 1;
		}
		printf("0x%llx 0x%llx\n", (unsigned long long)hit.vaddr,
		       (unsigned long long)hit.file_off);
		return 0;
	}

	test_x86();
	test_x86_nss_int();
	test_arm64();
	test_real();
	printf("\n%s (%d failure%s)\n", g_fail ? "FAILED" : "PASSED",
	       g_fail, g_fail == 1 ? "" : "s");
	return g_fail ? 1 : 0;
}
