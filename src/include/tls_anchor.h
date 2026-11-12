/*
 * String-anchor resolution of a TLS stack's keylog function.
 *
 * The key capture needs a uprobe on the function a TLS library calls every time
 * it derives a secret (OpenSSL's ssl_log_secret, BoringSSL's ssl_log_secret,
 * ...). That function is internal: on a distribution libssl, an Android
 * Conscrypt build or a library embedding BoringSSL statically, it is not in
 * .dynsym and .symtab has been stripped. What is always there are the NSS
 * keylog labels it receives — "CLIENT_TRAFFIC_SECRET_0", "CLIENT_RANDOM", ... —
 * fixed by the keylog format, so they survive stripping, LTO and renaming.
 *
 * The scan:
 *  1. finds every "LABEL\0" in the read-only sections;
 *  2. finds the instructions that materialize one of those addresses straight
 *     into the second-argument register (x86-64 `lea rsi,[rip+d32]`, arm64
 *     `adrp x1` + `add x1,x1,#imm`): that is a call passing the label as `label`;
 *     or into the first-argument one (rdi, x0): OpenSSL builds where
 *     ssl_log_secret() got inlined (Ubuntu 22.04's 3.0.2) call
 *     nss_keylog_int(label, ssl, random, random_len, secret, secret_len)
 *     directly, and that function sees every secret just as well;
 *  3. walks forward with an instruction decoder (x86_insn.h; arm64 is fixed
 *     width) to the first direct call, and votes for its target;
 *  4. keeps the target reached from the most *distinct* labels, and requires at
 *     least two of them: a function called with two different keylog labels
 *     as its label argument is the keylog function, a coincidence is not.
 *
 * Only votes where the label lands directly in the argument register count. A
 * label parked in a stack slot first (OpenSSL 3 does that for the TLS 1.3
 * secrets) simply does not vote, which keeps unrelated calls out of the tally.
 *
 * The result is a file offset ready for a uprobe. The entry probe fires before
 * the function checks whether a keylog callback is installed, so nothing has to
 * be configured in the process.
 */

#ifndef EPTRACER_TLS_ANCHOR_H
#define EPTRACER_TLS_ANCHOR_H

#include <stddef.h>
#include <stdint.h>

enum tls_anchor_arch {
	TLS_ANCHOR_X86_64 = 0,
	TLS_ANCHOR_ARM64  = 1,
};

/* Fewest distinct labels that must agree on a target */
#define TLS_ANCHOR_MIN_LABELS 2

/* A label found in the image: its index in the label table and address */
struct tls_anchor_label {
	unsigned index;
	uint64_t vaddr;
};

/* Where the keylog function takes its arguments, by the register the label
 * was loaded into at the call sites that voted for it */
enum tls_keylog_abi {
	/* ssl_log_secret(ssl, label, secret, secret_len) */
	TLS_KEYLOG_ABI_LOG_SECRET = 0,
	/* nss_keylog_int(label, ssl, random, random_len, secret, secret_len) */
	TLS_KEYLOG_ABI_NSS_INT = 1,
};

struct tls_anchor_hit {
	uint64_t vaddr;        /* entry of the keylog function */
	enum tls_keylog_abi abi;
	uint64_t file_off;     /* where that entry sits in the file: the uprobe offset */
	unsigned label_mask;   /* bit i set: label i was passed to it */
	unsigned labels;       /* number of distinct labels (popcount of the mask) */
	unsigned votes;        /* call sites that agreed */
};

/* Number of labels in the table, and the name of label i (for logs/tests). */
unsigned tls_anchor_label_count(void);
const char *tls_anchor_label_name(unsigned i);

/*
 * Resolve the keylog function of an ELF file (shared object or executable).
 * Returns 0 with *out filled, 1 when no target is agreed on by enough labels
 * (the image has no keylog support, or encrypts its strings), -1 when the file
 * cannot be read or is not a supported ELF.
 */
int tls_anchor_find(const char *path, struct tls_anchor_hit *out);

/* The same for an ELF image starting at elf_off in the file (a library stored
 * uncompressed in an APK). Offsets returned stay relative to the image: the
 * uprobe goes at elf_off + file_off in that file. */
int tls_anchor_find_at(const char *path, uint64_t elf_off, struct tls_anchor_hit *out);

/*
 * The code scan alone, over one executable region: exposed so the voting can be
 * tested on synthetic code. `code` is mapped at `code_vaddr`. Returns like
 * tls_anchor_find(), file_off left 0.
 */
int tls_anchor_scan_code(enum tls_anchor_arch arch,
			 const uint8_t *code, size_t len, uint64_t code_vaddr,
			 const struct tls_anchor_label *labels, size_t nlabels,
			 struct tls_anchor_hit *out);

/*
 * Fallback for stacks with no keylog function to probe (rustls on ring, an
 * OpenSSL linked in statically and built without one): their SHA-2 compression
 * functions, where every TLS 1.3 secret shows up as an HMAC key.
 *
 * In TLS 1.3 each secret becomes an HMAC key (HKDF), and HMAC's first
 * compressed block is that key XOR 0x36, padded with 0x36 to the block size:
 * a probe on the compression function can recognize it whatever the library.
 * The functions are found from the SHA-2 round constants they load (K256,
 * K512: the same in every implementation) and the unwind table (.eh_frame_hdr)
 * that maps the referencing instruction back to its function, which a stripped
 * object keeps. Only objects that also carry the TLS 1.3 derivation labels are
 * considered, so a plain libcrypto never gets a probe on its hot path.
 */
struct tls_sha_hit {
	uint64_t file_off;     /* entry of a block function: (state, data, nblocks) */
	unsigned bits;         /* 256: 64-byte blocks, 512: 128-byte blocks */
};

/* Returns the number of functions found (0..cap), -1 if the file cannot be read. */
int tls_anchor_find_hmac(const char *path, struct tls_sha_hit *out, size_t cap);
int tls_anchor_find_hmac_at(const char *path, uint64_t elf_off, struct tls_sha_hit *out, size_t cap);

/* The same on the crypto library of a split stack (OpenSSL's libcrypto, next
 * to the libssl whose keylog function is only reached when the application
 * installed a callback): it carries no TLS label, so none is required. */
int tls_anchor_find_hmac_crypto(const char *path, struct tls_sha_hit *out, size_t cap);

#endif /* EPTRACER_TLS_ANCHOR_H */
