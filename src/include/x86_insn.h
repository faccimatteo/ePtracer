/*
 * x86-64 instruction length decoder.
 *
 * Shared by the Go TLS probe placement (tracers/go_tls.c), which walks a
 * function to find its real RET instructions, and by the string-anchor scanner
 * (tracers/tls_anchor.c), which walks forward from a label reference to the call
 * that consumes it. Header-only because the tracers are #included into a single
 * translation unit by eptracer.c, while the standalone tests build them one by
 * one: the include guard keeps a single copy either way.
 */

#ifndef EPTRACER_X86_INSN_H
#define EPTRACER_X86_INSN_H

#include <stddef.h>

/* ---------------------------------------------------------------------------
 * x86-64 instruction length decoder
 *
 * Only lengths are needed, never operands, which keeps this to a pair of
 * attribute tables. Anything it cannot size returns 0 and stops the walk,
 * which is what makes the whole thing safe to rely on.
 * ------------------------------------------------------------------------- */

#define OP_MODRM    0x01
#define OP_IMM8     0x02
#define OP_IMM16    0x04
#define OP_IMMZ     0x08   /* 2 bytes under a 66 prefix, 4 otherwise */
#define OP_IMMV     0x10   /* 8 under REX.W, 2 under 66, 4 otherwise */
#define OP_MOFFS    0x20   /* absolute address: 4 under a 67 prefix, else 8 */
#define OP_BAD      0x40   /* not encodable in 64 bit mode */
#define OP_ENTER    0x80   /* the one instruction with two immediates */

/* Opcodes with no operand byte at all, and the prefixes, are simply 0 */
static const unsigned char x86_op1[256] = {
	/* 00 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMMZ, OP_BAD, OP_BAD,
	/* 08 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMMZ, OP_BAD, 0,
	/* 10 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMMZ, OP_BAD, OP_BAD,
	/* 18 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMMZ, OP_BAD, OP_BAD,
	/* 20 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMMZ, 0, OP_BAD,
	/* 28 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMMZ, 0, OP_BAD,
	/* 30 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMMZ, 0, OP_BAD,
	/* 38 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_IMM8, OP_IMMZ, 0, OP_BAD,
	/* 40 */ 0, 0, 0, 0, 0, 0, 0, 0,
	/* 48 */ 0, 0, 0, 0, 0, 0, 0, 0,
	/* 50 */ 0, 0, 0, 0, 0, 0, 0, 0,
	/* 58 */ 0, 0, 0, 0, 0, 0, 0, 0,
	/* 60 */ OP_BAD, OP_BAD, 0, OP_MODRM, 0, 0, 0, 0,
	/* 68 */ OP_IMMZ, OP_MODRM | OP_IMMZ, OP_IMM8, OP_MODRM | OP_IMM8, 0, 0, 0, 0,
	/* 70 */ OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8,
	/* 78 */ OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8,
	/* 80 */ OP_MODRM | OP_IMM8, OP_MODRM | OP_IMMZ, OP_BAD, OP_MODRM | OP_IMM8,
	/* 84 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 88 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 8c */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 90 */ 0, 0, 0, 0, 0, 0, 0, 0,
	/* 98 */ 0, 0, OP_BAD, 0, 0, 0, 0, 0,
	/* a0 */ OP_MOFFS, OP_MOFFS, OP_MOFFS, OP_MOFFS, 0, 0, 0, 0,
	/* a8 */ OP_IMM8, OP_IMMZ, 0, 0, 0, 0, 0, 0,
	/* b0 */ OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8,
	/* b8 */ OP_IMMV, OP_IMMV, OP_IMMV, OP_IMMV, OP_IMMV, OP_IMMV, OP_IMMV, OP_IMMV,
	/* c0 */ OP_MODRM | OP_IMM8, OP_MODRM | OP_IMM8, OP_IMM16, 0,
	/* c4 */ 0, 0, OP_MODRM | OP_IMM8, OP_MODRM | OP_IMMZ,
	/* c8 */ OP_ENTER, 0, OP_IMM16, 0, 0, OP_IMM8, OP_BAD, 0,
	/* d0 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_BAD, OP_BAD, OP_BAD, 0,
	/* d8 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* e0 */ OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8, OP_IMM8,
	/* e8 */ OP_IMMZ, OP_IMMZ, OP_BAD, OP_IMM8, 0, 0, 0, 0,
	/* f0 */ 0, 0, 0, 0, 0, 0, OP_MODRM, OP_MODRM,
	/* f8 */ 0, 0, 0, 0, 0, 0, OP_MODRM, OP_MODRM,
};

static const unsigned char x86_op2[256] = {
	/* 0f 00 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_BAD, 0, 0, 0,
	/* 0f 08 */ 0, 0, OP_BAD, 0, OP_BAD, OP_MODRM, 0, OP_MODRM | OP_IMM8,
	/* 0f 10 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 0f 18 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 0f 20 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_BAD, OP_BAD, OP_BAD, OP_BAD,
	/* 0f 28 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 0f 30 */ 0, 0, 0, 0, 0, 0, OP_BAD, 0,
	/* 0f 38 */ 0, OP_BAD, 0, OP_BAD, OP_BAD, OP_BAD, OP_BAD, OP_BAD,
	/* 0f 40 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 0f 48 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 0f 50 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 0f 58 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 0f 60 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 0f 68 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 0f 70 */ OP_MODRM | OP_IMM8, OP_MODRM | OP_IMM8, OP_MODRM | OP_IMM8, OP_MODRM | OP_IMM8,
	/* 0f 74 */ OP_MODRM, OP_MODRM, OP_MODRM, 0,
	/* 0f 78 */ OP_MODRM, OP_MODRM, OP_BAD, OP_BAD, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 0f 80 */ OP_IMMZ, OP_IMMZ, OP_IMMZ, OP_IMMZ, OP_IMMZ, OP_IMMZ, OP_IMMZ, OP_IMMZ,
	/* 0f 88 */ OP_IMMZ, OP_IMMZ, OP_IMMZ, OP_IMMZ, OP_IMMZ, OP_IMMZ, OP_IMMZ, OP_IMMZ,
	/* 0f 90 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 0f 98 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 0f a0 */ 0, 0, 0, OP_MODRM, OP_MODRM | OP_IMM8, OP_MODRM, OP_BAD, OP_BAD,
	/* 0f a8 */ 0, 0, 0, OP_MODRM, OP_MODRM | OP_IMM8, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 0f b0 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 0f b8 */ OP_MODRM, OP_MODRM, OP_MODRM | OP_IMM8, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 0f c0 */ OP_MODRM, OP_MODRM, OP_MODRM | OP_IMM8, OP_MODRM,
	/* 0f c4 */ OP_MODRM | OP_IMM8, OP_MODRM | OP_IMM8, OP_MODRM | OP_IMM8, OP_MODRM,
	/* 0f c8 */ 0, 0, 0, 0, 0, 0, 0, 0,
	/* 0f d0 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 0f d8 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 0f e0 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 0f e8 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 0f f0 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM,
	/* 0f f8 */ OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_MODRM, OP_BAD,
};

/*
 * x86_modrm_len
 *
 * Description:
 * Size of the ModR/M byte together with the SIB byte and displacement it
 * pulls in.
 *
 * Params:
 * const unsigned char *p: first byte of the ModR/M.
 * size_t max: bytes left in the buffer.
 *
 * Return:
 * Number of bytes consumed, 0 when the buffer is too short.
 * */
static size_t x86_modrm_len(const unsigned char *p, size_t max)
{
	unsigned char modrm = 0, mod = 0, rm = 0;
	size_t len = 1;

	if (max < 1)
		return 0;

	modrm = p[0];
	mod = (unsigned char)(modrm >> 6);
	rm  = (unsigned char)(modrm & 7);

	/* A register operand pulls in nothing else */
	if (mod == 3)
		return len;

	if (rm == 4) {
		unsigned char sib = 0;

		if (max < len + 1)
			return 0;
		sib = p[len];
		len++;
		/* No base register: the displacement is absolute */
		if (mod == 0 && (sib & 7) == 5)
			return len + 4 <= max ? len + 4 : 0;
	} else if (mod == 0 && rm == 5) {
		/* RIP relative */
		return len + 4 <= max ? len + 4 : 0;
	}

	if (mod == 1)
		return len + 1 <= max ? len + 1 : 0;
	if (mod == 2)
		return len + 4 <= max ? len + 4 : 0;

	return len;
}

/*
 * x86_insn_len
 *
 * Description:
 * Length of the instruction starting at p. Operands are not decoded, only
 * measured, which is all that is needed to walk a function and find where its
 * returns really are.
 *
 * Params:
 * const unsigned char *p: first byte of the instruction.
 * size_t max: bytes left in the function.
 *
 * Return:
 * Length in bytes, 0 when the instruction cannot be sized — which the caller
 * must treat as a refusal to go any further.
 * */
static size_t x86_insn_len(const unsigned char *p, size_t max)
{
	size_t pos = 0;
	int opsize = 0, addrsize = 0, rex_w = 0;
	unsigned char attr = 0, op = 0;
	const unsigned char *table = x86_op1;

	/* Legacy prefixes, then REX. Order is not enforced: a decoder only has
	 * to measure, and the hardware tolerates repetition anyway. */
	while (pos < max) {
		unsigned char b = p[pos];

		if (b == 0x66) { opsize = 1; pos++; continue; }
		if (b == 0x67) { addrsize = 1; pos++; continue; }
		if (b == 0xf0 || b == 0xf2 || b == 0xf3 ||
		    b == 0x2e || b == 0x36 || b == 0x3e || b == 0x26 ||
		    b == 0x64 || b == 0x65) { pos++; continue; }
		if (b >= 0x40 && b <= 0x4f) {
			rex_w = (b & 0x08) ? 1 : 0;
			pos++;
			continue;
		}
		break;
	}

	if (pos >= max)
		return 0;

	/* VEX and EVEX carry the opcode map in their payload, so the escape
	 * bytes are read here rather than through the tables */
	if (p[pos] == 0xc5 || p[pos] == 0xc4 || p[pos] == 0x62) {
		unsigned char kind = p[pos];
		size_t payload = kind == 0xc5 ? 1 : (kind == 0xc4 ? 2 : 3);
		unsigned char map = 1;

		if (pos + payload + 1 >= max)
			return 0;
		if (kind == 0xc4)
			map = (unsigned char)(p[pos + 1] & 0x1f);
		else if (kind == 0x62)
			map = (unsigned char)(p[pos + 1] & 0x07);
		/* the escape byte itself, its payload, then the opcode */
		pos += payload + 2;
		op = p[pos - 1];

		if (map == 1)
			attr = x86_op2[op];
		else if (map == 2)
			attr = OP_MODRM;
		else if (map == 3)
			attr = OP_MODRM | OP_IMM8;
		else
			return 0;
		/* Out of the one byte map: the group rules keyed on the opcode
		 * below must not fire. MULX is 0F38 F6, and reading it as the
		 * legacy F6 group would hand it an immediate it does not have. */
		table = NULL;
		/* A vector immediate is always a byte, whatever the tables say
		 * about the legacy encoding of the same opcode */
		if (attr & (OP_IMMZ | OP_IMMV | OP_MOFFS))
			attr = (unsigned char)((attr & ~(OP_IMMZ | OP_IMMV | OP_MOFFS)) | OP_IMM8);
		goto operands;
	}

	op = p[pos++];
	if (op == 0x0f) {
		if (pos >= max)
			return 0;
		op = p[pos++];
		if (op == 0x38) {
			if (pos >= max)
				return 0;
			pos++;
			attr = OP_MODRM;
			table = NULL;
			goto operands;
		}
		if (op == 0x3a) {
			if (pos >= max)
				return 0;
			pos++;
			attr = OP_MODRM | OP_IMM8;
			table = NULL;
			goto operands;
		}
		table = x86_op2;
	}

	attr = table[op];
	if (attr & OP_BAD)
		return 0;

operands:
	if (attr & OP_MODRM) {
		size_t consumed = 0;
		unsigned char reg = 0;

		if (pos >= max)
			return 0;
		reg = (unsigned char)((p[pos] >> 3) & 7);

		/* The two group opcodes whose immediate depends on the reg field */
		if (table == x86_op1 && (op == 0xf6 || op == 0xf7) && reg <= 1)
			attr |= (op == 0xf6) ? OP_IMM8 : OP_IMMZ;

		consumed = x86_modrm_len(p + pos, max - pos);
		if (consumed == 0)
			return 0;
		pos += consumed;
	}

	if (attr & OP_ENTER)
		pos += 3;
	if (attr & OP_IMM8)
		pos += 1;
	if (attr & OP_IMM16)
		pos += 2;
	if (attr & OP_IMMZ)
		pos += opsize ? 2u : 4u;
	if (attr & OP_IMMV)
		pos += rex_w ? 8u : (opsize ? 2u : 4u);
	if (attr & OP_MOFFS)
		pos += addrsize ? 4u : 8u;

	if (pos > max)
		return 0;
	return pos;
}

#endif /* EPTRACER_X86_INSN_H */
