// re_x64_text.c - renders one projected x86-64 instruction as text.
// Module: feature (C11).
// Owns: mnemonic selection for the group opcodes and the operand formatting.
// Depends: re_x64_priv.h and the opcode tables. Never reads the image.
#include "features/disasm/re_x64_priv.h"

#include "utils/text/re_strbuf.h"

// The size of a SIMD memory operand: the scalar forms end in ss or sd and reach four
// or eight bytes, and everything else reaches a whole register's worth.
static const char *simd_mem_kw(const re_insn_t *in, const char *m) {
    size_t n = m ? re_str(m).n : 0;
    // An mmx operand reaches eight bytes whatever the rest of the block says: the
    // same opcode in the same map is a 128-bit xmm operation under 0x66.
    if (in->reg >= RE_X64_MMX_BASE)
        return "qword ptr ";
    if (n >= 2 && m[n - 2] == 's' && m[n - 1] == 's')
        return "dword ptr ";
    if (n >= 2 && m[n - 2] == 's' && m[n - 1] == 'd')
        return "qword ptr ";
    // The projection states the vector width as the operand size, which is what it is
    // for a SIMD instruction, so 32 here means the operand reaches a ymm register.
    return in->opsize > 16u ? "ymmword ptr " : "xmmword ptr ";
}

// A size keyword, the way a disassembler spells a narrow access. A dword
// register and a qword register are implied by the name, so only the narrow ones
// and any mismatch need spelling out.
static const char *size_kw(const re_insn_t *in, unsigned reg_bytes) {
    if (reg_bytes == 1)
        return in->opsize == 2 ? "word ptr " : "byte ptr ";
    if (reg_bytes == 2 && in->opsize != 2)
        return in->opsize == 1 ? "" : "dword ptr ";
    if (in->opsize == 1)
        return "dword ptr ";
    return "";
}

// A register of the caller's width rather than the operand size, for the handful of
// forms that reach a narrower register than the rest of the instruction does.
static void put_reg_sz(re_strbuf_t *out, const re_insn_t *in, unsigned reg, uint8_t bytes) {
    const char *n = x64_reg_name_ex(reg, bytes, in->rex);
    re_strbuf_puts(out, n ? n : "?");
}

static void put_reg(re_strbuf_t *out, const re_insn_t *in, unsigned reg) {
    put_reg_sz(out, in, reg, (uint8_t)in->opsize);
}

// [base + index * scale + disp], in the order a person writes it. The registers of
// an address are as wide as addressing is, not as wide as the operand: a 128-bit
// move still reaches its address through a 64-bit register.
static void put_mem(re_strbuf_t *out, const re_insn_t *in) {
    if (in->has_mem && in->base == RE_REG_RIP) {
        re_strbuf_puts(out, "[rip");
        if (in->disp)
            re_strbuf_appendf(out, "%c0x%llx", in->disp < 0 ? '-' : '+',
                              (unsigned long long)(in->disp < 0 ? -in->disp : in->disp));
        re_strbuf_puts(out, "]");
        return;
    }
    re_strbuf_puts(out, "[");
    if (in->base != RE_REG_NONE)
        put_reg_sz(out, in, in->base, in->addrsize);
    if (in->index != RE_REG_NONE) {
        if (in->base != RE_REG_NONE)
            re_strbuf_puts(out, " + ");
        put_reg_sz(out, in, in->index, in->addrsize);
        if (in->scale > 1)
            re_strbuf_appendf(out, "*%u", in->scale);
    }
    if (in->disp) {
        if (in->base == RE_REG_NONE && in->index == RE_REG_NONE)
            re_strbuf_appendf(out, "0x%llx", (unsigned long long)in->disp);
        else
            re_strbuf_appendf(out, "%c0x%llx", in->disp < 0 ? '-' : '+',
                              (unsigned long long)(in->disp < 0 ? -in->disp : in->disp));
    }
    re_strbuf_puts(out, "]");
}

// The r/m operand, which is a register or a memory reference depending on the mod
// field, and the reg operand, which is always a register. The size keyword differs by
// instruction family: an x87 escape and a SIMD name each state their own width, and
// only an integer instruction falls back to the operand size.
static void put_rm(re_strbuf_t *out, const re_insn_t *in, const char *m) {
    unsigned map = X64_ID_MAP(in->insn_id);
    unsigned op = X64_ID_OP(in->insn_id);
    if (!in->is_mem) {
        unsigned reg = ((unsigned)in->modrm >> 3) & 7u;
        // lmsw reaches a sixteen bit register whatever the operand size says, which
        // is the one thing its register form does differently from smsw beside it.
        if (map == 1 && op == 0x01u && in->mod == 3u && reg == 6u)
            put_reg_sz(out, in, in->rm, 2);
        // The wait and monitor instructions spend 0x66 on selecting the encoding
        // rather than on narrowing the operand, so their register is a doubleword
        // unless REX.W widens it, and reading the prefix as a size prints ax.
        else if (map == 1 && op == 0xAEu && in->mod == 3u && reg == 6u && in->pfx != 0u)
            put_reg_sz(out, in, in->rm, (in->rex & 8u) ? 8u : 4u);
        else
            put_reg(out, in, in->rm);
        return;
    }
    // The width of a memory operand follows the register file the projection chose,
    // not the map: the 0F map holds the system instructions and the descriptors too,
    // and a state save is not as wide as the vector register in a move beside it.
    if (map == 0 && op >= 0xD8u && op <= 0xDFu)
        re_strbuf_puts(out, x64_x87_mem_kw(in));
    else if (in->reg >= RE_X64_XMM_BASE)
        re_strbuf_puts(out, simd_mem_kw(in, m));
    else
        re_strbuf_puts(out, size_kw(in, in->opsize));
    put_mem(out, in);
}

// The immediate's width decides how it reads. A 32-bit immediate is a bit pattern,
// and the decoder has already sign extended it to fill an int64, so printing that
// directly turns "mov edi, 0xdeadbeef" into "mov edi, -0x21524111" - a different
// number from the one the instruction carries. Only a genuine 64-bit immediate keeps
// its sign, because there the sign is part of the value.
static void put_imm_sz(re_strbuf_t *out, int64_t v, uint8_t opsize) {
    if (opsize && opsize < 8) {
        uint64_t mask = (1ull << (opsize * 8u)) - 1ull;
        re_strbuf_appendf(out, "0x%llx", (unsigned long long)((uint64_t)v & mask));
        return;
    }
    if (v < 0)
        re_strbuf_appendf(out, "-0x%llx", (unsigned long long)(-v));
    else
        re_strbuf_appendf(out, "0x%llx", (unsigned long long)v);
}

static void put_imm(re_strbuf_t *out, const re_insn_t *in) {
    put_imm_sz(out, in->imm, in->opsize);
}

// The r/m half of one of the opcodes that mix a vector register with a general
// purpose one. Its width comes from REX.W rather than from the operand size the
// vector projection wrote, and a memory operand is as wide as the encoding reaches
// rather than as wide as the register it could have named instead: pinsrw reads a
// word from memory and a doubleword from a register, which are one field apart.
static void put_gp_rm(re_strbuf_t *out, const re_insn_t *in, unsigned bytes, unsigned mem_bytes) {
    if (in->is_mem) {
        re_strbuf_puts(out, mem_bytes == 8u   ? "qword ptr "
                            : mem_bytes == 2u ? "word ptr "
                                              : "dword ptr ");
        put_mem(out, in);
        return;
    }
    unsigned r = (unsigned)in->ops[3] + ((in->rex & 1u) ? 8u : 0u);
    const char *n = x64_reg_name_ex(r, (uint8_t)bytes, in->rex);
    re_strbuf_puts(out, n ? n : "?");
}

// The opcodes whose operand list is not all of one kind. 0F 6E and 0F 7E move a
// doubleword or a quadword between a vector register and a general purpose one, and
// which side is which flips with the prefix: under 0x66 the 6E form loads into the
// vector register and the 7E form stores out of it. Printing both halves with the
// vector name the rest of the block uses turns "movd eax, xmm0" into a register move
// that cannot happen. pinsrw and pextrw take a word in and out of the same block.
static bool put_mixed_operands(re_strbuf_t *out, const re_insn_t *in, unsigned op) {
    unsigned wide = (in->rex & 8u) || in->vex_w ? 8u : 4u;
    if (op == 0x6Eu || op == 0x7Eu) {
        // The F3 form is the one that keeps both operands in the vector file.
        if (in->pfx > 1u)
            return false;
        re_strbuf_puts(out, " ");
        if (op == 0x6Eu) {
            put_reg(out, in, in->reg);
            re_strbuf_puts(out, ", ");
            put_gp_rm(out, in, wide, wide);
        } else {
            put_gp_rm(out, in, wide, wide);
            re_strbuf_puts(out, ", ");
            put_reg(out, in, in->reg);
        }
        return true;
    }
    if (op != 0xC4u && op != 0xC5u)
        return false;
    re_strbuf_puts(out, " ");
    if (op == 0xC4u) {
        put_reg(out, in, in->reg);
        re_strbuf_puts(out, ", ");
        put_gp_rm(out, in, 4u, 2u);
    } else {
        put_gp_rm(out, in, wide, wide);
        re_strbuf_puts(out, ", ");
        put_reg(out, in, in->reg);
    }
    re_strbuf_puts(out, ", ");
    put_imm_sz(out, in->imm, 1);
    return true;
}

// The control and debug register moves. One operand is a control or debug register
// number from the reg field, which REX.R extends like any other register number, and
// the other is always a 64-bit general purpose register: in 64-bit mode these
// instructions move the whole register whatever the REX byte says.
static void put_cr_dr(re_strbuf_t *out, const re_insn_t *in, unsigned op) {
    const char *kind = (op == 0x20u || op == 0x22u) ? "cr" : "dr";
    const char *gp = x64_reg_name_ex(in->rm, 8, in->rex);
    re_strbuf_puts(out, " ");
    if (op == 0x20u || op == 0x21u)
        re_strbuf_appendf(out, "%s, %s%u", gp ? gp : "?", kind, (unsigned)in->reg & 15u);
    else
        re_strbuf_appendf(out, "%s%u, %s", kind, (unsigned)in->reg & 15u, gp ? gp : "?");
}

// The operand forms that come from a ModRM field rather than from the opcode: the 0F
// groups, the 3DNow form whose selector is behind the ModRM byte, the control and
// debug register moves, the two opcodes that mix a vector register with a general
// purpose one, and the x87 escapes. Returns true when it printed the list.
static bool put_field_operands(re_strbuf_t *out, const re_insn_t *in, const char *m) {
    unsigned op = X64_ID_OP(in->insn_id);
    unsigned map = X64_ID_MAP(in->insn_id);
    // The 0F groups: the reg field is the operation, so the operand list is the r/m
    // operand alone, or nothing at all for the register forms that take none.
    if (map == 1 && x64_group0f_single(op)) {
        if (x64_group0f_silent(in))
            return true;
        re_strbuf_puts(out, " ");
        put_rm(out, in, m);
        if (x64_text_has_imm(in)) {
            re_strbuf_puts(out, ", ");
            put_imm(out, in);
        }
        return true;
    }
    // The 3DNow form: mmx registers, with the r/m field as the destination, which is
    // where the result of pfadd lands.
    if (map == 1 && op == 0x0Fu && !in->vex) {
        re_strbuf_puts(out, " ");
        if (in->is_mem) {
            re_strbuf_puts(out, "qword ptr ");
            put_mem(out, in);
        } else {
            put_reg(out, in, in->rm);
        }
        re_strbuf_puts(out, ", ");
        put_reg(out, in, in->reg);
        return true;
    }
    // mov to and from a control or debug register: one operand is a register and the
    // other is a number from the reg field.
    if (map == 1 && op >= 0x20u && op <= 0x23u) {
        put_cr_dr(out, in, op);
        return true;
    }
    if (map == 1 && put_mixed_operands(out, in, op))
        return true;
    if (map == 0 && op >= 0xD8u && op <= 0xDFu && in->mod == 3) {
        x64_x87_regs(out, in);
        return true;
    }
    if (map == 0 && op >= 0xD8u && op <= 0xDFu) {
        re_strbuf_puts(out, " ");
        put_rm(out, in, m);
        return true;
    }
    return false;
}

// The forms that reach no ModRM operand at all: the register pushes and pops, the
// accumulator forms of the arithmetic block and the mov block, and a bare immediate.
static bool put_plain_operands(re_strbuf_t *out, const re_insn_t *in) {
    unsigned op = X64_ID_OP(in->insn_id);
    unsigned map = X64_ID_MAP(in->insn_id);
    if (in->has_modrm)
        return false;
    if (map == 0 && op >= 0x50 && op <= 0x5F) {
        // The low three bits pick the register, not op minus 0x50. The block is two
        // runs of eight - push rax..rdi then pop rax..rdi - so subtracting 0x50
        // renders pop rdi as r15.
        unsigned r = (op & 0x07u) + ((in->rex & 1u) ? 8u : 0u);
        re_strbuf_puts(out, " ");
        put_reg(out, in, r);
        return true;
    }
    unsigned r = 0;
    uint8_t forced = 0;
    if (x64_implicit_reg(in, &r, &forced)) {
        re_insn_t v = *in; // a byte form needs its own size to name the register
        if (forced)
            v.opsize = forced;
        re_strbuf_puts(out, " ");
        put_reg(out, &v, r);
        re_strbuf_puts(out, ", ");
        // The immediate of a byte form is one byte wide, so printing the forty bit
        // pattern the decoder sign extended to reads as a different number.
        put_imm_sz(out, in->imm, forced ? forced : (uint8_t)in->opsize);
        return true;
    }
    if (x64_text_has_imm(in)) {
        // The separator is not decoration: without it the immediate is appended to the
        // mnemonic and "push 0x30" reads as an instruction called push0x30.
        re_strbuf_puts(out, " ");
        put_imm(out, in);
    }
    return true;
}

// Three of the 0F38 opcodes spend their prefix on choosing the instruction rather than
// on narrowing the operand: adcx, adox and crc32 are one opcode under three prefixes,
// and every one of them reads a doubleword by default whatever the prefix says.
static re_insn_t sized_for_pfx(const re_insn_t *in) {
    re_insn_t r = *in;
    unsigned op = X64_ID_OP(in->insn_id);
    if (X64_ID_MAP(in->insn_id) != 2u)
        return r;
    if ((op == 0xF6u && (in->pfx == 1u || in->pfx == 2u)) ||
        ((op == 0xF0u || op == 0xF1u) && in->pfx == 3u))
        r.opsize = (in->rex & 8u) ? 8u : 4u;
    return r;
}

// The operand forms, in the order x86 defines them. Most integer instructions are
// one of these five, and a form that is not recognised is left off rather than
// guessed, which is why the text is sometimes just a mnemonic.
static void put_operands(re_strbuf_t *out, const re_insn_t *in, const char *m) {
    unsigned op = X64_ID_OP(in->insn_id);
    unsigned map = X64_ID_MAP(in->insn_id);
    // An encoding with no name has no operand list either: the bytes are printed as
    // what they are rather than dressed up in registers the instruction cannot have.
    if (!m)
        return;
    re_insn_t sized = sized_for_pfx(in);
    in = &sized;
    if (put_field_operands(out, in, m))
        return;
    // A branch is checked before the forms that reach no ModRM byte, because a near
    // jump is one of those and its operand is a target rather than an immediate.
    if (in->is_call || in->is_branch) {
        re_strbuf_puts(out, " ");
        if (in->has_target)
            re_strbuf_appendf(out, "0x%llx", (unsigned long long)in->target);
        else if (in->has_mem)
            put_mem(out, in);
        return;
    }
    if (put_plain_operands(out, in))
        return;
    if (map == 0 && op == 0x8D) { // lea
        re_strbuf_puts(out, " ");
        put_reg(out, in, in->reg);
        re_strbuf_puts(out, ", ");
        put_mem(out, in);
        return;
    }
    re_strbuf_puts(out, " ");
    if (x64_is_group_op(in)) {
        put_rm(out, in, m);
        if (x64_text_has_imm(in)) {
            re_strbuf_puts(out, ", ");
            put_imm(out, in);
        }
        return;
    }
    // r/m first when the r/m field is the destination. movsxd (map0 0x63) is the
    // opposite form, movsxd r64, r/m32, so it must not share this branch.
    bool reg_first = (map == 0 && (op == 0x89 || op == 0xC6 || op == 0x88)) ||
                     (map == 1 && op >= 0x90 && op <= 0x9F) ||
                     (map == 1 && x64_simd_store(op, in->pfx));
    if (reg_first) {
        put_rm(out, in, m);
        re_strbuf_puts(out, ", ");
        put_reg(out, in, in->reg);
    } else {
        put_reg(out, in, in->reg);
        re_strbuf_puts(out, ", ");
        put_rm(out, in, m);
    }
    if (in->imm || x64_text_has_imm(in)) {
        re_strbuf_puts(out, ", ");
        put_imm(out, in);
    }
}

void x64_render(const re_insn_t *in, re_arena_t *a, re_strbuf_t *out) {
    const char *m = x64_text_mnemonic(in);
    const char *vs = in->vex ? x64_text_vex_special(in) : NULL;
    unsigned op = X64_ID_OP(in->insn_id);
    unsigned map = X64_ID_MAP(in->insn_id);
    (void)a;
    if (vs) {
        re_strbuf_puts(out, vs);
        return;
    }
    // The condition is the low four bits of the opcode, not the low three: js and the
    // seven opcodes above it would all read as jo otherwise, and every one of them is
    // a different branch. The move on condition block shares the same encoding.
    if (map == 0 && op >= 0x70 && op <= 0x7F) {
        re_strbuf_puts(out, x64_text_jcc(op));
    } else if (map == 1 && op >= 0x80 && op <= 0x8F) {
        re_strbuf_puts(out, x64_text_jcc(op));
    } else if (map == 1 && op >= 0x40 && op <= 0x4F) {
        re_strbuf_puts(out, x64_text_cmov(op));
    } else if (!m) {
        // An encoding with no name is printed as the data byte it is, and the bytes it
        // consumed are all the reader gets, because no operand list is honest for it.
        re_strbuf_puts(out, "db");
        return;
    } else {
        // A VEX encoding is the same instruction with a wider register file, and the
        // name says so with a v in front of the legacy one: addps becomes vaddps,
        // pshufb becomes vpshufb. The exceptions spell their own name above.
        if (in->vex)
            re_strbuf_putc(out, 'v');
        re_strbuf_puts(out, m);
    }
    put_operands(out, in, m);
}
