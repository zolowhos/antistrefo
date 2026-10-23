// re_x64_fmt.c - renders one x86-64 instruction from its form: prefixes, name, operands.
// Module: feature (C11).
// Owns: the operand spec interpreter, the register files, sizes and EVEX decorations.
// Depends: re_x64_form.h, re_x64_fmtmem.c for memory operands, and re_strbuf. The raw
// bytes are decoded again here, so nothing the projection left out is ever guessed.
#include "features/disasm/fmt/re_x64_fmt.h"

#include <string.h>

// A size-code match: the operand spec tokens are 1..3 characters, so a fixed
// length comparison is faster than strcmp and avoids the gate's libc ban.
static inline bool sc_eq(const char *s, const char *lit) {
    for (unsigned i = 0;; i++) {
        if (lit[i] == '\0')
            return s[i] == '\0';
        if (s[i] != lit[i])
            return false;
    }
}

static const char *const kGp[4][16] = {
    {"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b",
     "r14b", "r15b"},
    {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w",
     "r14w", "r15w"},
    {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d",
     "r13d", "r14d", "r15d"},
    {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
     "r14", "r15"},
};
static const char *const kByteRex[4] = {"spl", "bpl", "sil", "dil"};
static const char *const kSeg[8] = {"es", "cs", "ss", "ds", "fs", "gs", "?", "?"};

const char *x64_fmt_gp(unsigned reg, unsigned size, bool rex) {
    unsigned r = reg & 15u;
    if (size == 1u && rex && r >= 4u && r < 8u)
        return kByteRex[r - 4u];
    switch (size) {
        case 1:
            return kGp[0][r];
        case 2:
            return kGp[1][r];
        case 8:
            return kGp[3][r];
        default:
            return kGp[2][r];
    }
}

static void put_vec(re_strbuf_t *o, unsigned reg, unsigned size) {
    const char *f = size >= 64u ? "zmm" : (size >= 32u ? "ymm" : "xmm");
    re_strbuf_appendf(o, "%s%u", f, reg & 31u);
}

// The width of a size code in bytes. reg_size is the register a register operand of the
// same code names, which differs only for the fractions of a vector and the mixed codes.
static unsigned code_size(const x64_fctx_t *c, const char *s, bool *is_vec_frac) {
    unsigned vl = c->vlen;
    *is_vec_frac = false;
    if (sc_eq(s, "b"))
        return 1;
    if (sc_eq(s, "w") || sc_eq(s, "sh"))
        return 2;
    if (sc_eq(s, "d") || sc_eq(s, "ss"))
        return 4;
    if (sc_eq(s, "q") || sc_eq(s, "sd"))
        return 8;
    if (sc_eq(s, "t"))
        return 10;
    if (sc_eq(s, "dq"))
        return 16;
    if (sc_eq(s, "qq"))
        return 32;
    if (sc_eq(s, "v"))
        return c->osz;
    if (sc_eq(s, "z"))
        return c->osz == 2u ? 2u : 4u;
    if (sc_eq(s, "y"))
        return c->w ? 8u : 4u;
    if (sc_eq(s, "a"))
        return c->in->addrsize;
    if (sc_eq(s, "p"))
        return 2u + (c->osz == 2u ? 2u : (c->osz == 8u ? 8u : 4u));
    if (sc_eq(s, "x"))
        return vl;
    if (sc_eq(s, "zm"))
        return 64; // a whole cache line: movdir64b, enqcmd, the key locker wide forms
    *is_vec_frac = true;
    if (sc_eq(s, "h"))
        return vl / 2u;
    if (sc_eq(s, "r"))
        return vl / 4u;
    if (sc_eq(s, "e"))
        return vl / 8u;
    if (sc_eq(s, "u"))
        return vl == 16u ? 8u : vl;
    *is_vec_frac = false;
    return 0; // "m", and anything without a width
}

// The register width a vector operand of this code names: a fraction of the vector
// length still names at least an xmm register.
static unsigned vec_reg_size(const x64_fctx_t *c, const char *s) {
    bool frac;
    unsigned n = code_size(c, s, &frac);
    if (sc_eq(s, "u"))
        return c->vlen;
    if (n < 16u)
        return 16u;
    return n;
}

static unsigned gp_reg_size(const x64_fctx_t *c, const char *s) {
    bool frac;
    if (sc_eq(s, "bd") || sc_eq(s, "wd"))
        return 4;
    return code_size(c, s, &frac);
}

static unsigned mem_size(const x64_fctx_t *c, const char *s) {
    bool frac;
    if (sc_eq(s, "bd"))
        return 1;
    if (sc_eq(s, "wd"))
        return 2;
    return code_size(c, s, &frac);
}

// The immediate, as the unsigned value of the width the operand has.
static void put_imm(re_strbuf_t *o, const x64_fctx_t *c, const char *s) {
    const x64_insn_t *in = c->in;
    uint64_t v = (uint64_t)in->imm;
    unsigned w;
    if (sc_eq(s, "2")) {
        v = in->cls == XC_IW_IB ? in->imm2 : (((uint64_t)in->imm >> 8) & 0xFFu);
        w = 1;
    } else if (sc_eq(s, "b")) {
        w = 1;
    } else if (sc_eq(s, "w")) {
        w = 2;
    } else if (sc_eq(s, "d")) {
        w = 4;
    } else {
        w = c->osz; // z, v and s all read as the operand size once sign extended
    }
    if (w < 8u)
        v &= (1ull << (8u * w)) - 1u;
    re_strbuf_appendf(o, "0x%llx", (unsigned long long)v);
}

static uint64_t branch_target(const x64_insn_t *in, uint64_t addr) {
    uint64_t t = in->has_target ? in->target : addr + in->size + (uint64_t)in->imm;
    // Under a 0x67 prefix the instruction pointer the branch writes is 32 bits wide.
    return in->addrsize == 4u ? (t & 0xFFFFFFFFull) : t;
}

// The EVEX decorations after the first operand: the write mask and zeroing.
static void put_mask(re_strbuf_t *o, const x64_fctx_t *c) {
    if (!c->in->evex || !c->in->ev_aaa)
        return;
    re_strbuf_appendf(o, "{k%u}", (unsigned)c->in->ev_aaa);
    if (c->in->ev_z)
        re_strbuf_puts(o, "{z}");
}

// Fixed operands: the constant one, the counter, the port, the stack top and the rest.
static bool put_fixed(re_strbuf_t *o, const x64_fctx_t *c, const char *t) {
    if (sc_eq(t, "1"))
        re_strbuf_puts(o, "0x1");
    else if (sc_eq(t, "AL"))
        re_strbuf_puts(o, "al");
    else if (sc_eq(t, "CL"))
        re_strbuf_puts(o, "cl");
    else if (sc_eq(t, "DX"))
        re_strbuf_puts(o, "dx");
    else if (sc_eq(t, "ST"))
        re_strbuf_puts(o, "st");
    else if (sc_eq(t, "STi"))
        re_strbuf_appendf(o, (c->in->modrm & 7u) ? "st(%u)" : "st", c->in->modrm & 7u);
    else if (sc_eq(t, "FS"))
        re_strbuf_puts(o, "fs");
    else if (sc_eq(t, "GS"))
        re_strbuf_puts(o, "gs");
    else if (sc_eq(t, "XMM0"))
        re_strbuf_puts(o, "xmm0");
    else
        return false;
    return true;
}

// A register or memory operand from ModRM.rm, in the register file the kind names.
static void put_rm(re_strbuf_t *o, x64_fctx_t *c, char k, const char *s) {
    const x64_insn_t *in = c->in;
    if (in->mod != 3u && in->cls != XC_MODRM_NOMEM) {
        x64_fmt_mem(o, c, mem_size(c, s));
        return;
    }
    switch (k) {
        case 'W':
        case 'U':
            put_vec(o, in->vm, vec_reg_size(c, s));
            return;
        case 'Q':
        case 'N':
            re_strbuf_appendf(o, "mm%u", in->rm & 7u);
            return;
        case 'T':
            re_strbuf_appendf(o, "k%u", in->rm & 7u);
            return;
        default:
            re_strbuf_puts(o, x64_fmt_gp(in->rm, gp_reg_size(c, s), in->rex != 0));
    }
}

// One operand: the kind letter, then its size code.
static void put_operand(re_strbuf_t *o, x64_fctx_t *c, const char *t) {
    const x64_insn_t *in = c->in;
    char k = t[0];
    const char *s = t + 1;
    if (put_fixed(o, c, t))
        return;
    if (k == 'B' && (t[1] == 'R' || t[1] == 'E')) {
        // The MPX bounds registers: bnd0..bnd3 from reg, or from rm or memory.
        if (t[1] == 'E' && in->mod != 3u)
            x64_fmt_mem(o, c, 16);
        else
            re_strbuf_appendf(o, "bnd%u", (t[1] == 'R' ? in->reg : in->rm) & 3u);
        return;
    }
    switch (k) {
        case 'E':
        case 'M':
        case 'R':
        case 'W':
        case 'U':
        case 'Q':
        case 'N':
        case 'T':
            put_rm(o, c, k, s);
            return;
        case 'X':
            x64_fmt_vsib(o, c, s);
            return;
        case 'G':
            re_strbuf_puts(o, x64_fmt_gp(in->reg, gp_reg_size(c, s), in->rex != 0));
            return;
        case 'Z':
            re_strbuf_puts(o, x64_fmt_gp((in->opcode & 7u) + ((in->rex & 1u) ? 8u : 0u),
                                         gp_reg_size(c, s), in->rex != 0));
            return;
        case 'B':
            re_strbuf_puts(o, x64_fmt_gp(in->vv & 15u, gp_reg_size(c, s), false));
            return;
        case 'A':
            re_strbuf_puts(o, x64_fmt_gp(0, gp_reg_size(c, s), false));
            return;
        case 'I':
            put_imm(o, c, s);
            return;
        case 'J':
            re_strbuf_appendf(o, "0x%llx", (unsigned long long)branch_target(in, c->addr));
            return;
        case 'O':
            x64_fmt_moffs(o, c, mem_size(c, s));
            return;
        case 'S':
            re_strbuf_puts(o, kSeg[in->reg & 7u]);
            return;
        case 'C':
            re_strbuf_appendf(o, "cr%u", in->reg & 15u);
            return;
        case 'D':
            re_strbuf_appendf(o, "dr%u", in->reg & 15u);
            return;
        case 'V':
            put_vec(o, in->vr, vec_reg_size(c, s));
            return;
        case 'H':
            put_vec(o, in->vv, vec_reg_size(c, s));
            return;
        case 'L':
            put_vec(o, ((uint64_t)in->imm >> 4) & 15u, vec_reg_size(c, s));
            return;
        case 'P':
            re_strbuf_appendf(o, "mm%u", in->reg & 7u);
            return;
        case 'K':
            re_strbuf_appendf(o, "k%u", in->reg & 7u);
            return;
        case 'Y':
            re_strbuf_appendf(o, "k%u", in->vv & 7u);
            return;
        default:
            re_strbuf_puts(o, "?");
    }
}

// The embedded rounding or exception suppression a register form's EVEX.b selects.
static void put_rounding(re_strbuf_t *o, const x64_fctx_t *c) {
    static const char *const kRc[4] = {"{rn-sae}", "{rd-sae}", "{ru-sae}", "{rz-sae}"};
    const x64_insn_t *in = c->in;
    if (!in->evex || !in->ev_b || in->mod != 3u)
        return;
    if (c->form->fl & XF_ER)
        re_strbuf_appendf(o, ", %s", kRc[in->ev_ll & 3u]);
    else if (c->form->fl & XF_SAE)
        re_strbuf_puts(o, ", {sae}");
}

// The operand list. A legacy encoding has no H operand: the destination doubles as the
// first source there, which is the whole difference between addps and vaddps.
static void put_operands(re_strbuf_t *o, x64_fctx_t *c, const char *ops) {
    char tok[16];
    unsigned n = 0;
    const char *p = ops;
    while (*p) {
        size_t k = 0;
        while (*p && *p != ',' && k + 1u < sizeof(tok))
            tok[k++] = *p++;
        tok[k] = 0;
        if (*p == ',')
            p++;
        if (tok[0] == 'H' && !c->in->vex)
            continue;
        re_strbuf_puts(o, n ? ", " : " ");
        put_operand(o, c, tok);
        if (n == 0)
            put_mask(o, c);
        n++;
    }
    put_rounding(o, c);
}

// The prefixes a reader is told about: lock, the repeats of the string primitives, and
// the branch hints that change what a branch is allowed to reach.
static void put_prefixes(re_strbuf_t *o, const x64_fctx_t *c) {
    const x64_insn_t *in = c->in;
    unsigned op = in->opcode;
    bool str = in->map == 0 && ((op >= 0xA4u && op <= 0xA7u) || (op >= 0xAAu && op <= 0xAFu) ||
                                (op >= 0x6Cu && op <= 0x6Fu));
    bool cmp = in->map == 0 && (op == 0xA6u || op == 0xA7u || op == 0xAEu || op == 0xAFu);
    // The lock elision hints: F2 and F3 on a locked memory update, or on xchg, which
    // locks without being asked, and F3 alone on a plain store.
    bool xchg = in->map == 0 && (op == 0x86u || op == 0x87u);
    bool hle = in->is_mem && !(in->map == 1u && in->opcode == 0xC7u) &&
               ((in->lock && (c->form->fl & XF_LOCK)) || xchg);
    bool store =
        in->is_mem && in->map == 0 && (op == 0x88u || op == 0x89u || op == 0xC6u || op == 0xC7u);
    if (in->rep == 3u && hle)
        re_strbuf_puts(o, "xacquire ");
    else if (in->rep == 2u && (hle || store))
        re_strbuf_puts(o, "xrelease ");
    if (in->lock)
        re_strbuf_puts(o, "lock ");
    if (str && in->rep == 2u)
        re_strbuf_puts(o, cmp ? "repe " : "rep ");
    else if (str && in->rep == 3u)
        re_strbuf_puts(o, "repne ");
    else if (in->rep == 3u && c->branch)
        re_strbuf_puts(o, "bnd ");
    if (in->seg == 4u && c->indirect)
        re_strbuf_puts(o, "notrack ");
}

static unsigned eff_osz(const x64_insn_t *in, const x64_form_t *f) {
    if (f->fl & XF_F64)
        return 8;
    if (f->fl & XF_D64)
        return (in->rex & 8u) ? 8u : (in->p66 ? 2u : 8u);
    return in->opsize;
}

void x64_fmt_insn(const x64_insn_t *in, uint64_t addr, re_strbuf_t *o) {
    x64_fctx_t c;
    const x64_form_t *f = x64_form_find(in);
    const char *mn;
    const char *ops;
    if (!f) {
        re_strbuf_puts(o, "(bad)");
        return;
    }
    memset(&c, 0, sizeof(c));
    c.in = in;
    c.form = f;
    c.addr = addr;
    c.osz = eff_osz(in, f);
    c.vlen = x64_vlen(in);
    c.w = x64_wbit(in) != 0;
    mn = f->mn;
    ops = f->ops;
    // The bnd hint applies to the near transfers, not to the loop family beside them.
    c.branch =
        (f->fl & XF_F64) != 0 && in->map <= 1u &&
        !(in->map == 0 && ((in->opcode >= 0xE0u && in->opcode <= 0xE3u) || in->opcode == 0xEBu));
    c.indirect = in->map == 0 && in->opcode == 0xFFu &&
                 (((in->modrm >> 3) & 7u) == 2u || ((in->modrm >> 3) & 7u) == 4u);
    if (in->map == 0 && in->opcode == 0x90u && (in->rex & 1u) && in->pfx != 2u) {
        mn = "xchg"; // REX.B makes 90 a real exchange with r8
        ops = "Zv,Av";
    } else if (in->map == 0 && in->opcode == 0xE3u && in->addrsize == 4u) {
        mn = "jecxz";
    } else if (in->map == 1 && in->opcode == 0x0Fu && !in->vex) {
        mn = x64_3dnow_name((uint8_t)in->imm);
    }
    put_prefixes(o, &c);
    if (in->vex && (f->sp & XS_L))
        re_strbuf_putc(o, 'v');
    re_strbuf_puts(o, mn ? mn : "(bad)");
    c.simd = x64_fmt_is_simd(ops) || (in->map == 0 && in->opcode >= 0xD8u && in->opcode <= 0xDFu);
    c.ops = ops;
    put_operands(o, &c, ops);
}

// The vtable entry: the projected record carries its own bytes, and decoding them again
// recovers every field the projection has no room for.
void x64_render(const re_insn_t *in, re_arena_t *a, re_strbuf_t *out) {
    x64_insn_t x;
    (void)a;
    if (!in->size || !x64_decode(in->raw, in->size, in->addr, &x)) {
        re_strbuf_puts(out, "(bad)");
        return;
    }
    x64_fmt_insn(&x, in->addr, out);
}
