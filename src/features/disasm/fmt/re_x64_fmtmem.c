// re_x64_fmtmem.c - renders x86-64 memory operands: size keyword, segment, address.
// Module: feature (C11).
// Owns: the address text, the size keyword policy, VSIB, moffs, EVEX disp8*N.
// Depends: re_x64_fmt.h. Reads the decoded record only.
#include "features/disasm/fmt/re_x64_fmt.h"

#include <string.h>

static inline bool sc_eq(const char *s, const char *lit) {
    for (unsigned i = 0;; i++) {
        if (lit[i] == '\0')
            return s[i] == '\0';
        if (s[i] != lit[i])
            return false;
    }
}

static const char *size_kw(unsigned n) {
    switch (n) {
        case 1:
            return "byte ptr ";
        case 2:
            return "word ptr ";
        case 4:
            return "dword ptr ";
        case 6:
            return "fword ptr ";
        case 8:
            return "qword ptr ";
        case 10:
            return "tbyte ptr ";
        case 16:
            return "xmmword ptr ";
        case 32:
            return "ymmword ptr ";
        case 64:
            return "zmmword ptr ";
        default:
            return "";
    }
}

bool x64_fmt_is_simd(const char *ops) {
    const char *p = ops;
    while (*p) {
        char k = *p;
        bool word = (k == 'S' && p[1] == 'T') || (k == 'X' && p[1] == 'M');
        if (!word && strchr("VWUHLPQNKTYX", k))
            return true;
        while (*p && *p != ',')
            p++;
        if (*p == ',')
            p++;
    }
    return false;
}

// The width of a general purpose register operand in the spec, or 0. The shift count and
// the port are not the operand's width, so neither tells a reader the memory size.
static unsigned gp_width(const x64_fctx_t *c, const char *t) {
    char k = t[0];
    const char *s = t + 1;
    if (sc_eq(t, "AL"))
        return 1;
    if (!strchr("GZBA", k) && !(k == 'E' && c->in->mod == 3u))
        return 0;
    if (k == 'E')
        return 0; // the r/m operand is the memory operand itself
    if (sc_eq(s, "b"))
        return 1;
    if (sc_eq(s, "w"))
        return 2;
    if (sc_eq(s, "d") || sc_eq(s, "bd") || sc_eq(s, "wd"))
        return 4;
    if (sc_eq(s, "q"))
        return 8;
    if (sc_eq(s, "v"))
        return c->osz;
    if (sc_eq(s, "z"))
        return c->osz == 2u ? 2u : 4u;
    if (sc_eq(s, "y"))
        return c->w ? 8u : 4u;
    if (sc_eq(s, "a"))
        return c->in->addrsize;
    return 0;
}

// An integer instruction states the width of a memory operand only when no register
// operand of the same width already says it: "mov [rax], ecx" is unambiguous and
// "mov dword ptr [rax], 0x1" is not. Vector and x87 forms always state it.
static bool needs_kw(const x64_fctx_t *c, unsigned size) {
    const char *p = c->ops;
    if (c->simd)
        return true;
    while (*p) {
        char t[16];
        size_t k = 0;
        while (*p && *p != ',' && k + 1u < sizeof(t))
            t[k++] = *p++;
        t[k] = 0;
        if (*p == ',')
            p++;
        if (gp_width(c, t) == size)
            return false;
    }
    return true;
}

static unsigned elem_size(const x64_fctx_t *c) {
    switch (c->form->bc & XB_MASK) {
        case XB_1:
            return 1;
        case XB_2:
            return 2;
        case XB_4:
            return 4;
        case XB_8:
            return 8;
        case XB_W:
            return c->w ? 8u : 4u;
        default:
            return 0;
    }
}

static void put_seg(re_strbuf_t *o, const x64_insn_t *in) {
    if (in->seg == 5u)
        re_strbuf_puts(o, "fs:");
    else if (in->seg == 6u)
        re_strbuf_puts(o, "gs:");
}

static void put_disp(re_strbuf_t *o, int64_t d, bool alone, unsigned asz) {
    if (alone) {
        uint64_t v = (uint64_t)d;
        if (asz == 4u)
            v &= 0xFFFFFFFFull;
        re_strbuf_appendf(o, "0x%llx", (unsigned long long)v);
        return;
    }
    if (d)
        re_strbuf_appendf(o, "%c0x%llx", d < 0 ? '-' : '+',
                          (unsigned long long)(d < 0 ? 0u - (uint64_t)d : (uint64_t)d));
}

// The bracketed address with the given index register text, or none.
static void put_addr(re_strbuf_t *o, const x64_insn_t *in, const char *index, int64_t disp) {
    unsigned asz = in->addrsize;
    bool any = false;
    re_strbuf_putc(o, '[');
    if (in->base == RE_REG_RIP) {
        re_strbuf_puts(o, asz == 4u ? "eip" : "rip");
        any = true;
    } else if (in->base != RE_REG_NONE) {
        re_strbuf_puts(o, x64_fmt_gp(in->base, asz, false));
        any = true;
    }
    if (index) {
        if (any)
            re_strbuf_putc(o, '+');
        re_strbuf_puts(o, index);
        if (in->scale > 1u)
            re_strbuf_appendf(o, "*%u", (unsigned)in->scale);
        any = true;
    }
    put_disp(o, disp, !any, asz);
    re_strbuf_putc(o, ']');
}

// The displacement EVEX compresses: a disp8 counts in units of N, the memory operand's
// width, or the element's when the operand broadcasts or the form scales by element.
static int64_t scaled_disp(const x64_fctx_t *c, unsigned size) {
    const x64_insn_t *in = c->in;
    unsigned n = size;
    if (!in->evex || in->disp_size != 1u)
        return in->disp;
    if (in->ev_b || (c->form->fl & XF_T1S))
        n = elem_size(c);
    return in->disp * (int64_t)(n ? n : 1u);
}

// The MPX bndldx and bndstx address: base plus an index the scale does not apply to,
// always 64-bit, whatever the address size prefix says.
static bool put_mib(re_strbuf_t *o, const x64_insn_t *in) {
    bool any = false;
    if (!(in->map == 1u && (in->opcode == 0x1Au || in->opcode == 0x1Bu) && in->pfx == 0u))
        return false;
    re_strbuf_putc(o, '[');
    if (in->base != RE_REG_NONE && in->base != RE_REG_RIP) {
        re_strbuf_puts(o, x64_fmt_gp(in->base, 8, false));
        any = true;
    } else if (in->base == RE_REG_RIP) {
        re_strbuf_puts(o, "rip");
        any = true;
    }
    if (in->index != RE_REG_NONE) {
        re_strbuf_puts(o, any ? "+" : "");
        re_strbuf_puts(o, x64_fmt_gp(in->index, 8, false));
        any = true;
    }
    put_disp(o, in->disp, !any, 8);
    re_strbuf_putc(o, ']');
    return true;
}

void x64_fmt_mem(re_strbuf_t *o, const x64_fctx_t *c, unsigned size) {
    const x64_insn_t *in = c->in;
    if (put_mib(o, in))
        return;
    bool bcst = in->evex && in->ev_b && (c->form->bc & XB_MASK) && !(c->form->fl & XF_T1S);
    unsigned kw = bcst ? elem_size(c) : size;
    if (kw && needs_kw(c, kw))
        re_strbuf_puts(o, size_kw(kw));
    // lea computes an address and reads nothing, so no segment applies to it.
    if (!(in->map == 0 && in->opcode == 0x8Du))
        put_seg(o, in);
    put_addr(o, in, in->index == RE_REG_NONE ? NULL : x64_fmt_gp(in->index, in->addrsize, false),
             scaled_disp(c, size));
    if (bcst && kw)
        re_strbuf_appendf(o, "{1to%u}", size / kw);
}

void x64_fmt_vsib(re_strbuf_t *o, const x64_fctx_t *c, const char *spec) {
    const x64_insn_t *in = c->in;
    unsigned elem = spec[0] == 'q' ? 8u : 4u;
    unsigned iw = (spec[1] == 'h' && c->vlen > 16u) ? c->vlen / 2u : c->vlen;
    char idx[8];
    const char *f = iw >= 64u ? "zmm" : (iw >= 32u ? "ymm" : "xmm");
    int64_t disp = in->disp;
    snprintf(idx, sizeof(idx), "%s%u", f, (unsigned)(in->sib_idx & 31u));
    if (in->evex && in->disp_size == 1u)
        disp *= (int64_t)elem;
    re_strbuf_puts(o, size_kw(elem));
    put_seg(o, in);
    put_addr(o, in, idx, disp);
}

void x64_fmt_moffs(re_strbuf_t *o, const x64_fctx_t *c, unsigned size) {
    const x64_insn_t *in = c->in;
    uint64_t v = (uint64_t)in->imm;
    if (in->addrsize == 4u)
        v &= 0xFFFFFFFFull;
    if (size && needs_kw(c, size))
        re_strbuf_puts(o, size_kw(size));
    put_seg(o, in);
    re_strbuf_appendf(o, "[0x%llx]", (unsigned long long)v);
}
