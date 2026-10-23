// re_dcx_val.c - values as C text: precedence, widths, constants, names, globals.
// Module: feature (C11).
// Owns: expression text, width casts, and naming an address: function, import, string, data.
// Depends: re_dcx.h, re_pe. Text lives in the caller's arena and is never freed alone.
#include "features/dec/core/re_dcx.h"

#include "features/pe/re_pe.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

dx_val_t dx_text(re_arena_t *a, uint8_t prec, uint8_t w, const char *fmt, ...) {
    dx_val_t v;
    char buf[512];
    va_list ap;
    memset(&v, 0, sizeof(v));
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0)
        n = 0;
    if ((size_t)n >= sizeof(buf)) {
        // Too long for the scratch buffer: format again into an arena block that fits.
        char *big = (char *)re_arena_alloc(a, (size_t)n + 1);
        va_start(ap, fmt);
        if (big)
            vsnprintf(big, (size_t)n + 1, fmt, ap);
        va_end(ap);
        v.s = big ? big : "?";
    } else {
        v.s = (const char *)re_arena_memdup(a, buf, (size_t)n + 1);
    }
    v.prec = prec;
    v.w = w;
    v.nw = w;
    return v;
}

dx_val_t dx_cst(int64_t c, uint8_t w) {
    dx_val_t v;
    memset(&v, 0, sizeof(v));
    v.cst = true;
    v.c = c;
    v.w = w;
    v.prec = DX_P_PRIMARY;
    return v;
}

const char *dx_type(uint8_t w, bool sgn) {
    switch (w) {
        case 1:
            return sgn ? "int8_t" : "uint8_t";
        case 2:
            return sgn ? "int16_t" : "uint16_t";
        case 4:
            return sgn ? "int32_t" : "uint32_t";
        case 16:
            return "__m128i";
        default:
            return sgn ? "int64_t" : "uint64_t";
    }
}

static int64_t at_width(int64_t c, uint8_t w, bool sgn) {
    if (w >= 8)
        return c;
    uint64_t m = (1ull << (8u * w)) - 1u;
    uint64_t u = (uint64_t)c & m;
    if (sgn && (u >> (8u * w - 1u)) & 1u)
        return (int64_t)(u | ~m);
    return (int64_t)u;
}

int64_t dx_sext(int64_t c, uint8_t w) {
    return at_width(c, w ? w : 8, true);
}

static bool in_image(const dx_fn_t *x, uint64_t va) {
    const re_pe_t *pe = x->code->pe;
    return pe && va >= pe->image_base && va < pe->image_base + pe->size_of_image &&
           va - pe->image_base >= 0x1000u;
}

// Bytes of the mapped image at va, or false when the address has no file backing.
static bool img_read(const dx_fn_t *x, uint64_t va, uint8_t *buf, size_t n) {
    uint64_t off;
    const re_pe_t *pe = x->code->pe;
    if (!pe || !in_image(x, va))
        return false;
    if (!re_pe_rva2off(pe, (uint32_t)(va - pe->image_base), &off) || off + n > x->code->img.n)
        return false;
    memcpy(buf, (const uint8_t *)x->code->img.p + off, n);
    return true;
}

static void put_char(re_strbuf_t *sb, uint8_t ch) {
    if (ch == '"' || ch == '\\')
        re_strbuf_putc(sb, '\\'), re_strbuf_putc(sb, (char)ch);
    else if (ch == '\n')
        re_strbuf_puts(sb, "\\n");
    else if (ch == '\r')
        re_strbuf_puts(sb, "\\r");
    else if (ch == '\t')
        re_strbuf_puts(sb, "\\t");
    else
        re_strbuf_putc(sb, (char)ch);
}

static bool printable(uint8_t c) {
    return (c >= 0x20 && c < 0x7F) || c == '\n' || c == '\r' || c == '\t';
}

// A C string literal for the text at va, ascii or utf-16, or NULL when the bytes there
// are not a terminated run of at least four printable characters.
static const char *string_at(dx_fn_t *x, uint64_t va) {
    uint8_t buf[2 * 96 + 2];
    size_t got = sizeof(buf);
    while (got >= 8 && !img_read(x, va, buf, got))
        got /= 2;
    if (got < 8)
        return NULL;
    bool wide = buf[1] == 0 && printable(buf[0]);
    size_t step = wide ? 2 : 1, n = 0;
    while (n * step + step <= got && printable(buf[n * step]) && (!wide || buf[n * step + 1] == 0))
        n++;
    bool ended = n * step + step <= got && buf[n * step] == 0;
    if (n < 4 || (!ended && n < 64))
        return NULL;
    re_strbuf_t sb;
    re_strbuf_init(&sb, x->a);
    re_strbuf_puts(&sb, wide ? "L\"" : "\"");
    for (size_t i = 0; i < n && i < 80; i++)
        put_char(&sb, buf[i * step]);
    re_strbuf_puts(&sb, n > 80 || !ended ? "\"..." : "\"");
    return sb.p;
}

static const char *func_name(dx_fn_t *x, uint64_t va) {
    const re_fscan_t *s = x->d->scan;
    long i = s ? re_func_index_of(s, va) : -1;
    const re_func_t *g = i >= 0 ? re_func_at(s, (size_t)i) : NULL;
    if (!g || g->va != va)
        return re_code_in_code(x->code, va) && va == x->f->va ? NULL : NULL;
    if (g->name.n)
        return dx_text(x->a, DX_P_PRIMARY, 8, "%.*s", (int)g->name.n, g->name.p).s;
    return dx_text(x->a, DX_P_PRIMARY, 8, "sub_%llX", (unsigned long long)va).s;
}

static const char *import_at(dx_fn_t *x, uint64_t va) {
    const re_xrefset_t *xs = x->d->xrefs;
    size_t n = xs ? re_xref_to_count(xs, va) : 0;
    for (size_t i = 0; i < n; i++) {
        const re_xref_t *r = re_xref_to_at(xs, va, i);
        if (r && (r->flags & (RE_XRF_IMPORT | RE_XRF_EXPORT)) && r->name.n)
            return dx_text(x->a, DX_P_PRIMARY, 8, "%.*s", (int)r->name.n, r->name.p).s;
    }
    return NULL;
}

// The name of a global at va. deref says the value at va is wanted rather than its
// address: an import slot's value is the imported function, a data word's is a dword_.
const char *dx_global_name(dx_fn_t *x, uint64_t va, uint8_t w, bool deref) {
    static const char *const kPre[] = {"byte", "word", "dword", "qword", "xmmword"};
    const char *imp = import_at(x, va);
    const char *fn = deref ? NULL : func_name(x, va);
    unsigned k = w <= 1 ? 0 : w == 2 ? 1 : w == 4 ? 2 : w == 8 ? 3 : 4;
    if (imp)
        return deref ? imp : dx_text(x->a, DX_P_UNARY, 8, "&__imp_%s", imp).s;
    if (fn)
        return fn;
    if (!deref) {
        const char *s = string_at(x, va);
        if (s)
            return s;
        if (re_code_in_code(x->code, va))
            return dx_text(x->a, DX_P_PRIMARY, 8, "loc_%llX", (unsigned long long)va).s;
        return dx_text(x->a, DX_P_UNARY, 8, "&unk_%llX", (unsigned long long)va).s;
    }
    return dx_text(x->a, DX_P_PRIMARY, w, "%s_%llX", kPre[k], (unsigned long long)va).s;
}

// A literal. Addresses inside the image are named; small numbers print in decimal,
// the rest in hex, and a value whose signed reading is a small negative prints as one.
const char *dx_const_text(dx_fn_t *x, int64_t c, uint8_t w) {
    int64_t u = at_width(c, w ? w : 8, false);
    int64_t s = at_width(c, w ? w : 8, true);
    if (w >= 8 && in_image(x, (uint64_t)c))
        return dx_global_name(x, (uint64_t)c, 8, false);
    if (s < 0 && s > -0x10000)
        return s > -10 ? dx_text(x->a, DX_P_UNARY, w, "%lld", (long long)s).s
                       : dx_text(x->a, DX_P_UNARY, w, "-0x%llX", (unsigned long long)-s).s;
    if ((uint64_t)u < 10)
        return dx_text(x->a, DX_P_PRIMARY, w, "%llu", (unsigned long long)u).s;
    return dx_text(x->a, DX_P_PRIMARY, w, "0x%llX", (unsigned long long)u).s;
}

const char *dx_slot_name(dx_fn_t *x, int32_t off) {
    int32_t first = x->cc == RE_CC_SYSV ? 8 : 0x28;
    if (off >= first && (off - first) % 8 == 0)
        return dx_text(x->a, DX_P_PRIMARY, 8, "a%d",
                       (int)((off - first) / 8 + 1 + dx_max_reg_args(x)))
            .s;
    if (off >= 8 && off < first && x->cc != RE_CC_SYSV && off % 8 == 0)
        return dx_text(x->a, DX_P_PRIMARY, 8, "home_a%d", (int)(off / 8)).s;
    if (off < 0)
        return dx_text(x->a, DX_P_PRIMARY, 8, "var_%X", (unsigned)-off).s;
    return dx_text(x->a, DX_P_PRIMARY, 8, "arg_%X", (unsigned)off).s;
}

const char *dx_str(dx_fn_t *x, const dx_val_t *v) {
    if (v->s)
        return v->s;
    if (v->cst)
        return dx_const_text(x, v->c, v->w);
    if (v->stk) {
        dx_slot_t *sl = dx_slot(x, v->off, false);
        if (sl)
            sl->used = true;
        return dx_text(x->a, DX_P_UNARY, 8, "&%s", dx_slot_name(x, v->off)).s;
    }
    return "?";
}

static uint8_t text_prec(dx_fn_t *x, const dx_val_t *v) {
    if (v->s)
        return v->prec;
    const char *t = dx_str(x, v);
    return t[0] == '-' || t[0] == '&' ? DX_P_UNARY : DX_P_PRIMARY;
}

const char *dx_paren(dx_fn_t *x, const dx_val_t *v, uint8_t prec) {
    const char *t = dx_str(x, v);
    if (text_prec(x, v) >= prec)
        return t;
    return dx_text(x->a, DX_P_PRIMARY, v->w, "(%s)", t).s;
}

// v read at width w. A constant is truncated; a text whose C width exceeds w, or that
// must be read as signed, gets the cast that makes the C mean what the machine did.
dx_val_t dx_width(dx_fn_t *x, dx_val_t v, uint8_t w, bool sgn) {
    if (!w || w > 8)
        return v;
    if (v.cst) {
        v.c = at_width(v.c, w, sgn);
        v.w = w;
        return v;
    }
    uint8_t cw = v.nw ? v.nw : 8;
    if (v.stk && w == 8 && !sgn)
        return v;
    if (!sgn && cw <= w)
        return v;
    if (sgn && v.sg && cw == w)
        return v; // already a signed value of this width
    dx_val_t r =
        dx_text(x->a, DX_P_UNARY, w, "(%s)%s", dx_type(w, sgn), dx_paren(x, &v, DX_P_UNARY));
    r.mem = v.mem, r.fx = v.fx, r.deps = v.deps, r.seq = v.seq;
    r.sg = sgn;
    r.ann = v.ann; // a narrower read of the same computation
    return r;
}

const char *dx_at_width(dx_fn_t *x, const dx_val_t *v, uint8_t w, bool sgn) {
    dx_val_t r = dx_width(x, *v, w, sgn);
    return dx_str(x, &r);
}

const char *dx_reg_name(dx_fn_t *x, unsigned reg, uint8_t w) {
    static const char *const k64[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"};
    static const char *const k32[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
    if (reg >= DX_NREG)
        return "?";
    if (reg < 8)
        return w == 8 ? k64[reg] : k32[reg];
    return dx_text(x->a, DX_P_PRIMARY, w, w == 8 ? "r%u" : "r%ud", reg).s;
}

const char *dx_mint(dx_fn_t *x, uint8_t w, int reg) {
    dx_var_t v;
    v.name = dx_text(x->a, DX_P_PRIMARY, w, "v%u", ++x->next_v).s;
    v.w = w ? w : 8;
    v.reg = (int16_t)reg;
    RE_VEC_PUSH(&x->vars, x->a, v);
    return v.name;
}

bool dx_simple(const dx_val_t *v) {
    if (v->fx)
        return false;
    // a step of a division still being recognised: pure, so repeating its text is safe,
    // and a variable would hide the steps that follow from the rest of the idiom
    if (v->ann && v->ann->kind != DX_AN_QUOT && v->ann->kind != DX_AN_LIN &&
        v->ann->kind != DX_AN_ADDC)
        return true;
    // a short quotient or multiple reads better repeated than named: x - x / 10 * 10 is
    // then a remainder the idioms can see whole
    if (v->ann && v->ann->kind != DX_AN_ADDC && v->s && re_str(v->s).n <= 40)
        return true;
    return v->cst || v->stk || v->prec == DX_P_PRIMARY;
}
