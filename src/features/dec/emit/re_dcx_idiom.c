// re_dcx_idiom.c - divisions by a constant and constant multiples, read back as C.
// Module: feature (C11).
// Owns: the magic multiply annotations, the divisor they add up to, and x * c chains.
// Depends: re_dcx.h. A division is printed only after the exact instruction sequence
//           has been run on a spread of dividends and matched x / d on every one, so a
//           sequence that only looks like a division keeps its literal text.
#include "features/dec/core/re_dcx.h"

#include <math.h>
#include <string.h>

static uint64_t mask_w(unsigned W) {
    return W >= 64 ? ~0ull : (1ull << W) - 1u;
}

// v's low W bits read as a signed number.
static int64_t sx(uint64_t v, unsigned W) {
    v &= mask_w(W);
    if (W < 64 && ((v >> (W - 1)) & 1u))
        return (int64_t)(v | ~mask_w(W));
    return (int64_t)v;
}

static uint64_t sar64(int64_t v, unsigned s) {
    if (s >= 64)
        return v < 0 ? ~0ull : 0;
    return v < 0 ? ~(~(uint64_t)v >> s) : (uint64_t)v >> s;
}

static uint64_t umulh64(uint64_t a, uint64_t b) {
    uint64_t al = a & 0xFFFFFFFFu, ah = a >> 32, bl = b & 0xFFFFFFFFu, bh = b >> 32;
    uint64_t ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
    uint64_t mid = (ll >> 32) + (lh & 0xFFFFFFFFu) + (hl & 0xFFFFFFFFu);
    return hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
}

static uint64_t smulh64(uint64_t a, uint64_t b) {
    uint64_t h = umulh64(a, b);
    if ((int64_t)a < 0)
        h -= b;
    if ((int64_t)b < 0)
        h -= a;
    return h;
}

// The high half of the product, as the machine's one operand imul or mul leaves it.
static uint64_t high_half(const dx_ann_t *h, uint64_t xv) {
    unsigned W = h->w * 8u;
    if (W == 64)
        return h->sgn ? smulh64(xv, h->m) : umulh64(xv, h->m);
    if (h->sgn)
        return sar64(sx(xv, 32) * sx(h->m, 32), 32) & mask_w(32);
    return ((xv & mask_w(32)) * (h->m & mask_w(32))) >> 32;
}

// The quotient the annotated sequence computes for dividend xv: the high half (or the
// wide product), the dividend added back or the unsigned fix-up, the shift, and for a
// signed division the sign correction that rounds toward zero.
static uint64_t simulate(const dx_ann_t *h, uint64_t xv) {
    unsigned W = h->w * 8u;
    uint64_t mw = mask_w(W), t;
    if (h->wide) {
        uint64_t p = h->sgn ? (uint64_t)sx(xv, 32) * h->m : (xv & mw) * h->m;
        t = h->sar ? sar64((int64_t)p, h->sh) : h->sh >= 64 ? 0 : p >> h->sh;
        return (t + (h->sgn ? p >> 63 : 0)) & mw;
    }
    t = high_half(h, xv);
    if (h->sgn) {
        if (h->addx)
            t = (t + xv) & mw;
        t = sar64(sx(t, W), h->sh) & mw;
        return (t + (t >> (W - 1))) & mw;
    }
    if (h->fix == 3)
        t = ((((xv - t) & mw) >> 1) + t) & mw;
    return (h->sh >= 64 ? 0 : t >> h->sh) & mw;
}

static bool matches(const dx_ann_t *h, uint64_t xv, int64_t d) {
    unsigned W = h->w * 8u;
    uint64_t want = h->sgn ? (uint64_t)(sx(xv, W) / d) & mask_w(W) : (xv & mask_w(W)) / (uint64_t)d;
    return simulate(h, xv) == want;
}

// Whether the sequence is x / d for every dividend tried: the edges of the range, the
// multiples of d on either side of zero, and a fixed pseudo random spread.
static bool divides(const dx_ann_t *h, int64_t d) {
    unsigned W = h->w * 8u;
    uint64_t lo = h->sgn ? (uint64_t)1 << (W - 1) : 0, hi = h->sgn ? lo - 1 : mask_w(W);
    uint64_t seed = 0x9E3779B97F4A7C15ull;
    uint64_t edge[] = {0,
                       1,
                       2,
                       3,
                       (uint64_t)d - 1,
                       (uint64_t)d,
                       (uint64_t)d + 1,
                       2 * (uint64_t)d,
                       hi,
                       hi - 1,
                       lo,
                       lo + 1,
                       ~0ull,
                       (uint64_t)-d,
                       (uint64_t)-d + 1,
                       (uint64_t)-d - 1,
                       hi / (uint64_t)d * (uint64_t)d,
                       hi / (uint64_t)d * (uint64_t)d - 1};
    for (size_t i = 0; i < sizeof(edge) / sizeof(edge[0]); i++)
        if (!matches(h, edge[i], d))
            return false;
    for (unsigned i = 0; i < 96; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        if (!matches(h, seed >> (i & 31), d) || !matches(h, seed, d))
            return false;
    }
    return true;
}

// The divisor the annotated sequence divides by, or 0 when it is not a division.
static int64_t divisor(const dx_ann_t *h) {
    unsigned W = h->w * 8u, total;
    double meff;
    if (h->wide) {
        meff = (double)h->m, total = h->sh;
    } else if (h->sgn) {
        meff = (double)sx(h->m, W) + (h->addx ? ldexp(1.0, (int)W) : 0.0);
        total = W + h->sh;
    } else {
        meff = (double)(h->m & mask_w(W)) + (h->fix == 3 ? ldexp(1.0, (int)W) : 0.0);
        total = W + h->sh + (h->fix == 3 ? 1u : 0u);
    }
    if (meff < 1.0 || total > 127)
        return 0;
    double d = ldexp(1.0, (int)total) / meff;
    if (d < 1.5 || d > 4.0e18 || d > ldexp(1.0, (int)W - (h->sgn ? 1 : 0)))
        return 0;
    for (int64_t c = (int64_t)d - 1; c <= (int64_t)d + 1; c++)
        if (c >= 2 && divides(h, c))
            return c;
    return 0;
}

static const dx_ann_t *ann_of(const dx_val_t *v, uint8_t kind) {
    return v->ann && v->ann->kind == kind ? v->ann : NULL;
}

static bool same(const dx_val_t *a, const dx_val_t *b) {
    return a->seq && a->seq == b->seq;
}

static dx_ann_t *new_ann(dx_em_t *e, const dx_ann_t *from, uint8_t kind) {
    dx_ann_t *n = (dx_ann_t *)re_arena_alloc(e->x->a, sizeof(*n));
    if (!n)
        return NULL;
    if (from)
        *n = *from;
    else
        memset(n, 0, sizeof(*n));
    n->kind = kind;
    return n;
}

// Replace v's text with the quotient x / d and mark it as one.
static void as_quotient(dx_em_t *e, dx_val_t *v, const dx_ann_t *h, int64_t d) {
    dx_fn_t *x = e->x;
    dx_ann_t *q = new_ann(e, h, DX_AN_QUOT);
    if (!q)
        return;
    q->d = d;
    dx_val_t xv = dx_width(x, h->x, h->w, h->sgn);
    dx_val_t t =
        dx_text(x->a, DX_P_MUL, h->w, "%s / %lld", dx_paren(x, &xv, DX_P_MUL), (long long)d);
    t.nw = h->w;
    t.sg = h->sgn;
    t = dx_mix(e, t, &xv, NULL);
    t.ann = q;
    *v = t;
}

void dx_idiom_mulh(dx_em_t *e, dx_val_t *v, const dx_val_t *a, const dx_val_t *b, bool sgn,
                   uint8_t w) {
    const dx_val_t *k = b->cst ? b : a->cst ? a : NULL, *xv = k == b ? a : b;
    dx_ann_t *h;
    if (!k || xv->cst || xv->fx || (w != 4 && w != 8) || !(h = new_ann(e, NULL, DX_AN_HI)))
        return;
    h->sgn = sgn, h->w = w, h->m = (uint64_t)k->c & mask_w(w * 8u), h->x = *xv;
    v->ann = h;
}

void dx_idiom_ext(dx_em_t *e, dx_val_t *v, const dx_val_t *xv, bool sgn) {
    dx_ann_t *h;
    if (xv->cst || xv->fx || !(h = new_ann(e, NULL, DX_AN_EXT)))
        return;
    h->sgn = sgn, h->w = 4, h->x = *xv;
    v->ann = h;
}

// A product of a 32 bit value widened to 64 bits and a constant: the wide form of a
// division, as clang emits it, unless the constant is too small to be a magic.
static bool wide_start(dx_em_t *e, const dx_val_t *l, const dx_val_t *r, uint8_t w, dx_val_t *v) {
    const dx_ann_t *ext = ann_of(l, DX_AN_EXT);
    bool zext = !ext && !l->cst && !l->fx && l->w == 4 && w == 8;
    dx_ann_t *h;
    if (w != 8 || (!ext && !zext) || (uint64_t)r->c < 0x10000u || r->c < 0)
        return false;
    if (!(h = new_ann(e, NULL, DX_AN_HI)))
        return false;
    h->wide = true, h->w = 4, h->m = (uint64_t)r->c;
    h->sgn = ext ? ext->sgn : false;
    h->x = ext ? ext->x : *l;
    v->ann = h;
    return true;
}

// A shift of a value already on the way to a quotient: the shift after the product,
// the step of the unsigned fix-up, or the sign bit a signed division corrects with.
static void shift_step(dx_em_t *e, uint8_t k, const dx_val_t *l, int64_t s, uint8_t w,
                       dx_val_t *v) {
    const dx_ann_t *h = ann_of(l, DX_AN_HI);
    dx_ann_t *n;
    if (!h || s <= 0 || s >= 64)
        return;
    if (k == RE_OP_INTSHR && s == (int64_t)w * 8 - 1 && h->sgn) {
        if ((h->sh == 0 || h->sar) && (n = new_ann(e, h, DX_AN_SIGN)) != NULL)
            v->ann = n;
        return;
    }
    if (h->fix == 1) {
        if (k == RE_OP_INTSHR && s == 1 && (n = new_ann(e, h, DX_AN_HI)) != NULL)
            n->fix = 2, v->ann = n;
        return;
    }
    if (h->fix == 2 || !(n = new_ann(e, h, DX_AN_HI)))
        return;
    n->sh = (uint8_t)(n->sh + s);
    n->sar = n->sar || k == RE_OP_INTSAR;
    v->ann = n;
    int64_t d = h->sgn ? 0 : divisor(n);
    if (d)
        as_quotient(e, v, n, d); // unsigned: the shift is the last step
}

// The base and coefficient v is a multiple of: its own annotation, or v itself once.
static bool lin_of(const dx_val_t *v, dx_val_t *base, int64_t *c) {
    const dx_ann_t *a = ann_of(v, DX_AN_LIN);
    if (v->cst || v->fx || v->stk)
        return false;
    *base = a ? a->x : *v;
    *c = a ? a->d : 1;
    return true;
}

// v as c * base. Combined terms print as one product, a lone shift keeps its text.
static void as_linear(dx_em_t *e, dx_val_t *v, const dx_val_t *base, int64_t c, uint8_t w,
                      bool mixed) {
    dx_fn_t *x = e->x;
    dx_ann_t *n = new_ann(e, NULL, DX_AN_LIN);
    int64_t cw = dx_sext(c, w);
    if (!n)
        return;
    n->x = *base, n->d = cw, n->w = w, n->mixed = mixed;
    if (mixed && cw == 0) {
        *v = dx_cst(0, w);
        return;
    }
    if (mixed) {
        dx_val_t b = dx_width(x, *base, w, false);
        dx_val_t t = cw == 1
                         ? b
                         : dx_text(x->a, DX_P_MUL, w,
                                   (cw > -0x10000 && cw < 0x10000) ? "%s * %lld" : "%s * 0x%llX",
                                   dx_paren(x, &b, DX_P_MUL), (long long)cw);
        t.nw = b.nw > w ? b.nw : w;
        if (t.nw > 8)
            t.nw = 8;
        t = dx_mix(e, t, &b, NULL);
        *v = t;
    }
    v->ann = n;
}

// x - q * d where q is x / d: the remainder.
static bool mod_form(dx_em_t *e, const dx_val_t *l, const dx_val_t *r, uint8_t w, dx_val_t *v) {
    dx_fn_t *x = e->x;
    dx_val_t base;
    int64_t c;
    const dx_ann_t *q;
    if (!lin_of(r, &base, &c) || !(q = ann_of(&base, DX_AN_QUOT)) || q->d != c || !same(l, &q->x) ||
        w != q->w)
        return false;
    dx_val_t xv = dx_width(x, q->x, q->w, q->sgn);
    dx_val_t t = dx_text(x->a, DX_P_MUL, w, "%s %% %lld", dx_paren(x, &xv, DX_P_MUL), (long long)c);
    t.nw = w;
    t.sg = q->sgn;
    *v = dx_mix(e, t, &xv, NULL);
    return true;
}

static void add_sub(dx_em_t *e, uint8_t k, const dx_val_t *l, const dx_val_t *r, uint8_t w,
                    dx_val_t *v) {
    const dx_ann_t *hl = ann_of(l, DX_AN_HI), *hr = ann_of(r, DX_AN_HI);
    const dx_ann_t *sl = ann_of(l, DX_AN_SIGN), *sr = ann_of(r, DX_AN_SIGN);
    const dx_ann_t *h = hl ? hl : hr, *sg = h == hl ? sr : sl;
    dx_ann_t *n;
    if (k == RE_OP_INTADD && h && sg && h->sgn && sg->m == h->m && sg->wide == h->wide &&
        same(&sg->x, &h->x)) {
        int64_t d = divisor(h);
        if (d)
            as_quotient(e, v, h, d); // t + (t >> 31): the signed quotient
        return;
    }
    if (k == RE_OP_INTADD && h && !h->wide && h->sgn && !h->addx && h->sh == 0 &&
        same(h == hl ? r : l, &h->x) && (n = new_ann(e, h, DX_AN_HI)) != NULL) {
        n->addx = true; // the high half plus the dividend, for a magic past 2^31
        v->ann = n;
        return;
    }
    if (k == RE_OP_INTSUB && hr && !hr->sgn && !hr->wide && hr->fix == 0 && hr->sh == 0 &&
        same(l, &hr->x) && (n = new_ann(e, hr, DX_AN_HI)) != NULL) {
        n->fix = 1; // x - t, the first step of the unsigned fix-up
        v->ann = n;
        return;
    }
    if (k == RE_OP_INTADD && h && h->fix == 2 && (hl ? hr : hl) && (hl ? hr : hl)->fix == 0 &&
        (n = new_ann(e, h, DX_AN_HI)) != NULL) {
        n->fix = 3; // ((x - t) >> 1) + t
        v->ann = n;
        return;
    }
    if (k == RE_OP_INTSUB && mod_form(e, l, r, w, v))
        return;
    dx_val_t bl, br;
    int64_t cl, cr;
    if (lin_of(l, &bl, &cl) && lin_of(r, &br, &cr) && same(&bl, &br))
        as_linear(e, v, &bl, k == RE_OP_INTADD ? cl + cr : cl - cr, w, true);
}

static dx_ann_t *mark(dx_em_t *e, dx_val_t *v, uint8_t kind, const dx_val_t *xv, uint8_t w,
                      unsigned k) {
    dx_ann_t *n = new_ann(e, NULL, kind);
    if (!n)
        return NULL;
    n->x = *xv, n->w = w, n->sh = (uint8_t)k, n->sgn = true;
    v->ann = n;
    return n;
}

// A signed division by 2^k rounds toward zero by adding 2^k - 1 to a negative dividend
// first: x + ((x >> 31) & (2^k - 1)), or x - (x >> 31) when k is 1, then x >> k.
static void pow2_step(dx_em_t *e, uint8_t k, const dx_val_t *l, const dx_val_t *r, uint8_t w,
                      dx_val_t *v) {
    const dx_ann_t *a = l->ann, *b = r->ann;
    unsigned W = w * 8u;
    if (k == RE_OP_INTSAR && r->cst && r->c == (int64_t)W - 1 && !a && !l->cst && !l->fx) {
        mark(e, v, DX_AN_XSIGN, l, w, 0);
    } else if (k == RE_OP_INTSHR && r->cst && r->c > 0 && r->c < (int64_t)W) {
        unsigned bits = W - (unsigned)r->c; // the top bits that remain
        if (a && a->kind == DX_AN_XSIGN && a->w == w)
            mark(e, v, DX_AN_BIAS, &a->x, w, bits);
        else if (!a && bits == 1 && !l->cst && !l->fx)
            mark(e, v, DX_AN_BIAS, l, w, 1);
    } else if (k == RE_OP_INTAND && r->cst && a && a->kind == DX_AN_XSIGN && a->w == w) {
        uint64_t m = (uint64_t)r->c & mask_w(W);
        if (m && (m & (m + 1)) == 0 && m != mask_w(W)) {
            unsigned bits = 0;
            while (m >> bits)
                bits++;
            mark(e, v, DX_AN_BIAS, &a->x, w, bits);
        }
    } else if (k == RE_OP_INTADD && ((a && a->kind == DX_AN_BIAS && same(r, &a->x)) ||
                                     (b && b->kind == DX_AN_BIAS && same(l, &b->x)))) {
        const dx_ann_t *bias = a && a->kind == DX_AN_BIAS ? a : b;
        mark(e, v, DX_AN_PRE, &bias->x, w, bias->sh);
    } else if (k == RE_OP_INTSUB && b && b->kind == DX_AN_XSIGN && same(l, &b->x)) {
        mark(e, v, DX_AN_PRE, l, w, 1);
    } else if (k == RE_OP_INTSAR && r->cst && a && a->kind == DX_AN_PRE && a->w == w &&
               r->c == (int64_t)a->sh) {
        dx_ann_t h;
        memset(&h, 0, sizeof(h));
        h.sgn = true, h.w = w, h.x = a->x;
        as_quotient(e, v, &h, (int64_t)1 << a->sh);
    }
}

void dx_idiom_bin(dx_em_t *e, uint8_t k, const dx_val_t *l, const dx_val_t *r, uint8_t w,
                  dx_val_t *v) {
    dx_val_t base;
    int64_t c;
    if (k == RE_OP_INTMUL && r->cst && !l->cst) {
        if (!wide_start(e, l, r, w, v) && lin_of(l, &base, &c))
            as_linear(e, v, &base, (int64_t)((uint64_t)c * (uint64_t)r->c), w, true);
    } else if (k == RE_OP_INTSHL && r->cst && r->c > 0 && r->c < 64 && lin_of(l, &base, &c)) {
        const dx_ann_t *a = ann_of(l, DX_AN_LIN);
        as_linear(e, v, &base, (int64_t)((uint64_t)c << r->c), w, a && a->mixed);
    } else if ((k == RE_OP_INTSHR || k == RE_OP_INTSAR) && r->cst && ann_of(l, DX_AN_HI)) {
        shift_step(e, k, l, r->c, w, v);
    } else if ((k == RE_OP_INTADD || k == RE_OP_INTSUB) &&
               !(l->ann && l->ann->kind == DX_AN_BIAS) &&
               !(r->ann && (r->ann->kind == DX_AN_BIAS || r->ann->kind == DX_AN_XSIGN))) {
        add_sub(e, k, l, r, w, v);
    }
    if (!v->ann && (w == 4 || w == 8))
        pow2_step(e, k, l, r, w, v);
    if (!v->ann && k == RE_OP_INTADD && r->cst && !l->cst && !l->fx && !l->stk) {
        dx_ann_t *n = mark(e, v, DX_AN_ADDC, l, w, 0);
        if (n)
            n->d = r->c;
    }
}

// x >= 0 ? x : x + (2^k - 1), the select form of the bias before a signed x >> k.
void dx_idiom_select(dx_em_t *e, const dx_cond_t *c, const dx_val_t *no, const dx_val_t *yes,
                     uint8_t w, dx_val_t *v) {
    const dx_val_t *plus = no->ann && no->ann->kind == DX_AN_ADDC ? no : yes;
    const dx_val_t *bare = plus == no ? yes : no;
    const dx_ann_t *a = plus->ann;
    if (!a || a->kind != DX_AN_ADDC || !same(bare, &a->x) || c->kind != DX_C_REL || !c->r ||
        !re_str_eq_cstr(re_str(c->r), "0") || (w != 4 && w != 8))
        return;
    uint64_t m = (uint64_t)a->d & mask_w(w * 8u);
    if (!m || (m & (m + 1)) != 0 || m == mask_w(w * 8u))
        return;
    bool ge = c->op == DX_GE && bare == yes, lt = c->op == DX_LT && plus == yes;
    dx_val_t xs = dx_width(e->x, a->x, w, true);
    if ((!ge && !lt) || !re_str_eq_cstr(re_str(c->l), dx_paren(e->x, &xs, DX_P_SHIFT)))
        return;
    unsigned bits = 0;
    while (m >> bits)
        bits++;
    mark(e, v, DX_AN_PRE, &a->x, w, bits);
}
