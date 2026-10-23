// re_dcx_cond.c - branch conditions from the flags the last writer left.
// Module: feature (C11).
// Owns: recording a flag writer, and turning a condition nibble into C against it.
// Depends: re_dcx.h. A condition the writer does not decide is printed as the flags
//           it reads, never as a plausible comparison: that would be a wrong answer.
#include "features/dec/core/re_dcx.h"

#include <string.h>

static bool same_vn(re_varnode_t a, re_varnode_t b) {
    return a.space == b.space && a.offset == b.offset && a.size == b.size;
}

void dx_flag_set(dx_em_t *e, const re_ir_op_t *op) {
    dx_flag_t *f = &e->fl;
    memset(f, 0, sizeof(*f));
    if (!e->x->flive[e->gi])
        return; // nothing reads these flags: their operands are not uses
    f->ok = true;
    f->kind = (uint8_t)op->extra;
    f->w = (uint8_t)(op->in[0].size ? op->in[0].size : 8);
    f->id = e->gi;
    f->same = same_vn(op->in[0], op->in[1]);
    if ((f->kind == RE_SETF_ADD || f->kind == RE_SETF_SUB) && same_vn(op->in[0], e->last_out)) {
        f->ab = true;
        f->a = e->last_l;
        f->b = e->last_r;
    }
    f->l = dx_get(e, op->in[0]);
    f->r = f->same ? f->l : dx_get(e, op->in[1]);
    if (!f->l.seq)
        f->l.seq = ++e->seq;
    if (!f->r.seq)
        f->r.seq = f->same ? f->l.seq : ++e->seq;
}

static const char *const kRaw[16] = {
    "OF", "!OF", "CF", "!CF", "ZF",       "!ZF",      "CF || ZF",       "!CF && !ZF",
    "SF", "!SF", "PF", "!PF", "SF != OF", "SF == OF", "ZF || SF != OF", "!ZF && SF == OF",
};

static dx_cond_t raw(const char *s) {
    dx_cond_t c;
    memset(&c, 0, sizeof(c));
    c.kind = DX_C_RAW;
    c.raw = s;
    return c;
}

static dx_cond_t rel(dx_fn_t *x, dx_val_t l, dx_val_t r, uint8_t op, uint8_t w, bool sgn) {
    dx_cond_t c;
    memset(&c, 0, sizeof(c));
    dx_val_t lw = dx_width(x, l, w, sgn), rw = dx_width(x, r, w, sgn);
    c.l = dx_paren(x, &lw, DX_P_SHIFT);
    c.r = dx_paren(x, &rw, DX_P_SHIFT);
    c.op = op;
    // An unsigned ordering against a constant prints the constant unsigned: x <= -0x20
    // is true C for the same thing, but nobody reads it as 0xFFFFFFFFFFFFFFE0.
    if (!sgn && op != DX_EQ && op != DX_NE && rw.cst && dx_sext(rw.c, w) < 0)
        c.r = dx_text(x->a, DX_P_PRIMARY, w, "0x%llX",
                      (unsigned long long)rw.c & (w >= 8 ? ~0ull : (1ull << (8u * w)) - 1u))
                  .s;
    return c;
}

// The comparison forms: both operands are known, so every ordered condition is.
static dx_cond_t cmp_cond(dx_fn_t *x, dx_val_t l, dx_val_t r, unsigned cc, uint8_t w) {
    static const uint8_t kOp[16] = {0, 0, DX_LT, DX_GE, DX_EQ, DX_NE, DX_LE, DX_GT,
                                    0, 0, 0,     0,     DX_LT, DX_GE, DX_LE, DX_GT};
    if (cc >= RE_CC_JB && cc <= RE_CC_JA)
        return rel(x, l, r, kOp[cc], w, false);
    if (cc >= RE_CC_JL)
        return rel(x, l, r, kOp[cc], w, true);
    if (cc == RE_CC_JS || cc == RE_CC_JNS) {
        dx_val_t lw = dx_width(x, l, w, false), rw = dx_width(x, r, w, false);
        dx_val_t d = dx_text(x->a, DX_P_ADD, w, "%s - %s", dx_paren(x, &lw, DX_P_ADD),
                             dx_paren(x, &rw, DX_P_MUL));
        d.nw = 8;
        return rel(x, d, dx_cst(0, w), cc == RE_CC_JS ? DX_LT : DX_GE, w, true);
    }
    return raw(kRaw[cc & 15u]);
}

// A writer that only decides zero and sign of v, with OF and CF cleared when clr is
// set (test, and, or, xor), which makes the signed orderings against zero derivable.
static dx_cond_t zero_cond(dx_fn_t *x, dx_val_t v, unsigned cc, uint8_t w, bool clr) {
    dx_val_t z = dx_cst(0, w);
    switch (cc) {
        case RE_CC_JE:
            return rel(x, v, z, DX_EQ, w, false);
        case RE_CC_JNE:
            return rel(x, v, z, DX_NE, w, false);
        case RE_CC_JS:
            return rel(x, v, z, DX_LT, w, true);
        case RE_CC_JNS:
            return rel(x, v, z, DX_GE, w, true);
        default:
            break;
    }
    if (!clr)
        return raw(kRaw[cc & 15u]);
    switch (cc) {
        case RE_CC_JL:
            return rel(x, v, z, DX_LT, w, true);
        case RE_CC_JGE:
            return rel(x, v, z, DX_GE, w, true);
        case RE_CC_JLE:
            return rel(x, v, z, DX_LE, w, true);
        case RE_CC_JG:
            return rel(x, v, z, DX_GT, w, true);
        case RE_CC_JBE:
            return rel(x, v, z, DX_EQ, w, false);
        case RE_CC_JA:
            return rel(x, v, z, DX_NE, w, false);
        case RE_CC_JB:
            return raw("0");
        case RE_CC_JAE:
            return raw("1");
        default:
            return raw(kRaw[cc & 15u]);
    }
}

dx_cond_t dx_flag_cond(dx_em_t *e, unsigned cc) {
    dx_fn_t *x = e->x;
    const dx_flag_t *f = &e->fl;
    cc &= 15u;
    if (!f->ok)
        return raw(kRaw[cc]);
    switch (f->kind) {
        case RE_SETF_CMP:
            return cmp_cond(x, f->l, f->r, cc, f->w);
        case RE_SETF_TEST: {
            dx_val_t v = f->l;
            uint64_t ones = f->w >= 8 ? ~0ull : (1ull << (8u * f->w)) - 1u;
            // test x, -1 at the operand's width tests x itself
            bool all = f->r.cst && ((uint64_t)f->r.c & ones) == ones;
            if (!f->same && !all) {
                dx_val_t l = dx_width(x, f->l, f->w, false), r = dx_width(x, f->r, f->w, false);
                v = dx_text(x->a, DX_P_BAND, f->w, "%s & %s", dx_paren(x, &l, DX_P_BAND),
                            dx_paren(x, &r, DX_P_EQ));
                if (r.cst)
                    v = dx_text(x->a, DX_P_BAND, f->w, "%s & 0x%llX", dx_paren(x, &l, DX_P_BAND),
                                (unsigned long long)((uint64_t)r.c & ones));
            }
            return zero_cond(x, v, cc, f->w, true);
        }
        case RE_SETF_LOGIC:
            return zero_cond(x, f->l, cc, f->w, true);
        case RE_SETF_SUB:
            if (f->ab && cc != RE_CC_JE && cc != RE_CC_JNE)
                return cmp_cond(x, f->a, f->b, cc, f->w);
            return zero_cond(x, f->l, cc, f->w, false);
        case DX_FL_CF:
            if (cc == RE_CC_JB || cc == RE_CC_JAE)
                return rel(x, f->l, dx_cst(0, f->w), cc == RE_CC_JB ? DX_NE : DX_EQ, f->w, false);
            return raw(kRaw[cc]);
        default:
            if (f->kind == RE_SETF_ADD && f->ab && (cc == RE_CC_JB || cc == RE_CC_JAE)) {
                dx_val_t cf = dx_carry(e);
                return raw(cc == RE_CC_JB ? cf.s : dx_text(x->a, DX_P_UNARY, 1, "!%s", cf.s).s);
            }
            return zero_cond(x, f->l, cc, f->w, false);
    }
}

static uint8_t inverse(uint8_t op) {
    static const uint8_t k[] = {DX_NE, DX_EQ, DX_GE, DX_LT, DX_GT, DX_LE};
    return op < 6 ? k[op] : op;
}

static const dx_cond_t *dup_cond(dx_fn_t *x, const dx_cond_t *c) {
    dx_cond_t *n = (dx_cond_t *)re_arena_alloc(x->a, sizeof(*n));
    if (n)
        *n = *c;
    return n ? n : c;
}

static dx_cond_t not_cond(dx_fn_t *x, const dx_cond_t *c);

// a && b or a || b, either side optionally negated first.
dx_cond_t dx_cond_join(dx_fn_t *x, uint8_t kind, const dx_cond_t *a, bool na, const dx_cond_t *b,
                       bool nb) {
    dx_cond_t r, ta = na ? not_cond(x, a) : *a, tb = nb ? not_cond(x, b) : *b;
    memset(&r, 0, sizeof(r));
    r.kind = kind;
    r.a = dup_cond(x, &ta);
    r.b = dup_cond(x, &tb);
    return r;
}

// The negation, pushed down to the leaves: a comparison flips its operator and an
// && becomes an || of the negated sides, so a printed condition never wraps a whole
// compound in !( ).
static dx_cond_t not_cond(dx_fn_t *x, const dx_cond_t *c) {
    dx_cond_t r = *c;
    if (c->kind == DX_C_AND || c->kind == DX_C_OR)
        return dx_cond_join(x, c->kind == DX_C_AND ? DX_C_OR : DX_C_AND, c->a, true, c->b, true);
    if (c->kind == DX_C_REL || (!c->raw && c->l)) {
        r.op = inverse(c->op);
        return r;
    }
    if (c->raw && c->raw[0] == '0' && !c->raw[1])
        r.raw = "1";
    else if (c->raw && c->raw[0] == '1' && !c->raw[1])
        r.raw = "0";
    else
        r.raw = dx_text(x->a, DX_P_UNARY, 1, "!(%s)", c->raw ? c->raw : "?").s;
    return r;
}

static bool is_or_text(const dx_cond_t *c) {
    if (c->kind == DX_C_OR)
        return true;
    if (c->kind != DX_C_RAW && (c->kind == DX_C_REL || c->l))
        return false;
    for (const char *p = c->raw; p && *p; p++)
        if ((p[0] == '|' && p[1] == '|') || (p[0] == '&' && p[1] == '&'))
            return true;
    return false;
}

static bool write_wrapped(re_strbuf_t *b, bool wrap, char open) {
    return !wrap || re_strbuf_putc(b, open);
}

// One walk, one buffer. Copying each child into a new string made a chain of
// conditions quadratic, which is how a single function committed tens of gigabytes.
static bool cond_write(re_strbuf_t *b, const dx_cond_t *c) {
    static const char *const kSym[] = {"==", "!=", "<", ">=", "<=", ">"};
    bool pa;
    bool pb;
    const char *op;
    if (!c)
        return re_strbuf_puts(b, "?");
    if (c->kind != DX_C_AND && c->kind != DX_C_OR) {
        if (c->raw)
            return re_strbuf_puts(b, c->raw);
        if (!c->l || c->op > DX_GT)
            return re_strbuf_puts(b, "?");
        if (!re_strbuf_puts(b, c->l))
            return false;
        if (!re_strbuf_puts(b, " "))
            return false;
        if (!re_strbuf_puts(b, kSym[c->op]))
            return false;
        if (!re_strbuf_puts(b, " "))
            return false;
        return re_strbuf_puts(b, c->r);
    }
    pa = c->kind == DX_C_AND && c->a && is_or_text(c->a);
    pb = c->kind == DX_C_AND && c->b && is_or_text(c->b);
    op = c->kind == DX_C_AND ? " && " : " || ";
    return write_wrapped(b, pa, '(') && cond_write(b, c->a) && write_wrapped(b, pa, ')') &&
           re_strbuf_puts(b, op) && write_wrapped(b, pb, '(') && cond_write(b, c->b) &&
           write_wrapped(b, pb, ')');
}

static const char *cond_buf(dx_fn_t *x, const dx_cond_t *c) {
    re_strbuf_t sb;
    re_strbuf_init(&sb, x->a);
    if (!cond_write(&sb, c) || !re_strbuf_putc(&sb, 0))
        return "?";
    return sb.p;
}

const char *dx_cond_text(dx_fn_t *x, const dx_cond_t *c, bool neg) {
    if (!neg)
        return cond_buf(x, c);
    dx_cond_t n = not_cond(x, c);
    return cond_buf(x, &n);
}

dx_val_t dx_flag_value(dx_em_t *e, unsigned cc) {
    dx_cond_t c = dx_flag_cond(e, cc);
    dx_val_t v = dx_text(e->x->a, c.raw ? DX_P_UNARY : (c.op <= DX_NE ? DX_P_EQ : DX_P_REL), 1,
                         "%s", dx_cond_text(e->x, &c, false));
    if (c.raw && c.raw[0] != '!')
        v.prec = DX_P_LOR;
    v.nw = 4;
    v.seq = ++e->seq;
    v.mem = e->fl.l.mem || e->fl.r.mem;
    v.fx = e->fl.l.fx || e->fl.r.fx;
    v.deps = e->fl.l.deps | e->fl.r.deps;
    return v;
}

// The carry flag as a value: an unsigned borrow after a compare or a subtraction, the
// carry out of an addition, or whatever a bit test put there.
dx_val_t dx_carry(dx_em_t *e) {
    dx_fn_t *x = e->x;
    const dx_flag_t *f = &e->fl;
    if (f->ok && (f->kind == RE_SETF_CMP || (f->kind == RE_SETF_SUB && f->ab))) {
        dx_cond_t c = f->kind == RE_SETF_CMP ? cmp_cond(x, f->l, f->r, RE_CC_JB, f->w)
                                             : cmp_cond(x, f->a, f->b, RE_CC_JB, f->w);
        dx_val_t v = dx_text(x->a, DX_P_REL, 1, "%s", dx_cond_text(x, &c, false));
        v.nw = 4;
        return v;
    }
    if (f->ok && f->kind == RE_SETF_ADD && f->ab) {
        dx_val_t a = dx_width(x, f->a, f->w, false), b = dx_width(x, f->b, f->w, false);
        dx_val_t v =
            dx_text(x->a, DX_P_PRIMARY, 1, "__CFADD__(%s, %s)", dx_str(x, &a), dx_str(x, &b));
        v.nw = 4;
        return v;
    }
    if (f->ok && f->kind == DX_FL_CF)
        return f->l;
    if (f->ok && (f->kind == RE_SETF_TEST || f->kind == RE_SETF_LOGIC))
        return dx_cst(0, 1);
    if (f->ok && f->kind == RE_SETF_NEG) {
        // neg sets CF exactly when its operand, and so its result, is not zero: test
        // the operand, which is the result's text without its leading minus
        dx_val_t l = f->l;
        if (!l.cst && l.s && l.s[0] == '-' && l.s[1] != '0' && l.prec == DX_P_UNARY)
            l.s++;
        dx_cond_t c = rel(x, l, dx_cst(0, f->w), DX_NE, f->w, false);
        dx_val_t v = dx_text(x->a, DX_P_EQ, 1, "%s", dx_cond_text(x, &c, false));
        v.nw = 4;
        return v;
    }
    return dx_text(x->a, DX_P_PRIMARY, 1, "CF");
}
