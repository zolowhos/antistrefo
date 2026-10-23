// re_dcx_ops.c - what each IR op becomes: a pending expression or a statement.
// Module: feature (C11).
// Owns: constants, copies, loads, stores, arithmetic, casts, and the dispatch.
// Depends: re_dcx.h. Calls, returns and flags live in their own files; the frame
//           decides whether an address is a local, and the value layer prints it.
#include "features/dec/core/re_dcx.h"

#include "features/pe/re_pe.h"

#include <string.h>

static uint8_t maxu8(uint8_t a, uint8_t b) {
    return a > b ? a : b;
}

dx_val_t dx_mix(dx_em_t *e, dx_val_t v, const dx_val_t *p, const dx_val_t *q) {
    v.mem = p->mem || (q && q->mem);
    v.fx = p->fx || (q && q->fx);
    v.deps = p->deps | (q ? q->deps : 0);
    v.seq = ++e->seq;
    return v;
}

static bool is_frame(const dx_fn_t *x, re_varnode_t v) {
    return v.space == RE_SPACE_REG && (v.offset == DX_RSP || (v.offset == DX_RBP && x->fp));
}

// A register past the sixteen integer ones is an xmm or friend: it is not tracked, it
// is a variable named after itself, and every write to it is a statement.
static bool simd_reg(re_varnode_t v) {
    return v.space == RE_SPACE_REG && v.offset >= DX_NREG;
}

static const char *simd_name(dx_em_t *e, re_varnode_t v) {
    const re_disasm_t *d = e->x->code->dis;
    const char *n = d && d->reg_name ? d->reg_name(d->ctx, v.offset) : NULL;
    return n ? n : "xmm?";
}

dx_val_t dx_get_any(dx_em_t *e, re_varnode_t v, uint8_t w, bool sgn) {
    if (simd_reg(v))
        return dx_text(e->x->a, DX_P_PRIMARY, (uint8_t)v.size, "%s", simd_name(e, v));
    return dx_read(e, v, w, sgn);
}

void dx_def_any(dx_em_t *e, re_varnode_t out, dx_val_t v) {
    if (simd_reg(out)) {
        dx_flush_mem(e);
        dx_stmt(e, "%s = %s;", simd_name(e, out), dx_str(e->x, &v));
        return;
    }
    if (out.space == RE_SPACE_REG && out.offset == DX_RSP && !v.stk && !v.cst) {
        // rsp moved by a run time amount: name the new value, and address the frame
        // from it until the epilogue puts rsp back in terms of the frame.
        const char *n = dx_mint(e->x, 8, -1);
        dx_flush_mem(e);
        dx_stmt(e, "%s = %s;", n, dx_str(e->x, &v));
        e->rsp_dyn = dx_text(e->x->a, DX_P_PRIMARY, 8, "%s", n);
        e->has_rsp_dyn = true;
        return;
    }
    if (is_frame(e->x, out))
        return;
    dx_def(e, out, v);
}

static void op_var(dx_em_t *e, const re_ir_op_t *op) {
    if (op->out.space == RE_SPACE_STACK || op->out.space == RE_SPACE_IOP ||
        op->out.space == RE_SPACE_HEAP)
        return; // the address of a memory operand: its users name it directly
    dx_def_any(e, op->out, dx_get_any(e, op->in[0], (uint8_t)op->out.size, false));
}

static void op_const(dx_em_t *e, const re_ir_op_t *op) {
    if (op->out.space == RE_SPACE_CONST)
        return; // an operand; readers find its value by id
    dx_def_any(e, op->out, dx_cst(op->const_val, (uint8_t)op->out.size));
}

typedef struct {
    uint8_t op;
    const char *sym;
    uint8_t prec;
    bool sgn;
} bin_t;

static const bin_t kBin[] = {
    {RE_OP_INTADD, "+", DX_P_ADD, false},    {RE_OP_INTSUB, "-", DX_P_ADD, false},
    {RE_OP_INTMUL, "*", DX_P_MUL, false},    {RE_OP_INTDIV, "/", DX_P_MUL, true},
    {RE_OP_INTMOD, "%", DX_P_MUL, true},     {RE_OP_INTUDIV, "/", DX_P_MUL, false},
    {RE_OP_INTUMOD, "%", DX_P_MUL, false},   {RE_OP_INTAND, "&", DX_P_BAND, false},
    {RE_OP_INTOR, "|", DX_P_BOR, false},     {RE_OP_INTXOR, "^", DX_P_BXOR, false},
    {RE_OP_INTSHL, "<<", DX_P_SHIFT, false}, {RE_OP_INTSHR, ">>", DX_P_SHIFT, false},
    {RE_OP_INTSAR, ">>", DX_P_SHIFT, true},  {RE_OP_FADD, "+", DX_P_ADD, false},
    {RE_OP_FSUB, "-", DX_P_ADD, false},      {RE_OP_FMUL, "*", DX_P_MUL, false},
    {RE_OP_FDIV, "/", DX_P_MUL, false},
};

static bool fold(uint8_t k, int64_t a, int64_t b, int64_t *r) {
    switch (k) {
        case RE_OP_INTADD:
            *r = (int64_t)((uint64_t)a + (uint64_t)b);
            return true;
        case RE_OP_INTSUB:
            *r = (int64_t)((uint64_t)a - (uint64_t)b);
            return true;
        case RE_OP_INTMUL:
            *r = (int64_t)((uint64_t)a * (uint64_t)b);
            return true;
        case RE_OP_INTAND:
            *r = a & b;
            return true;
        case RE_OP_INTOR:
            *r = a | b;
            return true;
        case RE_OP_INTXOR:
            *r = a ^ b;
            return true;
        case RE_OP_INTSHL:
            *r = b >= 0 && b < 64 ? (int64_t)((uint64_t)a << b) : 0;
            return true;
        default:
            return false;
    }
}

static dx_val_t bin_text(dx_em_t *e, const bin_t *t, dx_val_t l, dx_val_t r, uint8_t w) {
    dx_fn_t *x = e->x;
    const char *sym = t->sym;
    // x + -5 reads better, and means the same at this width, as x - 5.
    if (t->op == RE_OP_INTADD && r.cst && dx_sext(r.c, w) < 0 && dx_sext(r.c, w) > -0x100000000ll)
        sym = "-", r.c = -dx_sext(r.c, w);
    // A mask prints as the bits it keeps: x & 0xFFFFFFF0, not x & -0x10.
    if ((t->op == RE_OP_INTAND || t->op == RE_OP_INTOR || t->op == RE_OP_INTXOR) && r.cst &&
        dx_sext(r.c, w) < 0) {
        uint64_t ones = w >= 8 ? ~0ull : (1ull << (8u * w)) - 1u;
        r = dx_text(x->a, DX_P_PRIMARY, w, "0x%llX", (unsigned long long)((uint64_t)r.c & ones));
    }
    // An address constant in arithmetic is a byte offset, not C pointer arithmetic.
    if (l.cst && dx_str(x, &l)[0] == '&')
        l = dx_text(x->a, DX_P_UNARY, 8, "(uint64_t)%s", dx_str(x, &l));
    if (r.cst && dx_str(x, &r)[0] == '&')
        r = dx_text(x->a, DX_P_UNARY, 8, "(uint64_t)%s", dx_str(x, &r));
    if (l.stk)
        l = dx_text(x->a, DX_P_UNARY, 8, "(uint64_t)%s", dx_str(x, &l));
    if (r.stk)
        r = dx_text(x->a, DX_P_UNARY, 8, "(uint64_t)%s", dx_str(x, &r));
    dx_val_t v = dx_text(x->a, t->prec, w, "%s %s %s", dx_paren(x, &l, t->prec), sym,
                         dx_paren(x, &r, (uint8_t)(t->prec + 1)));
    v.nw = maxu8(4, maxu8(l.cst ? 0 : l.nw, r.cst ? 0 : r.nw));
    if (v.nw > 8)
        v.nw = 8;
    return dx_mix(e, v, &l, &r);
}

static bool commutes(uint8_t k) {
    return k == RE_OP_INTADD || k == RE_OP_INTMUL || k == RE_OP_INTAND || k == RE_OP_INTOR ||
           k == RE_OP_INTXOR;
}

// x + 0, x | 0, x & -1, x * 1, x << 0 are x; x & 0 and x * 0 are 0; x | -1 is -1. A
// value with a side effect is never dropped, so only a pure x simplifies away.
static bool identity(dx_em_t *e, const re_ir_op_t *op, uint8_t k, dx_val_t l, dx_val_t r,
                     uint8_t w) {
    uint64_t ones = w >= 8 ? ~0ull : (1ull << (8u * w)) - 1u, c = (uint64_t)r.c & ones;
    bool keep = (c == 0 &&
                 (k == RE_OP_INTADD || k == RE_OP_INTSUB || k == RE_OP_INTOR || k == RE_OP_INTXOR ||
                  k == RE_OP_INTSHL || k == RE_OP_INTSHR || k == RE_OP_INTSAR)) ||
                (c == 1 && k == RE_OP_INTMUL) || (c == ones && k == RE_OP_INTAND);
    bool zero = c == 0 && (k == RE_OP_INTAND || k == RE_OP_INTMUL);
    bool all = c == ones && k == RE_OP_INTOR;
    if (!r.cst || l.fx || (!keep && !zero && !all))
        return false;
    if (keep)
        dx_def_any(e, op->out, dx_width(e->x, l, w, false));
    else
        dx_def_any(e, op->out, dx_cst(zero ? 0 : (int64_t)ones, w));
    return true;
}

static bool image_const(const dx_fn_t *x, const dx_val_t *v) {
    const re_pe_t *pe = x->code->pe;
    return v->cst && pe && (uint64_t)v->c >= pe->image_base &&
           (uint64_t)v->c < pe->image_base + pe->size_of_image;
}

// Record the index form of a product or a sum, so a later load or store through it can
// print as an array access.
static void index_form(dx_em_t *e, uint8_t k, const dx_val_t *l, const dx_val_t *r, dx_val_t *v) {
    dx_fn_t *x = e->x;
    if (k == RE_OP_INTMUL && r->cst && !l->cst &&
        (r->c == 1 || r->c == 2 || r->c == 4 || r->c == 8))
        v->ix = dx_str(x, l), v->ixk = (uint8_t)r->c;
    else if (k == RE_OP_INTSHL && r->cst && !l->cst && r->c >= 1 && r->c <= 3)
        v->ix = dx_str(x, l), v->ixk = (uint8_t)(1u << r->c);
    if (k != RE_OP_INTADD)
        return;
    const dx_val_t *base = image_const(x, r) || r->stk ? r : image_const(x, l) || l->stk ? l : NULL;
    const dx_val_t *idx = base == r ? l : r;
    if (!base || idx->cst || idx->stk)
        return;
    v->arr = true;
    v->astk = base->stk;
    v->abase = base->c;
    v->aoff = base->off;
    v->aidx = idx->ix ? idx->ix : dx_str(x, idx);
    v->ask = idx->ix ? idx->ixk : 1;
}

// v as the operand of a unary minus: parenthesised when its text starts with one, so a
// double negation prints "-(-x)" and never "--x".
static const char *neg_operand(dx_em_t *e, const dx_val_t *v) {
    const char *s = dx_paren(e->x, v, DX_P_UNARY);
    return s[0] == '-' ? dx_text(e->x->a, DX_P_PRIMARY, v->w, "(%s)", s).s : s;
}

static void op_bin(dx_em_t *e, const re_ir_op_t *op, const bin_t *t) {
    uint8_t w = (uint8_t)op->out.size;
    dx_val_t l = dx_get_any(e, op->in[0], w, t->sgn);
    dx_val_t r = dx_get_any(
        e, op->in[1],
        t->op == RE_OP_INTSHL || t->op == RE_OP_INTSHR || t->op == RE_OP_INTSAR ? 1 : w, t->sgn);
    int64_t c;
    if (commutes(t->op) && l.cst && !r.cst) {
        dx_val_t sw = l;
        l = r, r = sw; // the constant reads better on the right
    }
    // A scaled index is what a jump table load is indexed by: the switch's value.
    if (t->op == RE_OP_INTMUL && r.cst && (r.c == 4 || r.c == 8) && !l.cst)
        e->sw_idx = dx_str(e->x, &l);
    if (t->op == RE_OP_INTADD || t->op == RE_OP_INTSUB) {
        e->last_out = op->out;
        e->last_l = l;
        e->last_r = r;
    }
    if (op->in[2].space == RE_SPACE_FLAG) { // adc, sbb: the carry is a third operand
        dx_val_t cf = dx_carry(e);
        bool self = op->in[0].space == op->in[1].space && op->in[0].offset == op->in[1].offset;
        if (self && t->op == RE_OP_INTSUB) { // sbb r, r: 0 or -1 from the carry
            dx_val_t v = dx_text(e->x->a, DX_P_UNARY, w, "-%s", neg_operand(e, &cf));
            v.nw = 4;
            dx_def_any(e, op->out, dx_mix(e, v, &cf, NULL));
            return;
        }
        l = bin_text(e, t, l, r, w);
        r = cf;
    }
    if (l.cst && r.cst && fold(t->op, l.c, r.c, &c)) {
        dx_def_any(e, op->out, dx_cst(c, w));
        return;
    }
    if (op->in[2].space != RE_SPACE_FLAG && identity(e, op, t->op, l, r, w))
        return;
    if (l.stk && r.cst && (t->op == RE_OP_INTADD || t->op == RE_OP_INTSUB)) {
        dx_val_t s = l;
        s.off += (int32_t)(t->op == RE_OP_INTADD ? r.c : -r.c);
        dx_def_any(e, op->out, s);
        return;
    }
    if (op->out.space == RE_SPACE_REG && op->out.offset == DX_RSP && t->op == RE_OP_INTSUB &&
        l.stk && !r.cst) {
        dx_val_t v = dx_text(e->x->a, DX_P_PRIMARY, 8, "alloca(%s)", dx_str(e->x, &r));
        dx_def_any(e, op->out, dx_mix(e, v, &r, NULL));
        return;
    }
    if (t->op == RE_OP_INTSAR)
        l = dx_width(e->x, l, w, true);
    dx_val_t v = bin_text(e, t, l, r, w);
    v.sg = t->sgn;
    if (op->in[2].space != RE_SPACE_FLAG)
        dx_idiom_bin(e, t->op, &l, &r, w, &v);
    index_form(e, t->op, &l, &r, &v);
    dx_def_any(e, op->out, v);
}

static void op_unary(dx_em_t *e, const re_ir_op_t *op, const char *pre) {
    uint8_t w = (uint8_t)op->out.size;
    dx_val_t l = dx_get_any(e, op->in[0], w, false);
    if (l.cst) {
        dx_def_any(e, op->out, dx_cst(pre[0] == '-' ? -l.c : ~l.c, w));
        return;
    }
    if (pre[0] == '-' && l.s && l.s[0] == '-' && l.s[1] != '0' && l.prec == DX_P_UNARY) {
        dx_val_t v = l; // -(-x) is x: the operand text follows the inner minus
        v.s++;
        dx_def_any(e, op->out, v);
        return;
    }
    dx_val_t v = dx_text(e->x->a, DX_P_UNARY, w, "%s%s", pre,
                         pre[0] == '-' ? neg_operand(e, &l) : dx_paren(e->x, &l, DX_P_UNARY));
    v.nw = maxu8(4, l.nw);
    dx_def_any(e, op->out, dx_mix(e, v, &l, NULL));
}

static void op_cast(dx_em_t *e, const re_ir_op_t *op) {
    uint8_t w = (uint8_t)op->out.size, iw = (uint8_t)op->in[0].size;
    bool sgn = (op->extra & RE_CAST_SIGNED) != 0;
    dx_val_t l = dx_get_any(e, op->in[0], iw, sgn);
    dx_val_t v = l;
    if (sgn && !l.cst && w > iw) {
        v = dx_text(e->x->a, DX_P_UNARY, w, "(%s)%s", dx_type(w, true), dx_str(e->x, &l));
        v.sg = true;
    }
    if (!l.cst)
        v = dx_mix(e, v, &l, NULL);
    v.w = w;
    v.nw = sgn ? w : maxu8(iw, l.cst ? 0 : (l.nw < iw ? l.nw : iw));
    v.ann = NULL;
    if (w == 8 && iw == 4)
        dx_idiom_ext(e, &v, &l, sgn); // a widening a wide division multiplies
    dx_def_any(e, op->out, v);
}

// Operations C has no operator for, printed as the compiler intrinsics that name them.
static const char *intrinsic(uint8_t k, uint8_t w) {
    bool q = w == 8;
    switch (k) {
        case RE_OP_ROL:
            return w == 1 ? "_rotl8" : w == 2 ? "_rotl16" : q ? "_rotl64" : "_rotl";
        case RE_OP_ROR:
            return w == 1 ? "_rotr8" : w == 2 ? "_rotr16" : q ? "_rotr64" : "_rotr";
        case RE_OP_POPCNT:
            return q ? "__popcnt64" : "__popcnt";
        case RE_OP_LZCNT:
            return q ? "__lzcnt64" : "__lzcnt";
        case RE_OP_TZCNT:
            return q ? "_tzcnt_u64" : "_tzcnt_u32";
        case RE_OP_BSWAP:
            return q ? "_byteswap_uint64" : w == 2 ? "_byteswap_ushort" : "_byteswap_ulong";
        case RE_OP_UMULH:
            return q ? "__umulh" : "__umulh32";
        case RE_OP_IMULH:
            return q ? "__mulh" : "__mulh32";
        case RE_OP_MEMCPY:
            return "memcpy";
        case RE_OP_MEMSET:
            return "memset";
        default:
            return NULL;
    }
}

static void op_call_like(dx_em_t *e, const re_ir_op_t *op, const char *fn) {
    uint8_t w = (uint8_t)(op->out.size ? op->out.size : 8);
    dx_val_t a = dx_get_any(e, op->in[0], w, op->op == RE_OP_IMULH);
    bool two = op->in[1].size != 0 && op->op != RE_OP_POPCNT && op->op != RE_OP_BSWAP &&
               op->op != RE_OP_LZCNT && op->op != RE_OP_TZCNT;
    dx_val_t b = two ? dx_get_any(e, op->in[1], w, op->op == RE_OP_IMULH) : a;
    dx_val_t v = two ? dx_text(e->x->a, DX_P_PRIMARY, w, "%s(%s, %s)", fn, dx_str(e->x, &a),
                               dx_str(e->x, &b))
                     : dx_text(e->x->a, DX_P_PRIMARY, w, "%s(%s)", fn, dx_str(e->x, &a));
    v = dx_mix(e, v, &a, two ? &b : NULL);
    if ((op->op == RE_OP_IMULH || op->op == RE_OP_UMULH) && two)
        dx_idiom_mulh(e, &v, &a, &b, op->op == RE_OP_IMULH, w);
    if (op->op == RE_OP_MEMCPY || op->op == RE_OP_MEMSET) {
        dx_flush_mem(e);
        dx_stmt(e, "%s;", v.s);
        return;
    }
    dx_def_any(e, op->out, v);
}

static void op_flow_misc(dx_em_t *e, const re_ir_op_t *op) {
    dx_fn_t *x = e->x;
    dx_block_t *blk = &x->b[e->b];
    if (op->op == RE_OP_INT) {
        dx_flush_mem(e);
        if (op->const_val == 3)
            dx_stmt(e, "__debugbreak();");
        else if (op->const_val == 0x29) {
            dx_val_t code = dx_read(e, re_ir_vn(RE_SPACE_REG, 4, 1), 4, false);
            dx_stmt(e, "__fastfail(%s);", dx_str(x, &code));
        } else if (op->const_val == 0)
            dx_stmt(e, "__syscall();");
        else
            dx_stmt(e, "__int(0x%llX);", (unsigned long long)op->const_val);
        return;
    }
    if (op->op == RE_OP_CBRANCH && blk->term == DX_T_COND) {
        blk->cond = dx_flag_cond(e, op->extra);
        return;
    }
    if (op->op != RE_OP_BRANCH)
        return;
    if (blk->term == DX_T_SWITCH) {
        blk->swv = e->sw_idx;
    } else if (blk->term == DX_T_EXIT && blk->target) {
        dx_emit_tail(e, op);
    } else if (blk->term == DX_T_EXIT) {
        dx_emit_tail(e, op);
    }
}

static void op_select(dx_em_t *e, const re_ir_op_t *op) {
    uint8_t w = (uint8_t)op->out.size;
    dx_cond_t c = dx_flag_cond(e, op->extra);
    dx_val_t a = dx_get_any(e, op->in[0], w, false), b = dx_get_any(e, op->in[1], w, false);
    dx_val_t v = dx_text(e->x->a, DX_P_COND, w, "%s ? %s : %s", dx_cond_text(e->x, &c, false),
                         dx_paren(e->x, &b, DX_P_LOR), dx_paren(e->x, &a, DX_P_COND));
    v = dx_mix(e, v, &a, &b);
    dx_idiom_select(e, &c, &a, &b, w, &v);
    dx_def_any(e, op->out, v);
}

// The ops with a handler of their own; false sends the op to the arithmetic tables.
static bool op_named(dx_em_t *e, const re_ir_op_t *op) {
    switch (op->op) {
        case RE_OP_CONST:
            op_const(e, op);
            return true;
        case RE_OP_VAR:
            op_var(e, op);
            return true;
        case RE_OP_LOAD:
            dx_op_load(e, op);
            return true;
        case RE_OP_STORE:
            dx_op_store(e, op);
            return true;
        case RE_OP_INTNEG:
            op_unary(e, op, "-");
            return true;
        case RE_OP_BITNOT:
            op_unary(e, op, "~");
            return true;
        case RE_OP_CAST:
        case RE_OP_FCAST:
        case RE_OP_SLICE:
            op_cast(e, op);
            return true;
        case RE_OP_CMP:
            dx_flag_set(e, op);
            return true;
        case RE_OP_SETCC:
            dx_def_any(e, op->out, dx_flag_value(e, op->extra));
            return true;
        case RE_OP_SELECT:
            op_select(e, op);
            return true;
        case RE_OP_CALL:
        case RE_OP_CALLIND:
            dx_emit_call(e, op);
            return true;
        case RE_OP_RETURN:
            dx_emit_return(e, op);
            return true;
        default:
            return false;
    }
}

void dx_emit_op(dx_em_t *e, const re_ir_op_t *op) {
    if (op_named(e, op))
        return;
    for (size_t i = 0; i < sizeof(kBin) / sizeof(kBin[0]); i++)
        if (kBin[i].op == op->op) {
            op_bin(e, op, &kBin[i]);
            return;
        }
    const char *fn = intrinsic((uint8_t)op->op, (uint8_t)op->out.size);
    if (fn) {
        op_call_like(e, op, fn);
        return;
    }
    op_flow_misc(e, op);
}
