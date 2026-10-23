// re_dcx_frame.c - the stack frame: where rsp is, what rbp means, which slots exist.
// Module: feature (C11).
// Owns: the constant table, frame address tracking, the slot table and its facts.
// Depends: re_dcx.h. Offsets are relative to rsp on entry, so a slot keeps one name
//           whether it is reached through rsp before or after a push, or through rbp.
#include "features/dec/core/re_dcx.h"

#include <string.h>

// Every constant and folded temporary by id. Ids are minted once per function, so one
// table covers every block and nothing needs resetting between them.
void dx_consts(dx_fn_t *x) {
    uint32_t n = x->ir.next_uniq + 1, total = 0;
    x->nuniq = n;
    x->cv = (int64_t *)re_arena_calloc(x->a, n, sizeof(int64_t));
    x->cvk = (uint8_t *)re_arena_calloc(x->a, n, 1);
    x->uq = (dx_sv_t *)re_arena_calloc(x->a, n, sizeof(dx_sv_t));
    x->uqk = (uint8_t *)re_arena_calloc(x->a, n, 1);
    x->opbase = (uint32_t *)re_arena_calloc(x->a, x->nb + 1, sizeof(uint32_t));
    for (uint32_t k = 0; k < x->nreal; k++) {
        const re_ir_block_t *blk = x->b[k].ir;
        x->opbase[k] = total;
        total += (uint32_t)blk->n_ops;
        for (size_t i = 0; i < blk->n_ops; i++) {
            const re_ir_op_t *op = &blk->ops[i];
            bool slot = op->out.space == RE_SPACE_CONST || op->out.space == RE_SPACE_UNIQUE;
            if (op->op == RE_OP_CONST && slot && op->out.offset < n) {
                x->cv[op->out.offset] = op->const_val;
                x->cvk[op->out.offset] = 1;
            }
        }
    }
    // The scale each index temporary carries, read once the constants are all known.
    for (uint32_t k = 0; k < x->nreal; k++) {
        const re_ir_block_t *blk = x->b[k].ir;
        for (size_t i = 0; i < blk->n_ops; i++) {
            const re_ir_op_t *op = &blk->ops[i];
            int64_t c;
            if (op->out.space != RE_SPACE_UNIQUE || op->out.offset >= n ||
                !dx_cval(x, op->in[1], &c))
                continue;
            if (op->op == RE_OP_INTMUL && (c == 1 || c == 2 || c == 4 || c == 8))
                x->uqk[op->out.offset] = (uint8_t)c;
            else if (op->op == RE_OP_INTSHL && c >= 0 && c <= 3)
                x->uqk[op->out.offset] = (uint8_t)(1u << c);
        }
    }
    for (uint32_t k = x->nreal; k <= x->nb; k++)
        x->opbase[k] = total;
    x->nops_all = total;
}

bool dx_cval(const dx_fn_t *x, re_varnode_t v, int64_t *out) {
    if (v.space != RE_SPACE_CONST && v.space != RE_SPACE_UNIQUE)
        return false;
    if (v.offset >= x->nuniq || !x->cvk[v.offset])
        return false;
    *out = x->cv[v.offset];
    return true;
}

void dx_frame_init(const dx_fn_t *x, dx_frame_t *fr, uint32_t b) {
    memset(fr, 0, sizeof(*fr));
    fr->sp = x->b[b].sp_in;
    if (x->fp && b != 0) {
        fr->reg[DX_RBP].stk = true;
        fr->reg[DX_RBP].off = x->fp_off;
    }
}

dx_sv_t dx_frame_eval(const dx_fn_t *x, const dx_frame_t *fr, re_varnode_t v) {
    dx_sv_t r = {false, 0};
    if (!v.size && v.space == RE_SPACE_UNIQUE)
        return r; // an unused input
    if (v.space == RE_SPACE_STACK && fr->sp != DX_SP_UNKNOWN) {
        r.stk = true;
        r.off = fr->sp + (int16_t)v.offset;
    } else if (v.space == RE_SPACE_REG && v.offset == DX_RSP && fr->sp != DX_SP_UNKNOWN) {
        r.stk = true;
        r.off = fr->sp;
    } else if (v.space == RE_SPACE_REG && v.offset < DX_NREG && v.offset != DX_RSP) {
        r = fr->reg[v.offset];
    } else if (v.space == RE_SPACE_UNIQUE && v.offset < x->nuniq) {
        r = x->uq[v.offset];
    }
    return r;
}

// The frame address an op computes, when it computes one: a copy, or a constant added
// to or subtracted from one. Anything else leaves the frame.
static dx_sv_t op_value(const dx_fn_t *x, const dx_frame_t *fr, const re_ir_op_t *op) {
    dx_sv_t r = {false, 0};
    dx_sv_t p = dx_frame_eval(x, fr, op->in[0]);
    dx_sv_t q = dx_frame_eval(x, fr, op->in[1]);
    int64_t c;
    if (op->op == RE_OP_VAR)
        return p;
    if (op->op == RE_OP_INTADD && p.stk && dx_cval(x, op->in[1], &c))
        r.stk = true, r.off = p.off + (int32_t)c;
    else if (op->op == RE_OP_INTADD && q.stk && dx_cval(x, op->in[0], &c))
        r.stk = true, r.off = q.off + (int32_t)c;
    else if (op->op == RE_OP_INTSUB && p.stk && dx_cval(x, op->in[1], &c))
        r.stk = true, r.off = p.off - (int32_t)c;
    return r;
}

void dx_frame_step(dx_fn_t *x, dx_frame_t *fr, const re_ir_op_t *op) {
    dx_sv_t r = op_value(x, fr, op);
    if (op->op == RE_OP_CALL || op->op == RE_OP_CALLIND) {
        for (unsigned g = 0; g < DX_NREG; g++)
            if (dx_volatile(x, g))
                fr->reg[g].stk = false;
        return;
    }
    if (op->out.space == RE_SPACE_UNIQUE && op->out.offset < x->nuniq) {
        x->uq[op->out.offset] = r;
        return;
    }
    if (op->out.space != RE_SPACE_REG || op->out.offset >= DX_NREG)
        return;
    if (op->out.offset == DX_RSP) {
        fr->sp = r.stk ? r.off : DX_SP_UNKNOWN;
        return;
    }
    if (op->out.size < 8)
        r.stk = false;
    fr->reg[op->out.offset] = r;
}

dx_slot_t *dx_slot(dx_fn_t *x, int32_t off, bool make) {
    size_t lo = 0, hi = RE_VEC_LEN(&x->slots);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        dx_slot_t *s = RE_VEC_PTR(&x->slots, dx_slot_t, mid);
        if (s->off == off)
            return s;
        if (s->off < off)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (!make)
        return NULL;
    dx_slot_t ns;
    memset(&ns, 0, sizeof(ns));
    ns.off = off;
    if (!RE_VEC_PUSH(&x->slots, x->a, ns))
        return NULL;
    dx_slot_t *v = RE_VEC_PTR(&x->slots, dx_slot_t, 0);
    memmove(&v[lo + 1], &v[lo], (RE_VEC_LEN(&x->slots) - 1 - lo) * sizeof(dx_slot_t));
    v[lo] = ns;
    return &v[lo];
}

static void touch(dx_fn_t *x, dx_sv_t s, uint8_t w, bool wr) {
    dx_slot_t *sl = s.stk ? dx_slot(x, s.off, true) : NULL;
    if (!sl)
        return;
    if (w > sl->w)
        sl->w = w;
    if (wr)
        sl->wr = true;
    else
        sl->rd = true;
}

static void escape(dx_fn_t *x, dx_sv_t s) {
    dx_slot_t *sl = s.stk ? dx_slot(x, s.off, true) : NULL;
    if (sl)
        sl->taken = true;
}

// What one op says about the frame: the slots it reads and writes, and the addresses
// it lets escape. An address that escapes makes its slot memory rather than a scalar.
static void observe(dx_fn_t *x, const dx_frame_t *fr, const re_ir_op_t *op) {
    if (op->op == RE_OP_LOAD) {
        touch(x, dx_frame_eval(x, fr, op->in[0]), (uint8_t)op->out.size, false);
        return;
    }
    if (op->op == RE_OP_STORE) {
        touch(x, dx_frame_eval(x, fr, op->in[2]), (uint8_t)op->in[0].size, true);
        escape(x, dx_frame_eval(x, fr, op->in[1]));
        return;
    }
    if (op->op == RE_OP_CALL || op->op == RE_OP_CALLIND) {
        for (unsigned p = 0; p < dx_max_reg_args(x); p++)
            escape(x, fr->reg[dx_arg_reg(x, p)]);
        return;
    }
    if (op->op == RE_OP_VAR || op->op == RE_OP_LOAD)
        return;
    int64_t c;
    for (unsigned i = 0; i < 4; i++) {
        dx_sv_t s = dx_frame_eval(x, fr, op->in[i]);
        bool offset_add = (op->op == RE_OP_INTADD || op->op == RE_OP_INTSUB) &&
                          dx_cval(x, op->in[i ^ 1u], &c) && i < 2;
        if (s.stk && !offset_add && op->in[i].space != RE_SPACE_STACK)
            escape(x, s);
        // A frame address plus a run time index is an array based at that address.
        if (s.stk && !offset_add && op->op == RE_OP_INTADD && i < 2) {
            re_varnode_t o = op->in[i ^ 1u];
            uint8_t k = o.space == RE_SPACE_UNIQUE && o.offset < x->nuniq && x->uqk[o.offset]
                            ? x->uqk[o.offset]
                            : 1;
            dx_slot_t *sl = dx_slot(x, s.off, true);
            if (sl && (!sl->idx_w || k < sl->idx_w))
                sl->idx_w = k;
        }
    }
}

// The extent of each frame array: from its base up to the next slot that cannot be one
// of its elements, a save slot, or the return address. Its elements print as base[k].
static void arrays(dx_fn_t *x) {
    size_t n = RE_VEC_LEN(&x->slots);
    for (size_t i = 0; i < n; i++) {
        dx_slot_t *b = RE_VEC_PTR(&x->slots, dx_slot_t, i);
        int32_t limit = 0;
        if (!b->idx_w || b->elem || b->off >= 0)
            continue;
        size_t j = i + 1;
        for (; j < n; j++) {
            dx_slot_t *e = RE_VEC_PTR(&x->slots, dx_slot_t, j);
            bool fits = (e->off - b->off) % b->idx_w == 0 && e->w <= b->idx_w && !e->idx_w &&
                        !e->save && !e->outarg && e->off < 0;
            if (!fits) {
                limit = e->off;
                break;
            }
            e->elem = true;
            e->abase = b->off;
        }
        if (j == n)
            limit = 0;
        if (b->w > b->idx_w)
            b->w = b->idx_w;
        b->alen = (uint32_t)((limit - b->off) / b->idx_w);
        if (!b->alen)
            b->alen = 1;
    }
}

// Where rbp points, when the prologue makes it the frame pointer: a copy of rsp, or
// rsp plus a constant, written in the entry block.
static void find_fp(dx_fn_t *x, const dx_frame_t *fr, const re_ir_op_t *op, uint32_t b) {
    if (b != 0 || x->fp || op->out.space != RE_SPACE_REG || op->out.offset != DX_RBP)
        return;
    dx_sv_t r = op_value(x, fr, op);
    if (r.stk && op->out.size == 8) {
        x->fp = true;
        x->fp_off = r.off;
    }
}

static void frame_block(dx_fn_t *x, uint32_t b) {
    dx_frame_t fr;
    const re_ir_block_t *blk = x->b[b].ir;
    dx_frame_init(x, &fr, b);
    for (size_t k = 0; k < blk->n_ops; k++) {
        const re_ir_op_t *op = &blk->ops[k];
        x->op_sp[x->opbase[b] + k] = fr.sp;
        observe(x, &fr, op);
        find_fp(x, &fr, op, b);
        dx_frame_step(x, &fr, op);
    }
    for (uint32_t i = 0; i < dx_nsucc(x, b); i++) {
        uint32_t s = dx_succ(x, b, i);
        if (s != DX_NONE && x->b[s].sp_in == DX_SP_UNKNOWN && s != 0)
            x->b[s].sp_in = fr.sp;
    }
}

// Blocks in reverse post order, so every block but a loop header sees its entry rsp
// from a predecessor that was already walked.
void dx_frame_pass(dx_fn_t *x) {
    re_vec_init(&x->slots, sizeof(dx_slot_t));
    x->op_sp = (int32_t *)re_arena_calloc(x->a, x->nops_all + 1, sizeof(int32_t));
    for (uint32_t k = 0; k < x->nb; k++)
        x->b[k].sp_in = DX_SP_UNKNOWN;
    x->b[0].sp_in = 0;
    for (uint32_t i = 0; i < x->norder; i++) {
        uint32_t b = x->order[i];
        if (b < x->nreal)
            frame_block(x, b);
    }
    arrays(x);
}
