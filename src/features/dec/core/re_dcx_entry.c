// re_dcx_entry.c - the function's interface: parameters, saved registers, the return.
// Module: feature (C11).
// Owns: whether rax is a return value, the parameter list and widths, save and home slots.
// Depends: re_dcx.h. Parameters are the argument registers live on entry, which is a
//           fact about this body, not a guess from the bytes before the first call.
#include "features/dec/core/re_dcx.h"

// What last wrote rax before a return: the function's own computation, a call whose
// callee is known to return a value, a call nothing is known about, or a void call.
#define DX_RV_OWN 1u
#define DX_RV_CALL 2u
#define DX_RV_UNKNOWN 4u

// The width a callee's value comes back at: 4 for a BOOL, DWORD or a summarised body
// that writes eax, 8 otherwise.
static uint8_t call_width(const re_dc_proto_t *pr, const dx_sum_t *sm) {
    if (pr)
        return pr->ret == 'i' || pr->ret == 'u' ? 4 : 8;
    return sm && sm->ret_w ? sm->ret_w : 8;
}

// The kind of the last write to rax in block b before its end, or 0 when b has none,
// with the width that write leaves in *w.
static unsigned last_rax_def(const dx_fn_t *x, uint32_t b, uint8_t *w) {
    const re_ir_block_t *blk = x->b[b].ir;
    for (size_t k = blk ? blk->n_ops : 0; k-- > 0;) {
        const re_ir_op_t *op = &blk->ops[k];
        if (op->op == RE_OP_CALL || op->op == RE_OP_CALLIND) {
            re_dc_proto_t pr;
            *w = 8;
            if (dx_proto_at(x, op->addr, &pr)) {
                *w = call_width(&pr, NULL);
                return pr.ret == 'v' ? 8u : DX_RV_CALL; // a void import leaves rax undefined
            }
            const dx_sum_t *sm =
                op->op == RE_OP_CALL ? dx_summary(x, (uint64_t)op->const_val) : NULL;
            if (sm) {
                *w = call_width(NULL, sm);
                return sm->has_ret ? DX_RV_CALL : 8u;
            }
            return DX_RV_UNKNOWN;
        }
        if (op->out.space == RE_SPACE_REG && op->out.offset == 0 && op->op != RE_OP_RETURN) {
            *w = (uint8_t)(op->out.size < 8 ? op->out.size : 8);
            return DX_RV_OWN;
        }
    }
    return 0;
}

// The kinds of write to rax that reach this return, searching back through blocks
// that do not write rax themselves.
static unsigned ret_value_kinds(dx_fn_t *x, uint32_t b, uint8_t *seen) {
    uint32_t queue[64], nq = 0;
    unsigned kinds = 0;
    uint8_t w = 0;
    queue[nq++] = b;
    seen[b] = 1;
    for (uint32_t qi = 0; qi < nq; qi++) {
        uint32_t v = queue[qi];
        unsigned k = last_rax_def(x, v, &w);
        if (k) {
            kinds |= k;
            if (k != 8u && w > x->ret_w)
                x->ret_w = w; // the widest value any return carries
            continue;
        }
        for (uint32_t j = 0; j < x->b[v].n_pred && nq < 64; j++) {
            uint32_t p = x->b[v].pred[j];
            if (!seen[p]) {
                seen[p] = 1;
                queue[nq++] = p;
            }
        }
    }
    return kinds;
}

// Whether some path from the entry reaches a return without writing rax: one bit of
// backward dataflow, set by a return block that does not write rax before it returns,
// carried back through every block that does not write rax either.
static bool ret_reads_entry_rax(const dx_fn_t *x, uint8_t *need) {
    bool changed = true;
    while (changed) {
        changed = false;
        for (uint32_t i = x->norder; i-- > 0;) {
            uint32_t b = x->order[i];
            bool writes = (x->b[b].def & 1u) != 0;
            bool n = x->b[b].term == DX_T_RET && !writes;
            for (uint32_t j = 0; j < dx_nsucc(x, b) && !writes; j++) {
                uint32_t sb = dx_succ(x, b, j);
                n |= sb != DX_NONE && need[sb];
            }
            if (n && !need[b]) {
                need[b] = 1;
                changed = true;
            }
        }
    }
    return need[0] != 0;
}

// The kind of value a block that jumps out of the function returns, as a tail call: a
// listed import says by its prototype, a summarised callee by its body, and any other
// jump to another function is a call nothing is known about.
static unsigned tail_kind(const dx_fn_t *x, uint32_t b) {
    if (b >= x->nreal || x->b[b].term != DX_T_EXIT || x->b[b].i1 <= x->b[b].i0)
        return 0;
    const re_insn_t *last = RE_VEC_PTR(&x->insns, re_insn_t, x->b[b].i1 - 1);
    re_dc_proto_t pr;
    if (!last->is_branch || last->is_call)
        return 0;
    if (dx_proto_at(x, last->addr, &pr))
        return pr.ret == 'v' ? 0 : DX_RV_CALL;
    const dx_sum_t *sm = x->b[b].target ? dx_summary(x, x->b[b].target) : NULL;
    if (sm)
        return sm->has_ret ? DX_RV_CALL : 0;
    return x->b[b].target ? DX_RV_UNKNOWN : 0;
}

// A function returns a value when every path to a return writes rax and something says
// the value is meant. A value the body computes itself is. One that only a callee left
// behind is when the callers read it, or, with no caller to ask, when that callee is
// known to return one; callers that all overwrite rax unread make it void.
void dx_facts_rets(dx_fn_t *x) {
    uint8_t *seen = (uint8_t *)re_arena_calloc(x->a, x->nb + 1, 1);
    uint8_t *need = (uint8_t *)re_arena_calloc(x->a, x->nb + 1, 1);
    unsigned kinds = 0;
    if (!seen || !need || ret_reads_entry_rax(x, need)) {
        x->has_ret = false;
        return;
    }
    for (uint32_t i = 0; i < x->norder; i++) {
        uint32_t b = x->order[i];
        kinds |= tail_kind(x, b); // a tail call returns whatever its callee returns
        if (x->b[b].term != DX_T_RET)
            continue;
        for (uint32_t k = 0; k < x->nb; k++)
            seen[k] = 0;
        kinds |= ret_value_kinds(x, b, seen);
    }
    if (kinds & DX_RV_OWN) {
        x->has_ret = true;
        return;
    }
    if (!(kinds & (DX_RV_CALL | DX_RV_UNKNOWN))) {
        x->has_ret = false;
        return;
    }
    int u = dx_callers_read_rax(x);
    x->has_ret = u > 0 || (u < 0 && (kinds & DX_RV_CALL));
}

static void widen(uint8_t *w, uint16_t size) {
    if (size > *w)
        *w = (uint8_t)size;
}

// The widths each parameter is read at before anything overwrites it.
static void param_widths(dx_fn_t *x) {
    for (uint32_t b = 0; b < x->nreal; b++) {
        uint32_t defd = 0;
        const re_ir_block_t *blk = x->b[b].ir;
        for (size_t k = 0; k < blk->n_ops; k++) {
            const re_ir_op_t *op = &blk->ops[k];
            for (unsigned i = 0; i < 4; i++) {
                re_varnode_t v = op->in[i];
                int pos =
                    v.space == RE_SPACE_REG && v.offset < DX_NREG ? dx_arg_pos(x, v.offset) : -1;
                bool live = (x->b[b].live_in >> (v.offset & 15u)) & 1u;
                if (pos >= 0 && pos < x->nparams && live && !(defd >> v.offset & 1u))
                    widen(&x->pw[pos], v.size);
            }
            if (op->out.space == RE_SPACE_REG && op->out.offset < DX_NREG)
                defd |= 1u << op->out.offset;
        }
    }
    for (unsigned p = 0; p < x->nparams; p++)
        if (!x->pw[p])
            x->pw[p] = 8;
}

// Prologue stores of a register's entry value: a callee saved register's save slot, or
// an argument register's home slot. Any other write to such a slot is noted, because
// then the slot is a variable after all.
static void saves(dx_fn_t *x) {
    for (uint32_t b = 0; b < x->nreal; b++) {
        uint32_t defd = 0;
        dx_frame_t fr;
        const re_ir_block_t *blk = x->b[b].ir;
        dx_frame_init(x, &fr, b);
        for (size_t k = 0; k < blk->n_ops; k++) {
            const re_ir_op_t *op = &blk->ops[k];
            dx_sv_t s = op->op == RE_OP_STORE ? dx_frame_eval(x, &fr, op->in[2]) : (dx_sv_t){0};
            dx_slot_t *sl = s.stk ? dx_slot(x, s.off, false) : NULL;
            re_varnode_t v = op->in[1];
            bool ent =
                b == 0 && v.space == RE_SPACE_REG && v.offset < DX_NREG && !(defd >> v.offset & 1u);
            int pos = ent ? dx_arg_pos(x, v.offset) : -1;
            if (sl && ent && !dx_volatile(x, v.offset) && v.offset != DX_RSP && !sl->save)
                sl->save = (uint8_t)(v.offset + 1);
            else if (sl && ent && pos >= 0 && x->cc != RE_CC_SYSV && s.off == 8 * (pos + 1) &&
                     !sl->home)
                sl->home = (uint8_t)(pos + 1);
            else if (sl && !(ent && (sl->save == v.offset + 1 || sl->home == pos + 1)))
                sl->wr_other = true;
            if (op->out.space == RE_SPACE_REG && op->out.offset < DX_NREG)
                defd |= 1u << op->out.offset;
            dx_frame_step(x, &fr, op);
        }
    }
}

void dx_facts_entry(dx_fn_t *x) {
    uint32_t in = x->b[0].live_in;
    int32_t first = x->cc == RE_CC_SYSV ? 8 : 0x28;
    x->nparams = 0;
    for (unsigned p = 0; p < dx_max_reg_args(x); p++)
        if (in & (1u << dx_arg_reg(x, p)))
            x->nparams = (uint8_t)(p + 1);
    saves(x);
    for (size_t i = 0; i < RE_VEC_LEN(&x->slots); i++) {
        const dx_slot_t *sl = RE_VEC_PTR(&x->slots, dx_slot_t, i);
        if (sl->off >= first && sl->rd && (sl->off - first) % 8 == 0) {
            uint32_t k = (uint32_t)(sl->off - first) / 8 + 1;
            if (k < 32 && k > x->nstk)
                x->nstk = (uint8_t)k;
        }
        if (sl->home && sl->rd && sl->home > x->nparams)
            x->nparams = sl->home;
    }
    if (x->nstk)
        x->nparams = (uint8_t)dx_max_reg_args(x);
    param_widths(x);
}
