// re_dcx_graph.c - cuts the walked instructions into blocks, lowers them, links them.
// Module: feature (C11).
// Owns: block boundaries, per block lowering, terminators, successors and predecessors.
// Depends: re_dcx.h. One IR block per graph block, so every later pass sees the
//           control flow the machine has and never a single address ordered run.
#include "features/dec/core/re_dcx.h"

#include <string.h>

uint32_t dx_block_at(const dx_fn_t *x, uint64_t va) {
    uint32_t lo = 0, hi = x->nreal;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (x->b[mid].va == va)
            return mid;
        if (x->b[mid].va < va)
            lo = mid + 1;
        else
            hi = mid;
    }
    return DX_NONE;
}

uint32_t dx_nsucc(const dx_fn_t *x, uint32_t b) {
    const dx_block_t *p = &x->b[b];
    switch (p->term) {
        case DX_T_FALL:
        case DX_T_JUMP:
            return p->succ[0] != DX_NONE ? 1u : 0u;
        case DX_T_COND:
            return 2;
        case DX_T_SWITCH:
            return p->n_sw + (p->succ[1] != DX_NONE ? 1u : 0u);
        default:
            return 0;
    }
}

// The i-th successor. A switch lists its cases first and its default last; a hole in
// the table is DX_NONE and callers skip it.
uint32_t dx_succ(const dx_fn_t *x, uint32_t b, uint32_t i) {
    const dx_block_t *p = &x->b[b];
    if (p->term == DX_T_SWITCH)
        return i < p->n_sw ? p->sw[i] : p->succ[1];
    return i < 2 ? p->succ[i] : DX_NONE;
}

// One block per run of instructions between starts. A run also ends at a gap, which is
// where the walk stopped decoding.
static uint32_t cut(dx_fn_t *x, const uint8_t *marks, uint64_t lo) {
    size_t n = RE_VEC_LEN(&x->insns);
    uint32_t nb = 0;
    for (size_t i = 0; i < n; i++) {
        const re_insn_t *in = RE_VEC_PTR(&x->insns, re_insn_t, i);
        const re_insn_t *pv = i ? RE_VEC_PTR(&x->insns, re_insn_t, i - 1) : NULL;
        bool start = !pv || (marks[in->addr - lo] & 2u) || dx_ends_block(x, pv) ||
                     pv->addr + pv->size != in->addr;
        if (start) {
            if (nb)
                x->b[nb - 1].i1 = (uint32_t)i;
            memset(&x->b[nb], 0, sizeof(dx_block_t));
            x->b[nb].va = in->addr;
            x->b[nb].i0 = (uint32_t)i;
            nb++;
        }
        x->b[nb - 1].end = in->addr + in->size;
    }
    if (nb)
        x->b[nb - 1].i1 = (uint32_t)n;
    return nb;
}

// Lower every block into its own IR block, counting the ops each instruction made.
static bool lower_all(dx_fn_t *x) {
    const re_disasm_t *dis = x->code->dis;
    x->nops = (uint16_t *)re_arena_calloc(x->a, RE_VEC_LEN(&x->insns) + 1, sizeof(uint16_t));
    if (!x->nops || !dis || !dis->lower)
        return false;
    re_ir_func_init(&x->ir);
    x->ir.entry = x->f->va;
    for (uint32_t k = 0; k < x->nreal; k++) {
        dx_block_t *b = &x->b[k];
        if (!re_ir_block_begin(&x->ir, x->a, b->va, b->end - b->va))
            return false;
        for (uint32_t i = b->i0; i < b->i1; i++) {
            const re_insn_t *in = RE_VEC_PTR(&x->insns, re_insn_t, i);
            size_t n = dis->lower(dis->ctx, in, &x->ir, x->a);
            x->nops[i] = (uint16_t)n;
            if (!n)
                x->n_unlowered++;
        }
        x->ir.end = b->end;
        re_ir_block_end(&x->ir);
    }
    for (uint32_t k = 0; k < x->nreal; k++)
        x->b[k].ir = &x->ir.blocks[k];
    return true;
}

// A branch out of the function, as a block of its own with no instructions, so a
// conditional tail jump still has somewhere to point.
static uint32_t exit_to(dx_fn_t *x, uint64_t va) {
    for (uint32_t k = x->nreal; k < x->nb; k++)
        if (x->b[k].target == va)
            return k;
    dx_block_t *e = &x->b[x->nb];
    memset(e, 0, sizeof(*e));
    e->term = DX_T_EXIT;
    e->target = va;
    e->va = va;
    return x->nb++;
}

static uint32_t to_block(dx_fn_t *x, uint64_t va) {
    uint32_t t = dx_block_at(x, va);
    return t != DX_NONE ? t : exit_to(x, va);
}

static void switch_succs(dx_fn_t *x, dx_block_t *b, const re_jtable_t *t) {
    b->term = DX_T_SWITCH;
    b->n_sw = t->count;
    b->sw = (uint32_t *)re_arena_alloc(x->a, (t->count ? t->count : 1) * sizeof(uint32_t));
    b->succ[1] = DX_NONE;
    for (uint32_t i = 0; i < t->count; i++) {
        uint64_t va = re_jtable_target(x->code, t, i);
        b->sw[i] = va ? dx_block_at(x, va) : DX_NONE;
    }
}

// What the last instruction of a block does with control.
static void terminate(dx_fn_t *x, uint32_t k) {
    dx_block_t *b = &x->b[k];
    const re_insn_t *in = RE_VEC_PTR(&x->insns, re_insn_t, b->i1 - 1);
    b->succ[0] = b->succ[1] = DX_NONE;
    b->target = in->has_target ? in->target : 0;
    if (in->is_return) {
        b->term = DX_T_RET;
    } else if (in->is_branch && in->is_conditional) {
        b->term = DX_T_COND;
        b->succ[0] = to_block(x, in->target);
        b->succ[1] = to_block(x, in->addr + in->size);
    } else if (in->is_branch && !in->is_call) {
        const re_jtable_t *t = in->has_target ? NULL : dx_table_at(x, in->addr);
        uint32_t s = in->has_target ? dx_block_at(x, in->target) : DX_NONE;
        if (t)
            switch_succs(x, b, t);
        b->term = t ? DX_T_SWITCH : s != DX_NONE ? DX_T_JUMP : DX_T_EXIT;
        b->succ[0] = s;
    } else if (dx_ends_block(x, in)) {
        b->term = DX_T_EXIT;
    } else {
        b->succ[0] = dx_block_at(x, b->end);
        b->term = b->succ[0] != DX_NONE ? DX_T_FALL : DX_T_EXIT;
    }
}

void dx_link(dx_fn_t *x) {
    for (uint32_t k = 0; k < x->nb; k++)
        x->b[k].n_pred = 0;
    for (uint32_t k = 0; k < x->nb; k++)
        for (uint32_t i = 0; i < dx_nsucc(x, k); i++) {
            uint32_t s = dx_succ(x, k, i);
            if (s != DX_NONE)
                x->b[s].n_pred++;
        }
    for (uint32_t k = 0; k < x->nb; k++) {
        x->b[k].pred = (uint32_t *)re_arena_alloc(x->a, (x->b[k].n_pred + 1) * sizeof(uint32_t));
        x->b[k].n_pred = 0;
    }
    for (uint32_t k = 0; k < x->nb; k++)
        for (uint32_t i = 0; i < dx_nsucc(x, k); i++) {
            uint32_t s = dx_succ(x, k, i);
            if (s != DX_NONE)
                x->b[s].pred[x->b[s].n_pred++] = k;
        }
}

bool dx_build(dx_fn_t *x) {
    uint64_t lo = 0;
    uint8_t *marks = dx_walk(x, &lo);
    size_t n = RE_VEC_LEN(&x->insns);
    if (!marks || !n)
        return false;
    // Room for the worst case, left unzeroed: cut and exit_to clear each block as they
    // take it, and nothing reads past nb. Zeroing the whole bound cost more than the
    // decompilation of most functions, since a block is far larger than an instruction.
    x->b = (dx_block_t *)re_arena_alloc(x->a, (2 * n + 2) * sizeof(dx_block_t));
    if (!x->b)
        return false;
    x->nreal = x->nb = cut(x, marks, lo);
    if (!lower_all(x))
        return false;
    for (uint32_t k = 0; k < x->nreal; k++)
        terminate(x, k);
    dx_link(x);
    dx_dominators(x);
    return true;
}

// After the flow passes: a conditional branch the constant pass decided is now an
// unconditional jump or nothing, and the graph has to say so before anything walks it.
void dx_refresh(dx_fn_t *x) {
    bool changed = false;
    for (uint32_t k = 0; k < x->nreal; k++) {
        dx_block_t *b = &x->b[k];
        const re_ir_block_t *blk = b->ir;
        if (b->term != DX_T_COND || !blk || !blk->n_ops)
            continue;
        uint8_t last = (uint8_t)blk->ops[blk->n_ops - 1].op;
        if (last == RE_OP_BRANCH) {
            b->term = DX_T_JUMP;
            b->succ[1] = DX_NONE;
            changed = true;
        } else if (last == RE_OP_NOP) {
            b->term = DX_T_FALL;
            b->succ[0] = b->succ[1];
            b->succ[1] = DX_NONE;
            changed = true;
        }
    }
    if (!changed)
        return;
    dx_link(x);
    dx_dominators(x);
}
