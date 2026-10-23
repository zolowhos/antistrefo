// re_dcx_users.c - what the callers of a function do with the rax it leaves behind.
// Module: feature (C11).
// Owns: the caller side evidence for whether a function returns a value.
// Depends: re_dcx.h, re_xref, the arch lowering. A body whose every return carries the
//           result of a call cannot say by itself whether it returns that result; the
//           code after each call site can, by reading rax or by overwriting it first.
#include "features/dec/core/re_dcx.h"

#define DX_USE_BUDGET 48u // instructions examined after one call site, across paths
#define DX_USE_SITES 64u  // call sites examined per function

typedef enum { DX_U_KILL, DX_U_READ, DX_U_MORE } dx_use_t;

// What one instruction does to rax: reads it, overwrites it (a call, or a write of 32
// bits or more), or neither.
static dx_use_t insn_use(const dx_fn_t *x, const re_insn_t *in) {
    const re_disasm_t *dis = x->code->dis;
    re_ir_func_t f;
    if (in->is_call)
        return DX_U_KILL;
    re_ir_func_init(&f);
    if (!dis || !dis->lower || !re_ir_block_begin(&f, x->a, in->addr, in->size))
        return DX_U_READ;
    size_t n = dis->lower(dis->ctx, in, &f, x->a);
    re_ir_block_end(&f);
    if (!n)
        return DX_U_READ; // not lifted: assume the worst
    const re_ir_block_t *b = &f.blocks[0];
    for (size_t k = 0; k < b->n_ops; k++) {
        const re_ir_op_t *op = &b->ops[k];
        for (unsigned i = 0; i < 4; i++) {
            re_varnode_t v = op->in[i];
            if (v.size && !(op->op == RE_OP_STORE && i == 0) && v.space == RE_SPACE_REG &&
                v.offset == 0)
                return DX_U_READ;
        }
        if (op->out.space == RE_SPACE_REG && op->out.offset == 0 && op->out.size >= 4)
            return DX_U_KILL;
    }
    return DX_U_MORE;
}

// Whether the code after the call at site reads rax before overwriting it, following
// both arms of a branch. 1 reads, 0 never does, -1 cannot tell (a return hands rax to
// this caller's own caller, an indirect jump goes anywhere, the budget ran out).
static int site_reads(const dx_fn_t *x, const re_insn_t *call) {
    uint64_t work[16];
    unsigned nw = 0, spent = 0;
    work[nw++] = call->addr + call->size;
    while (nw) {
        uint64_t va = work[--nw];
        for (;;) {
            re_insn_t in;
            if (++spent > DX_USE_BUDGET || !re_code_insn(x->code, va, &in) || !in.size)
                return -1;
            if (in.is_return)
                return -1;
            dx_use_t u = insn_use(x, &in);
            if (u == DX_U_READ)
                return 1;
            if (u == DX_U_KILL)
                break;
            if (in.is_branch && (!in.has_target || nw >= 15))
                return -1;
            if (in.is_branch && in.is_conditional) {
                work[nw++] = in.target;
            } else if (in.is_branch) {
                va = in.target;
                continue;
            }
            va += in.size;
        }
    }
    return 0;
}

// 1 when some caller reads the value this function leaves in rax, 0 when callers exist
// and none does, -1 when nothing can be said: no direct call reaches it, or its
// address is taken or jumped to, so an unseen caller may read it.
int dx_callers_read_rax(const dx_fn_t *x) {
    const re_xrefset_t *xs = x->d->xrefs;
    size_t n = xs ? re_xref_to_count(xs, x->f->va) : 0;
    bool unsure = false;
    if (!n || n > DX_USE_SITES)
        return -1;
    for (size_t i = 0; i < n; i++) {
        const re_xref_t *r = re_xref_to_at(xs, x->f->va, i);
        re_insn_t call;
        if (!r || r->kind != RE_XR_CALL || !re_code_insn(x->code, r->from, &call) ||
            !call.is_call || !call.has_target)
            return -1;
        int u = site_reads(x, &call);
        if (u > 0)
            return 1; // one reader is enough
        unsure |= u < 0;
    }
    return unsure ? -1 : 0;
}
