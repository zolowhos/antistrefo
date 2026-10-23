// re_dcx_facts.c - what the whole function establishes before a statement prints.
// Module: feature (C11).
// Owns: the calling convention tables, call arity, liveness, parameters, saves, return.
// Depends: re_dcx.h. Liveness is over the sixteen integer registers per block, and is
//           what decides which values must live in a variable across a block edge.
#include "features/dec/core/re_dcx.h"

static const uint8_t kMsArgs[] = {1, 2, 8, 9};         // rcx, rdx, r8, r9
static const uint8_t kSysvArgs[] = {7, 6, 2, 1, 8, 9}; // rdi, rsi, rdx, rcx, r8, r9

static bool sysv(const dx_fn_t *x) {
    return x->cc == RE_CC_SYSV;
}

unsigned dx_max_reg_args(const dx_fn_t *x) {
    return sysv(x) ? 6u : 4u;
}

unsigned dx_arg_reg(const dx_fn_t *x, unsigned pos) {
    if (pos >= dx_max_reg_args(x))
        return DX_NREG;
    return sysv(x) ? kSysvArgs[pos] : kMsArgs[pos];
}

int dx_arg_pos(const dx_fn_t *x, unsigned reg) {
    for (unsigned p = 0; p < dx_max_reg_args(x); p++)
        if (dx_arg_reg(x, p) == reg)
            return (int)p;
    return -1;
}

// The registers a call may overwrite. rbx, rbp, r12-r15 survive in both conventions;
// rsi and rdi survive only in the Microsoft one.
bool dx_volatile(const dx_fn_t *x, unsigned reg) {
    if (reg == 3 || reg == 4 || reg == 5 || (reg >= 12 && reg <= 15))
        return false;
    if (reg == 6 || reg == 7)
        return sysv(x);
    return reg < DX_NREG;
}

uint32_t dx_op_index(const dx_fn_t *x, uint32_t b, size_t k) {
    return x->opbase[b] + (uint32_t)k;
}

static uint32_t volatile_mask(const dx_fn_t *x) {
    uint32_t m = 0;
    for (unsigned g = 0; g < DX_NREG; g++)
        if (dx_volatile(x, g))
            m |= 1u << g;
    return m;
}

// The register arguments of one call: the highest argument register written since the
// previous call in this block decides how many, and an import whose prototype is known
// overrides that guess.
bool dx_proto_at(const dx_fn_t *x, uint64_t site, re_dc_proto_t *out) {
    const re_xref_t *xr = x->d->xrefs ? re_xref_from_at(x->d->xrefs, site, 0) : NULL;
    if (!xr)
        return false;
    if (xr->name.n)
        return re_dc_proto_find(xr->name, out);
    // a call into this image reaches a function a signature or symbol may have named
    const re_fscan_t *s = x->d->scan;
    long i =
        s && (xr->kind == RE_XR_CALL || xr->kind == RE_XR_JUMP) ? re_func_index_of(s, xr->to) : -1;
    const re_func_t *g = i >= 0 ? re_func_at(s, (size_t)i) : NULL;
    return g && g->va == xr->to && g->name.n && re_dc_proto_find(g->name, out);
}

int dx_tail_nargs(const dx_fn_t *x, const re_ir_op_t *op) {
    re_dc_proto_t pr;
    const dx_sum_t *sm;
    unsigned n;
    if (dx_proto_at(x, op->addr, &pr))
        n = pr.nargs;
    else if (op->const_val && (sm = dx_summary(x, (uint64_t)op->const_val)) != NULL)
        n = sm->nparams;
    else
        return -1;
    return (int)(n < dx_max_reg_args(x) ? n : dx_max_reg_args(x));
}

static uint8_t call_arity(const dx_fn_t *x, const re_ir_op_t *op, uint32_t wrote) {
    uint8_t n = 0;
    re_dc_proto_t pr;
    if (dx_proto_at(x, op->addr, &pr))
        return (uint8_t)(pr.nargs < dx_max_reg_args(x) ? pr.nargs : dx_max_reg_args(x));
    // A direct call to a function this image contains takes what that body reads.
    const dx_sum_t *sm = op->op == RE_OP_CALL ? dx_summary(x, (uint64_t)op->const_val) : NULL;
    if (sm)
        return sm->nstk ? (uint8_t)dx_max_reg_args(x) : sm->nparams;
    for (unsigned p = 0; p < dx_max_reg_args(x); p++)
        if (wrote & (1u << dx_arg_reg(x, p)))
            n = (uint8_t)(p + 1);
    return n;
}

static bool frame_reg(const dx_fn_t *x, unsigned g) {
    return g == DX_RSP || (g == DX_RBP && x->fp);
}

// The register bits one op reads and writes, for liveness.
static void op_rw(const dx_fn_t *x, uint32_t gi, const re_ir_op_t *op, uint32_t *use,
                  uint32_t *def) {
    *use = *def = 0;
    for (unsigned i = 0; i < 4; i++) {
        re_varnode_t v = op->in[i];
        if (!v.size || (op->op == RE_OP_STORE && i == 0))
            continue; // an unused input, or the width carrier
        if (v.space == RE_SPACE_REG && v.offset < DX_NREG && !frame_reg(x, v.offset))
            *use |= 1u << v.offset;
    }
    if (op->op == RE_OP_CALL || op->op == RE_OP_CALLIND) {
        for (unsigned p = 0; p < x->call_nargs[gi]; p++)
            *use |= 1u << dx_arg_reg(x, p);
        *def = volatile_mask(x);
        return;
    }
    if (op->op == RE_OP_RETURN) {
        *use = x->has_ret ? 1u : 0u;
        return;
    }
    // A jump to another function is a tail call: it reads that function's arguments.
    if (op->op == RE_OP_BRANCH) {
        int n = dx_tail_nargs(x, op);
        for (int p = 0; p < n; p++)
            *use |= 1u << dx_arg_reg(x, (unsigned)p);
    }
    if (op->out.space == RE_SPACE_REG && op->out.offset < DX_NREG &&
        !frame_reg(x, op->out.offset)) {
        if (op->out.size < 4)
            *use |= 1u << op->out.offset;
        *def |= 1u << op->out.offset;
    }
}

static void block_rw(dx_fn_t *x, uint32_t b) {
    dx_block_t *p = &x->b[b];
    p->use = p->def = 0;
    for (size_t k = 0; p->ir && k < p->ir->n_ops; k++) {
        uint32_t u, d;
        op_rw(x, dx_op_index(x, b, k), &p->ir->ops[k], &u, &d);
        p->use |= u & ~p->def;
        p->def |= d;
    }
}

static void liveness(dx_fn_t *x) {
    bool changed = true;
    for (uint32_t k = 0; k < x->nb; k++) {
        block_rw(x, k);
        x->b[k].live_in = x->b[k].use;
        x->b[k].live_out = 0;
    }
    while (changed) {
        changed = false;
        for (uint32_t i = x->norder; i-- > 0;) {
            uint32_t b = x->order[i], out = 0;
            for (uint32_t j = 0; j < dx_nsucc(x, b); j++) {
                uint32_t s = dx_succ(x, b, j);
                if (s != DX_NONE)
                    out |= x->b[s].live_in;
            }
            uint32_t in = x->b[b].use | (out & ~x->b[b].def);
            if (out != x->b[b].live_out || in != x->b[b].live_in)
                changed = true;
            x->b[b].live_out = out;
            x->b[b].live_in = in;
        }
    }
}

static void arity_block(dx_fn_t *x, uint32_t b) {
    uint32_t wrote = 0;
    const re_ir_block_t *blk = x->b[b].ir;
    for (size_t k = 0; k < blk->n_ops; k++) {
        const re_ir_op_t *op = &blk->ops[k];
        if (op->op == RE_OP_CALL || op->op == RE_OP_CALLIND) {
            x->call_nargs[dx_op_index(x, b, k)] = call_arity(x, op, wrote);
            wrote = 0;
        } else if (op->out.space == RE_SPACE_REG && op->out.offset < DX_NREG) {
            wrote |= 1u << op->out.offset;
        }
    }
}

// Stack arguments: the outgoing slots just above the shadow area, written in this block
// since the previous call and never read by this function, in order from the first.
// A listed import takes exactly its prototype's stack arguments, however many fresh
// outgoing slots the block happened to write before the call.
static uint8_t proto_stack(const dx_fn_t *x, const re_ir_op_t *op, uint8_t n) {
    re_dc_proto_t pr;
    unsigned regs = dx_max_reg_args(x);
    if (!dx_proto_at(x, op->addr, &pr))
        return n;
    unsigned want = pr.nargs > regs ? pr.nargs - regs : 0;
    return n > want ? (uint8_t)want : n;
}

static void stack_args_block(dx_fn_t *x, uint32_t b) {
    int32_t fresh[32];
    unsigned nf = 0;
    dx_frame_t fr;
    const re_ir_block_t *blk = x->b[b].ir;
    int32_t base = sysv(x) ? 0 : 0x20;
    dx_frame_init(x, &fr, b);
    for (size_t k = 0; k < blk->n_ops; k++) {
        const re_ir_op_t *op = &blk->ops[k];
        uint32_t gi = dx_op_index(x, b, k);
        if (op->op == RE_OP_STORE) {
            dx_sv_t s = dx_frame_eval(x, &fr, op->in[2]);
            if (s.stk && nf < 32)
                fresh[nf++] = s.off;
        } else if ((op->op == RE_OP_CALL || op->op == RE_OP_CALLIND) && fr.sp != DX_SP_UNKNOWN) {
            uint8_t n = 0;
            for (bool more = true; more && n < 12;) {
                int32_t want = fr.sp + base + 8 * n;
                dx_slot_t *sl = dx_slot(x, want, false);
                more = false;
                for (unsigned i = 0; i < nf && sl && !sl->rd && !sl->taken; i++)
                    more |= fresh[i] == want;
                if (more)
                    sl->outarg = true, n++;
            }
            // A callee whose body was summarised reads exactly its own stack parameters.
            const dx_sum_t *sm =
                op->op == RE_OP_CALL ? dx_summary(x, (uint64_t)op->const_val) : NULL;
            if (sm && n > sm->nstk)
                n = sm->nstk;
            n = proto_stack(x, op, n);
            x->call_nstk[gi] = n;
            // Stack arguments follow the register ones, so a call that has any takes
            // all of the register arguments too, written here or passed through.
            if (n)
                x->call_nargs[gi] = (uint8_t)dx_max_reg_args(x);
            nf = 0;
        }
        dx_frame_step(x, &fr, op);
    }
}

void dx_facts_rets(dx_fn_t *x);
void dx_facts_entry(dx_fn_t *x);

void dx_facts(dx_fn_t *x) {
    x->call_nargs = (uint8_t *)re_arena_calloc(x->a, x->nops_all + 1, 1);
    x->call_nstk = (uint8_t *)re_arena_calloc(x->a, x->nops_all + 1, 1);
    for (uint32_t k = 0; k < x->nreal; k++) {
        arity_block(x, k);
        stack_args_block(x, k);
    }
    x->has_ret = true;
    liveness(x);
    dx_facts_rets(x);
    if (!x->has_ret)
        liveness(x);
    dx_facts_entry(x);
}
