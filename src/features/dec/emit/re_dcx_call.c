// re_dcx_call.c - calls, tail calls and returns, with arguments the ABI actually passes.
// Module: feature (C11).
// Owns: the callee's name, the argument list, the result, and the return statement.
// Depends: re_dcx.h. Arguments are the argument registers in convention order plus the
//           outgoing stack slots the frame pass matched to this call, never "every
//           register written since the last call".
#include "features/dec/core/re_dcx.h"

#include <string.h>

static const char *name_of_target(dx_em_t *e, uint64_t target) {
    const re_fscan_t *s = e->x->d->scan;
    long i = s ? re_func_index_of(s, target) : -1;
    const re_func_t *g = i >= 0 ? re_func_at(s, (size_t)i) : NULL;
    if (g && g->va == target && g->name.n)
        return dx_text(e->x->a, DX_P_PRIMARY, 8, "%.*s", (int)g->name.n, g->name.p).s;
    return dx_text(e->x->a, DX_P_PRIMARY, 8, "sub_%llX", (unsigned long long)target).s;
}

// The name a call site calls: an import or export the cross references name at this
// site, a recovered function, or the indirect target expression itself.
const char *dx_callee(dx_em_t *e, const re_ir_op_t *op) {
    dx_fn_t *x = e->x;
    const re_xref_t *xr = x->d->xrefs ? re_xref_from_at(x->d->xrefs, e->va, 0) : NULL;
    if (xr && xr->name.n && (xr->flags & (RE_XRF_IMPORT | RE_XRF_EXPORT)))
        return dx_text(x->a, DX_P_PRIMARY, 8, "%.*s", (int)xr->name.n, xr->name.p).s;
    if (op->op == RE_OP_CALL)
        return name_of_target(e, (uint64_t)op->const_val);
    if (!op->in[0].size)
        return "indirect";
    dx_val_t t = dx_read(e, op->in[0], 8, false);
    if (t.cst)
        return name_of_target(e, (uint64_t)t.c);
    return dx_paren(x, &t, DX_P_PRIMARY);
}

static void put_arg(dx_fn_t *x, re_strbuf_t *sb, const dx_val_t *v, bool *first) {
    if (!*first)
        re_strbuf_puts(sb, ", ");
    *first = false;
    re_strbuf_puts(sb, dx_at_width(x, v, v->w ? v->w : 8, false));
}

// The argument list: n register arguments, then the stack arguments the frame pass
// matched to this call, read from what the outgoing stores left.
static const char *arg_list(dx_em_t *e, unsigned n, unsigned nstk) {
    dx_fn_t *x = e->x;
    re_strbuf_t sb;
    bool first = true;
    re_strbuf_init(&sb, x->a);
    re_strbuf_puts(&sb, "");
    // A trailing argument register nothing in this function wrote holds whatever the
    // caller left there: a variadic callee spills it, but this call passes nothing.
    while (n && !nstk && !e->has[dx_arg_reg(x, n - 1)])
        n--;
    for (unsigned p = 0; p < n; p++) {
        dx_val_t v = dx_get(e, re_ir_vn(RE_SPACE_REG, 8, (uint16_t)dx_arg_reg(x, p)));
        put_arg(x, &sb, &v, &first);
    }
    int32_t base = x->cc == RE_CC_SYSV ? 0 : 0x20;
    for (unsigned k = 0; k < nstk; k++) {
        int32_t want = e->fr.sp + base + 8 * (int32_t)k;
        dx_val_t v = dx_text(x->a, DX_P_PRIMARY, 8, "?");
        for (uint32_t i = 0; i < e->nout; i++)
            if (e->outoff[i] == want)
                v = e->outv[i];
        put_arg(x, &sb, &v, &first);
    }
    return sb.p ? sb.p : "";
}

static bool effect(const dx_val_t *v) {
    return v->s && (v->fx || v->mem);
}

// The argument register whose pending value may stay inside this call's text rather
// than become a variable first: the only argument with a side effect or a memory
// read, read here and nowhere after, held in no other register, and the latest effect
// still pending, so leaving it to the call reorders nothing.
static unsigned inline_arg(dx_em_t *e, unsigned n) {
    unsigned pick = DX_NREG, cnt = 0;
    for (unsigned p = 0; p < n; p++) {
        unsigned r = dx_arg_reg(e->x, p);
        if (e->has[r] && effect(&e->reg[r]) && (++cnt, e->left[r] == 1))
            pick = r;
    }
    for (uint32_t i = 0; i < e->nout; i++)
        cnt += effect(&e->outv[i]);
    if (cnt != 1 || pick == DX_NREG)
        return DX_NREG;
    uint32_t seq = e->reg[pick].seq;
    for (unsigned r = 0; r < DX_NREG; r++)
        if (r != pick && e->has[r] && e->left[r] && effect(&e->reg[r]) && e->reg[r].seq >= seq)
            return DX_NREG;
    const dx_val_t *fv[4] = {&e->fl.l, &e->fl.r, &e->fl.a, &e->fl.b};
    for (unsigned i = 0; e->fl.ok && i < 4; i++)
        if (effect(fv[i]) && fv[i]->seq >= seq)
            return DX_NREG;
    return pick;
}

static unsigned written_args(dx_em_t *e) {
    unsigned n = 0;
    for (unsigned p = 0; p < dx_max_reg_args(e->x); p++)
        if (e->wrote & (1u << dx_arg_reg(e->x, p)))
            n = p + 1;
    return n;
}

void dx_emit_call(dx_em_t *e, const re_ir_op_t *op) {
    dx_fn_t *x = e->x;
    dx_flush_mem_but(e, inline_arg(e, x->call_nargs[e->gi]));
    const char *fn = dx_callee(e, op);
    const char *args = arg_list(e, x->call_nargs[e->gi], x->call_nstk[e->gi]);
    dx_val_t v = dx_text(x->a, DX_P_PRIMARY, 8, "%s(%s)", fn, args);
    re_dc_proto_t pr;
    const dx_sum_t *sm = NULL;
    if (dx_proto_at(x, e->va, &pr)) {
        if (pr.ret == 'i' || pr.ret == 'u') {
            v.w = v.nw = 4; // a BOOL, DWORD or NTSTATUS lives in eax
            v.sg = pr.ret == 'i';
        }
    } else if (op->op == RE_OP_CALL && (sm = dx_summary(x, (uint64_t)op->const_val)) != NULL &&
               sm->has_ret && sm->ret_w && sm->ret_w < 8) {
        v.w = v.nw = sm->ret_w; // the callee writes only eax, ax or al
    }
    v.fx = v.mem = true;
    v.seq = ++e->seq;
    for (unsigned r = 0; r < DX_NREG; r++)
        if (dx_volatile(x, r))
            e->has[r] = 0;
    e->wrote = 0;
    e->nout = 0;
    e->fl.ok = false; // a call leaves the flags undefined
    dx_def(e, re_ir_vn(RE_SPACE_REG, 8, 0), v);
}

void dx_emit_return(dx_em_t *e, const re_ir_op_t *op) {
    dx_fn_t *x = e->x;
    (void)op;
    if (!x->has_ret) {
        dx_flush_mem(e);
        dx_stmt(e, "return;");
        return;
    }
    dx_val_t v = dx_get(e, re_ir_vn(RE_SPACE_REG, 8, 0));
    uint8_t w = v.w ? v.w : 8;
    if (w > x->ret_w)
        x->ret_w = w;
    dx_stmt(e, "return %s;", dx_at_width(x, &v, w, false));
}

// A jump out of the function at its end is a call whose result is this function's: a
// direct jmp to another function, or a jmp through an import slot or a register.
void dx_emit_tail(dx_em_t *e, const re_ir_op_t *op) {
    dx_fn_t *x = e->x;
    unsigned n = written_args(e);
    const char *fn = "JUMPOUT";
    const re_xref_t *xr = x->d->xrefs ? re_xref_from_at(x->d->xrefs, e->va, 0) : NULL;
    if (xr && xr->name.n && (xr->flags & (RE_XRF_IMPORT | RE_XRF_EXPORT))) {
        fn = dx_text(x->a, DX_P_PRIMARY, 8, "%.*s", (int)xr->name.n, xr->name.p).s;
    } else if (op->const_val) {
        fn = name_of_target(e, (uint64_t)op->const_val);
    } else if (op->in[0].size) {
        dx_val_t t = dx_read(e, op->in[0], 8, false);
        fn = t.cst ? name_of_target(e, (uint64_t)t.c) : dx_paren(x, &t, DX_P_PRIMARY);
    }
    re_dc_proto_t pr;
    bool known = dx_proto_at(x, e->va, &pr);
    int tn = dx_tail_nargs(x, op); // the prototype or the callee's own body
    if (tn >= 0)
        n = (unsigned)tn;
    else if (n < x->nparams)
        n = x->nparams;
    dx_flush_mem_but(e, inline_arg(e, n));
    const char *args = arg_list(e, n, 0);
    if (x->has_ret && !(known && pr.ret == 'v')) {
        uint8_t rw = known && (pr.ret == 'i' || pr.ret == 'u') ? 4 : 8;
        if (x->ret_w < rw)
            x->ret_w = rw;
        dx_stmt(e, "return %s(%s);", fn, args);
    } else {
        dx_stmt(e, "%s(%s);", fn, args);
    }
}
