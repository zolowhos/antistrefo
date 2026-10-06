// re_decompile.c - renders one function's lowered IR as C-like source.
// Module: feature (C11).
// Owns: which statement each op becomes, the signature, and the locals.
// Depends: re_dc_print, re_dc_walk, re_code, re_xref, re_stack, re_strbuf.
// Depends: re_dc_print (the emitter state), re_dc_walk (the block structure),
//           re_code, re_xref (call names), re_stack (the signature). The decoder is
//           reached only through the re_disasm_t vtable, so no x86 detail appears.
#include "features/dec/re_decompile.h"

#include "features/code/re_jtable.h"
#include "features/code/re_stack.h"
#include "features/dec/re_dc_fold.h"
#include "features/dec/re_dc_print.h"
#include "features/dec/re_dc_proto.h"
#include "features/flow/re_flow.h"
#include "features/indirect/re_dc_indirect.h"
#include "utils/mem/re_vec.h"
#include "utils/text/re_fmt.h"

#include <stdio.h>
#include <string.h>

static void call_args(re_dc_emit_t *e, re_strbuf_t *args) {
    char scratch[RE_DC_TEXT];
    bool first = true;
    re_strbuf_init(args, e->a);
    for (uint16_t r = 1; r < RE_DC_REGS; r++) {
        if (!e->touched[r])
            continue;
        if (!first)
            re_strbuf_puts(args, ", ");
        re_strbuf_puts(args, re_dc_val(e, re_ir_vn(RE_SPACE_REG, 8, r), scratch));
        first = false;
    }
    memset(e->touched, 0, sizeof(e->touched));
}

static void emit_call(re_dc_emit_t *e, const re_ir_op_t *op) {
    const re_xref_t *xr = e->xrefs ? re_xref_from_at(e->xrefs, e->insn_addr, 0) : NULL;
    // RFLAGS is volatile across a call, so a comparison pending from before one
    // says nothing about a branch that follows it.
    e->have_cmp = false;
    re_str_t name = re_dc_mint(e, "v", e->next_tmp++);
    re_strbuf_t args;
    if (op->op == RE_OP_CALLIND) {
        char ind[96];
        if (re_dc_indirect_format(e->code, op->addr, ind, sizeof(ind))) {
            re_dc_stmt(e, "%s = %s", (const char *)name.p, ind);
            re_dc_bind(e, op->out, name);
            return;
        }
    }
    if (op->extra & RE_FOLD_SKIP)
        return;
    call_args(e, &args);
    {
        char proto[96];
        if (xr && re_dc_proto_format(xr->name, args.p ? args.p : "", proto, sizeof(proto))) {
            if (op->extra & RE_FOLD_STMT)
                re_dc_stmt(e, "%s", proto);
            else
                re_dc_stmt(e, "%s = %s", (const char *)name.p, proto);
            re_dc_bind(e, op->out, name);
            return;
        }
    }
    if (op->extra & RE_FOLD_STMT) {
        re_dc_stmt(e, "sub_%llx(%s)", (unsigned long long)op->const_val, args.p ? args.p : "");
        re_dc_bind(e, op->out, name);
        return;
    }
    if (xr && xr->name.p && xr->name.n) {
        uint32_t n =
            (uint32_t)(xr->name.n < (uint32_t)(RE_DC_TEXT - 1) ? xr->name.n : RE_DC_TEXT - 1);
        re_dc_stmt(e, "%s = %.*s(%s)", (const char *)name.p, (int)n, (const char *)xr->name.p,
                   args.p);
    } else {
        re_dc_stmt(e, "%s = call_0x%llx(%s)", (const char *)name.p,
                   (unsigned long long)op->const_val, args.p);
    }
    re_dc_bind(e, op->out, name);
}

static void emit_cbranch(re_dc_emit_t *e, const re_ir_op_t *op, const re_dc_walk_t *w) {
    uint32_t lbl = re_dc_label_of(w, (uint64_t)op->const_val);
    char dest[RE_DC_TEXT];
    char expr[160];
    if (lbl)
        re_dc_fmt(dest, sizeof(dest), "L%u", (unsigned long long)lbl);
    else
        re_dc_fmt(dest, sizeof(dest), "0x%llx", (unsigned long long)op->const_val);
    if (e->have_cmp && re_dc_flag_expr(e, op->extra, expr, sizeof(expr))) {
        re_dc_stmt(e, "if (%s) goto %s", expr, dest);
    } else if (e->have_cmp) {
        re_dc_stmt(e, "if (cc_%s) goto %s", re_dc_ccname(op->extra), dest);
    } else {
        re_dc_stmt(e, "if (cond) goto %s", dest);
    }
    e->have_cmp = false;
}

static bool emit_switch(re_dc_emit_t *e, const re_ir_op_t *op, const re_dc_walk_t *w,
                        const re_jtable_t *jt) {
    uint32_t i;
    (void)op;
    if (!jt || !jt->count)
        return false;
    re_dc_line(e, "switch (index) {");
    for (i = 0; i < jt->count; i++) {
        uint64_t dest = re_jtable_target(e->code, jt, i);
        uint32_t cl = dest ? re_dc_label_of(w, dest) : 0;
        if (cl)
            re_dc_stmt(e, "case %u: goto L%u", i, cl);
        else
            re_dc_line(e, "case %u:", i);
    }
    re_dc_line(e, "}");
    return true;
}

static void emit_flow(re_dc_emit_t *e, const re_ir_op_t *op, const re_dc_walk_t *w) {
    uint32_t lbl = re_dc_label_of(w, (uint64_t)op->const_val);
    if (op->op == RE_OP_BRANCH) {
        const re_jtable_t *jt = re_jtable_for(e->jtables, op->addr);
        if (op->addr && (uint64_t)op->const_val == e->next_addr)
            return;
        if (emit_switch(e, op, w, jt))
            return;
        if (lbl)
            re_dc_stmt(e, "goto L%u", lbl);
        else
            re_dc_stmt(e, "goto 0x%llx", (unsigned long long)op->const_val);
        return;
    }
    if (op->op == RE_OP_CBRANCH) {
        emit_cbranch(e, op, w);
        return;
    }
    if (op->op == RE_OP_RETURN) {
        char a[RE_DC_TEXT];
        if (op->extra & RE_FOLD_STMT) {
            re_strbuf_t args;
            call_args(e, &args);
            re_dc_stmt(e, "return sub_%llx(%s)", (unsigned long long)op->const_val,
                       args.p ? args.p : "");
            return;
        }
        re_dc_stmt(e, "return %s", re_dc_val(e, op->in[0], a));
        return;
    }
    if (op->op == RE_OP_INT) {
        // A trap out of the modelled world: syscall, sysenter or an int. The
        // number is all the architecture states about what happens next.
        re_dc_stmt(e, "interrupt(0x%llx)", (unsigned long long)op->const_val);
        return;
    }
    if (op->op == RE_OP_CALL || op->op == RE_OP_CALLIND) {
        emit_call(e, op);
        return;
    }
    if (op->op == RE_OP_CAST) {
        char a[RE_DC_TEXT];
        re_str_t name = re_dc_mint(e, "v", e->next_tmp++);
        re_dc_stmt(e, "%s = (%s)%s", (const char *)name.p, re_dc_type((uint16_t)op->out.size),
                   re_dc_val(e, op->in[0], a));
        re_dc_bind(e, op->out, name);
        return;
    }
    if (op->op == RE_OP_UNIMPL) {
        e->n_unknown++;
        return;
    }
}

static void emit_move(re_dc_emit_t *e, const re_ir_op_t *op) {
    char a[RE_DC_TEXT], b[RE_DC_TEXT];
    re_str_t name = re_dc_mint(e, "v", e->next_tmp++);
    int16_t disp = 0;
    bool natural;
    if (op->op == RE_OP_LOAD) {
        natural = op->in[0].space == RE_SPACE_STACK &&
                  re_dc_slot_width(e, disp = (int16_t)op->in[0].offset) == op->out.size;
        if (op->extra & RE_FOLD_DISP)
            re_dc_stmt(e, "%s = *(%s *)(%s + 0x%llx)", (const char *)name.p,
                       re_dc_type(op->out.size), re_dc_val(e, op->in[0], a),
                       (unsigned long long)op->const_val);
        else if (natural)
            re_dc_stmt(e, "%s = %s", (const char *)name.p, re_dc_local(e, disp));
        else
            re_dc_stmt(e, "%s = *(%s *)%s", (const char *)name.p, re_dc_type(op->out.size),
                       re_dc_val(e, op->in[0], a));
        re_dc_bind(e, op->out, name);
        return;
    }
    natural = op->in[2].space == RE_SPACE_STACK &&
              re_dc_slot_width(e, disp = (int16_t)op->in[2].offset) == op->in[0].size;
    if (natural)
        re_dc_stmt(e, "%s = %s", re_dc_local(e, disp), re_dc_val(e, op->in[1], b));
    else
        re_dc_stmt(e, "*(%s *)%s = %s", re_dc_type(op->in[0].size), re_dc_val(e, op->in[2], a),
                   re_dc_val(e, op->in[1], b));
}

static void emit_copy(re_dc_emit_t *e, const re_ir_op_t *op) {
    char a[RE_DC_TEXT];
    re_str_t name;
    // A write into a flag varnode is the lowering recording a flag result, not
    // a statement a reader needs: the branch that consumes it prints the value.
    if (op->out.space == RE_SPACE_FLAG)
        return;
    if (op->extra & RE_FOLD_ALIAS) {
        char tmp[RE_DC_TEXT];
        const char *n = re_dc_val(e, op->in[0], tmp);
        size_t k = 0;
        re_str_t s;
        while (n[k] && k < RE_DC_TEXT - 1)
            k++;
        s.p = (const char *)re_arena_memdup(e->a, n, k);
        s.n = (uint32_t)k;
        re_dc_bind(e, op->out, s);
        return;
    }
    name = re_dc_mint(e, "v", e->next_tmp++);
    if (op->in[0].space == RE_SPACE_CONST && op->in[0].offset < RE_DC_VARS)
        e->caddr[op->in[0].offset] = true;
    if (op->out.space != RE_SPACE_STACK && op->out.space != RE_SPACE_HEAP)
        re_dc_stmt(e, "%s = %s", (const char *)name.p, re_dc_val(e, op->in[0], a));
    re_dc_bind(e, op->out, name);
}

static void take_const(re_dc_emit_t *e, const re_ir_op_t *op) {
    if (op->out.offset < RE_DC_VARS)
        e->cval[op->out.offset] = op->const_val;
    if (op->extra & RE_CONST_OPERAND)
        return;
    re_str_t name = re_dc_mint(e, "v", e->next_tmp++);
    re_dc_stmt(e, "%s = %lld", (const char *)name.p, (long long)op->const_val);
    re_dc_bind(e, op->out, name);
}

static void emit_fn(re_dc_emit_t *e, const re_ir_op_t *op) {
    char a[RE_DC_TEXT], b[RE_DC_TEXT], c[RE_DC_TEXT];
    const char *fn = re_dc_fnop(op->op);
    re_str_t name;
    if (op->op == RE_OP_MEMCPY || op->op == RE_OP_MEMSET) {
        re_dc_stmt(e, "%s(%s, %s, %s)", fn, re_dc_val(e, op->in[0], a), re_dc_val(e, op->in[1], b),
                   re_dc_val(e, op->in[2], c));
        return;
    }
    name = re_dc_mint(e, "v", e->next_tmp++);
    if (op->in[1].size == 0)
        re_dc_stmt(e, "%s = %s(%s)", (const char *)name.p, fn, re_dc_val(e, op->in[0], a));
    else
        re_dc_stmt(e, "%s = %s(%s, %s)", (const char *)name.p, fn, re_dc_val(e, op->in[0], a),
                   re_dc_val(e, op->in[1], b));
    re_dc_bind(e, op->out, name);
}

// A float conversion, which prints as the cast it is at the width it lands at.
static void emit_fcast(re_dc_emit_t *e, const re_ir_op_t *op) {
    char a[RE_DC_TEXT];
    re_str_t name = re_dc_mint(e, "v", e->next_tmp++);
    re_dc_stmt(e, "%s = (%s)%s", (const char *)name.p, re_dc_ftype(op->out.size),
               re_dc_val(e, op->in[0], a));
    re_dc_bind(e, op->out, name);
}

static void emit_setcc(re_dc_emit_t *e, const re_ir_op_t *op) {
    re_str_t name = re_dc_mint(e, "v", e->next_tmp++);
    char expr[160];
    if (e->have_cmp && re_dc_flag_expr(e, op->extra, expr, sizeof(expr)))
        re_dc_stmt(e, "%s = (%s) ? 1 : 0", (const char *)name.p, expr);
    else
        re_dc_stmt(e, "%s = cc_%s", (const char *)name.p, re_dc_ccname(op->extra));
    re_dc_bind(e, op->out, name);
}

static void emit_select(re_dc_emit_t *e, const re_ir_op_t *op) {
    char a[RE_DC_TEXT], b[RE_DC_TEXT];
    re_str_t name = re_dc_mint(e, "v", e->next_tmp++);
    char expr[160];
    if (e->have_cmp && re_dc_flag_expr(e, op->extra, expr, sizeof(expr)))
        re_dc_stmt(e, "%s = (%s) ? %s : %s", (const char *)name.p, expr, re_dc_val(e, op->in[1], b),
                   re_dc_val(e, op->in[0], a));
    else
        re_dc_stmt(e, "%s = cmov_%s(%s, %s)", (const char *)name.p, re_dc_ccname(op->extra),
                   re_dc_val(e, op->in[0], a), re_dc_val(e, op->in[1], b));
    re_dc_bind(e, op->out, name);
}

static void emit_op(re_dc_emit_t *e, const re_ir_op_t *op, const re_dc_walk_t *w) {
    char a[RE_DC_TEXT], b[RE_DC_TEXT], c[RE_DC_TEXT];
    const char *bin = re_dc_binop(op->op);
    re_str_t name;
    if (op->op == RE_OP_CONST) {
        take_const(e, op);
        return;
    }
    if (op->op == RE_OP_NOP)
        return;
    if (op->op == RE_OP_VAR) {
        emit_copy(e, op);
        return;
    }
    if (op->op == RE_OP_LOAD || op->op == RE_OP_STORE) {
        emit_move(e, op);
        return;
    }
    if (op->op == RE_OP_SETCC) {
        emit_setcc(e, op);
        return;
    }
    if (op->op == RE_OP_SELECT) {
        emit_select(e, op);
        return;
    }
    if (op->op == RE_OP_FCAST) {
        emit_fcast(e, op);
        return;
    }
    if (re_dc_fnop(op->op)) {
        emit_fn(e, op);
        return;
    }
    if (bin) {
        name = re_dc_mint(e, "v", e->next_tmp++);
        if (op->op == RE_OP_INTSAR) {
            re_dc_stmt(e, "%s = (int64_t)%s >> %s", (const char *)name.p,
                       re_dc_val(e, op->in[0], a), re_dc_val(e, op->in[1], b));
        } else if (op->in[2].space == RE_SPACE_FLAG) {
            // adc or sbb: the carry is a read, and the printed statement shows it
            re_dc_stmt(e, "%s = %s %s %s + %s", (const char *)name.p, re_dc_val(e, op->in[0], a),
                       bin, re_dc_val(e, op->in[1], b), re_dc_val(e, op->in[2], c));
        } else {
            re_dc_stmt(e, "%s = %s %s %s", (const char *)name.p, re_dc_val(e, op->in[0], a), bin,
                       re_dc_val(e, op->in[1], b));
        }
        re_dc_bind(e, op->out, name);
        return;
    }
    if (op->op == RE_OP_CMP) {
        snprintf(e->cmp_l, RE_DC_TEXT, "%s", re_dc_val(e, op->in[0], a));
        snprintf(e->cmp_r, RE_DC_TEXT, "%s", re_dc_val(e, op->in[1], b));
        e->have_cmp = true;
        e->flag_writer = (uint8_t)op->extra;
        return;
    }
    emit_flow(e, op, w);
}

static void emit_params(re_dc_emit_t *e, const re_stack_t *st) {
    uint32_t nargs = st ? st->n_params : 0;
    if (nargs > RE_CC_MAX_ARGS)
        nargs = RE_CC_MAX_ARGS;
    re_strbuf_puts(e->o, "(");
    for (uint32_t i = 0; i < nargs; i++) {
        if (i)
            re_strbuf_puts(e->o, ", ");
        re_strbuf_puts(e->o, re_cc_ret_type(st));
        re_strbuf_puts(e->o, re_cc_arg_reg_name(st->cc, st->arg_regs[i]));
    }
    re_strbuf_puts(e->o, ") {\n");
}

static void emit_sig(re_dc_emit_t *e, const re_func_t *f, const re_stack_t *st) {
    static const char *k_cc[] = {"unknown", "ms64", "sysv"};
    const char *cc = (st && st->cc < 3) ? k_cc[st->cc] : "unknown";
    re_strbuf_puts(e->o, "// ");
    re_strbuf_put_hex64(e->o, f->va, 16);
    re_strbuf_puts(e->o, " ");
    if (f->flags & RE_FUNC_EXPORT)
        re_strbuf_puts(e->o, "export ");
    if (f->flags & RE_FUNC_THUNK)
        re_strbuf_puts(e->o, "tailcall ");
    re_strbuf_appendf(e->o, "size=0x%llx conv=%s args=%u frame=0x%llx\n",
                      (unsigned long long)f->size, cc, st ? st->n_params : 0,
                      (unsigned long long)(st ? st->frame_size : 0));
    re_strbuf_puts(e->o, "uint64_t ");
    if (f->name.n)
        re_strbuf_put_re_str(e->o, f->name);
    else {
        re_strbuf_puts(e->o, "sub_");
        re_strbuf_put_hex64(e->o, f->va, 0);
    }
    emit_params(e, st);
}

static void emit_locals(re_dc_emit_t *e, const re_stack_t *st) {
    for (uint32_t i = 0; i < e->n_sw; i++) {
        int16_t disp = e->sw_disp[i];
        uint8_t w = e->sw_w[i];
        const char *t = re_dc_type(w);
        if (w != 1 && w != 2 && w != 4 && w != 8)
            continue;
        re_strbuf_puts(e->o, "    ");
        re_strbuf_puts(e->o, t);
        re_strbuf_puts(e->o, " ");
        re_strbuf_puts(e->o, re_dc_local(e, disp));
        re_strbuf_puts(e->o, ";\n");
    }
    (void)st;
}

// comes back. A label goes in before the first instruction of a block, so the reader
// sees the shape of the control flow rather than a jump with no destination nearby.
static size_t ops_so_far(const re_ir_func_t *ir) {
    if (!ir->n_blocks)
        return 0;
    return ir->blocks[ir->n_blocks - 1].n_ops;
}

static const re_ir_op_t *ops_from(const re_ir_func_t *ir, size_t at) {
    if (!ir->n_blocks || at >= ir->blocks[ir->n_blocks - 1].n_ops)
        return NULL;
    return &ir->blocks[ir->n_blocks - 1].ops[at];
}

static uint16_t *lower_body(re_dc_emit_t *e, const re_dc_walk_t *w, re_ir_func_t *ir,
                            uint64_t entry, uint64_t size, re_code_t *code, re_flow_stat_t *fl) {
    size_t n = RE_VEC_LEN(&w->insns);
    uint16_t *produced = (uint16_t *)re_arena_calloc(e->a, n ? n : 1, sizeof(uint16_t));
    if (!produced || !re_ir_block_begin(ir, e->a, entry, size))
        return NULL;
    for (size_t i = 0; i < n; i++) {
        const re_insn_t *in = RE_VEC_PTR(&w->insns, re_insn_t, i);
        size_t pre = ops_so_far(ir);
        e->insn_addr = in->addr;
        e->next_addr = in->addr + in->size;
        e->dis->lower(NULL, in, ir, e->a);
        produced[i] = (uint16_t)(ops_so_far(ir) - pre);
    }
    re_flow_apply(ir, code, e->a, fl);
    re_dc_fold(ir);
    re_dc_learn_widths(e, ir);
    return produced;
}

static void print_body(re_dc_emit_t *e, const re_dc_walk_t *w, const re_ir_func_t *ir,
                       const uint16_t *produced) {
    size_t n = RE_VEC_LEN(&w->insns);
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        const re_insn_t *in = RE_VEC_PTR(&w->insns, re_insn_t, i);
        uint32_t lbl = re_dc_label_of(w, in->addr);
        if (lbl) {
            re_strbuf_puts(e->o, "L");
            re_strbuf_put_u64(e->o, lbl);
            re_strbuf_puts(e->o, ":\n");
        }
        if (!produced[i]) {
            re_dc_unlowered(e, in);
            continue;
        }
        for (size_t j = 0; j < produced[i] && k < ops_so_far(ir); j++, k++) {
            const re_ir_op_t *op = ops_from(ir, k);
            e->map_va = in->addr;
            if (op)
                emit_op(e, op, w);
        }
    }
}
bool re_decompile_ok(const re_decomp_t *d, const re_func_t *f) {
    re_dc_walk_t w = {0};
    if (!d || !f || !d->code || !d->arena)
        return false;
    re_dc_walk(d->code, f, &w, d->arena);
    return RE_VEC_LEN(&w.insns) > 0;
}

void re_decompile_func(const re_decomp_t *d, const re_func_t *f, const re_stack_t *st,
                       re_strbuf_t *out) {
    re_dc_emit_t e = {0};
    re_ir_func_t ir;
    re_dc_walk_t w = {0};
    if (!d || !f || !out || !d->code || !d->arena)
        return;
    re_dc_walk(d->code, f, &w, d->arena);
    e.o = out;
    e.a = d->arena;
    e.xrefs = d->xrefs;
    e.st = st;
    e.dis = d->code->dis;
    e.jtables = d->jtables;
    e.code = d->code;
    e.sites = d->sites;
    {
        re_flow_stat_t fl;
        uint16_t *produced;
        re_flow_stat_init(&fl, d->arena);
        re_ir_func_init(&ir);
        produced = lower_body(&e, &w, &ir, f->va, f->size, d->code, &fl);
        re_dc_stackstrs(&e, &fl);
        emit_sig(&e, f, st);
        emit_locals(&e, st);
        if (produced)
            print_body(&e, &w, &ir, produced);
    }
    re_strbuf_puts(out, "}\n");
}
