// re_dcx_emit.c - turns each block's ops into statements, keeping values as expressions.
// Module: feature (C11).
// Owns: use counts, the register state, definitions, flushing, and the block driver.
// Depends: re_dcx.h. A value used once is inlined where it is used; a value used more
//           than once, or live past the block, gets a variable. A pending value that
//           reads memory or calls is written out before any store or call could change
//           what it would read, so inlining never reorders a side effect.
#include "features/dec/core/re_dcx.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static bool frame_reg(const dx_fn_t *x, unsigned g) {
    return g == DX_RSP || (g == DX_RBP && x->fp);
}

static void widen(uint8_t *w, unsigned size) {
    if (size > *w)
        *w = (uint8_t)size;
}

// sbb r, r: the result is 0 or -1 from the carry alone, so r itself is not read.
static bool self_sbb(const re_ir_op_t *op) {
    return op->op == RE_OP_INTSUB && op->in[2].size && op->in[2].space == RE_SPACE_FLAG &&
           op->in[0].space == op->in[1].space && op->in[0].offset == op->in[1].offset;
}

static void count_reads(dx_fn_t *x, const re_ir_op_t *op, uint32_t gi, uint32_t *last,
                        uint32_t *uqdef, uint32_t b) {
    for (unsigned i = self_sbb(op) ? 2u : 0u; i < 4; i++) {
        re_varnode_t v = op->in[i];
        // An unused input is a zero sized temporary; the store's first input only
        // carries the width; a return's rax is counted below, when there is a value.
        if (!v.size || (op->op == RE_OP_STORE && i == 0) || op->op == RE_OP_RETURN)
            continue;
        if (v.space == RE_SPACE_REG && v.offset < DX_NREG && !frame_reg(x, v.offset)) {
            if (last[v.offset] != DX_NONE)
                x->uses[last[v.offset]]++;
            else if (b != 0) // an entry block read of a live in register is a save
                widen(&x->rv_w[v.offset], v.size);
        } else if (v.space == RE_SPACE_UNIQUE && v.offset < x->nuniq &&
                   uqdef[v.offset] != DX_NONE) {
            x->uses[uqdef[v.offset]]++;
        }
    }
    (void)gi;
}

static void count_args(dx_fn_t *x, unsigned n, uint32_t *last) {
    for (unsigned p = 0; p < n; p++) {
        unsigned r = dx_arg_reg(x, p);
        if (last[r] != DX_NONE)
            x->uses[last[r]]++;
        else
            widen(&x->rv_w[r], 8);
    }
}

static bool flags_read_first(const dx_fn_t *x, uint32_t s) {
    const re_ir_block_t *blk = s < x->nreal ? x->b[s].ir : NULL;
    for (size_t k = 0; blk && k < blk->n_ops; k++) {
        uint8_t o = (uint8_t)blk->ops[k].op;
        if (o == RE_OP_CMP)
            return false;
        if (o == RE_OP_CBRANCH || o == RE_OP_SETCC || o == RE_OP_SELECT)
            return true;
    }
    return false;
}

static bool reads_flags(const re_ir_op_t *op) {
    if (op->op == RE_OP_CBRANCH || op->op == RE_OP_SETCC || op->op == RE_OP_SELECT)
        return true;
    for (unsigned i = 0; i < 4; i++)
        if (op->in[i].size && op->in[i].space == RE_SPACE_FLAG)
            return true;
    return false;
}

// Which flag writers are read: walking back from the block's end, a writer is live
// when a reader follows it before the next writer, or the block's successor reads the
// flags it starts with. A dead writer's operands are not reads, which is what lets the
// result of an add inline into its one real use.
static void flag_liveness(dx_fn_t *x, uint32_t b) {
    const re_ir_block_t *blk = x->b[b].ir;
    bool live = false;
    for (uint32_t i = 0; i < dx_nsucc(x, b); i++)
        live |= dx_succ(x, b, i) != DX_NONE && flags_read_first(x, dx_succ(x, b, i));
    for (size_t k = blk->n_ops; k-- > 0;) {
        const re_ir_op_t *op = &blk->ops[k];
        bool writer = op->op == RE_OP_CMP || op->out.space == RE_SPACE_FLAG;
        if (writer) {
            x->flive[dx_op_index(x, b, k)] = live;
            live = false;
        }
        if (reads_flags(op))
            live = true;
        if (op->op == RE_OP_CALL || op->op == RE_OP_CALLIND)
            live = false;
    }
}

static void count_block(dx_fn_t *x, uint32_t b, uint32_t *uqdef) {
    uint32_t last[DX_NREG];
    const re_ir_block_t *blk = x->b[b].ir;
    for (unsigned r = 0; r < DX_NREG; r++)
        last[r] = DX_NONE;
    for (size_t k = 0; k < blk->n_ops; k++) {
        const re_ir_op_t *op = &blk->ops[k];
        uint32_t gi = dx_op_index(x, b, k);
        if (op->op != RE_OP_CMP || x->flive[gi])
            count_reads(x, op, gi, last, uqdef, b);
        if (op->op == RE_OP_CALL || op->op == RE_OP_CALLIND) {
            count_args(x, x->call_nargs[gi], last);
            for (unsigned r = 0; r < DX_NREG; r++)
                if (dx_volatile(x, r))
                    last[r] = DX_NONE;
            last[0] = gi;
        } else if (op->op == RE_OP_RETURN && x->has_ret && last[0] != DX_NONE) {
            x->uses[last[0]]++;
        } else if (op->op == RE_OP_BRANCH && x->b[b].term == DX_T_EXIT) {
            // a tail call: every argument it may pass is a read, or a value used once
            // as an argument would also print as a statement of its own
            int n = dx_tail_nargs(x, op);
            count_args(x, n >= 0 ? (unsigned)n : dx_max_reg_args(x), last);
        }
        if (op->out.space == RE_SPACE_REG && op->out.offset < DX_NREG &&
            !frame_reg(x, op->out.offset))
            last[op->out.offset] = gi;
        else if (op->out.space == RE_SPACE_UNIQUE && op->out.offset < x->nuniq)
            uqdef[op->out.offset] = gi;
    }
    for (unsigned r = 0; r < DX_NREG; r++) {
        if (last[r] == DX_NONE || !((x->b[b].live_out >> r) & 1u))
            continue;
        x->esc[last[r]] = 1;
        const re_ir_op_t *d = &blk->ops[last[r] - x->opbase[b]];
        widen(&x->rv_w[r], d->op == RE_OP_CALL || d->op == RE_OP_CALLIND ? 8u : d->out.size);
    }
}

// How often each op's result is read before it is overwritten, and which register
// results leave their block. This is what decides inlining against a variable.
void dx_usecount(dx_fn_t *x) {
    uint32_t *uqdef = (uint32_t *)re_arena_alloc(x->a, (x->nuniq + 1) * sizeof(uint32_t));
    x->uses = (uint16_t *)re_arena_calloc(x->a, x->nops_all + 1, sizeof(uint16_t));
    x->esc = (uint8_t *)re_arena_calloc(x->a, x->nops_all + 1, 1);
    x->flive = (uint8_t *)re_arena_calloc(x->a, x->nops_all + 1, 1);
    if (!uqdef || !x->uses || !x->esc || !x->flive)
        return;
    memset(uqdef, 0xFF, (x->nuniq + 1) * sizeof(uint32_t));
    for (uint32_t b = 0; b < x->nreal; b++)
        flag_liveness(x, b);
    for (uint32_t b = 0; b < x->nreal; b++)
        count_block(x, b, uqdef);
    for (unsigned r = 0; r < DX_NREG; r++)
        if (x->rv_w[r] && x->rv_w[r] < 4)
            x->rv_w[r] = 4;
}

void dx_stmt(dx_em_t *e, const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    dx_stmt_t s;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if ((size_t)n >= sizeof(buf)) {
        char *big = (char *)re_arena_alloc(e->x->a, (size_t)n + 1);
        if (!big)
            return;
        va_start(ap, fmt);
        vsnprintf(big, (size_t)n + 1, fmt, ap);
        va_end(ap);
        s.s = big;
    } else {
        s.s = (const char *)re_arena_memdup(e->x->a, buf, (size_t)n + 1);
    }
    s.va = e->va;
    RE_VEC_PUSH(&e->x->b[e->b].stmts, e->x->a, s);
}

// The variable a register lives in between blocks: its parameter name when it is a
// parameter, otherwise a vN minted the first time a block needs it.
static const char *regvar(dx_fn_t *x, unsigned r) {
    int pos = dx_arg_pos(x, r);
    if (x->rv_name[r])
        return x->rv_name[r];
    if (pos >= 0 && pos < x->nparams) {
        x->rv_name[r] = dx_text(x->a, DX_P_PRIMARY, 8, "a%d", pos + 1).s;
        return x->rv_name[r];
    }
    x->rv_name[r] = dx_mint(x, x->rv_w[r] ? x->rv_w[r] : 8, (int)r);
    return x->rv_name[r];
}

static dx_val_t name_val(const char *name, uint8_t w, unsigned r) {
    dx_val_t v;
    memset(&v, 0, sizeof(v));
    v.s = name;
    v.prec = DX_P_PRIMARY;
    v.w = v.nw = w ? w : 8;
    v.deps = r < DX_NREG ? 1u << r : 0;
    return v;
}

dx_val_t dx_materialize(dx_em_t *e, dx_val_t v) {
    uint8_t w = v.w ? v.w : 8;
    if (v.w && v.nw > v.w)
        v = dx_width(e->x, v, v.w, false);
    const char *t = dx_mint(e->x, w > 8 ? 8 : w, -1);
    dx_stmt(e, "%s = %s;", t, dx_str(e->x, &v));
    dx_val_t r = name_val(t, w, DX_NREG);
    r.seq = v.seq;
    return r;
}

// Write out every pending value matching the test, oldest first. Two registers holding
// the same pending value share one variable, so a call is never printed twice.
static bool flagval_hit(const dx_val_t *v, uint32_t dep, bool mem) {
    return (mem && (v->mem || v->fx)) || (v->deps & dep);
}

static void flush_where(dx_em_t *e, uint32_t dep, bool mem, unsigned skip) {
    for (;;) {
        uint32_t best = DX_NONE, bseq = 0xFFFFFFFFu;
        dx_val_t *slot[DX_NREG + 4];
        unsigned ns = 0;
        for (unsigned r = 0; r < DX_NREG; r++)
            if (r != skip && e->has[r] && e->left[r] && flagval_hit(&e->reg[r], dep, mem) &&
                e->reg[r].seq < bseq)
                best = r, bseq = e->reg[r].seq;
        dx_val_t *fv[4] = {&e->fl.l, &e->fl.r, &e->fl.a, &e->fl.b};
        for (unsigned i = 0; e->fl.ok && i < 4; i++)
            if ((i < 2 || e->fl.ab) && fv[i]->s && flagval_hit(fv[i], dep, mem) &&
                fv[i]->seq < bseq)
                best = DX_NREG + i, bseq = fv[i]->seq;
        if (best == DX_NONE)
            return;
        for (unsigned r = 0; r < DX_NREG; r++)
            if (r != skip && e->has[r] && e->reg[r].seq == bseq &&
                flagval_hit(&e->reg[r], dep, mem))
                slot[ns++] = &e->reg[r];
        for (unsigned i = 0; e->fl.ok && i < 4; i++)
            if (fv[i]->s && fv[i]->seq == bseq && flagval_hit(fv[i], dep, mem))
                slot[ns++] = fv[i];
        dx_val_t m = dx_materialize(e, *slot[0]);
        for (unsigned i = 0; i < ns; i++)
            *slot[i] = m;
    }
}

void dx_flush_mem(dx_em_t *e) {
    flush_where(e, 0, true, DX_NREG);
}

void dx_flush_mem_but(dx_em_t *e, unsigned keep) {
    flush_where(e, 0, true, keep);
}

dx_val_t dx_get(dx_em_t *e, re_varnode_t v) {
    int64_t c;
    dx_sv_t s = dx_frame_eval(e->x, &e->fr, v);
    if (s.stk && v.space != RE_SPACE_REG) {
        dx_val_t r = dx_cst(0, 8);
        r.cst = false, r.stk = true, r.off = s.off;
        return r;
    }
    if (v.space == RE_SPACE_CONST && dx_cval(e->x, v, &c))
        return dx_cst(c, (uint8_t)v.size);
    if ((v.space == RE_SPACE_UNIQUE || v.space == RE_SPACE_CONST) && v.offset < e->x->nuniq) {
        if (e->uqv[v.offset].s || e->uqv[v.offset].cst || e->uqv[v.offset].stk)
            return e->uqv[v.offset];
        if (dx_cval(e->x, v, &c))
            return dx_cst(c, (uint8_t)v.size);
    }
    if (v.space == RE_SPACE_REG && v.offset < DX_NREG) {
        if (s.stk) {
            dx_val_t r = dx_cst(0, 8);
            r.cst = false, r.stk = true, r.off = s.off;
            return r;
        }
        if (e->has[v.offset]) {
            if (e->left[v.offset] && e->left[v.offset] != 0xFFFFu)
                e->left[v.offset]--;
            return e->reg[v.offset];
        }
        if (v.offset == DX_RSP && e->has_rsp_dyn)
            return e->rsp_dyn;
        dx_val_t r =
            name_val(dx_reg_name(e->x, v.offset, v.size >= 8 ? 8 : 4), (uint8_t)v.size, DX_NREG);
        r.ent = (uint8_t)(v.offset + 1);
        return r;
    }
    if (v.space == RE_SPACE_FLAG)
        return dx_carry(e);
    if (v.space == RE_SPACE_STACK) {
        // a frame address after rsp moved by an amount only known at run time
        const char *base = e->has_rsp_dyn ? dx_str(e->x, &e->rsp_dyn) : "rsp";
        int16_t d = (int16_t)v.offset;
        if (!d)
            return dx_text(e->x->a, DX_P_PRIMARY, 8, "%s", base);
        return dx_text(e->x->a, DX_P_ADD, 8, "%s %s 0x%X", base, d < 0 ? "-" : "+",
                       (unsigned)(d < 0 ? -d : d));
    }
    return dx_text(e->x->a, DX_P_PRIMARY, (uint8_t)v.size, "?");
}

dx_val_t dx_read(dx_em_t *e, re_varnode_t v, uint8_t w, bool sgn) {
    return dx_width(e->x, dx_get(e, v), w, sgn);
}

// A register result. A value that leaves the block lands in the register's variable; a
// value read once stays pending; a value read often enough to matter gets a temporary.
static void def_reg(dx_em_t *e, unsigned r, dx_val_t v, uint16_t size) {
    dx_fn_t *x = e->x;
    uint16_t uses = x->uses[e->gi];
    if (dx_arg_pos(x, r) >= 0)
        e->wrote |= 1u << r;
    if (x->esc[e->gi] && !v.stk) {
        const char *name = regvar(x, r);
        uint8_t vw = x->rv_w[r] ? x->rv_w[r] : 8;
        uint8_t aw = v.w && v.w < vw ? v.w : vw;
        flush_where(e, 1u << r, false, r);
        if (!v.s || v.s != name)
            dx_stmt(e, "%s = %s;", name, dx_at_width(x, &v, aw, false));
        v = name_val(name, x->rv_w[r], r);
        uses = 0xFFFFu;
    } else if (uses == 0 && v.fx) {
        dx_stmt(e, "%s;", dx_str(x, &v));
    } else if (uses > 1 && !dx_simple(&v)) {
        v = dx_materialize(e, v);
    }
    if (!v.w || v.w > size)
        v.w = (uint8_t)size;
    e->reg[r] = v;
    e->has[r] = 1;
    e->left[r] = uses;
}

void dx_def(dx_em_t *e, re_varnode_t out, dx_val_t v) {
    if (!v.seq)
        v.seq = ++e->seq;
    if (out.space == RE_SPACE_REG && out.offset < DX_NREG && !frame_reg(e->x, out.offset)) {
        def_reg(e, out.offset, v, out.size);
    } else if ((out.space == RE_SPACE_UNIQUE || out.space == RE_SPACE_CONST) &&
               out.offset < e->x->nuniq) {
        if (e->x->uses[e->gi] > 1 && !dx_simple(&v))
            v = dx_materialize(e, v);
        e->uqv[out.offset] = v;
    } else if (out.space == RE_SPACE_FLAG && out.offset == RE_FLAG_CF && e->x->flive[e->gi]) {
        e->fl.ok = true;
        e->fl.kind = DX_FL_CF;
        e->fl.l = v;
        e->fl.ab = false;
    }
}

// The flags a block starts with: its single predecessor's, or every predecessor's when
// they all end on the same writer. A back edge has not been emitted yet, so a loop
// header never inherits, which is the conservative answer.
static void inherit_flags(dx_em_t *e, uint32_t b) {
    const dx_block_t *p = &e->x->b[b];
    memset(&e->fl, 0, sizeof(e->fl));
    for (uint32_t i = 0; i < p->n_pred; i++) {
        const dx_block_t *q = &e->x->b[p->pred[i]];
        if (!q->emitted || !q->fl_out.ok || (i && q->fl_out.id != e->fl.id)) {
            memset(&e->fl, 0, sizeof(e->fl));
            return;
        }
        e->fl = q->fl_out;
    }
}

static void block_init(dx_em_t *e, uint32_t b) {
    dx_fn_t *x = e->x;
    e->b = b;
    dx_frame_init(x, &e->fr, b);
    memset(e->has, 0, sizeof(e->has));
    memset(e->left, 0, sizeof(e->left));
    e->wrote = 0;
    e->nout = 0;
    e->sw_idx = NULL;
    inherit_flags(e, b);
    for (unsigned r = 0; r < DX_NREG; r++) {
        int pos = dx_arg_pos(x, r);
        if (!((x->b[b].live_in >> r) & 1u) || frame_reg(x, r))
            continue;
        if (b == 0 && !(pos >= 0 && pos < x->nparams))
            continue; // an entry value: read as the raw register, tagged as such
        e->reg[r] = name_val(regvar(x, r), b == 0 && pos >= 0 ? x->pw[pos] : x->rv_w[r], r);
        if (b == 0 && pos >= 0)
            e->reg[r].ent = (uint8_t)(r + 1);
        e->reg[r].seq = ++e->seq;
        e->has[r] = 1;
        e->left[r] = 0xFFFFu;
    }
}

static void unlowered(dx_em_t *e, const re_insn_t *in) {
    re_strbuf_t t;
    re_strbuf_init(&t, e->x->a);
    if (e->x->code->dis && e->x->code->dis->render)
        e->x->code->dis->render(e->x->code->dis->ctx, in, e->x->a, &t);
    dx_stmt(e, "__asm { %s }", t.p ? t.p : "?");
    // What it wrote is unknown, so the registers it names read as themselves from here.
    if (in->reg < DX_NREG)
        e->has[in->reg] = 0;
    if (!in->is_mem && in->rm < DX_NREG)
        e->has[in->rm] = 0;
    e->fl.ok = false;
}

static void emit_block(dx_em_t *e, uint32_t b) {
    dx_fn_t *x = e->x;
    dx_block_t *blk = &x->b[b];
    size_t k = 0;
    block_init(e, b);
    re_vec_init(&blk->stmts, sizeof(dx_stmt_t));
    for (uint32_t i = blk->i0; i < blk->i1; i++) {
        const re_insn_t *in = RE_VEC_PTR(&x->insns, re_insn_t, i);
        e->va = in->addr;
        if (!x->nops[i]) {
            unlowered(e, in);
            continue;
        }
        for (uint16_t j = 0; j < x->nops[i] && k < blk->ir->n_ops; j++, k++) {
            e->gi = dx_op_index(x, b, k);
            dx_emit_op(e, &blk->ir->ops[k]);
            dx_frame_step(x, &e->fr, &blk->ir->ops[k]);
        }
    }
    bool carry = false;
    for (uint32_t i = 0; i < dx_nsucc(x, b); i++)
        carry |= dx_succ(x, b, i) != DX_NONE && flags_read_first(x, dx_succ(x, b, i));
    if (carry && e->fl.ok && (e->fl.l.fx || e->fl.r.fx))
        flush_where(e, 0, true, DX_NREG);
    blk->fl_out = carry ? e->fl : (dx_flag_t){0};
    blk->emitted = true;
}

void dx_emit_all(dx_fn_t *x) {
    dx_em_t e;
    memset(&e, 0, sizeof(e));
    e.x = x;
    e.uqv = (dx_val_t *)re_arena_calloc(x->a, x->nuniq + 1, sizeof(dx_val_t));
    if (!e.uqv)
        return;
    for (uint32_t i = 0; i < x->norder; i++) {
        uint32_t b = x->order[i];
        if (b < x->nreal)
            emit_block(&e, b);
        else
            x->b[b].emitted = true;
    }
}
