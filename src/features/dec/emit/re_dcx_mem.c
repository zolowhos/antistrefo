// re_dcx_mem.c - loads and stores: frame slots, arrays, globals, segment reads.
// Module: feature (C11).
// Owns: what an access prints as: a local, base[k], table[i], a global, or *(T *)p.
// Depends: re_dcx.h. Split from re_dcx_ops.c, which keeps arithmetic and the dispatch.
#include "features/dec/core/re_dcx.h"

#include <string.h>

static const char *gs_name(uint8_t w) {
    return w == 1   ? "__readgsbyte"
           : w == 2 ? "__readgsword"
           : w == 4 ? "__readgsdword"
                    : "__readgsqword";
}

// A frame slot read: a saved register coming back, a parameter's home or stack slot,
// or a local variable, at the width the instruction read it.
// The name a frame slot prints as, and the width that name stands for: its own name,
// or base[k] when it is an element of a frame array.
static const char *slot_ref(dx_fn_t *x, const dx_slot_t *sl, int32_t off, uint8_t *ew) {
    const dx_slot_t *b = sl->elem ? dx_slot(x, sl->abase, false) : sl;
    if (b && b->idx_w) {
        *ew = b->idx_w;
        return dx_text(x->a, DX_P_PRIMARY, b->idx_w, "%s[%d]", dx_slot_name(x, b->off),
                       (int)((off - b->off) / b->idx_w))
            .s;
    }
    *ew = sl->w;
    return dx_slot_name(x, off);
}

static bool load_slot(dx_em_t *e, int32_t off, uint8_t w, dx_val_t *out) {
    dx_fn_t *x = e->x;
    dx_slot_t *sl = dx_slot(x, off, false);
    int32_t first = x->cc == RE_CC_SYSV ? 8 : 0x28;
    if (!sl)
        return false;
    if (sl->save && !sl->wr_other) {
        *out = dx_text(x->a, DX_P_PRIMARY, 8, "%s", dx_reg_name(x, sl->save - 1u, 8));
        out->ent = sl->save;
        return true;
    }
    if (sl->home && !sl->wr_other && sl->home <= x->nparams) {
        *out = dx_text(x->a, DX_P_PRIMARY, x->pw[sl->home - 1], "a%u", sl->home);
        return true;
    }
    sl->used = off < first;
    uint8_t sw = sl->w;
    const char *n = slot_ref(x, sl, off, &sw);
    if (w == sw || off >= first)
        *out = dx_text(x->a, DX_P_PRIMARY, w, "%s", n);
    else if (w < sw)
        *out = dx_text(x->a, DX_P_UNARY, w, "(%s)%s", dx_type(w, false), n);
    else
        *out = dx_text(x->a, DX_P_UNARY, w, "*(%s *)&%s", dx_type(w, false), n);
    out->mem = true;
    return true;
}

// base[i] for an access at base + i * w whose element width is the access width: a
// global table, or an array in the frame. NULL when the address has no such form.
static const char *indexed(dx_em_t *e, const dx_val_t *a, uint8_t w) {
    dx_fn_t *x = e->x;
    if (!a->arr || a->ask != w || !a->aidx)
        return NULL;
    if (!a->astk)
        return dx_text(x->a, DX_P_PRIMARY, w, "%s[%s]",
                       dx_global_name(x, (uint64_t)a->abase, w, true), a->aidx)
            .s;
    const dx_slot_t *sl = dx_slot(x, a->aoff, false);
    if (!sl || sl->idx_w != w)
        return NULL;
    return dx_text(x->a, DX_P_PRIMARY, w, "%s[%s]", dx_slot_name(x, a->aoff), a->aidx).s;
}

void dx_op_load(dx_em_t *e, const re_ir_op_t *op) {
    dx_fn_t *x = e->x;
    uint8_t w = (uint8_t)op->out.size;
    dx_val_t v;
    dx_sv_t s = dx_frame_eval(x, &e->fr, op->in[0]);
    if (op->in[0].space == RE_SPACE_IOP) {
        v = dx_text(x->a, DX_P_PRIMARY, w, "%s(0x%X)", gs_name(w), (unsigned)op->in[0].offset);
        v.mem = true;
    } else if (!(s.stk && load_slot(e, s.off, w, &v))) {
        dx_val_t a = dx_read(e, op->in[0], 8, false);
        const char *ix = indexed(e, &a, w);
        if (ix)
            v = dx_text(x->a, DX_P_PRIMARY, w, "%s", ix);
        else if (a.cst && w <= 8)
            v = dx_text(x->a, DX_P_PRIMARY, w, "%s", dx_global_name(x, (uint64_t)a.c, w, true));
        else
            v = dx_text(x->a, DX_P_UNARY, w, "*(%s *)%s", dx_type(w, false),
                        dx_paren(x, &a, DX_P_UNARY));
        v = dx_mix(e, v, &a, NULL);
        v.mem = true;
    }
    v.w = v.nw = w;
    dx_def_any(e, op->out, v);
}

// A store into the frame: an outgoing argument the next call takes, a register save or
// a parameter home the prologue makes (both invisible), or an assignment to a local.
static bool store_slot(dx_em_t *e, int32_t off, uint8_t w, dx_val_t val) {
    dx_fn_t *x = e->x;
    dx_slot_t *sl = dx_slot(x, off, false);
    int32_t first = x->cc == RE_CC_SYSV ? 8 : 0x28;
    if (!sl)
        return false;
    if (sl->outarg && e->nout < 16) {
        e->outv[e->nout] = val;
        e->outoff[e->nout++] = off;
        return true;
    }
    if ((sl->save && val.ent == sl->save) ||
        (sl->home && val.ent && dx_arg_pos(x, val.ent - 1u) == (int)sl->home - 1))
        return true;
    dx_flush_mem(e);
    sl->used = off < first;
    uint8_t sw = sl->w;
    const char *n = slot_ref(x, sl, off, &sw);
    if (w == sw || off >= first)
        dx_stmt(e, "%s = %s;", n, dx_at_width(x, &val, w, false));
    else
        dx_stmt(e, "*(%s *)&%s = %s;", dx_type(w, false), n, dx_at_width(x, &val, w, false));
    return true;
}

void dx_op_store(dx_em_t *e, const re_ir_op_t *op) {
    dx_fn_t *x = e->x;
    uint8_t w = (uint8_t)op->in[0].size;
    dx_val_t val = dx_get_any(e, op->in[1], w, false);
    dx_sv_t s = dx_frame_eval(x, &e->fr, op->in[2]);
    if (s.stk && store_slot(e, s.off, w, val))
        return;
    dx_val_t a = dx_read(e, op->in[2], 8, false);
    dx_flush_mem(e);
    if (op->in[2].space == RE_SPACE_IOP)
        dx_stmt(e, "__writegs%s(0x%X, %s);",
                w == 8   ? "qword"
                : w == 4 ? "dword"
                         : "byte",
                (unsigned)op->in[2].offset, dx_str(x, &val));
    else if (indexed(e, &a, w))
        dx_stmt(e, "%s = %s;", indexed(e, &a, w), dx_at_width(x, &val, w, false));
    else if (a.cst)
        dx_stmt(e, "%s = %s;", dx_global_name(x, (uint64_t)a.c, w, true),
                dx_at_width(x, &val, w, false));
    else
        dx_stmt(e, "*(%s *)%s = %s;", dx_type(w, false), dx_paren(x, &a, DX_P_UNARY),
                dx_at_width(x, &val, w, false));
}
