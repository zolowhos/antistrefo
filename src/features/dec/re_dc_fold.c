// re_dc_fold.c - turns a register transfer list into the expression it computed.
// Module: feature (C11).
// Owns: copy propagation, dead saves, and the stack-pointer restore fold.
// Depends: re_dc_fold.h. No printing and no allocation; ops are rewritten in place.
#include "features/dec/re_dc_fold.h"

#include <string.h>

static bool same(re_varnode_t a, re_varnode_t b) {
    return a.space == b.space && a.offset == b.offset && a.size == b.size;
}

static void nop(re_ir_op_t *op) {
    memset(op, 0, sizeof(*op));
    op->op = RE_OP_NOP;
}

static re_ir_op_t *at(re_ir_func_t *f, size_t i, size_t *n) {
    size_t bi, k, seen = 0;
    for (bi = 0; bi < f->n_blocks; bi++) {
        if (i < seen + f->blocks[bi].n_ops) {
            *n = 0;
            for (k = 0; k < f->n_blocks; k++)
                *n += f->blocks[k].n_ops;
            return &f->blocks[bi].ops[i - seen];
        }
        seen += f->blocks[bi].n_ops;
    }
    *n = seen;
    return NULL;
}

static bool reads(const re_ir_op_t *op, re_varnode_t v) {
    unsigned i;
    for (i = 0; i < 4; i++) {
        if (same(op->in[i], v))
            return true;
    }
    return false;
}

static void subst_in(re_ir_op_t *op, re_varnode_t from, re_varnode_t to) {
    unsigned i;
    for (i = 0; i < 4; i++) {
        if (same(op->in[i], from))
            op->in[i] = to;
    }
}

// The register an add or sub writes and a store uses as its address. That is the
// stack pointer for this body, whichever number the backend gave it.
static bool find_sp(re_ir_func_t *f, uint16_t *sp) {
    size_t n = 0, i;
    bool saw = false;
    at(f, 0, &n);
    for (i = 0; i < n && !saw; i++) {
        re_ir_op_t *op = at(f, i, &n);
        if (op->op == RE_OP_STORE && op->in[2].space == RE_SPACE_REG) {
            *sp = op->in[2].offset;
            saw = true;
        }
    }
    if (!saw)
        return false;
    for (i = 0; i < n; i++) {
        re_ir_op_t *op = at(f, i, &n);
        if ((op->op == RE_OP_INTADD || op->op == RE_OP_INTSUB) && op->out.space == RE_SPACE_REG &&
            op->out.offset == *sp)
            return true;
    }
    return false;
}

static void kill_sp(re_ir_func_t *f, uint16_t sp) {
    size_t n = 0, i;
    at(f, 0, &n);
    for (i = 0; i < n; i++) {
        re_ir_op_t *op = at(f, i, &n);
        bool arith = op->op == RE_OP_INTADD || op->op == RE_OP_INTSUB || op->op == RE_OP_CAST;
        if (arith && op->out.space == RE_SPACE_REG && op->out.offset == sp)
            nop(op);
        else if (op->in[2].space == RE_SPACE_FLAG && op->out.space == RE_SPACE_REG &&
                 op->out.offset == sp)
            nop(op);
        else if ((op->op == RE_OP_STORE || op->op == RE_OP_LOAD) &&
                 op->in[2].space == RE_SPACE_REG && op->in[2].offset == sp)
            nop(op);
        else if (op->op == RE_OP_LOAD && op->in[0].space == RE_SPACE_REG && op->in[0].offset == sp)
            nop(op);
    }
}

// A stack store of a register whose slot is never loaded is a save that nothing
// reads. A load of a slot into a register that nothing later reads is the matching
// restore. Both are noise, and leaving them in is what declares local_p.
static void kill_saves(re_ir_func_t *f) {
    size_t n = 0, i, j;
    at(f, 0, &n);
    for (i = 0; i < n; i++) {
        re_ir_op_t *op = at(f, i, &n);
        bool loaded = false;
        if (op->op == RE_OP_STORE && op->in[2].space == RE_SPACE_STACK) {
            for (j = i + 1; j < n; j++) {
                if (at(f, j, &n)->op == RE_OP_LOAD && same(at(f, j, &n)->in[0], op->in[2]))
                    loaded = true;
            }
            if (!loaded)
                nop(op);
        }
        if (op->op == RE_OP_LOAD && op->in[0].space == RE_SPACE_STACK &&
            op->out.space == RE_SPACE_REG) {
            bool used = false;
            for (j = i + 1; j < n; j++) {
                if (reads(at(f, j, &n), op->out))
                    used = true;
            }
            if (!used)
                nop(op);
        }
    }
}

static re_varnode_t src_of(re_ir_func_t *f, re_varnode_t v) {
    size_t n = 0, i, guard = 0;
    at(f, 0, &n);
    while (v.space == RE_SPACE_REG && guard++ < 8) {
        bool found = false;
        for (i = 0; i < n; i++) {
            re_ir_op_t *op = at(f, i, &n);
            if (op->op == RE_OP_VAR && same(op->out, v) && op->in[0].space == RE_SPACE_REG) {
                v = op->in[0];
                found = true;
                break;
            }
        }
        if (!found)
            break;
    }
    return v;
}

static void propagate(re_ir_func_t *f) {
    size_t n = 0, i, j;
    at(f, 0, &n);
    for (i = 0; i < n; i++) {
        re_ir_op_t *def = at(f, i, &n);
        re_varnode_t to;
        if (def->op != RE_OP_VAR || def->out.space != RE_SPACE_REG)
            continue;
        if (def->in[0].space != RE_SPACE_REG)
            continue;
        to = src_of(f, def->in[0]);
        for (j = i + 1; j < n; j++)
            subst_in(at(f, j, &n), def->out, to);
        def->in[0] = to;
        def->extra |= RE_FOLD_ALIAS;
    }
}

static bool used_later(re_ir_func_t *f, size_t i, re_varnode_t v) {
    size_t n = 0, j;
    at(f, 0, &n);
    for (j = i + 1; j < n; j++) {
        re_ir_op_t *op = at(f, j, &n);
        if (reads(op, v))
            return true;
        if (same(op->out, v) && op->op != RE_OP_NOP)
            return false;
    }
    return false;
}

static void calls(re_ir_func_t *f) {
    size_t n = 0, i, last = (size_t)-1;
    at(f, 0, &n);
    for (i = 0; i < n; i++) {
        re_ir_op_t *op = at(f, i, &n);
        if (op->op != RE_OP_CALL && op->op != RE_OP_CALLIND)
            continue;
        last = i;
        if (!used_later(f, i, op->out))
            op->extra |= RE_FOLD_STMT;
    }
    if (last == (size_t)-1)
        return;
    for (i = last + 1; i < n; i++) {
        re_ir_op_t *op = at(f, i, &n);
        if (op->op == RE_OP_RETURN && same(op->in[0], at(f, last, &n)->out)) {
            at(f, last, &n)->extra = RE_FOLD_SKIP;
            op->extra |= RE_FOLD_STMT;
            op->const_val = at(f, last, &n)->const_val;
        }
    }
}

static void fold_disp(re_ir_func_t *f) {
    size_t n = 0, i, j, uses;
    at(f, 0, &n);
    for (i = 0; i < n; i++) {
        re_ir_op_t *add = at(f, i, &n);
        re_varnode_t base;
        int64_t disp;
        if (add->op != RE_OP_INTADD && add->op != RE_OP_INTSUB)
            continue;
        if (add->in[1].space != RE_SPACE_CONST && add->in[0].space != RE_SPACE_CONST)
            continue;
        base = add->in[0].space == RE_SPACE_CONST ? add->in[1] : add->in[0];
        disp = add->const_val;
        uses = 0;
        for (j = i + 1; j < n; j++) {
            re_ir_op_t *op = at(f, j, &n);
            if (op->op == RE_OP_LOAD && same(op->in[0], add->out))
                uses++;
            else if (op->op == RE_OP_STORE && same(op->in[2], add->out))
                uses++;
        }
        if (uses != 1)
            continue;
        for (j = i + 1; j < n; j++) {
            re_ir_op_t *op = at(f, j, &n);
            if (op->op == RE_OP_LOAD && same(op->in[0], add->out)) {
                op->in[0] = base;
                op->const_val = disp;
                op->extra |= RE_FOLD_DISP;
            } else if (op->op == RE_OP_STORE && same(op->in[2], add->out)) {
                op->in[2] = base;
                op->const_val = disp;
                op->extra |= RE_FOLD_DISP;
            }
        }
        nop(add);
    }
}

void re_dc_fold(re_ir_func_t *f) {
    uint16_t sp = 0;
    if (!f || !f->n_blocks)
        return;
    if (find_sp(f, &sp))
        kill_sp(f, sp);
    kill_saves(f);
    propagate(f);
    fold_disp(f);
    calls(f);
}
