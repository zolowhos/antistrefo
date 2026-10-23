// re_constprop.c - constant and copy propagation over one function's IR.
// Module: feature (C11).
// Owns: the value tables, the folding rules, and the opaque predicate decision.
// Depends: re_flow.h, re_ir. Only full eight byte register states are tracked,
//           because a four byte write leaves the high half architecturally
//           defined and folding through it would print a wrong value.
#include "features/flow/re_flow.h"

#include <string.h>

// One tracked location. A location is a register or a constant id, keyed the
// same way the SSA pass keys definitions so the two passes describe one state.
// A cell that is not known says nothing: the pass never invents a value.
typedef struct {
    int64_t val;   // the known value, when gen is current
    uint32_t gen;  // the block the value was written in; any other block reads unknown
    uint8_t space; // re_space_t provenance of the tracked location
} cell_t;

// Forgetting everything at a block start is a new generation, not a cleared table:
// clearing all the cells for every block was the pass's whole cost.
typedef struct {
    cell_t cell[RE_FLOW_MAX_KEYS];
    re_flow_stat_t *st;
    uint32_t gen; // the current block's generation, never 0
} env_t;

static bool known(const env_t *e, uint32_t k) {
    return e->cell[k].gen == e->gen;
}

// A constant operand is recorded under a unique id rather than in a register,
// and the emitter resolves it by that id, so the table indexes the id directly.
// An id past the bound was never minted into the table, so it names nothing.
static bool const_known(const env_t *e, const re_varnode_t *vn, int64_t *out) {
    // Constant ids share the table with the register band above RE_FLOW_REG_BASE,
    // so an id at or past the band names nothing here rather than a register.
    if (vn->offset >= RE_FLOW_REG_BASE || !known(e, vn->offset))
        return false;
    *out = e->cell[vn->offset].val;
    return true;
}

static void put(env_t *e, uint32_t k, int64_t v) {
    if (k >= RE_FLOW_REG_BASE)
        return;
    e->cell[k].val = v;
    e->cell[k].space = 0xFF; // the constant tables provenance marker
    e->cell[k].gen = e->gen;
}

static void put_reg(env_t *e, uint32_t k, uint16_t off, int64_t v) {
    if (k >= RE_FLOW_MAX_KEYS || off >= RE_FLOW_MAX_KEYS)
        return;
    e->cell[k].val = v;
    e->cell[k].space = RE_SPACE_REG;
    e->cell[k].gen = e->gen;
}

static void kill(env_t *e, uint32_t k) {
    if (k < RE_FLOW_MAX_KEYS)
        e->cell[k].gen = 0;
}

static uint32_t reg_key(uint16_t off) {
    return RE_FLOW_REG_BASE + (uint32_t)off;
}

// The value of an input varnode, when the pass can name it. A register is
// known when the last full write to it was tracked; a constant or a temporary
// is known when the op that defined it was seen, because both live in the same
// id table the lowering mints them into; anything else has no value here.
static bool get(env_t *e, const re_varnode_t *vn, int64_t *out) {
    uint32_t k;
    if (!e || !out)
        return false;
    if (vn->space == RE_SPACE_CONST || vn->space == RE_SPACE_UNIQUE)
        return const_known(e, vn, out);
    if (vn->space != RE_SPACE_REG || vn->size != 8)
        return false;
    k = reg_key(vn->offset);
    if (k >= RE_FLOW_MAX_KEYS || !known(e, k) || e->cell[k].space != RE_SPACE_REG)
        return false;
    *out = e->cell[k].val;
    return true;
}

static void count(env_t *e, size_t *which, size_t n) {
    if (!e->st || !which)
        return;
    *which += n;
}

// The folding rules: the ops with two known inputs whose result is exactly
// the C expression their printed form claims. Divisions and shifts by zero
// are not folded, because the trap they would raise is a behaviour the pass
// has no business deciding.
static bool fold_bin(re_op_kind_t k, int64_t a, int64_t b, int64_t *out) {
    switch (k) {
        case RE_OP_INTADD:
            *out = (int64_t)((uint64_t)a + (uint64_t)b);
            return true;
        case RE_OP_INTSUB:
            *out = (int64_t)((uint64_t)a - (uint64_t)b);
            return true;
        case RE_OP_INTMUL:
            *out = (int64_t)((uint64_t)a * (uint64_t)b);
            return true;
        case RE_OP_INTAND:
            *out = a & b;
            return true;
        case RE_OP_INTOR:
            *out = a | b;
            return true;
        case RE_OP_INTXOR:
            *out = a ^ b;
            return true;
        case RE_OP_INTSHL:
            if (b < 0 || b > 63)
                return false;
            *out = (int64_t)((uint64_t)a << (unsigned)b);
            return true;
        case RE_OP_INTSHR:
            if (b < 0 || b > 63)
                return false;
            *out = (int64_t)((uint64_t)a >> (unsigned)b);
            return true;
        case RE_OP_INTSAR:
            if (b < 0 || b > 63)
                return false;
            *out = a >> (unsigned)b;
            return true;
        default:
            return false;
    }
}

// A comparison with both sides known, evaluated instead of printed. The
// signed and unsigned pairs differ in how they read the operands, and folding
// the wrong one is a wrong branch. Only the writer's own condition set is
// honoured: a source or destination flag condition the comparison cannot
// decide is left for the branch to print as the named flag it is.
static bool fold_cmp(unsigned cc, int64_t a, int64_t b, bool *out) {
    switch (cc) {
        case RE_CC_JE:
            *out = a == b;
            return true;
        case RE_CC_JNE:
            *out = a != b;
            return true;
        case RE_CC_JB:
            *out = (uint64_t)a < (uint64_t)b;
            return true;
        case RE_CC_JAE:
            *out = (uint64_t)a >= (uint64_t)b;
            return true;
        case RE_CC_JBE:
            *out = (uint64_t)a <= (uint64_t)b;
            return true;
        case RE_CC_JA:
            *out = (uint64_t)a > (uint64_t)b;
            return true;
        case RE_CC_JL:
            *out = a < b;
            return true;
        case RE_CC_JGE:
            *out = a >= b;
            return true;
        case RE_CC_JLE:
            *out = a <= b;
            return true;
        case RE_CC_JG:
            *out = a > b;
            return true;
        default:
            return false;
    }
}

// The flag writer a test leaves behind decides zero and sign of the bitwise
// and, which is all the branch after it can read from it.
static bool fold_test(unsigned cc, int64_t a, int64_t b, bool *out) {
    int64_t m = a & b;
    switch (cc) {
        case RE_CC_JE:
            *out = m == 0;
            return true;
        case RE_CC_JNE:
            *out = m != 0;
            return true;
        case RE_CC_JS:
            *out = m < 0;
            return true;
        case RE_CC_JNS:
            *out = m >= 0;
            return true;
        default:
            return false;
    }
}

// A full eight byte register write records the value; a smaller write kills
// the cell, because the upper half stays architecturally defined and a fold
// that ignored it would print a value the machine never held.
static void track_out(env_t *e, const re_ir_op_t *op) {
    int64_t r;
    // An op with a zero sized out defines nothing: the comparison and the
    // branches carry a zeroed destination, and tracking it would write cell
    // zero with a value no instruction produced.
    if (op->out.size == 0)
        return;
    if (op->out.space == RE_SPACE_CONST) {
        if (op->out.offset < RE_FLOW_MAX_KEYS)
            put(e, op->out.offset, op->const_val);
        return;
    }
    if (op->out.space == RE_SPACE_UNIQUE) {
        if (op->op == RE_OP_CONST && op->out.offset < RE_FLOW_MAX_KEYS)
            put(e, op->out.offset, op->const_val);
        return;
    }
    if (op->out.space != RE_SPACE_REG)
        return;
    if (op->op == RE_OP_CONST) {
        int64_t v = op->const_val;
        if (op->out.size == 8)
            put_reg(e, reg_key(op->out.offset), op->out.offset, v);
        else if (op->out.size == 4)
            put_reg(e, reg_key(op->out.offset), op->out.offset, (int64_t)(uint32_t)(uint64_t)v);
        else
            kill(e, reg_key(op->out.offset));
        return;
    }
    if (op->op == RE_OP_VAR && op->out.size == 8 && get(e, &op->in[0], &r)) {
        put_reg(e, reg_key(op->out.offset), op->out.offset, r);
        return;
    }
    kill(e, reg_key(op->out.offset));
}

// Rewrite one op in place when both inputs are known and the op folds. Only a
// temporary destination is rewritten: a register destination would have to
// become a constant op shaped in a way the lowering never produces, and the
// emitter resolves constants through a table the shape would corrupt. The
// tracker still records the register's value, which is what the predicate
// decision reads, so the fold is a printing choice and not a knowledge limit.
static void try_fold(env_t *e, re_ir_op_t *op) {
    int64_t a, b, r;
    if (op->out.space != RE_SPACE_UNIQUE)
        return;
    if (op->op != RE_OP_INTADD && op->op != RE_OP_INTSUB && op->op != RE_OP_INTMUL &&
        op->op != RE_OP_INTAND && op->op != RE_OP_INTOR && op->op != RE_OP_INTXOR &&
        op->op != RE_OP_INTSHL && op->op != RE_OP_INTSHR && op->op != RE_OP_INTSAR)
        return;
    if (!get(e, &op->in[0], &a) || !get(e, &op->in[1], &b))
        return;
    if (!fold_bin(op->op, a, b, &r))
        return;
    op->op = RE_OP_CONST;
    op->const_val = r;
    op->extra = 0;
    op->in[0] = op->in[1] = op->in[2] = re_ir_vn(0xFF, 0, 0);
    count(e, &e->st->n_const, 1);
}

// One opaque predicate: the comparison is the op immediately before the
// branch, both its operands are known, and the condition folds to a fact.
// The branch becomes the unconditional jump it always ran as, or nothing at
// all when the taken side never executes.
static void try_pred(env_t *e, const re_ir_op_t *cmp, re_ir_op_t *br) {
    int64_t a, b;
    bool res;
    unsigned cbr;
    if (!cmp || !br || cmp->op != RE_OP_CMP)
        return;
    if (cmp->extra != RE_SETF_CMP && cmp->extra != RE_SETF_TEST)
        return;
    if (!get(e, &cmp->in[0], &a) || !get(e, &cmp->in[1], &b))
        return;
    cbr = br->extra;
    if (cmp->extra == RE_SETF_CMP ? !fold_cmp(cbr, a, b, &res) : !fold_test(cbr, a, b, &res))
        return;
    if (res) {
        br->op = RE_OP_BRANCH;
        br->extra = 0;
    } else {
        br->op = RE_OP_NOP;
    }
    count(e, &e->st->n_pred, 1);
}

void re_flow_constprop(re_ir_func_t *f, re_arena_t *a, re_flow_stat_t *st) {
    env_t e;
    const re_ir_op_t *prev = NULL;
    if (!f)
        return;
    (void)a;
    memset(&e, 0, sizeof(e));
    e.st = st;
    for (size_t bi = 0; bi < f->n_blocks; bi++) {
        // A block can be entered from more than one place, so nothing known at the
        // end of the block before it in address order holds at its start. Carrying
        // the table across turned real branches at a join into "opaque predicates".
        if (++e.gen == 0) {
            memset(e.cell, 0, sizeof(e.cell)); // the stamp wrapped: clear once, really
            e.gen = 1;
        }
        prev = NULL;
        for (size_t k = 0; k < f->blocks[bi].n_ops; k++) {
            re_ir_op_t *op = &f->blocks[bi].ops[k];
            try_fold(&e, op);
            track_out(&e, op);
            // The pending comparison must be the op immediately before the
            // branch: the pair is adjacency, not an interval, so nothing can
            // write flags in between and be ignored.
            if (op->op == RE_OP_CBRANCH)
                try_pred(&e, prev, op);
            prev = op;
        }
    }
}
