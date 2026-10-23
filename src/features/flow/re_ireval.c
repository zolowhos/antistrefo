// re_ireval.c - executes one function's IR with a step budget and a memory sandbox.
// Module: feature (C11).
// Owns: the register file, the overlay, and the per op arithmetic.
// Depends: re_ireval.h, re_code. A value is known only when every input was known.
#include "features/flow/re_ireval.h"

#include <string.h>

typedef struct {
    re_ireval_t *e;
    const re_code_t *c;
    uint64_t pc;
    bool taken; // a conditional branch decided its direction
    bool go;    // the direction it decided
} ev_t;

static bool reg_of(const re_varnode_t *v, unsigned *r) {
    if (v->space != RE_SPACE_REG || v->offset >= 16u)
        return false;
    *r = v->offset;
    return true;
}

static bool value_of(const ev_t *x, const re_varnode_t *v, const re_ir_op_t *op, uint64_t *dst) {
    unsigned r;
    if (v->space == RE_SPACE_CONST) {
        *dst = (uint64_t)op->const_val;
        return true;
    }
    if (!reg_of(v, &r) || !x->e->known[r])
        return false;
    *dst = x->e->regs[r];
    return true;
}

static void set_reg(ev_t *x, const re_varnode_t *v, uint64_t val, bool known) {
    unsigned r;
    uint64_t mask;
    if (!reg_of(v, &r))
        return;
    mask = v->size >= 8u ? ~0ull : ((1ull << (v->size * 8u)) - 1u);
    x->e->known[r] = known;
    if (known)
        x->e->regs[r] = v->size >= 4u ? (val & mask) : ((x->e->regs[r] & ~mask) | (val & mask));
}

static uint64_t bin(re_op_kind_t op, uint64_t lhs, uint64_t rhs, uint16_t bits) {
    uint64_t mask = bits >= 64u ? ~0ull : ((1ull << bits) - 1u);
    lhs &= mask;
    rhs &= mask;
    switch (op) {
        case RE_OP_INTADD:
            return (lhs + rhs) & mask;
        case RE_OP_INTSUB:
            return (lhs - rhs) & mask;
        case RE_OP_INTMUL:
            return (lhs * rhs) & mask;
        case RE_OP_INTAND:
            return lhs & rhs;
        case RE_OP_INTOR:
            return lhs | rhs;
        case RE_OP_INTXOR:
            return lhs ^ rhs;
        case RE_OP_INTSHL:
            return rhs >= bits ? 0u : (lhs << rhs) & mask;
        case RE_OP_INTSHR:
            return rhs >= bits ? 0u : lhs >> rhs;
        case RE_OP_ROL:
            rhs &= bits - 1u;
            return bits ? ((lhs << rhs) | (lhs >> (bits - rhs))) & mask : lhs;
        case RE_OP_ROR:
            rhs &= bits - 1u;
            return bits ? ((lhs >> rhs) | (lhs << (bits - rhs))) & mask : lhs;
        default:
            return 0;
    }
}

static bool image_at(const re_code_t *c, uint64_t va, uint64_t *dst, uint16_t size) {
    uint64_t off = 0;
    re_span_t s;
    if (va < c->base || !re_pe_rva2off(c->pe, (uint32_t)(va - c->base), &off))
        return false;
    if (size > 8u || !re_rd(c->img, off, size, &s))
        return false;
    *dst = 0;
    for (uint16_t i = 0; i < size; i++) {
        uint8_t byte = 0;
        re_rd8(s, i, &byte);
        *dst |= (uint64_t)byte << (i * 8u);
    }
    return true;
}

// A store the run already made wins over the image, which is the copy on write.
static bool read_mem(ev_t *x, uint64_t va, uint64_t *dst, uint16_t size) {
    for (uint32_t i = 0; i < x->e->n_writes; i++) {
        if (x->e->waddr[i] == va && x->e->wsize[i] == size) {
            *dst = x->e->wval[i];
            return true;
        }
    }
    return image_at(x->c, va, dst, size);
}

static void write_mem(ev_t *x, uint64_t va, uint64_t val, uint16_t size) {
    for (uint32_t i = 0; i < x->e->n_writes; i++) {
        if (x->e->waddr[i] == va && x->e->wsize[i] == size) {
            x->e->wval[i] = val;
            return;
        }
    }
    if (x->e->n_writes >= RE_IR_WRITES) {
        x->e->stopped = true;
        return;
    }
    x->e->waddr[x->e->n_writes] = va;
    x->e->wval[x->e->n_writes] = val;
    x->e->wsize[x->e->n_writes] = (uint8_t)size;
    x->e->n_writes++;
}

static void do_load(ev_t *x, const re_ir_op_t *op) {
    uint64_t addr = 0;
    uint64_t val = 0;
    bool ok = value_of(x, &op->in[0], op, &addr) && read_mem(x, addr, &val, op->out.size);
    set_reg(x, &op->out, val, ok);
}

static void do_store(ev_t *x, const re_ir_op_t *op) {
    uint64_t addr = 0;
    uint64_t val = 0;
    if (value_of(x, &op->in[0], op, &addr) && value_of(x, &op->in[1], op, &val))
        write_mem(x, addr, val, op->in[1].size ? op->in[1].size : 8u);
}

static void do_bin(ev_t *x, const re_ir_op_t *op) {
    uint64_t a = 0;
    uint64_t b = 0;
    bool ok = value_of(x, &op->in[0], op, &a) && value_of(x, &op->in[1], op, &b);
    set_reg(x, &op->out, ok ? bin(op->op, a, b, (uint16_t)(op->out.size * 8u)) : 0u, ok);
}

static void step_op(ev_t *x, const re_ir_op_t *op) {
    uint64_t v = 0;
    switch (op->op) {
        case RE_OP_CONST:
            set_reg(x, &op->out, (uint64_t)op->const_val, true);
            break;
        case RE_OP_VAR:
            set_reg(x, &op->out, v, value_of(x, &op->in[0], op, &v));
            break;
        case RE_OP_LOAD:
            do_load(x, op);
            break;
        case RE_OP_STORE:
            do_store(x, op);
            break;
        case RE_OP_INTADD:
        case RE_OP_INTSUB:
        case RE_OP_INTMUL:
        case RE_OP_INTAND:
        case RE_OP_INTOR:
        case RE_OP_INTXOR:
        case RE_OP_INTSHL:
        case RE_OP_INTSHR:
        case RE_OP_ROL:
        case RE_OP_ROR:
            do_bin(x, op);
            break;
        case RE_OP_BITNOT:
            set_reg(x, &op->out, value_of(x, &op->in[0], op, &v) ? ~v : 0u,
                    value_of(x, &op->in[0], op, &v));
            break;
        case RE_OP_NOP:
            break;
        default:
            if (op->out.space == RE_SPACE_REG)
                set_reg(x, &op->out, 0, false); // an op this evaluator does not model
            break;
    }
}

// One instruction: lower it, then run its ops. A transfer ends the straight run.
static bool step_insn(ev_t *x, const re_insn_t *in, re_arena_t *mem) {
    const re_disasm_t *dis = x->c->dis;
    re_ir_func_t ir;
    re_ir_func_init(&ir);
    if (!dis || !dis->lower || !re_ir_block_begin(&ir, mem, in->addr, in->size))
        return false;
    dis->lower(dis->ctx, in, &ir, mem);
    re_ir_block_end(&ir);
    if (ir.n_blocks)
        for (size_t k = 0; k < ir.blocks[0].n_ops; k++)
            step_op(x, &ir.blocks[0].ops[k]);
    return true;
}

bool re_ireval_run(const re_code_t *c, const re_func_t *fn, re_arena_t *mem, re_ireval_t *ev) {
    ev_t x;
    memset(ev, 0, sizeof(*ev));
    x.e = ev;
    x.c = c;
    x.pc = fn->va;
    x.taken = false;
    while (ev->steps < RE_IR_STEPS && !ev->stopped) {
        re_insn_t in;
        ev->steps++;
        if (!re_code_insn(c, x.pc, &in) || !in.size)
            break;
        if (!step_insn(&x, &in, mem))
            break;
        if (in.is_return || in.is_call)
            break;
        if (in.is_branch && in.is_conditional) {
            ev->stopped = true; // a branch needs the flags, which this run does not track
            break;
        }
        if (in.is_branch)
            break;
        x.pc += in.size;
    }
    return ev->steps > 1u;
}

bool re_ireval_bytes(const re_ireval_t *e, uint64_t va, uint8_t *dst, size_t n) {
    for (size_t i = 0; i < n; i++) {
        bool found = false;
        for (uint32_t w = 0; w < e->n_writes && !found; w++) {
            if (e->wsize[w] == 1u && e->waddr[w] == va + i) {
                dst[i] = (uint8_t)e->wval[w];
                found = true;
            }
        }
        if (!found)
            return false;
    }
    return n > 0;
}
