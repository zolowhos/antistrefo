// re_x64_lower2.c - the second integer tranche of the x86-64 lowering.
// Module: feature (C11).
// Owns: the shared helpers, the shifts, muldiv, the stack forms, and map zero.
// Depends: re_x64_priv.h. Every form refuses rather than guesses: an operand
//           shape this file does not model comes back false, and the emitter
//           prints the instruction as a comment instead of a wrong statement.
#include "features/disasm/re_x64_priv.h"

#include "features/dec/re_ir.h"

// Read the r/m operand as a value. A register is its own varnode; a memory
// operand is a load, because every later statement names a value the reader
// can see rather than an address the value sat at.
bool x64_ld_read_rm(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, uint16_t size,
                    re_varnode_t *out) {
    re_varnode_t addr;
    re_ir_op_t o;
    if (!in->is_mem) {
        *out = x64_lower_rm(in);
        return true;
    }
    if (!x64_lower_addr(f, a, in, &addr))
        return false;
    o = x64_lower_mk(RE_OP_LOAD);
    o.out = x64_lower_uniq(f, size);
    *out = o.out;
    o.in[0] = addr;
    return x64_lower_push(f, a, o);
}

// Write a value back to a memory r/m. Register destinations are written by the
// operation itself, so this is only ever called for the memory ones.
bool x64_ld_store_rm(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, re_varnode_t val) {
    re_varnode_t addr;
    re_ir_op_t o;
    if (!x64_lower_addr(f, a, in, &addr))
        return false;
    o = x64_lower_mk(RE_OP_STORE);
    o.in[0] = x64_lower_rm(in);
    o.in[1] = val;
    o.in[2] = addr;
    return x64_lower_push(f, a, o);
}

// Read, operate, write back: the shared shape of every rmw form. The varnode
// holding the result comes back for the flag writer that follows.
static bool rmw2(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, re_op_kind_t kind,
                 re_varnode_t second, re_varnode_t *out_result) {
    uint16_t sz = x64_lower_osize(in);
    re_varnode_t val;
    re_ir_op_t o;
    if (!x64_ld_read_rm(f, a, in, sz, &val))
        return false;
    o = x64_lower_mk(kind);
    o.out = in->is_mem ? x64_lower_uniq(f, sz) : val;
    o.in[0] = val;
    o.in[1] = second;
    if (!x64_lower_push(f, a, o))
        return false;
    *out_result = o.out;
    if (in->is_mem && !x64_ld_store_rm(f, a, in, o.out))
        return false;
    return true;
}

// One op into a register destination, with the result varnode handed back. The
// shape every unary and three operand form lands in, shared with the other
// lowering files.
bool x64_ld_form2(re_ir_func_t *f, re_arena_t *a, re_op_kind_t kind, re_varnode_t dst,
                  re_varnode_t a0, re_varnode_t b0, re_varnode_t *result) {
    re_ir_op_t o = x64_lower_mk(kind);
    o.out = dst;
    o.in[0] = a0;
    o.in[1] = b0;
    *result = dst;
    return x64_lower_push(f, a, o);
}

// An instruction the architecture knows to do nothing: the nop forms, the hint
// nops, endbr. It emits one op so the scoreboard counts it as modelled, and the
// emitter prints nothing for it.
bool x64_ld_nop(re_ir_func_t *f, re_arena_t *a) {
    return x64_lower_push(f, a, x64_lower_mk(RE_OP_NOP));
}

bool x64_ld_int(re_ir_func_t *f, re_arena_t *a, int64_t v) {
    re_ir_op_t o = x64_lower_mk(RE_OP_INT);
    o.const_val = v;
    return x64_lower_push(f, a, o);
}

// The shift and rotate group: C0, C1, D0, D1, D2 and D3. The reg field picks
// the operation and the count is an immediate or CL. Carry rotations read CF,
// which is the one flag read on this path.
static bool lower_rclrcr(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, re_varnode_t count,
                         bool left) {
    uint16_t sz = x64_lower_osize(in);
    re_varnode_t val, res;
    re_ir_op_t o;
    if (!x64_ld_read_rm(f, a, in, sz, &val))
        return false;
    o = x64_lower_mk(left ? RE_OP_ROL : RE_OP_ROR);
    o.out = in->is_mem ? x64_lower_uniq(f, sz) : val;
    o.in[0] = val;
    o.in[1] = count;
    o.in[2] = x64_flag_vn(RE_FLAG_CF);
    if (!x64_lower_push(f, a, o))
        return false;
    res = o.out;
    if (in->is_mem && !x64_ld_store_rm(f, a, in, res))
        return false;
    return x64_flags_result(f, a, RE_SETF_SHIFT, res);
}

static bool lower_shiftgrp(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in,
                           re_varnode_t count) {
    re_varnode_t result;
    re_op_kind_t kind;
    switch (in->reg & 7u) {
        case 0:
            kind = RE_OP_ROL;
            break;
        case 1:
            kind = RE_OP_ROR;
            break;
        case 2:
        case 3:
            return lower_rclrcr(f, a, in, count, (in->reg & 7u) == 2);
        case 4:
        case 6:
            kind = RE_OP_INTSHL;
            break;
        case 5:
            kind = RE_OP_INTSHR;
            break;
        case 7:
            kind = RE_OP_INTSAR;
            break;
        default:
            return false;
    }
    if (!rmw2(f, a, in, kind, count, &result))
        return false;
    return x64_flags_result(f, a, RE_SETF_SHIFT, result);
}

// The count operand of the shift group: an immediate, a one, or CL.
static bool shift_count(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, re_varnode_t *out) {
    unsigned op = RE_INSN_OPCODE(in);
    if (op == 0xC0 || op == 0xC1)
        return x64_lower_imm(f, a, in->imm, out);
    if (op == 0xD0 || op == 0xD1)
        return x64_lower_imm(f, a, 1, out);
    *out = re_ir_vn(RE_SPACE_REG, 1, 1);
    return true;
}

// Multiply and divide. The one operand forms write the register pair, so the
// high half comes first and reads the value the low half is about to overwrite.
// The divide forms keep the dividend in a temporary so the remainder statement
// reads what was divided, not the quotient.
static bool lower_muldiv(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in) {
    unsigned sel = in->reg & 7u;
    uint16_t sz = x64_lower_osize(in);
    re_varnode_t val, lo, hi, orig;
    re_ir_op_t o;
    if (sel <= 3)
        return false; // test, not and neg have their own paths
    if (!x64_ld_read_rm(f, a, in, sz, &val))
        return false;
    lo = re_ir_vn(RE_SPACE_REG, sz, 0);
    hi = re_ir_vn(RE_SPACE_REG, sz, sz == 1 ? 4 : 2);
    if (sel == 4 || sel == 5) {
        o = x64_lower_mk(sel == 4 ? RE_OP_UMULH : RE_OP_IMULH);
        o.out = hi;
        o.in[0] = lo;
        o.in[1] = val;
        if (!x64_lower_push(f, a, o))
            return false;
        o = x64_lower_mk(RE_OP_INTMUL);
        o.out = lo;
        o.in[0] = lo;
        o.in[1] = val;
        return x64_lower_push(f, a, o);
    }
    o = x64_lower_mk(RE_OP_VAR);
    o.out = orig = x64_lower_uniq(f, sz);
    o.in[0] = lo;
    if (!x64_lower_push(f, a, o))
        return false;
    o = x64_lower_mk(sel == 6 ? RE_OP_INTUDIV : RE_OP_INTDIV);
    o.out = lo;
    o.in[0] = orig;
    o.in[1] = val;
    if (!x64_lower_push(f, a, o))
        return false;
    o = x64_lower_mk(sel == 6 ? RE_OP_INTUMOD : RE_OP_INTMOD);
    o.out = hi;
    o.in[0] = orig;
    o.in[1] = val;
    return x64_lower_push(f, a, o);
}

static bool lower_incdec(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, bool inc) {
    re_varnode_t one, result;
    if (!x64_lower_imm(f, a, 1, &one))
        return false;
    if (!rmw2(f, a, in, inc ? RE_OP_INTADD : RE_OP_INTSUB, one, &result))
        return false;
    return x64_flags_result(f, a, RE_SETF_INCDEC, result);
}

static bool lower_notneg(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, bool neg) {
    re_varnode_t result;
    if (!rmw2(f, a, in, neg ? RE_OP_INTNEG : RE_OP_BITNOT, re_ir_vn(RE_SPACE_UNIQUE, 0, 0),
              &result))
        return false;
    if (!neg)
        return true;
    return x64_flags_result(f, a, RE_SETF_NEG, result);
}

// A register to register exchange: three copies through a temporary, which is
// what the printed statements show and what the hardware does in one.
static bool xchg_regs(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, unsigned b) {
    uint16_t sz = x64_lower_osize(in);
    re_varnode_t t = x64_lower_uniq(f, sz);
    re_ir_op_t o;
    o = x64_lower_mk(RE_OP_VAR);
    o.out = t;
    o.in[0] = re_ir_vn(RE_SPACE_REG, sz, (uint16_t)b);
    if (!x64_lower_push(f, a, o))
        return false;
    o.out = re_ir_vn(RE_SPACE_REG, sz, (uint16_t)b);
    o.in[0] = re_ir_vn(RE_SPACE_REG, sz, in->reg);
    if (!x64_lower_push(f, a, o))
        return false;
    o.out = re_ir_vn(RE_SPACE_REG, sz, in->reg);
    o.in[0] = t;
    return x64_lower_push(f, a, o);
}

static bool xchg_mem(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in) {
    uint16_t sz = x64_lower_osize(in);
    re_varnode_t addr, t;
    re_ir_op_t o;
    if (!x64_lower_addr(f, a, in, &addr))
        return false;
    o = x64_lower_mk(RE_OP_LOAD);
    o.out = t = x64_lower_uniq(f, sz);
    o.in[0] = addr;
    if (!x64_lower_push(f, a, o))
        return false;
    o = x64_lower_mk(RE_OP_STORE);
    o.in[0] = x64_lower_rm(in);
    o.in[1] = re_ir_vn(RE_SPACE_REG, sz, in->reg);
    o.in[2] = addr;
    if (!x64_lower_push(f, a, o))
        return false;
    o = x64_lower_mk(RE_OP_VAR);
    o.out = re_ir_vn(RE_SPACE_REG, sz, in->reg);
    o.in[0] = t;
    return x64_lower_push(f, a, o);
}

static bool lower_xchg(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in) {
    if (!in->is_mem)
        return xchg_regs(f, a, in, in->rm);
    return xchg_mem(f, a, in);
}

// The stack forms. A push subtracts the width from rsp and stores; a pop loads
// and adds: printed, the exact sequence the hardware performs.
static bool push_val(re_ir_func_t *f, re_arena_t *a, re_varnode_t val, uint16_t sz) {
    re_varnode_t width;
    re_ir_op_t o;
    if (!x64_lower_imm(f, a, sz, &width))
        return false;
    o = x64_lower_mk(RE_OP_INTSUB);
    o.out = re_ir_vn(RE_SPACE_REG, 8, 4);
    o.in[0] = o.out;
    o.in[1] = width;
    if (!x64_lower_push(f, a, o))
        return false;
    o = x64_lower_mk(RE_OP_STORE);
    o.in[0] = re_ir_vn(RE_SPACE_HEAP, sz, 0);
    o.in[1] = val;
    o.in[2] = re_ir_vn(RE_SPACE_REG, 8, 4);
    return x64_lower_push(f, a, o);
}

static bool lower_push(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in) {
    uint16_t sz = x64_lower_osize(in);
    unsigned op = RE_INSN_OPCODE(in);
    re_varnode_t val;
    if (op == 0x68 || op == 0x6A)
        return x64_lower_imm(f, a, in->imm, &val) && push_val(f, a, val, sz);
    if (op >= 0x50 && op <= 0x57)
        val = re_ir_vn(RE_SPACE_REG, sz, (op & 7u) + ((in->rex & 1u) ? 8u : 0u));
    else if (!x64_ld_read_rm(f, a, in, sz, &val))
        return false;
    return push_val(f, a, val, sz);
}

static bool lower_pop(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in) {
    uint16_t sz = x64_lower_osize(in);
    unsigned op = RE_INSN_OPCODE(in);
    re_varnode_t val, width;
    re_ir_op_t o;
    if (in->is_mem)
        val = x64_lower_uniq(f, sz);
    else if (op == 0x8F)
        val = re_ir_vn(RE_SPACE_REG, sz, in->rm);
    else
        val = re_ir_vn(RE_SPACE_REG, sz, (op & 7u) + ((in->rex & 1u) ? 8u : 0u));
    o = x64_lower_mk(RE_OP_LOAD);
    o.out = val;
    o.in[0] = re_ir_vn(RE_SPACE_REG, 8, 4);
    if (!x64_lower_push(f, a, o))
        return false;
    if (in->is_mem && !x64_ld_store_rm(f, a, in, val))
        return false;
    if (!x64_lower_imm(f, a, sz, &width))
        return false;
    o = x64_lower_mk(RE_OP_INTADD);
    o.out = re_ir_vn(RE_SPACE_REG, 8, 4);
    o.in[0] = o.out;
    o.in[1] = width;
    return x64_lower_push(f, a, o);
}

// A widening: movzx, movsx, movsxd and the accumulator sign extensions. The
// memory source is loaded first at its own narrow width, which is what makes
// the printed cast tell the truth about the value that was widened.
bool x64_ld_extend(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, bool sgn, uint16_t srcw) {
    re_varnode_t val;
    re_ir_op_t o = x64_lower_mk(RE_OP_CAST);
    // The source is read at its own width and the destination is written at the
    // operand size. x64_lower_osize answers the source width for these opcodes, so
    // neither side can come from it: that made movzx eax, byte write a byte.
    if (!in->is_mem)
        val = re_ir_vn(RE_SPACE_REG, srcw, in->rm);
    else if (!x64_ld_read_rm(f, a, in, srcw, &val))
        return false;
    o.out = re_ir_vn(RE_SPACE_REG, in->opsize, in->reg);
    o.in[0] = val;
    o.const_val = srcw;
    if (sgn)
        o.extra = RE_CAST_SIGNED;
    return x64_lower_push(f, a, o);
}

// The accumulator sign extensions: 98 widens the low half of rax into rax and
// 99 copies the sign of rax into rdx. Both are casts between the two halves.
// cbw, cwde and cdqe widen the low half of the accumulator into all of it.
static bool lower_acc_extend(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in) {
    uint16_t sz = x64_lower_osize(in);
    re_ir_op_t o = x64_lower_mk(RE_OP_CAST);
    o.out = re_ir_vn(RE_SPACE_REG, sz, 0);
    o.in[0] = re_ir_vn(RE_SPACE_REG, (uint16_t)(sz / 2), 0);
    o.const_val = sz / 2;
    o.extra = RE_CAST_SIGNED;
    return x64_lower_push(f, a, o);
}

// cwd, cdq and cqo fill the data register with the accumulator's sign bit: the high
// half of the double width value a signed division then takes.
static bool lower_acc_sign(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in) {
    uint16_t sz = x64_lower_osize(in);
    re_varnode_t k;
    if (!x64_lower_imm(f, a, (int64_t)sz * 8 - 1, &k))
        return false;
    re_ir_op_t o = x64_lower_mk(RE_OP_INTSAR);
    o.out = re_ir_vn(RE_SPACE_REG, sz, 2);
    o.in[0] = re_ir_vn(RE_SPACE_REG, sz, 0);
    o.in[1] = k;
    return x64_lower_push(f, a, o);
}

// The ModRM forms of the map zero tranche: the F6 and F7 group, the inc and
// dec group, the stack forms, the exchanges and the widening moves.
static bool lower2_modrm(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, unsigned op) {
    unsigned sel = in->reg & 7u;
    if (op == 0xF6 || op == 0xF7) {
        if (sel == 2)
            return lower_notneg(f, a, in, false);
        if (sel == 3)
            return lower_notneg(f, a, in, true);
        if (sel >= 4)
            return lower_muldiv(f, a, in);
        return false;
    }
    if (op == 0xFE || op == 0xFF) {
        if (sel <= 1)
            return lower_incdec(f, a, in, sel == 0);
        if (op == 0xFF && sel == 6)
            return lower_push(f, a, in);
        return false;
    }
    if (op == 0x8F)
        return lower_pop(f, a, in);
    if (op >= 0x50 && op <= 0x57)
        return lower_push(f, a, in);
    if (op >= 0x58 && op <= 0x5F)
        return lower_pop(f, a, in);
    if (op >= 0x40 && op <= 0x4F)
        return lower_incdec(f, a, in, op < 0x48);
    if (op == 0x86 || op == 0x87)
        return lower_xchg(f, a, in);
    if (op == 0x63) // movsxd: map zero, not 0F 63, which is packsswb
        return x64_ld_extend(f, a, in, true, 4);
    if (op == 0x98)
        return lower_acc_extend(f, a, in);
    if (op == 0x99)
        return lower_acc_sign(f, a, in);
    if (op == 0x69 || op == 0x6B) {
        re_varnode_t imm, val;
        if (!x64_lower_imm(f, a, in->imm, &imm))
            return false;
        if (!x64_ld_read_rm(f, a, in, x64_lower_osize(in), &val))
            return false;
        return x64_ld_form2(f, a, RE_OP_INTMUL, x64_lower_reg(in, in->reg), val, imm, &val);
    }
    return false;
}

// The map zero tranche: everything the integer block and the forms above did
// not claim. The flag only instructions (clc, stc, cli and friends) stay
// unmodelled on purpose: a wrong flag write would be worse than a comment.
bool x64_lower2(const re_insn_t *in, re_ir_func_t *f, re_arena_t *a) {
    unsigned op = RE_INSN_OPCODE(in);
    re_varnode_t count;
    if (RE_INSN_MAP(in) != 0 || !x64_lower_uniq_ok(f))
        return false;
    if (op == 0x90)
        return x64_ld_nop(f, a); // nop, and pause under F3: both do nothing
    if (op >= 0x91 && op <= 0x97)
        return xchg_regs(f, a, in, (op & 7u) + ((in->rex & 1u) ? 8u : 0u));
    if (op == 0xC0 || op == 0xC1 || op == 0xD0 || op == 0xD1 || op == 0xD2 || op == 0xD3) {
        if (!shift_count(f, a, in, &count))
            return false;
        return lower_shiftgrp(f, a, in, count);
    }
    // The carry forms and the test with an immediate belong to lower3, which
    // also holds the map one tranche; everything below stays here.
    if ((op >= 0x10 && op <= 0x15) || (op >= 0x18 && op <= 0x1D) ||
        (op >= 0x80 && op <= 0x83 && ((in->reg & 7u) == 2u || (in->reg & 7u) == 3u)) ||
        ((op == 0xF6 || op == 0xF7) && (in->reg & 7u) == 0u))
        return x64_lower3_map0(in, f, a);
    if (op == 0xCD)
        return x64_ld_int(f, a, in->imm);
    return lower2_modrm(f, a, in, op);
}
