// re_x64_lower3.c - the carry forms and the map one tranche of the lowering.
// Module: feature (C11).
// Owns: adc and sbb, the test with an immediate, and the 0F map's integers.
// Depends: re_x64_priv.h. The shared helpers live in lower2, the flag model in
//           flags; nothing here re-derives an operand shape.
#include "features/disasm/re_x64_priv.h"

#include "features/dec/re_ir.h"

// The r/m destination form of a carry operation: read, add or subtract with the
// carry, write back, and record the result for the branch that follows.
static bool carry_rm(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, re_op_kind_t kind,
                     unsigned wr, re_varnode_t second) {
    uint16_t sz = x64_lower_osize(in);
    re_varnode_t dst, res;
    re_ir_op_t o;
    if (!x64_ld_read_rm(f, a, in, sz, &dst))
        return false;
    o = x64_lower_mk(kind);
    o.out = in->is_mem ? x64_lower_uniq(f, sz) : dst;
    o.in[0] = dst;
    o.in[1] = second;
    o.in[2] = x64_flag_vn(RE_FLAG_CF);
    if (!x64_lower_push(f, a, o))
        return false;
    res = o.out;
    if (in->is_mem && !x64_ld_store_rm(f, a, in, res))
        return false;
    return x64_flags_result(f, a, wr, res);
}

// adc and sbb: an add or subtract whose second input is the carry the previous
// operation left. The carry read is explicit, so the printed statement is the
// truth, and the result writes the flags through the usual writer record.
static bool lower_carry(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, bool sub) {
    unsigned op = RE_INSN_OPCODE(in);
    re_op_kind_t kind = sub ? RE_OP_INTSUB : RE_OP_INTADD;
    unsigned wr = sub ? RE_SETF_SUB : RE_SETF_ADD;
    uint16_t sz = x64_lower_osize(in);
    re_varnode_t second, dst;
    re_ir_op_t o;
    if (op == 0x14 || op == 0x15 || op == 0x1C || op == 0x1D) {
        // the accumulator forms: no ModRM, the destination is rax by definition
        if (!x64_lower_imm(f, a, in->imm, &second))
            return false;
        dst = re_ir_vn(RE_SPACE_REG, sz, 0);
        o = x64_lower_mk(kind);
        o.out = dst;
        o.in[0] = dst;
        o.in[1] = second;
        o.in[2] = x64_flag_vn(RE_FLAG_CF);
        if (!x64_lower_push(f, a, o))
            return false;
        return x64_flags_result(f, a, wr, dst);
    }
    if (op >= 0x80 && op <= 0x83) {
        // the group form: r/m destination, immediate second operand
        if (!x64_lower_imm(f, a, in->imm, &second))
            return false;
        return carry_rm(f, a, in, kind, wr, second);
    }
    if ((op & 2u) != 0) {
        // 0x12 and 0x13: register destination, the r/m side is the source
        if (!x64_ld_read_rm(f, a, in, sz, &second))
            return false;
        dst = x64_lower_reg(in, in->reg);
        o = x64_lower_mk(kind);
        o.out = dst;
        o.in[0] = dst;
        o.in[1] = second;
        o.in[2] = x64_flag_vn(RE_FLAG_CF);
        if (!x64_lower_push(f, a, o))
            return false;
        return x64_flags_result(f, a, wr, dst);
    }
    // 0x10 and 0x11: r/m destination, register source
    return carry_rm(f, a, in, kind, wr, x64_lower_reg(in, in->reg));
}

// The test with an immediate, F6 and F7 reg zero. Both operands are real, so
// the recorded pair carries them exactly as a register test does.
static bool lower_test_imm(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in) {
    re_varnode_t val, imm;
    if (!x64_ld_read_rm(f, a, in, x64_lower_osize(in), &val))
        return false;
    if (!x64_lower_imm(f, a, in->imm, &imm))
        return false;
    return x64_flags_pair(f, a, RE_SETF_TEST, val, imm);
}

// The map zero forms lower3 owns, called from lower2's dispatcher: the carry
// forms, and the test with an immediate.
bool x64_lower3_map0(const re_insn_t *in, re_ir_func_t *f, re_arena_t *a) {
    unsigned op = RE_INSN_OPCODE(in);
    if (!x64_lower_uniq_ok(f))
        return false;
    if ((op >= 0x10 && op <= 0x15) || (op >= 0x18 && op <= 0x1D))
        return lower_carry(f, a, in, (op & 8u) != 0);
    if (op >= 0x80 && op <= 0x83 && ((in->reg & 7u) == 2u || (in->reg & 7u) == 3u))
        return lower_carry(f, a, in, (in->reg & 7u) == 3u);
    if ((op == 0xF6 || op == 0xF7) && (in->reg & 7u) == 0u)
        return lower_test_imm(f, a, in);
    return false;
}

// The bit test writes CF from the selected bit: shift the value right by the
// index, and the low bit of that is the flag. A write into a flag varnode is
// invisible in the printed body, which is exactly right for a flag write.
static bool bt_flag(re_ir_func_t *f, re_arena_t *a, uint16_t sz, re_varnode_t val,
                    re_varnode_t idx) {
    re_varnode_t shifted, low, one;
    re_ir_op_t o;
    if (!x64_lower_imm(f, a, 1, &one))
        return false;
    o = x64_lower_mk(RE_OP_INTSHR);
    o.out = shifted = x64_lower_uniq(f, sz);
    o.in[0] = val;
    o.in[1] = idx;
    if (!x64_lower_push(f, a, o))
        return false;
    o = x64_lower_mk(RE_OP_INTAND);
    o.out = low = x64_lower_uniq(f, 1);
    o.in[0] = shifted;
    o.in[1] = one;
    if (!x64_lower_push(f, a, o))
        return false;
    o = x64_lower_mk(RE_OP_VAR);
    o.out = x64_flag_vn(RE_FLAG_CF);
    o.in[0] = low;
    return x64_lower_push(f, a, o);
}

// bt, bts, btr and btc. The reg field of 0F BA names the operation by its own
// numbering, which this normalises to zero, five, six and seven. Three of the
// four write the bit back, which is one more operation on the same value.
static bool lower_btfam(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, unsigned sel,
                        re_varnode_t idx) {
    uint16_t sz = x64_lower_osize(in);
    re_varnode_t val, bit, res, one;
    re_ir_op_t o;
    if (!x64_ld_read_rm(f, a, in, sz, &val))
        return false;
    if (!bt_flag(f, a, sz, val, idx))
        return false;
    if (sel == 0)
        return true; // bt only sets the flag
    if (!x64_lower_imm(f, a, 1, &one))
        return false;
    // 1 << idx. The constant needs its own varnode: reusing one for both the input and
    // the result shifted an undefined temporary, which printed as "? << n".
    o = x64_lower_mk(RE_OP_INTSHL);
    o.out = bit = x64_lower_uniq(f, sz);
    o.in[0] = one;
    o.in[1] = idx;
    if (!x64_lower_push(f, a, o))
        return false;
    o = x64_lower_mk(sel == 5 ? RE_OP_INTOR : sel == 7 ? RE_OP_INTXOR : RE_OP_BITNOT);
    o.out = res = x64_lower_uniq(f, sz);
    o.in[0] = sel == 5 || sel == 7 ? val : bit;
    o.in[1] = sel == 5 || sel == 7 ? bit : val;
    if (!x64_lower_push(f, a, o))
        return false;
    if (sel == 6) {
        // btr clears: the inverted mask has to be anded in afterwards
        re_varnode_t inv = res;
        o = x64_lower_mk(RE_OP_INTAND);
        o.out = res = x64_lower_uniq(f, sz);
        o.in[0] = val;
        o.in[1] = inv;
        if (!x64_lower_push(f, a, o))
            return false;
    }
    if (in->is_mem)
        return x64_ld_store_rm(f, a, in, res);
    o = x64_lower_mk(RE_OP_VAR);
    o.out = val;
    o.in[0] = res;
    return x64_lower_push(f, a, o);
}

// setcc and cmovcc read the flags the last writer established. The condition
// nibble travels in extra either way; the emitter resolves it against the
// pending writer, and prints an honest flag name when it cannot.
static bool lower_conditional(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, bool set) {
    re_varnode_t val, addr;
    re_ir_op_t o;
    if (set) {
        o = x64_lower_mk(RE_OP_SETCC);
        o.extra = RE_INSN_OPCODE(in) & 15u;
        o.out = re_ir_vn(RE_SPACE_REG, 1, in->reg);
        return x64_lower_push(f, a, o);
    }
    if (!in->is_mem) {
        o = x64_lower_mk(RE_OP_SELECT);
        o.extra = RE_INSN_OPCODE(in) & 15u;
        o.out = x64_lower_reg(in, in->reg);
        o.in[0] = o.out;
        o.in[1] = x64_lower_rm(in);
        return x64_lower_push(f, a, o);
    }
    if (!x64_lower_addr(f, a, in, &addr))
        return false;
    o = x64_lower_mk(RE_OP_LOAD);
    o.out = val = x64_lower_uniq(f, x64_lower_osize(in));
    o.in[0] = addr;
    if (!x64_lower_push(f, a, o))
        return false;
    o = x64_lower_mk(RE_OP_SELECT);
    o.extra = RE_INSN_OPCODE(in) & 15u;
    o.out = x64_lower_reg(in, in->reg);
    o.in[0] = o.out;
    o.in[1] = val;
    return x64_lower_push(f, a, o);
}

// The two operand imul, 0F AF. Only the low half is written, which is what a C
// multiply means; the wide form is the F7 path in lower2.
static bool lower_imul2(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in) {
    re_varnode_t val;
    re_ir_op_t o;
    if (!x64_ld_read_rm(f, a, in, x64_lower_osize(in), &val))
        return false;
    o = x64_lower_mk(RE_OP_INTMUL);
    o.out = x64_lower_reg(in, in->reg);
    o.in[0] = o.out;
    o.in[1] = val;
    return x64_lower_push(f, a, o);
}

// A unary register form whose source is the r/m side: popcnt and the two scans.
static bool lower_unary(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, re_op_kind_t kind) {
    re_varnode_t val;
    re_ir_op_t o;
    if (!x64_ld_read_rm(f, a, in, x64_lower_osize(in), &val))
        return false;
    o = x64_lower_mk(kind);
    o.out = x64_lower_reg(in, in->reg);
    o.in[0] = val;
    return x64_lower_push(f, a, o);
}

// The map one tranche: the condition moves, the extensions, the bit tests, the
// bit scans, the byte swap, and the trap instructions. Everything else in the
// map belongs to the SIMD file or stays unmodelled on purpose. The hint nop
// forms emit nothing because that is all they are.
bool x64_lower2_map1(const re_insn_t *in, re_ir_func_t *f, re_arena_t *a) {
    unsigned op = RE_INSN_OPCODE(in);
    uint8_t pfx = in->pfx;
    if (RE_INSN_MAP(in) != 1 || !x64_lower_uniq_ok(f))
        return false;
    if (op == 0x1E || op == 0x1F || op == 0x18 || op == 0x19 || op == 0x1C || op == 0x1D ||
        op == 0x0D || op == 0x0E || op == 0x77)
        return x64_ld_nop(f, a);
    if (op == 0x05 || op == 0x34 || op == 0x35)
        return x64_ld_int(f, a, 0);
    if (op >= 0x40 && op <= 0x4F)
        return lower_conditional(f, a, in, false);
    if (op >= 0x90 && op <= 0x9F)
        return lower_conditional(f, a, in, true);
    if (op == 0xA3 || op == 0xAB || op == 0xB3 || op == 0xBB) {
        unsigned sel = op == 0xA3 ? 0 : op == 0xAB ? 5 : op == 0xB3 ? 6 : 7;
        return lower_btfam(f, a, in, sel, re_ir_vn(RE_SPACE_REG, x64_lower_osize(in), in->reg));
    }
    if (op == 0xBA && (in->reg & 7u) >= 4u) {
        re_varnode_t idx;
        if (!x64_lower_imm(f, a, in->imm, &idx))
            return false;
        return lower_btfam(f, a, in, in->reg & 7u, idx);
    }
    if (op == 0xAF)
        return lower_imul2(f, a, in);
    if (op == 0xB6 || op == 0xB7)
        return x64_ld_extend(f, a, in, false, op == 0xB6 ? 1 : 2);
    if (op == 0xBE || op == 0xBF)
        return x64_ld_extend(f, a, in, true, op == 0xBE ? 1 : 2);
    if (op == 0xB8 && pfx == 2)
        return lower_unary(f, a, in, RE_OP_POPCNT);
    if (op == 0xBC && pfx == 2)
        return lower_unary(f, a, in, RE_OP_TZCNT);
    if (op == 0xBD && pfx == 2)
        return lower_unary(f, a, in, RE_OP_LZCNT);
    if (op >= 0xC8 && op <= 0xCF) {
        re_ir_op_t o = x64_lower_mk(RE_OP_BSWAP);
        o.out = o.in[0] =
            re_ir_vn(RE_SPACE_REG, x64_lower_osize(in), (op & 7u) + ((in->rex & 1u) ? 8u : 0u));
        return x64_lower_push(f, a, o);
    }
    return false;
}
