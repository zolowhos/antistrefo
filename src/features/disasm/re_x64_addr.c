// re_x64_addr.c - the effective address of an x86-64 memory operand, as IR ops.
// Module: feature (C11).
// Owns: base + index * scale + displacement, frame slots, and segment relative reads.
// Depends: re_x64_priv.h and re_ir. Split from re_x64_lower.c so the address is built
//           in one place: every load, store and lea in the lowering goes through here.
#include "features/disasm/re_x64_priv.h"

#include "features/dec/re_ir.h"

// The segment override an instruction carries: 0x64 is fs, 0x65 is gs, 0 is none.
// The decoder keeps the raw encoding, so the prefix run is read back from it. Only
// fs and gs matter in long mode; the other four overrides are ignored by the CPU.
static unsigned seg_of(const re_insn_t *in) {
    for (unsigned i = 0; i < in->size && i < sizeof(in->raw); i++) {
        uint8_t b = in->raw[i];
        if (b == 0x64u || b == 0x65u)
            return b;
        bool prefix = b == 0xF0u || b == 0xF2u || b == 0xF3u || b == 0x2Eu || b == 0x36u ||
                      b == 0x3Eu || b == 0x26u || b == 0x66u || b == 0x67u;
        if (!prefix && (b & 0xF0u) != 0x40u)
            break;
    }
    return 0;
}

static bool push_bin(re_ir_func_t *f, re_arena_t *a, re_op_kind_t k, re_varnode_t l, re_varnode_t r,
                     re_varnode_t *out) {
    re_ir_op_t o = x64_lower_mk(k);
    o.out = x64_lower_uniq(f, 8);
    o.in[0] = l;
    o.in[1] = r;
    if (!x64_lower_push(f, a, o))
        return false;
    *out = o.out;
    return true;
}

// index * scale, as a multiply by a constant so a reader sees the element size.
static bool scaled_index(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, re_varnode_t *out) {
    re_varnode_t idx = re_ir_vn(RE_SPACE_REG, 8, in->index);
    re_varnode_t k;
    if (in->scale <= 1) {
        *out = idx;
        return true;
    }
    if (!x64_lower_imm(f, a, in->scale, &k))
        return false;
    return push_bin(f, a, RE_OP_INTMUL, idx, k, out);
}

// A segment relative read: fs:[n] or gs:[n]. The offset is the identity of the
// location (gs:[0x30] is the TEB, gs:[0x60] the PEB), so it is kept as the varnode's
// offset in the I/O space and the emitter names it rather than dereferencing it.
static bool seg_addr(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, unsigned seg,
                     re_varnode_t *out) {
    re_ir_op_t o = x64_lower_mk(RE_OP_VAR);
    o.out = re_ir_vn(RE_SPACE_IOP, 8, (uint16_t)in->disp);
    o.extra = seg;
    if (!x64_lower_push(f, a, o))
        return false;
    *out = o.out;
    return true;
}

// The address of the memory operand, emitted as ops so every later reader sees how it
// was formed. RIP relative is a constant; rsp relative with no index is a frame slot,
// named by its displacement so the emitter can turn it into a local; everything else is
// arithmetic over the registers it names. rbp is deliberately not a frame slot here,
// because most x64 code uses it as an ordinary register, and the emitter decides from
// the function's own prologue whether it points into the frame.
bool x64_lower_addr(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, re_varnode_t *out) {
    unsigned seg = seg_of(in);
    re_varnode_t acc = re_ir_vn(RE_SPACE_UNIQUE, 0, 0);
    bool have = false;
    if (seg && in->base == RE_REG_NONE && in->index == RE_REG_NONE && !in->rip_rel)
        return seg_addr(f, a, in, seg, out);
    if (in->rip_rel || (in->base == 4 && in->index == RE_REG_NONE)) {
        re_ir_op_t op = in->rip_rel ? x64_lower_mk(RE_OP_CONST) : x64_lower_mk(RE_OP_VAR);
        op.out = in->rip_rel ? re_ir_vn(RE_SPACE_CONST, 8, (uint16_t)f->next_uniq++)
                             : re_ir_vn(RE_SPACE_STACK, 8, (uint16_t)(int16_t)in->disp);
        op.const_val = in->rip_rel ? (int64_t)in->mem : 0;
        // An address exists only to be an operand of the load or store that follows,
        // so the emitter is told not to print it as a statement of its own.
        if (in->rip_rel)
            op.extra = RE_CONST_OPERAND;
        if (!x64_lower_push(f, a, op))
            return false;
        *out = op.out;
        return true;
    }
    // base + disp first, then the index: for a frame array that makes the first sum the
    // array's own address, which is the slot a reader names.
    if (in->base != RE_REG_NONE) {
        acc = re_ir_vn(RE_SPACE_REG, 8, in->base);
        have = true;
    }
    if (in->disp != 0 || (in->base == RE_REG_NONE && in->index == RE_REG_NONE)) {
        re_varnode_t k;
        if (!x64_lower_imm(f, a, in->disp, &k))
            return false;
        if (have && !push_bin(f, a, RE_OP_INTADD, acc, k, &acc))
            return false;
        if (!have)
            acc = k;
        have = true;
    }
    if (in->index != RE_REG_NONE) {
        re_varnode_t idx;
        if (!scaled_index(f, a, in, &idx))
            return false;
        if (have && !push_bin(f, a, RE_OP_INTADD, acc, idx, &acc))
            return false;
        if (!have)
            acc = idx;
    }
    *out = acc;
    return true;
}
