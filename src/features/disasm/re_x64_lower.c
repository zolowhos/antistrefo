// re_x64_lower.c - lowers a projected x86-64 instruction into the register IR.
// Module: feature (C11).
// Owns: the shared primitives, the mov and test forms, integer arithmetic, flow.
// Depends: re_x64_priv.h. The lowering is deliberately stateless with respect to
//           control flow: it reads one instruction and emits ops for it. Constant
//           folding and register tracking belong to the emitter, which already has
//           to model control flow, and a backend that remembered cross instruction
//           state would have to be reset per function. The one counter it does keep
//           lives in the IR, which is itself per function.
#include "features/disasm/re_x64_priv.h"

#include "features/dec/re_ir.h"

// The operation size in bytes, shared with the other lowering files. Most forms
// follow the operand size prefix, but a few
// have their own width and get it wrong if the prefix is consulted instead. Only 0x82
// is byte sized among the immediate group: 0x80, 0x81 and 0x83 all honour the prefix,
// and treating them as byte operations would misread every stack adjustment.
uint16_t x64_lower_osize(const re_insn_t *in) {
    unsigned op = RE_INSN_OPCODE(in);
    unsigned map = RE_INSN_MAP(in);
    if (map == 1 && (op == 0xB6 || op == 0xB7 || op == 0xBE || op == 0xBF))
        return 1;
    if (map == 0 && (op == 0x88 || op == 0x8A || op == 0xC6 || (op >= 0xB0 && op <= 0xB7) ||
                     (op >= 0x70 && op <= 0x7F) || op == 0x82))
        return 1;
    return (uint16_t)in->opsize;
}

re_varnode_t x64_lower_reg(const re_insn_t *in, unsigned r) {
    return re_ir_vn(RE_SPACE_REG, x64_lower_osize(in), (uint16_t)r);
}

// A constant varnode. The value is not in the varnode, it is in the op that defines
// it, which is what lets a 64 bit immediate travel through a 16 bit offset field.
// The offset is a unique id, because two constants in the same function must be told
// apart by whatever consumes them: an address and an immediate both print through
// this path, and folding the wrong one would be a silent wrong answer.
static re_varnode_t const_vn(re_ir_func_t *f) {
    return re_ir_vn(RE_SPACE_CONST, 8, (uint16_t)f->next_uniq++);
}

re_varnode_t x64_lower_uniq(re_ir_func_t *f, uint16_t size) {
    return re_ir_vn(RE_SPACE_UNIQUE, size, (uint16_t)f->next_uniq++);
}

// A fresh temporary, or false when the function has run out. The bound matters: the
// emitter names temporaries through a fixed table, so a function that minted more
// than the table holds could not be printed correctly. Refusing is better than
// printing a name that refers to the wrong value.
bool x64_lower_uniq_ok(const re_ir_func_t *f) {
    return f->next_uniq < RE_UNIQ_MAX;
}

re_ir_op_t x64_lower_mk(re_op_kind_t kind) {
    re_ir_op_t op = re_ir_mkop((re_ir_op_t){0});
    op.op = kind;
    return op;
}

bool x64_lower_push(re_ir_func_t *f, re_arena_t *a, re_ir_op_t op) {
    return re_ir_emit(f, a, op) != NULL;
}

// The r/m operand as a value. A register is its own name; a memory operand is a
// value of unknown provenance until a load brings it in.
re_varnode_t x64_lower_rm(const re_insn_t *in) {
    if (!in->is_mem)
        return x64_lower_reg(in, in->rm);
    return re_ir_vn(RE_SPACE_HEAP, x64_lower_osize(in), 0);
}

// The address of a memory operand is built in re_x64_addr.c.

// An immediate operand, emitted as its own CONST so the value is in the IR and not
// only in a field the emitter would have to know to look in. This is what the
// emitter's constant folding resolves, the same way it resolves an address.
bool x64_lower_imm(re_ir_func_t *f, re_arena_t *a, int64_t v, re_varnode_t *out) {
    re_ir_op_t op = x64_lower_mk(RE_OP_CONST);
    op.out = const_vn(f);
    op.const_val = v;
    op.extra = RE_CONST_OPERAND;
    if (!x64_lower_push(f, a, op))
        return false;
    *out = op.out;
    return true;
}

// The three mov forms that carry an immediate. Separated from the register forms
// because they are the only ones that need a second varnode, and mixing the two is
// what made this function too long to read.
static bool lower_mov_imm(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in) {
    unsigned op = RE_INSN_OPCODE(in);
    re_ir_op_t o;
    re_varnode_t addr = re_ir_vn(RE_SPACE_UNIQUE, 0, 0);
    if (op >= 0xB0 && op <= 0xBF) {
        // B0..B7 are the byte forms and count from al; B8..BF are the full width
        // forms and count from rax again, which is the restart the encoding makes
        // at B8. Reading both ranges from one base put every full width immediate
        // in r8 through r15, which no program that used rax ever wrote.
        unsigned r = op < 0xB8u ? (op - 0xB0u) : (op - 0xB8u);
        o = x64_lower_mk(RE_OP_CONST);
        o.out = x64_lower_reg(in, r + ((in->rex & 1u) ? 8u : 0u));
        o.const_val = in->imm;
        return x64_lower_push(f, a, o);
    }
    if (!in->is_mem) { // mov reg, imm
        o = x64_lower_mk(RE_OP_CONST);
        o.out = x64_lower_rm(in);
        o.const_val = in->imm;
        return x64_lower_push(f, a, o);
    }
    // A store of a constant: the address, then the value, then the store. The two live
    // in separate varnodes because the emitter folds the constant it last saw, and
    // overwriting the address with the value would lose the store target.
    re_varnode_t imm;
    if (!x64_lower_addr(f, a, in, &addr) || !x64_lower_imm(f, a, in->imm, &imm))
        return false;
    o = x64_lower_mk(RE_OP_STORE);
    o.in[0] = x64_lower_rm(in);
    o.in[1] = imm;
    o.in[2] = addr;
    return x64_lower_push(f, a, o);
}

static bool lower_mov(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in) {
    unsigned op = RE_INSN_OPCODE(in);
    re_ir_op_t o;
    re_varnode_t addr = re_ir_vn(RE_SPACE_UNIQUE, 0, 0);
    if (op == 0xC6 || op == 0xC7 || (op >= 0xB0 && op <= 0xBF))
        return lower_mov_imm(f, a, in);
    if (op == 0x88 || op == 0x89) { // mov r/m, reg
        // With a register destination this is a copy, not a store: compilers emit
        // this encoding for most register moves, and reading it as a store through
        // the destination printed nearly every function as a pointer write.
        if (!in->is_mem) {
            o = x64_lower_mk(RE_OP_VAR);
            o.out = x64_lower_reg(in, in->rm);
            o.in[0] = x64_lower_reg(in, in->reg);
            return x64_lower_push(f, a, o);
        }
        if (!x64_lower_addr(f, a, in, &addr))
            return false;
        o = x64_lower_mk(RE_OP_STORE);
        o.in[0] = x64_lower_rm(in);
        o.in[1] = x64_lower_reg(in, in->reg);
        o.in[2] = addr;
        return x64_lower_push(f, a, o);
    }
    if (op == 0x8A || op == 0x8B) { // mov reg, r/m
        o = x64_lower_mk(in->is_mem ? RE_OP_LOAD : RE_OP_VAR);
        o.out = x64_lower_reg(in, in->reg);
        if (in->is_mem) {
            if (!x64_lower_addr(f, a, in, &addr))
                return false;
            o.in[0] = addr;
        } else {
            o.in[0] = x64_lower_reg(in, in->rm);
        }
        return x64_lower_push(f, a, o);
    }
    if (op == 0x8D) { // lea reg, mem
        // The result is the address, not what is stored there, so the address op is
        // the substance of the instruction and the register is a copy of it.
        re_varnode_t src;
        if (!x64_lower_addr(f, a, in, &src))
            return false;
        o = x64_lower_mk(RE_OP_VAR);
        o.out = x64_lower_reg(in, in->reg);
        o.in[0] = src;
        return x64_lower_push(f, a, o);
    }
    return false;
}

// The operation an arithmetic opcode performs. The 0x00..0x3D block is eight
// operations in runs of eight, so the operation is the top three bits of the opcode
// and the low five only choose the form. The two carry operations are lower2's
// business, because a carry is a flag read and the flag model lives with the
// helpers both files share.
static re_op_kind_t arith_kind(unsigned op) {
    static const re_op_kind_t kOps[8] = {RE_OP_INTADD, RE_OP_INTOR,  RE_OP_UNIMPL, RE_OP_UNIMPL,
                                         RE_OP_INTAND, RE_OP_INTSUB, RE_OP_INTXOR, RE_OP_CMP};
    if (op <= 0x3D)
        return kOps[op >> 3];
    if (op >= 0x80 && op <= 0x83)
        return RE_OP_INTADD; // refined by the reg field
    return RE_OP_UNIMPL;
}

// The immediate group picks its operation from the reg field, so 0x83 is eight
// different instructions. The two with a carry (ADC, SBB) belong to lower2 for the
// same reason as above: the carry is a flag read, not a second operand.
static re_op_kind_t group_kind(unsigned reg) {
    static const re_op_kind_t k[8] = {RE_OP_INTADD, RE_OP_INTOR,  RE_OP_UNIMPL, RE_OP_UNIMPL,
                                      RE_OP_INTAND, RE_OP_INTSUB, RE_OP_INTXOR, RE_OP_CMP};
    return k[reg & 7u];
}

// A read modify write: a load, then the operation. When the destination is memory
// the result is stored back; when it is a register it is simply left there. Split
// out so lower_alu stays readable, and because the IR has no in place arithmetic.
// A read modify write: a load, then the operation. When the destination is memory
// the result is stored back; when it is a register it is simply left there. The
// varnode holding the result comes back, because the flag writer that follows an
// arithmetic memory form records exactly that value.
static bool lower_rmw(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, re_op_kind_t kind,
                      re_varnode_t second, re_varnode_t dest, bool store_back,
                      re_varnode_t *out_result) {
    // store_back is the r/m destination form, r/m = r/m op reg; without it the form is
    // reg = reg op r/m, and the register is the left operand: sub ecx, [m] is ecx - [m].
    bool reg_first = !store_back;
    re_ir_op_t o = x64_lower_mk(RE_OP_LOAD);
    re_ir_op_t result;
    re_varnode_t addr;
    re_varnode_t result_vn;
    if (!x64_lower_addr(f, a, in, &addr))
        return false;
    o.out = x64_lower_uniq(f, x64_lower_osize(in));
    o.in[0] = addr;
    if (!x64_lower_push(f, a, o))
        return false;
    result = x64_lower_mk(kind);
    // A register destination is written directly; a memory one needs a temporary,
    // because the value has to exist before it can be stored.
    result.out = (dest.space == RE_SPACE_REG) ? dest : x64_lower_uniq(f, x64_lower_osize(in));
    result.in[0] = reg_first ? second : o.out;
    result.in[1] = reg_first ? o.out : second;
    if (!x64_lower_push(f, a, result))
        return false;
    result_vn = result.out;
    *out_result = result_vn;
    if (!store_back)
        return true;
    // The store goes back to the address the load used. Building it a second time
    // would print the same address computation twice.
    o = x64_lower_mk(RE_OP_STORE);
    o.in[0] = x64_lower_rm(in);
    o.in[1] = result_vn;
    o.in[2] = addr;
    return x64_lower_push(f, a, o);
}

// test is not cmp: it computes the same flags but from a bitwise and of its two
// operands, which is what the recorded writer says. Lowering it as a comparison
// against that value would print "if (rax == rax)", which is never what the author
// wrote and always vacuously true, so both real operands are recorded instead and
// the emitter builds the condition the flags actually established.
static bool lower_test(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in) {
    re_varnode_t val;
    // A memory operand is read first: the condition has to name the value tested,
    // not an address with no definition behind it.
    if (!x64_ld_read_rm(f, a, in, x64_lower_osize(in), &val))
        return false;
    return x64_flags_pair(f, a, RE_SETF_TEST, val, x64_lower_reg(in, in->reg));
}

// xor r, r and sub r, r: the compiler's way of writing zero. Lowered as the constant
// it produces, so the body says 0 rather than "x ^ x" about a value nobody needed.
static bool lower_zero_idiom(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, unsigned wr) {
    re_ir_op_t o = x64_lower_mk(RE_OP_CONST);
    o.out = x64_lower_reg(in, in->rm);
    o.const_val = 0;
    if (!x64_lower_push(f, a, o))
        return false;
    return x64_flags_result(f, a, wr, o.out);
}

// Whether this opcode form carries an immediate. It cannot be inferred from the
// immediate being non zero, because "and qword [rax+0x18], 0" is a real instruction
// whose immediate is zero, and reading that as a register operand would substitute a
// register for a number the author wrote. So the form decides, from the opcode.
static bool alu_has_imm(unsigned op) {
    if (op >= 0x80 && op <= 0x83) // the group form always has an immediate byte
        return true;
    if (op <= 0x3D) // 0x00..0x3D: the low three bits pick the form
        return (op & 7u) == 4u || (op & 7u) == 5u;
    if (op == 0x81 || op == 0xA9 || op == 0xBA || op == 0xC1) // test with immediate
        return true;
    return false;
}

// The accumulator forms 0x04, 0x05 and 0x0C, 0x0D, 0x14, 0x15 and their relatives
// have no ModRM byte, so their operand is rax by definition and the projection leaves
// the register fields unset. Reading the unset field would name a random register.
static bool alu_is_acc(unsigned op) {
    return op <= 0x3D && ((op & 7u) == 4u || (op & 7u) == 5u);
}

// The register destination of a two operand form. The 0x00..0x3B block is laid out
// in fours: the first pair is r/m with a register, the second pair is a register with
// r/m. So bit 1 picks the direction and bit 0 only picks the width.
static bool alu_to_reg(unsigned op) {
    if (op > 0x3D || alu_is_acc(op))
        return false;
    return (op & 2u) != 0u;
}

// The flag writer an arithmetic operation pairs with, or RE_SETF_COUNT when the
// operation writes no flag a branch could meaningfully test. Only the zero and
// sign of the result survive this path; carry based conditions print as flags.
static unsigned arith_writer(re_op_kind_t kind) {
    switch (kind) {
        case RE_OP_INTADD:
            return RE_SETF_ADD;
        case RE_OP_INTSUB:
            return RE_SETF_SUB;
        case RE_OP_INTAND:
        case RE_OP_INTOR:
        case RE_OP_INTXOR:
            return RE_SETF_LOGIC;
        default:
            return RE_SETF_COUNT;
    }
}

// The register destination forms: the accumulator with no ModRM byte, and the
// register to register and register to immediate forms. Both write the result
// over the first operand, which is what the printed statement shows.
static bool lower_alu_reg(re_ir_func_t *f, re_arena_t *a, re_op_kind_t kind, re_varnode_t second,
                          re_varnode_t dst, re_varnode_t *result) {
    re_ir_op_t o = x64_lower_mk(kind);
    o.out = dst;
    o.in[0] = dst;
    o.in[1] = second;
    *result = dst;
    return x64_lower_push(f, a, o);
}

// The comparison. It writes nothing, so its operands are the record, and the
// writer kind is what tells the emitter which conditions those operands decide.
// A memory operand has to be read first: a printed condition must name a value
// the reader can see, not an address the value was sitting at.
static bool lower_cmp(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, re_varnode_t second,
                      bool acc, bool to_reg) {
    re_varnode_t left = acc ? x64_lower_reg(in, 0) : x64_lower_rm(in);
    if (in->is_mem) {
        re_varnode_t addr;
        re_ir_op_t o = x64_lower_mk(RE_OP_LOAD);
        if (!x64_lower_addr(f, a, in, &addr))
            return false;
        o.out = x64_lower_uniq(f, x64_lower_osize(in));
        left = o.out;
        o.in[0] = addr;
        if (!x64_lower_push(f, a, o))
            return false;
    }
    // cmp reg, r/m (3A, 3B) compares the register against the r/m side: the order of
    // the operands is the order of every ordered condition that reads the flags.
    if (to_reg)
        return x64_flags_pair(f, a, RE_SETF_CMP, second, left);
    return x64_flags_pair(f, a, RE_SETF_CMP, left, second);
}

static bool lower_alu(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in) {
    unsigned op = RE_INSN_OPCODE(in);
    re_op_kind_t kind = arith_kind(op);
    re_varnode_t second = re_ir_vn(RE_SPACE_UNIQUE, 0, 0);
    re_varnode_t result = re_ir_vn(RE_SPACE_UNIQUE, 0, 0);
    re_varnode_t dst;
    bool imm_form = alu_has_imm(op);
    bool acc = alu_is_acc(op);
    bool to_reg = alu_to_reg(op);
    unsigned wr;
    if (op >= 0x80 && op <= 0x83)
        kind = group_kind(in->reg);
    if (kind == RE_OP_UNIMPL || !x64_lower_uniq_ok(f))
        return false;
    if (imm_form && !x64_lower_imm(f, a, in->imm, &second))
        return false;
    if (!imm_form)
        second = x64_lower_reg(in, in->reg);
    if (kind == RE_OP_CMP)
        return lower_cmp(f, a, in, second, acc, to_reg);
    if ((kind == RE_OP_INTXOR || kind == RE_OP_INTSUB) && !imm_form && !acc && !in->is_mem &&
        in->reg == in->rm)
        return lower_zero_idiom(f, a, in, arith_writer(kind));
    if (acc) {
        if (!lower_alu_reg(f, a, kind, second, x64_lower_reg(in, 0), &result))
            return false;
    } else if (in->is_mem) {
        if (!lower_rmw(f, a, in, kind, second,
                       to_reg ? x64_lower_reg(in, in->reg) : x64_lower_rm(in), !to_reg, &result))
            return false;
    } else {
        // reg = reg op r/m reads the r/m register as the second operand; the other
        // direction reads the reg field. Using reg for both made sub rcx, r8 rcx - rcx.
        dst = to_reg ? x64_lower_reg(in, in->reg) : x64_lower_rm(in);
        if (to_reg)
            second = x64_lower_rm(in);
        if (!lower_alu_reg(f, a, kind, second, dst, &result))
            return false;
    }
    wr = arith_writer(kind);
    return wr == RE_SETF_COUNT || x64_flags_result(f, a, wr, result);
}

// Branches, calls and returns, which are the ops the CFG work needs and the only
// ones here that carry control flow. A direct transfer carries its resolved target
// as the op's constant, and an indirect one carries nothing, because an indirect
// target is not knowable from the instruction. A conditional branch carries its
// whole four bit condition, because which flag bits it reads is a property of the
// branch, and what those bits mean is a property of the writer it follows.
static bool lower_flow(const re_insn_t *in, re_ir_func_t *f, re_arena_t *a) {
    re_ir_op_t o = x64_lower_mk(RE_OP_UNIMPL);
    int64_t t = (int64_t)in->target;
    if (in->is_return) {
        o.op = RE_OP_RETURN;
        // The integer return value is rax. A float return would come back in xmm0,
        // which this emitter does not model, so naming rax is the honest minimum.
        o.out = x64_lower_reg(in, 0);
        o.in[0] = o.out;
        return x64_lower_push(f, a, o);
    }
    if (!in->is_call && !in->is_branch)
        return false;
    // An indirect transfer carries its target as an input: the register, or the value
    // loaded from the memory operand, so a reader sees what was called or jumped to.
    if (!in->has_target && !in->is_conditional) {
        re_varnode_t tv;
        if (!x64_ld_read_rm(f, a, in, 8, &tv))
            return false;
        o.in[0] = in->is_mem ? tv : re_ir_vn(RE_SPACE_REG, 8, in->rm);
    }
    if (in->is_call) {
        o.op = in->has_target ? RE_OP_CALL : RE_OP_CALLIND;
        o.out = re_ir_vn(RE_SPACE_REG, 8, 0);
        o.const_val = t;
        return x64_lower_push(f, a, o);
    }
    o.op = in->is_conditional ? RE_OP_CBRANCH : RE_OP_BRANCH;
    o.out = x64_lower_uniq(f, 1);
    o.const_val = t;
    o.extra = in->is_conditional ? (unsigned)(RE_INSN_OPCODE(in) & 15u) : 0u;
    return x64_lower_push(f, a, o);
}

// How many ops the current block already holds, so a caller can tell how many this
// instruction added. The vtable contract is a count, not a yes, and an instruction
// with an immediate or a memory address is worth several ops.
static size_t ops_in(const re_ir_func_t *f) {
    if (!f->n_blocks)
        return 0;
    return f->blocks[f->n_blocks - 1].n_ops;
}

// The dispatch. Map one splits three ways: the SIMD block, which has its own file
// and its own widths, the second integer tranche, and the forms this file keeps.
// Map zero falls through to the second tranche for everything the integer block
// above does not claim.
static bool lower_one(const re_insn_t *in, re_ir_func_t *f, re_arena_t *a) {
    unsigned map = RE_INSN_MAP(in);
    unsigned op = RE_INSN_OPCODE(in);
    if (lower_flow(in, f, a))
        return true;
    if (map == 1) {
        if (x64_lower_simd(in, f, a))
            return true;
        return x64_lower2_map1(in, f, a);
    }
    if (op == 0x84 || op == 0x85)
        return lower_test(f, a, in);
    if ((op >= 0x88 && op <= 0x8D) || op == 0xC6 || op == 0xC7 || (op >= 0xB0 && op <= 0xBF))
        return lower_mov(f, a, in);
    if (op >= 0x80 && op <= 0x83) {
        // the group form: six of the eight selectors are plain arithmetic and stay
        // here; only adc (/2) and sbb (/3) read the carry, so only they go to lower2.
        // Sending /0 and /1 there lowered every add and or with an immediate as a
        // carry operation.
        unsigned sel = in->reg & 7u;
        if (sel != 2u && sel != 3u)
            return lower_alu(f, a, in);
        return x64_lower2(in, f, a);
    }
    if (arith_kind(op) != RE_OP_UNIMPL)
        return lower_alu(f, a, in);
    return x64_lower2(in, f, a);
}

size_t x64_lower(const re_insn_t *in, re_ir_func_t *f, re_arena_t *a) {
    size_t before = ops_in(f);
    size_t after;
    if (!lower_one(in, f, a))
        return 0;
    after = ops_in(f);
    // Stamp every op with the instruction it came from, so an annotation, a
    // deobfuscation pass or a scoreboard can find its site without re-decoding.
    if (f->n_blocks) {
        re_ir_block_t *b = &f->blocks[f->n_blocks - 1];
        for (size_t k = before; k < after; k++)
            b->ops[k].addr = in->addr;
    }
    return after - before;
}
