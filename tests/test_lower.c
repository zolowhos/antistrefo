// test_lower.c - the x86-64 lowering, one idiom at a time.
// Module: test (C11).
// Owns: the IR shapes each instruction family must produce when lowered.
// Depends: re_core through the disassembler vtable, the same path the
//           decompiler drives, so what is tested is what prints.
#include "re_test.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "features/dec/re_ir.h"
#include "features/disasm/re_x64_priv.h"
#include "features/meta/re_disasm.h"
#include "utils/mem/re_arena.h"

int re_test_count = 0;
int re_test_fail = 0;

#define RE_LT_ADDR 0x140001000ull

// Decode and lower one instruction. Returns the ops it produced; the record
// stays in ir for the assertions that follow.
static size_t low1(re_arena_t *a, const re_disasm_t *dis, re_ir_func_t *ir, const uint8_t *p,
                   size_t n) {
    re_insn_t in;
    re_span_t span = {p, n};
    if (!dis->decode(dis->ctx, RE_LT_ADDR, span, &in))
        return (size_t)-1; // a decode failure, which no vector here relies on
    return dis->lower(dis->ctx, &in, ir, a);
}

// The first op of the given kind, or NULL.
static const re_ir_op_t *find_op(const re_ir_func_t *ir, re_op_kind_t k) {
    for (size_t b = 0; b < ir->n_blocks; b++) {
        for (size_t i = 0; i < ir->blocks[b].n_ops; i++) {
            if (ir->blocks[b].ops[i].op == k)
                return &ir->blocks[b].ops[i];
        }
    }
    return NULL;
}

// The arithmetic block: add with its recorded result writer, the carry forms,
// and the shifts with their own writer kinds.
static void check_alu(const re_disasm_t *dis, re_arena_t *a) {
    re_ir_func_t ir;
    static const uint8_t kAdd[] = {0x48, 0x83, 0xC0, 0x01}; // add rax, 1
    static const uint8_t kAdc[] = {0x48, 0x11, 0xD8};       // adc rax, rbx
    static const uint8_t kShl[] = {0x48, 0xC1, 0xE0, 0x04}; // shl rax, 4
    static const uint8_t kSar[] = {0x48, 0xD1, 0xF8};       // sar rax, 1
    static const uint8_t kShr[] = {0x48, 0xD1, 0xE8};       // shr rax, 1
    static const uint8_t kRol[] = {0x48, 0xC1, 0xC0, 0x04}; // rol rax, 4
    static const uint8_t kRorCl[] = {0x48, 0xD3, 0xC8};     // ror rax, cl
    const re_ir_op_t *o;
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 4);
    RE_CHECK(low1(a, dis, &ir, kAdd, sizeof(kAdd)) > 0);
    o = find_op(&ir, RE_OP_INTADD);
    RE_CHECK(o != NULL);
    o = find_op(&ir, RE_OP_CMP);
    RE_CHECK(o != NULL && o->extra == RE_SETF_ADD);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 3);
    RE_CHECK(low1(a, dis, &ir, kAdc, sizeof(kAdc)) > 0);
    o = find_op(&ir, RE_OP_INTADD);
    RE_CHECK(o != NULL && o->in[2].space == RE_SPACE_FLAG);
    RE_CHECK(o != NULL && o->in[2].offset == RE_FLAG_CF);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 4);
    RE_CHECK(low1(a, dis, &ir, kShl, sizeof(kShl)) > 0);
    RE_CHECK(find_op(&ir, RE_OP_INTSHL) != NULL);
    o = find_op(&ir, RE_OP_CMP);
    RE_CHECK(o != NULL && o->extra == RE_SETF_SHIFT);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 3);
    RE_CHECK(low1(a, dis, &ir, kSar, sizeof(kSar)) > 0);
    RE_CHECK(find_op(&ir, RE_OP_INTSAR) != NULL);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 3);
    RE_CHECK(low1(a, dis, &ir, kShr, sizeof(kShr)) > 0);
    RE_CHECK(find_op(&ir, RE_OP_INTSHR) != NULL);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 4);
    RE_CHECK(low1(a, dis, &ir, kRol, sizeof(kRol)) > 0);
    RE_CHECK(find_op(&ir, RE_OP_ROL) != NULL);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 3);
    RE_CHECK(low1(a, dis, &ir, kRorCl, sizeof(kRorCl)) > 0);
    RE_CHECK(find_op(&ir, RE_OP_ROR) != NULL);
}

// Multiply and divide: the wide forms write the pair, the divide forms keep the
// dividend in a temporary so the remainder reads what was divided.
static void check_muldiv(const re_disasm_t *dis, re_arena_t *a) {
    re_ir_func_t ir;
    static const uint8_t kMul[] = {0x48, 0xF7, 0xE1};         // mul rcx
    static const uint8_t kDiv[] = {0x48, 0xF7, 0xF1};         // div rcx
    static const uint8_t kImul[] = {0x48, 0x6B, 0xC1, 0x05};  // imul rax, rcx, 5
    static const uint8_t kImul2[] = {0x48, 0x0F, 0xAF, 0xC1}; // imul rax, rcx
    const re_ir_op_t *o;
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 3);
    RE_CHECK(low1(a, dis, &ir, kMul, sizeof(kMul)) > 0);
    o = find_op(&ir, RE_OP_UMULH);
    RE_CHECK(o != NULL && o->out.offset == 2); // rdx takes the high half
    RE_CHECK(find_op(&ir, RE_OP_INTMUL) != NULL);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 3);
    RE_CHECK(low1(a, dis, &ir, kDiv, sizeof(kDiv)) > 0);
    RE_CHECK(find_op(&ir, RE_OP_INTUDIV) != NULL);
    RE_CHECK(find_op(&ir, RE_OP_INTUMOD) != NULL);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 4);
    RE_CHECK(low1(a, dis, &ir, kImul, sizeof(kImul)) > 0);
    o = find_op(&ir, RE_OP_INTMUL);
    RE_CHECK(o != NULL && o->in[1].space == RE_SPACE_CONST);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 4);
    RE_CHECK(low1(a, dis, &ir, kImul2, sizeof(kImul2)) > 0);
    RE_CHECK(find_op(&ir, RE_OP_INTMUL) != NULL);
}

// The condition forms: setcc and cmov carry the nibble, a branch carries the
// whole four bits, and a test before a js is exactly the sign case the old
// three bit table got wrong.
static void check_conditions(const re_disasm_t *dis, re_arena_t *a) {
    re_ir_func_t ir;
    static const uint8_t kTestJs[] = {0x48, 0x85, 0xC0, 0x78, 0x05}; // test rax,rax; js
    static const uint8_t kCmpJe[] = {0x48, 0x39, 0xC8, 0x74, 0x05};  // cmp rax,rcx; je
    static const uint8_t kSete[] = {0x0F, 0x94, 0xC0};               // sete al
    static const uint8_t kCmov[] = {0x48, 0x0F, 0x44, 0xC1};         // cmov rax, rcx
    static const uint8_t kCmovNs[] = {0x48, 0x0F, 0x49, 0xC1};       // cmovns rax, rcx
    const re_ir_op_t *o;
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 8);
    RE_CHECK(low1(a, dis, &ir, kTestJs, 3) > 0);
    o = find_op(&ir, RE_OP_CMP);
    RE_CHECK(o != NULL && o->extra == RE_SETF_TEST);
    // the second instruction of the pair: decode skips the first by hand
    {
        re_insn_t in;
        re_span_t span = {kTestJs + 3, 2};
        RE_CHECK(dis->decode(dis->ctx, RE_LT_ADDR + 3, span, &in));
        RE_CHECK(dis->lower(dis->ctx, &in, &ir, a) > 0);
    }
    o = find_op(&ir, RE_OP_CBRANCH);
    RE_CHECK(o != NULL && o->extra == RE_CC_JS);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 8);
    RE_CHECK(low1(a, dis, &ir, kCmpJe, 3) > 0);
    {
        re_insn_t in;
        re_span_t span = {kCmpJe + 3, 2};
        RE_CHECK(dis->decode(dis->ctx, RE_LT_ADDR + 3, span, &in));
        RE_CHECK(dis->lower(dis->ctx, &in, &ir, a) > 0);
    }
    o = find_op(&ir, RE_OP_CBRANCH);
    RE_CHECK(o != NULL && o->extra == RE_CC_JE);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 3);
    RE_CHECK(low1(a, dis, &ir, kSete, sizeof(kSete)) > 0);
    o = find_op(&ir, RE_OP_SETCC);
    RE_CHECK(o != NULL && o->extra == RE_CC_JE);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 4);
    RE_CHECK(low1(a, dis, &ir, kCmov, sizeof(kCmov)) > 0);
    o = find_op(&ir, RE_OP_SELECT);
    RE_CHECK(o != NULL && o->extra == RE_CC_JE);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 4);
    RE_CHECK(low1(a, dis, &ir, kCmovNs, sizeof(kCmovNs)) > 0);
    o = find_op(&ir, RE_OP_SELECT);
    RE_CHECK(o != NULL && o->extra == RE_CC_JNS);
}

// The stack and the widening forms: a push is a subtract and a store, a pop a
// load and an add, the signed widenings carry the signed bit, and cdq is a shift.
static void check_stack_and_casts(const re_disasm_t *dis, re_arena_t *a) {
    re_ir_func_t ir;
    static const uint8_t kPush[] = {0x55};                    // push rbp
    static const uint8_t kPop[] = {0x5D};                     // pop rbp
    static const uint8_t kMovsx[] = {0x48, 0x0F, 0xBF, 0xC1}; // movsx rax, cx
    static const uint8_t kMovzx[] = {0x0F, 0xB7, 0xC1};       // movzx eax, cx
    static const uint8_t kCdq[] = {0x99};                     // cdq
    const re_ir_op_t *o;
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 1);
    RE_CHECK(low1(a, dis, &ir, kPush, 1) > 0);
    RE_CHECK(find_op(&ir, RE_OP_STORE) != NULL);
    o = find_op(&ir, RE_OP_INTSUB);
    RE_CHECK(o != NULL && o->out.offset == 4); // rsp
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 1);
    RE_CHECK(low1(a, dis, &ir, kPop, 1) > 0);
    RE_CHECK(find_op(&ir, RE_OP_LOAD) != NULL);
    RE_CHECK(find_op(&ir, RE_OP_INTADD) != NULL);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 4);
    RE_CHECK(low1(a, dis, &ir, kMovsx, sizeof(kMovsx)) > 0);
    o = find_op(&ir, RE_OP_CAST);
    RE_CHECK(o != NULL && (o->extra & RE_CAST_SIGNED));
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 3);
    RE_CHECK(low1(a, dis, &ir, kMovzx, sizeof(kMovzx)) > 0);
    o = find_op(&ir, RE_OP_CAST);
    RE_CHECK(o != NULL && !(o->extra & RE_CAST_SIGNED));
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 1);
    RE_CHECK(low1(a, dis, &ir, kCdq, 1) > 0);
    o = find_op(&ir, RE_OP_INTSAR); // edx = eax >> 31: the sign, not a widening of ax
    RE_CHECK(o != NULL && o->out.offset == 2 && o->out.size == 4 && o->in[0].offset == 0 &&
             o->in[0].size == 4);
}

// The rest of the integer tranche and the honest refusals: neg with its writer,
// the bit count forms, the silent no-ops, the trap, and the x87 escape.
static void check_misc(const re_disasm_t *dis, re_arena_t *a) {
    re_ir_func_t ir;
    static const uint8_t kNeg[] = {0x48, 0xF7, 0xD8};          // neg rax
    static const uint8_t kBswap[] = {0x48, 0x0F, 0xC8};        // bswap rax
    static const uint8_t kTzcnt[] = {0xF3, 0x0F, 0xBC, 0xC1};  // tzcnt eax, ecx
    static const uint8_t kPopcnt[] = {0xF3, 0x0F, 0xB8, 0xC1}; // popcnt eax, ecx
    static const uint8_t kNop[] = {0x90};                      // nop
    static const uint8_t kEndbr[] = {0xF3, 0x0F, 0x1E, 0xFA};  // endbr64
    static const uint8_t kSyscall[] = {0x0F, 0x05};            // syscall
    static const uint8_t kX87[] = {0xD9, 0x00};                // fld dword [rax]
    const re_ir_op_t *o;
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 3);
    RE_CHECK(low1(a, dis, &ir, kNeg, sizeof(kNeg)) > 0);
    o = find_op(&ir, RE_OP_INTNEG);
    RE_CHECK(o != NULL);
    o = find_op(&ir, RE_OP_CMP);
    RE_CHECK(o != NULL && o->extra == RE_SETF_NEG);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 4);
    RE_CHECK(low1(a, dis, &ir, kBswap, sizeof(kBswap)) > 0);
    RE_CHECK(find_op(&ir, RE_OP_BSWAP) != NULL);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 4);
    RE_CHECK(low1(a, dis, &ir, kTzcnt, sizeof(kTzcnt)) > 0);
    RE_CHECK(find_op(&ir, RE_OP_TZCNT) != NULL);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 4);
    RE_CHECK(low1(a, dis, &ir, kPopcnt, sizeof(kPopcnt)) > 0);
    RE_CHECK(find_op(&ir, RE_OP_POPCNT) != NULL);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 1);
    RE_CHECK_EQ_U(low1(a, dis, &ir, kNop, 1), 1);
    RE_CHECK(find_op(&ir, RE_OP_NOP) != NULL);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 4);
    RE_CHECK_EQ_U(low1(a, dis, &ir, kEndbr, sizeof(kEndbr)), 1);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 2);
    RE_CHECK(low1(a, dis, &ir, kSyscall, 2) > 0);
    RE_CHECK(find_op(&ir, RE_OP_INT) != NULL);
    // x87 stays unmodelled on purpose: a comment in the body beats a wrong value.
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 2);
    RE_CHECK_EQ_U(low1(a, dis, &ir, kX87, 2), 0);
}

// The bit tests and the vector forms. The bit test writes CF through a flag
// varnode, and the float forms carry their widths in the ops themselves.
static void check_bits_and_vec(const re_disasm_t *dis, re_arena_t *a) {
    re_ir_func_t ir;
    static const uint8_t kBit[] = {0x48, 0x0F, 0xA3, 0xD9};            // bt rcx, rbx
    static const uint8_t kFadd[] = {0xF3, 0x0F, 0x58, 0xC1};           // addss xmm0, xmm1
    static const uint8_t kMovdqa[] = {0x66, 0x0F, 0x6F, 0x00};         // movdqa xmm0, [rax]
    static const uint8_t kCvtsi2sd[] = {0xF2, 0x48, 0x0F, 0x2A, 0xC1}; // cvtsi2sd xmm0, rcx
    static const uint8_t kUcomis[] = {0x66, 0x0F, 0x2E, 0xC1};         // ucomisd xmm0, xmm1
    const re_ir_op_t *o;
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 4);
    RE_CHECK(low1(a, dis, &ir, kBit, sizeof(kBit)) > 0);
    o = find_op(&ir, RE_OP_VAR);
    RE_CHECK(o != NULL && o->out.space == RE_SPACE_FLAG && o->out.offset == RE_FLAG_CF);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 4);
    RE_CHECK(low1(a, dis, &ir, kFadd, sizeof(kFadd)) > 0);
    o = find_op(&ir, RE_OP_FADD);
    RE_CHECK(o != NULL && o->out.size == 4);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 4);
    RE_CHECK(low1(a, dis, &ir, kMovdqa, sizeof(kMovdqa)) > 0);
    o = find_op(&ir, RE_OP_LOAD);
    RE_CHECK(o != NULL && o->out.size == 16);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 5);
    RE_CHECK(low1(a, dis, &ir, kCvtsi2sd, sizeof(kCvtsi2sd)) > 0);
    RE_CHECK(find_op(&ir, RE_OP_FCAST) != NULL);
    re_ir_func_init(&ir);
    re_ir_block_begin(&ir, a, RE_LT_ADDR, 4);
    RE_CHECK(low1(a, dis, &ir, kUcomis, sizeof(kUcomis)) > 0);
    o = find_op(&ir, RE_OP_CMP);
    RE_CHECK(o != NULL && o->extra == RE_SETF_CMP);
}

int main(void) {
    re_arena_t a;
    const re_disasm_t *dis = re_disasm_find("x86-64");
    RE_CHECK(dis != NULL);
    if (!dis)
        return re_test_report("lower");
    re_arena_init(&a, 4u << 20);
    check_alu(dis, &a);
    check_muldiv(dis, &a);
    check_conditions(dis, &a);
    check_stack_and_casts(dis, &a);
    check_misc(dis, &a);
    check_bits_and_vec(dis, &a);
    re_arena_free(&a);
    return re_test_report("lower");
}
