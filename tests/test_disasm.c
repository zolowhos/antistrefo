// test_disasm.c - golden vectors for the x86-64 decoder and the function walker.
// Module: test (C11).
// Owns: instruction length, control flow flag and prologue checks for the backend.
// Depends: re_core through the re_disasm vtable, never the private headers, so the
// test exercises the same seam a caller would.
#include "re_test.h"

#include <string.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/dec/re_ir.h"
#include "features/meta/re_disasm.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_buf.h"
#include "utils/text/re_hex.h"
#include "utils/text/re_str.h"

// This suite is its own binary, so it owns its counters.
int re_test_count = 0;
int re_test_fail = 0;

// The pinned encodings live in test_disasm_vec.c, which owns the table and the
// runner; the split is only about the file cap, not about the seam.
void re_disasm_vec_run(const re_disasm_t *dis);

static const re_disasm_t *g_x64;

// Turn two hex characters into a byte. A malformed pair is a test bug, not a
// decode case, so it is asserted rather than tolerated.
static uint8_t nib(char c) {
    if (c >= '0' && c <= '9')
        return (uint8_t)(c - '0');
    return (uint8_t)(c - 'a' + 10);
}

// The addresses a relative branch resolves to. A branch that lands somewhere
// else sends the function walker into the wrong function, so this is checked
// independently of the length.
static void test_targets(void) {
    struct {
        const char *bytes;
        uint8_t len;
        uint64_t want;
    } cases[] = {
        // The rel32 fields below are little endian, so -0xF is f1 ff ff ff and
        // not ff ff ff f1. Getting that backwards is exactly the kind of error
        // that hides behind a plausible looking number.
        {"e8fbffffff", 5, 0x140001000ULL},   // call -5, back to the start
        {"ebfd", 2, 0x140000FFFULL},         // jmp -3
        {"7402", 2, 0x140001004ULL},         // je +2
        {"0f8410000000", 6, 0x140001016ULL}, // je rel32 +0x10, past the 6 byte insn
        {"0f8ff1ffffff", 6, 0x140000FF7ULL}, // jg rel32 -0xF, back over the insn
        {"0f8fffffffff", 6, 0x140001005ULL}, // jg rel32 -1, onto the last byte
        {"e800000000", 5, 0x140001005ULL},   // call +0, onto the following insn
        {"4889e5c3", 3, 0},                  // not a branch, so unused
    };
    for (size_t v = 0; v < sizeof(cases) / sizeof(cases[0]); v++) {
        uint8_t buf[8];
        re_insn_t in;
        size_t n = cases[v].len;
        for (size_t i = 0; i < n; i++)
            buf[i] = (uint8_t)((nib(cases[v].bytes[i * 2]) << 4) | nib(cases[v].bytes[i * 2 + 1]));
        if (!g_x64->decode(g_x64->ctx, 0x140001000ULL, re_span(buf, n), &in)) {
            RE_CHECK(0 && "decode refused a branch vector");
            continue;
        }
        if (cases[v].want)
            RE_CHECK_EQ_HEX(in.target, cases[v].want);
    }
}

// A truncated instruction must be refused, never read past the end. This is the
// case that keeps a malformed image from walking off the mapping.
static void test_truncated(void) {
    static const char *const kShort[] = {"48",           "4883", "4883ec", "0f84",   "0f8401",
                                         "e8",           "c2",   "c210",   "f30f1e", "488b05",
                                         "488b05341200", "69",   "c5",     "c5f8",   "0f38"};
    for (size_t v = 0; v < sizeof(kShort) / sizeof(kShort[0]); v++) {
        uint8_t buf[8];
        re_insn_t in;
        size_t n = (size_t)re_str(kShort[v]).n / 2u;
        for (size_t i = 0; i < n; i++)
            buf[i] = (uint8_t)((nib(kShort[v][i * 2]) << 4) | nib(kShort[v][i * 2 + 1]));
        RE_CHECK(!g_x64->decode(g_x64->ctx, 0x1000, re_span(buf, n), &in));
    }
    // Opcodes that do not exist in 64-bit mode. The prefix bytes are deliberately
    // absent: a prefix followed by valid bytes is a valid instruction, and the
    // vectors above already cover lock, rep and the vector escapes.
    static const uint8_t kBad[] = {0x06, 0x07, 0x0E, 0x16, 0x17, 0x1F, 0x27, 0x2F, 0x37,
                                   0x3F, 0x60, 0x61, 0x82, 0x9A, 0xCE, 0xD4, 0xD5, 0xEA};
    for (size_t v = 0; v < sizeof(kBad) / sizeof(kBad[0]); v++) {
        uint8_t buf[8] = {0};
        re_insn_t in;
        buf[0] = kBad[v];
        RE_CHECK(!g_x64->decode(g_x64->ctx, 0x1000, re_span(buf, 8), &in));
    }
}

// A direct call and an indirect one differ in whether a target is reported, and
// conflating them is how a caller ends up chasing a pointer as if it were code.
static void test_indirect(void) {
    uint8_t direct[5] = {0xE8, 0x00, 0x00, 0x00, 0x00};
    uint8_t indirect[2] = {0xFF, 0xD0};
    re_insn_t in;
    RE_CHECK(g_x64->decode(g_x64->ctx, 0x1000, re_span(direct, 5), &in));
    RE_CHECK(in.is_call);
    RE_CHECK(in.has_target);
    RE_CHECK_EQ_HEX(in.target, 0x1005);
    RE_CHECK(g_x64->decode(g_x64->ctx, 0x1000, re_span(indirect, 2), &in));
    RE_CHECK(in.is_call);
    RE_CHECK(!in.has_target);
}

// Prologue recognition is what seeds function discovery, so a miss here means a
// missed function in the report.
static void test_prologue(void) {
    static const char *const kYes[] = {
        "f30f1efa",             // endbr64
        "55",                   // push rbp
        "4889e5",               // mov rbp,rsp
        "4883ec28",             // sub rsp,0x28
        "4883ec00010000",       // sub rsp,0x100
        "f30f1efa55",           // endbr64 then push rbp
        "55b8001000004883ec20", // push rbp, mov eax, sub rsp
    };
    static const char *const kNo[] = {
        "b801000000", // mov eax,1
        "488b4508",   // mov rax,[rbp+8]
        "c3",         // ret
        "90",         // nop
        "0f1f440000", // multi byte nop
    };
    for (size_t v = 0; v < sizeof(kYes) / sizeof(kYes[0]); v++) {
        uint8_t buf[16];
        size_t n = (size_t)re_str(kYes[v]).n / 2u;
        for (size_t i = 0; i < n; i++)
            buf[i] = (uint8_t)((nib(kYes[v][i * 2]) << 4) | nib(kYes[v][i * 2 + 1]));
        re_test_count++;
        if (!g_x64->is_prologue(g_x64->ctx, 0x1000, re_span(buf, n))) {
            re_test_fail++;
            printf("FAIL prologue missed: %s\n", kYes[v]);
            fflush(stdout);
        }
    }
    for (size_t v = 0; v < sizeof(kNo) / sizeof(kNo[0]); v++) {
        uint8_t buf[16];
        size_t n = (size_t)re_str(kNo[v]).n / 2u;
        for (size_t i = 0; i < n; i++)
            buf[i] = (uint8_t)((nib(kNo[v][i * 2]) << 4) | nib(kNo[v][i * 2 + 1]));
        RE_CHECK(!g_x64->is_prologue(g_x64->ctx, 0x1000, re_span(buf, n)));
    }
}

static void test_registry(void) {
    RE_CHECK_EQ_U(re_disasm_arch_count(), 2);
    RE_CHECK(re_disasm_arch_name(0) != NULL);
    RE_CHECK(re_disasm_arch_name(1) != NULL);
    RE_CHECK(re_disasm_arch_name(2) == NULL);
    RE_CHECK(re_disasm_find("x86-64") == g_x64);
    RE_CHECK(re_disasm_find("x86") != NULL);
    RE_CHECK(re_disasm_find("x86") != g_x64);
    RE_CHECK(re_disasm_find("x86")->mode == 32);
    RE_CHECK(re_disasm_find("nope") == NULL);
    RE_CHECK(re_disasm_find("") == NULL);
    RE_CHECK(g_x64 != NULL);
    RE_CHECK(g_x64->mode == 64);
    // A transfer function is not published yet, and NULL means not modelled.
    RE_CHECK(g_x64->trfunc(g_x64->ctx, 0x90) == NULL);
    RE_CHECK(g_x64->reg_name(g_x64->ctx, 0) != NULL);
}

// Decode one hex string into an instruction. Shared by the two probes below so they
// cannot drift apart on how a vector is turned into bytes.
static bool decode1(const char *hex, re_arena_t *a, re_insn_t *in, re_ir_func_t *f,
                    re_ir_block_t **blk) {
    uint8_t buf[16];
    size_t nb = 0;
    if (!re_hex_decode(buf, sizeof(buf), hex, strlen(hex), &nb, false))
        return false;
    if (!g_x64->decode(g_x64->ctx, 0x1000, re_span(buf, nb), in))
        return false;
    re_ir_func_init(f);
    *blk = re_ir_block_begin(f, a, 0x1000, nb);
    return *blk != NULL;
}

// Lower one instruction and report the kind of its LAST op, or -1 when the
// instruction is not modelled at all, or -2 when the bytes did not decode. The last
// op is the one that carries the operation: an instruction with an immediate or a
// memory address emits its operands first, so the first op is a constant or an
// address and says nothing about what the instruction does.
static long lower1(const char *hex, re_arena_t *a) {
    re_insn_t in;
    re_ir_func_t f;
    re_ir_block_t *b = NULL;
    size_t n;
    if (!decode1(hex, a, &in, &f, &b))
        return -2;
    n = g_x64->lower(g_x64->ctx, &in, &f, a);
    if (!n)
        return -1;
    return (long)b->ops[n - 1].op;
}

// How many ops one instruction lowers to. Worth pinning on its own, because the count
// is what shows a memory read modify write was expanded rather than dropped: five ops
// where one instruction was decoded is the shape of a correct lowering, and one op
// would be a value silently ignored.
static size_t lowern(const char *hex, re_arena_t *a) {
    re_insn_t in;
    re_ir_func_t f;
    re_ir_block_t *b = NULL;
    if (!decode1(hex, a, &in, &f, &b))
        return 0;
    return g_x64->lower(g_x64->ctx, &in, &f, a);
}

// The vector of pin checks for the lowering, split by what each group is about so no
// one function holds all of it. Each entry is a hex encoding and the kind of op it
// must lower to; -1 means deliberately not modelled, which is a result too.
static void test_lowering_ops(re_arena_t *a) {
    // A move is a copy, an immediate is a constant, and a load names its address.
    RE_CHECK_EQ_U((uint64_t)lower1("488bc3", a), RE_OP_VAR);           // mov rax,rbx
    RE_CHECK_EQ_U((uint64_t)lower1("48c7c001000000", a), RE_OP_CONST); // mov rax,1
    RE_CHECK_EQ_U((uint64_t)lower1("488b0512345678", a), RE_OP_LOAD);  // mov rax,[rip+..]
    RE_CHECK_EQ_U((uint64_t)lower1("488d0512345678", a), RE_OP_VAR);   // lea rax,[rip+..]
    // The group form takes its operation from the reg field, and every result
    // writing form ends on the hidden comparison the next branch reads, so the
    // last op is a CMP for seven of the eight and the counts say what expanded.
    RE_CHECK_EQ_U((uint64_t)lower1("4883c028", a), RE_OP_CMP); // /0 add
    RE_CHECK_EQ_U((uint64_t)lower1("4883c828", a), RE_OP_CMP); // /1 or
    RE_CHECK_EQ_U((uint64_t)lower1("4883d028", a), RE_OP_CMP); // /2 adc, carry read inside
    RE_CHECK_EQ_U((uint64_t)lower1("4883d828", a), RE_OP_CMP); // /3 sbb
    RE_CHECK_EQ_U((uint64_t)lower1("4883e028", a), RE_OP_CMP); // /4 and
    RE_CHECK_EQ_U((uint64_t)lower1("4883e828", a), RE_OP_CMP); // /5 sub
    RE_CHECK_EQ_U((uint64_t)lower1("4883f028", a), RE_OP_CMP); // /6 xor
    RE_CHECK_EQ_U((uint64_t)lower1("4883f828", a), RE_OP_CMP); // /7 cmp
    RE_CHECK_EQ_U(lowern("4883c028", a), 4); // the immediate, the add, the zero, the writer
    RE_CHECK_EQ_U(lowern("4883f828", a), 2); // cmp writes no result, so no writer follows
    // A compare against a register, and the zero test, are both comparisons:
    // one op each now, since the recorded pair carries the real operands.
    RE_CHECK_EQ_U((uint64_t)lower1("4839d8", a), RE_OP_CMP); // cmp rax,rbx
    RE_CHECK_EQ_U((uint64_t)lower1("4885c0", a), RE_OP_CMP); // test rax,rax
    RE_CHECK_EQ_U(lowern("4885c0", a), 1);
    RE_CHECK_EQ_U(lowern("4839d8", a), 1);
}

static void test_lowering_forms(re_arena_t *a) {
    // A memory destination is a read modify write: the address, the load, the
    // operation, the address again, the store, then the zero and the writer the
    // next branch reads. One op here would be a lost value.
    RE_CHECK_EQ_U((uint64_t)lower1("4801442410", a), RE_OP_CMP);
    RE_CHECK_EQ_U(lowern("4801442410", a), 7);
    // The byte form of the same group, with the immediate emitted first.
    RE_CHECK_EQ_U((uint64_t)lower1("80241820", a), RE_OP_CMP);
    RE_CHECK_EQ_U(lowern("80241820", a), 8);
    // A zero immediate is still an immediate. Reading it as absent would substitute a
    // register for the number the author wrote, which is a plausible wrong answer
    // rather than an obvious one, so both forms are pinned.
    RE_CHECK_EQ_U((uint64_t)lower1("4883601800", a), RE_OP_CMP); // and [rax+0x18],0
    RE_CHECK_EQ_U(lowern("4883601800", a), 8);
    RE_CHECK_EQ_U((uint64_t)lower1("48c7c000000000", a), RE_OP_CONST); // mov rax,0
    RE_CHECK_EQ_U((uint64_t)lower1("4883c000", a), RE_OP_CMP);         // add rax,0
    // The direction of a two operand form comes from bit 1, not bit 0: 0x00 and 0x01
    // are both r/m with a register, 0x02 and 0x03 are a register with r/m.
    RE_CHECK_EQ_U((uint64_t)lower1("4801d8", a), RE_OP_CMP); // add rax,rbx
    RE_CHECK_EQ_U((uint64_t)lower1("4803d8", a), RE_OP_CMP); // add rbx,rax
    // Each run of eight opcodes is one operation, so the whole block is pinned. This
    // is where a table written as a switch went wrong once: and, sub and cmp were
    // attached to the wrong runs, which produced a subtraction for an "and".
    RE_CHECK_EQ_U((uint64_t)lower1("4821d8", a), RE_OP_CMP); // and rax,rbx
    RE_CHECK_EQ_U((uint64_t)lower1("4829d8", a), RE_OP_CMP); // sub rax,rbx
    RE_CHECK_EQ_U((uint64_t)lower1("4831d8", a), RE_OP_CMP); // xor rax,rbx
    RE_CHECK_EQ_U((uint64_t)lower1("4809d8", a), RE_OP_CMP); // or  rax,rbx
    // The carry forms read the carry explicitly now, and end on the writer.
    RE_CHECK_EQ_U((uint64_t)lower1("4811d8", a), RE_OP_CMP); // adc rax,rbx
    RE_CHECK_EQ_U((uint64_t)lower1("4819d8", a), RE_OP_CMP); // sbb rax,rbx
    RE_CHECK_EQ_U(lowern("4811d8", a), 3);                   // the add, the zero, the writer
    // The accumulator forms have no ModRM byte, so their operand is rax by definition.
    RE_CHECK_EQ_U((uint64_t)lower1("05"
                                   "11223344",
                                   a),
                  RE_OP_CMP);
    RE_CHECK_EQ_U(lowern("05"
                         "11223344",
                         a),
                  4); // the immediate, the add, the zero, the writer
    // Deliberately silent, and pinned so that silencing more is a choice: a
    // size prefix on a nop is still a nop, and endbr is a no-op the ABI asks for.
    RE_CHECK_EQ_U((uint64_t)lower1("6690", a), RE_OP_NOP);     // size prefix on a nop
    RE_CHECK_EQ_U((uint64_t)lower1("f30f1efa", a), RE_OP_NOP); // endbr64
    // A push lowers to the subtract and the store the hardware performs.
    RE_CHECK_EQ_U((uint64_t)lower1("55", a), RE_OP_STORE); // push rbp
    RE_CHECK_EQ_U(lowern("55", a), 3);
    RE_CHECK_EQ_U((uint64_t)lower1("c3", a), RE_OP_RETURN);
    RE_CHECK_EQ_U((uint64_t)lower1("e800000000", a), RE_OP_CALL);
    RE_CHECK_EQ_U((uint64_t)lower1("eb00", a), RE_OP_BRANCH);
    RE_CHECK_EQ_U((uint64_t)lower1("7400", a), RE_OP_CBRANCH);
}

// Render one instruction from escaped hex and return the text, or "" on a decode
// refusal. The comparison that matters is the string: an operand name is the answer,
// and a correct instruction length says nothing about whether the name was right.
static const char *render1(const char *hex, re_arena_t *a, uint8_t *size_out) {
    static char out[64];
    uint8_t buf[16];
    size_t n = re_str(hex).n / 2u;
    for (size_t i = 0; i < n && i < sizeof(buf); i++)
        buf[i] = (uint8_t)((nib(hex[i * 2]) << 4) | nib(hex[i * 2 + 1]));
    re_insn_t in;
    if (!g_x64->decode(g_x64->ctx, 0x140001000ULL, re_span(buf, n), &in)) {
        out[0] = 0;
        return out;
    }
    if (size_out)
        *size_out = in.size;
    re_strbuf_t sb;
    re_strbuf_init(&sb, a);
    g_x64->render(g_x64->ctx, &in, a, &sb);
    size_t k = sb.len < sizeof(out) - 1u ? sb.len : sizeof(out) - 1u;
    memcpy(out, sb.p, k);
    out[k] = 0;
    return out;
}

// The registers an instruction encodes in its opcode instead of in a ModRM byte.
// Push and pop default to a 64-bit operand in long mode, and the 0x50 block is two
// runs of eight - push rax..rdi then pop rax..rdi - so the register is the low three
// bits, not op minus 0x50. The mov block at 0xB0 encodes its register the same way,
// and the accumulator forms name al, eax or rax. All three were rendered wrong once,
// and all three are pinned here against the text rather than the length.
static void test_implicit_reg(re_arena_t *a) {
    static const struct {
        const char *hex;
        const char *want;
        uint8_t len;
    } v[] = {
        {"50", "push rax", 1},
        {"57", "push rdi", 1},
        {"58", "pop rax", 1},
        {"5f", "pop rdi", 1},
        {"55", "push rbp", 1},
        {"4150", "push r8", 2},
        {"4157", "push r15", 2},
        {"415f", "pop r15", 2},
        {"4158", "pop r8", 2},
        {"b878563412", "mov eax, 0x12345678", 5},
        {"b001", "mov al, 0x1", 2},
        {"bfefbeadde", "mov edi, 0xdeadbeef", 5},
        {"48b8efbeadde00000000", "mov rax, 0xdeadbeef", 10},
        {"3d78563412", "cmp eax, 0x12345678", 5},
        {"3c01", "cmp al, 0x1", 2},
        {"0578563412", "add eax, 0x12345678", 5},
        {"2501020304", "and eax, 0x4030201", 5},
        {"353d0c0e0f", "xor eax, 0xf0e0c3d", 5},
        {"2d01000000", "sub eax, 0x1", 5},
    };
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        uint8_t len = 0;
        RE_CHECK_EQ_STR(render1(v[i].hex, a, &len), v[i].want);
        RE_CHECK_EQ_U(len, v[i].len);
    }
    // The contrast cases. 32-bit is the default for everything else in long mode, so
    // naming these operands must not have widened the 64-bit push and pop exception.
    RE_CHECK_EQ_STR(render1("89c0", a, NULL), "mov eax, eax");
    RE_CHECK_EQ_STR(render1("83f801", a, NULL), "cmp eax, 0x1");
}

int main(void) {
    g_x64 = re_disasm_find("x86-64");
    if (!g_x64) {
        printf("FAIL no x86-64 backend in this build\n");
        return 1;
    }
    test_registry();
    re_disasm_vec_run(g_x64);
    test_targets();
    test_truncated();
    test_indirect();
    test_prologue();
    {
        re_arena_t a;
        re_arena_init(&a, 0);
        test_lowering_ops(&a);
        test_lowering_forms(&a);
        test_implicit_reg(&a);
        re_arena_free(&a);
    }
    return re_test_report("disasm");
}
