// test_disasm_vec.c - the pinned encodings: one real instruction per vector.
// Module: test (C11).
// Owns: the length, flag and refusal vectors the decoder is checked against.
// Depends: re_disasm.h through the vtable, so the vectors are checked at the same
// seam a caller uses. Split from the suite because the table grew past the
// point where the suite could hold it and still stay inside the file cap.
#include "re_test.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "features/meta/re_disasm.h"
#include "utils/mem/re_arena.h"
#include "utils/text/re_str.h"
#include "utils/text/re_strbuf.h"

typedef struct {
    const char *name;
    const char *bytes; // escaped hex, two characters per byte
    uint8_t len;       // instruction length in bytes
    bool call;
    bool branch;
    bool cond;
    bool ret;
} vec_t;

// Each entry pins one encoding: the length first, because a wrong length
// desynchronises every instruction after it, then the control flow flags. The
// group in the middle was added after a differential run against objdump over
// eight real binaries found the length of every one of them wrong.
static const vec_t kVec[] = {
    {"push rbp", "55", 1, false, false, false, false},
    {"pop rbp", "5d", 1, false, false, false, false},
    {"mov rbp,rsp", "4889e5", 3, false, false, false, false},
    {"mov rbp,rsp via mov", "488bec", 3, false, false, false, false},
    {"sub rsp,0x28", "4883ec28", 4, false, false, false, false},
    {"sub rsp,0x1234", "4881ec34120000", 7, false, false, false, false},
    {"add rsp,0x28", "4883c428", 4, false, false, false, false},
    {"leave", "c9", 1, false, false, false, false},
    {"ret", "c3", 1, false, false, false, true},
    {"ret 0x10", "c21000", 3, false, false, false, true},
    {"endbr64", "f30f1efa", 4, false, false, false, false},
    {"endbr32", "f30f1efb", 4, false, false, false, false},
    {"nop", "90", 1, false, false, false, false},
    {"multi byte nop", "0f1f440000", 5, false, false, false, false},
    {"int3", "cc", 1, false, false, false, false},
    {"call rel32", "e801000000", 5, true, false, false, false},
    {"jmp rel8", "eb01", 2, false, true, false, false},
    {"jmp rel32", "e901000000", 5, false, true, false, false},
    {"je rel8", "7401", 2, false, true, true, false},
    {"jne rel8", "7501", 2, false, true, true, false},
    {"je rel32", "0f8401000000", 6, false, true, true, false},
    {"jg rel32", "0f8f01000000", 6, false, true, true, false},
    {"loop", "e2fe", 2, false, true, true, false},
    {"jrcxz rel8", "e3fe", 2, false, true, true, false},
    {"jecxz rel8", "67e3fe", 3, false, true, true, false},
    {"mov eax,imm32", "b811223344", 5, false, false, false, false},
    {"movabs rax,imm64", "48b81122334455667788", 10, false, false, false, false},
    {"mov al,imm8", "b011", 2, false, false, false, false},
    {"mov rax,[rip+0x1234]", "488b0534120000", 7, false, false, false, false},
    {"mov rax,[rbp+8]", "488b4508", 4, false, false, false, false},
    {"mov rax,[rbp-8]", "488b45f8", 4, false, false, false, false},
    {"mov rbx,[rsp+0x28]", "488b5c2428", 5, false, false, false, false},
    {"mov [rbp-0x28],rbx", "48895dd8", 4, false, false, false, false},
    {"cmp qword [rbp+0x20],0", "48837d2000", 5, false, false, false, false},
    {"cmp byte [rax],0", "803800", 3, false, false, false, false},
    {"movzx eax,byte [rax]", "0fb600", 3, false, false, false, false},
    {"test eax,eax", "85c0", 2, false, false, false, false},
    {"movsxd rax,dword [rbp+4]", "48634504", 4, false, false, false, false},
    {"imul eax,[rbp+4],3", "69450403000000", 7, false, false, false, false},
    {"imul eax,[rbp+4],imm8", "6b450403", 4, false, false, false, false},
    {"push imm8", "6a10", 2, false, false, false, false},
    {"push imm32", "6811223344", 5, false, false, false, false},
    {"xchg rax,rbx", "4893", 2, false, false, false, false},
    {"bswap rax", "480fc8", 3, false, false, false, false},
    {"setz al", "0f94c0", 3, false, false, false, false},
    {"cmovz rax,rbx", "480f44c3", 4, false, false, false, false},
    {"syscall", "0f05", 2, false, false, false, false},
    {"ud2", "0f0b", 2, false, false, false, false},
    {"ud0", "0fff00", 3, false, false, false, false},
    {"cpuid", "0fa2", 2, false, false, false, false},
    {"rdtsc", "0f31", 2, false, false, false, false},
    // iretq returns, but it is not classified as one: the flag drives the IR's
    // return op, and a privilege changing return is not the same operation.
    {"iretq", "cf", 1, false, false, false, false},
    {"insb", "6c", 1, false, false, false, false},
    {"insd", "6d", 1, false, false, false, false},
    {"outsb", "6e", 1, false, false, false, false},
    {"outsd", "6f", 1, false, false, false, false},
    {"mov gs:[0x60],rax", "654889342560000000", 9, false, false, false, false},
    {"opsize 16 mov ax,[rax]", "668b07", 3, false, false, false, false},
    {"addrsize 32 mov eax,[eax]", "678b00", 3, false, false, false, false},
    {"lock inc dword [rax]", "f0ff00", 3, false, false, false, false},
    {"mov al,[0x1122334455667788]", "a08877665544332211", 9, false, false, false, false},
    {"addrsize 32 mov al,[0x11223344]", "67a044332211", 6, false, false, false, false},
    {"mov rax,cr3", "0f20d8", 3, false, false, false, false},
    {"mov cr3,rax", "0f22d8", 3, false, false, false, false},
    {"vzeroupper", "c5f877", 3, false, false, false, false},
    {"vmovdqu ymm0,[rax]", "c5fe6f00", 4, false, false, false, false},
    {"vmovdqa ymm0,ymm0", "c5f96fc0", 4, false, false, false, false},
    {"vpxor ymm0,ymm1,ymm0", "c5f5efc0", 4, false, false, false, false},
    {"vmovss xmm0,[rax]", "c5fa1000", 4, false, false, false, false},
    {"xor cl,cl", "32c9", 2, false, false, false, false},
    {"xor eax,eax", "31c0", 2, false, false, false, false},
    {"xorps xmm0,xmm0", "0f57c0", 3, false, false, false, false},
    {"pxor xmm0,xmm0", "660fefc0", 4, false, false, false, false},
    {"pshufd xmm0,xmm0,0", "660f70c000", 5, false, false, false, false},
    {"lddqu xmm0,[rax]", "f20ff000", 4, false, false, false, false},
    {"addsubps xmm0,xmm0", "f20fd0c0", 4, false, false, false, false},
    {"psubusb xmm0,xmm0", "660fd8c0", 4, false, false, false, false},
    {"paddq mm0,mm0", "0fd4c0", 3, false, false, false, false},
    {"pmovmskb eax,mm0", "0fd7c0", 3, false, false, false, false},
    {"psadbw xmm0,xmm0", "660ff6c0", 4, false, false, false, false},
    {"movq mm0,mm0", "0f7fc0", 3, false, false, false, false},
    {"call through rax", "ffd0", 2, true, false, false, false},
    {"jmp through rax", "ffe0", 2, false, true, false, false},
    {"call through [rax]", "ff10", 2, true, false, false, false},
    {"push through [rax]", "ff30", 2, false, false, false, false},
    {"pop through [rax]", "8f00", 2, false, false, false, false},
    {"inc byte [rax]", "fe00", 2, false, false, false, false},
    {"xabort", "c6f813", 3, false, false, false, false},
    {"xbegin rel32", "c7f813000000", 6, false, false, false, false},
};

// Encodings the processor faults on rather than executing, so a decoder that
// accepts one invents an instruction out of the bytes that follow and the walk
// loses its place. Every entry here was accepted before the differential run.
static const char *const kReserved[] = {
    "fe5a1900",     // fe /3, only inc and dec exist
    "ffff00",       // ff /7, no encoding at all
    "ffed0b00",     // ff /5 with mod 3, a far jump needs a memory operand
    "ffe80b00",     // ff /5 the same
    "8f09000000",   // 8f /1, pop is reg 0 only
    "c6ce1300",     // c6 /1, no meaning at all
    "c6f01300",     // c6 /6
    "c7ce13000000", // c7 /1
    "c7d213000000", // c7 /2
    "f20f2ec1",     // F2 ucomisd: invalid SIMD encoding
};

static uint8_t nib(char c) {
    if (c >= '0' && c <= '9')
        return (uint8_t)(c - '0');
    return (uint8_t)(c - 'a' + 10);
}

// Decode an escaped hex string, or false when it does not decode. The caller
// decides whether that is a failure or the expected answer.
static bool decode_hex(const re_disasm_t *dis, const char *hex, re_insn_t *in, uint8_t *len) {
    uint8_t buf[16];
    size_t n = re_str(hex).n / 2u;
    for (size_t i = 0; i < n; i++)
        buf[i] = (uint8_t)((nib(hex[i * 2]) << 4) | nib(hex[i * 2 + 1]));
    if (!dis->decode(dis->ctx, 0x140001000ULL, re_span(buf, n), in))
        return false;
    *len = in->size;
    return true;
}

static void check_vectors(const re_disasm_t *dis) {
    for (size_t v = 0; v < sizeof(kVec) / sizeof(kVec[0]); v++) {
        const vec_t *t = &kVec[v];
        re_insn_t in;
        uint8_t len = 0;
        if (2u * (size_t)t->len != (size_t)re_str(t->bytes).n) {
            re_test_count++;
            re_test_fail++;
            printf("FAIL %s: len %u does not match \"%s\"\n", t->name, t->len, t->bytes);
            fflush(stdout);
            continue;
        }
        re_test_count++;
        if (!decode_hex(dis, t->bytes, &in, &len)) {
            re_test_fail++;
            printf("FAIL %s: decode refused \"%s\"\n", t->name, t->bytes);
            fflush(stdout);
            continue;
        }
        if (in.size != t->len) {
            re_test_fail++;
            printf("FAIL %s: length %u, want %u (%s)\n", t->name, in.size, t->len, t->bytes);
            fflush(stdout);
        }
        if (in.is_call != t->call || in.is_branch != t->branch || in.is_conditional != t->cond ||
            in.is_return != t->ret) {
            re_test_fail++;
            printf("FAIL %s: flags c=%d b=%d cond=%d ret=%d, want c=%d b=%d cond=%d "
                   "ret=%d\n",
                   t->name, in.is_call, in.is_branch, in.is_conditional, in.is_return, t->call,
                   t->branch, t->cond, t->ret);
            fflush(stdout);
        }
        // A control flow instruction that claims no target sends the walker off
        // the end of the function, and one that claims a target it does not have
        // sends it into data. Both are checked here rather than per vector.
        if (t->call || t->branch) {
            re_test_count++;
            bool want_target =
                re_str(t->bytes).n > 2u && !(t->bytes[0] == 'f' && t->bytes[1] == 'f');
            if (in.has_target != want_target) {
                re_test_fail++;
                printf("FAIL %s: has_target %d, want %d\n", t->name, in.has_target, want_target);
                fflush(stdout);
            }
        }
    }
}

// The reserved encodings above must be refused, and the neighbouring valid forms
// must not be refused by the same test, or a decoder that refused everything
// would pass this half.
static void check_reserved(const re_disasm_t *dis) {
    for (size_t v = 0; v < sizeof(kReserved) / sizeof(kReserved[0]); v++) {
        re_insn_t in;
        uint8_t len = 0;
        RE_CHECK(!decode_hex(dis, kReserved[v], &in, &len));
    }
    re_insn_t in;
    uint8_t len = 0;
    RE_CHECK(decode_hex(dis, "fe00", &in, &len));
    RE_CHECK_EQ_U(len, 2);
    RE_CHECK(decode_hex(dis, "ff30", &in, &len)); // ff /6 push, mod 0
    RE_CHECK_EQ_U(len, 2);
    RE_CHECK(decode_hex(dis, "c6f81300", &in, &len)); // xabort, the one encoding
    RE_CHECK_EQ_U(len, 3);
}

// Rendered text vectors. The name of an encoding is not its length and not its
// flags, so nothing else here pins it: every entry was checked by hand against the
// manual, and each one covers a case where the opcode alone does not decide the text.
// The decode address is fixed, which is what makes the branch targets below stable.
static const char *const kText[][2] = {
    {"660f10c1", "movupd xmm0, xmm1"},
    {"f30f10c1", "movss xmm0, xmm1"},
    {"f20f10c1", "movsd xmm0, xmm1"},
    {"660f58c1", "addpd xmm0, xmm1"},
    {"660f2ec1", "ucomisd xmm0, xmm1"},
    {"660f5ac1", "cvtpd2ps xmm0, xmm1"},
    {"660f70c005", "pshufd xmm0, xmm0, 0x5"},
    {"f20ff000", "lddqu xmm0, xmmword ptr [rax]"},
    {"660f6f00", "movdqa xmm0, xmmword ptr [rax]"},
    {"670f6f00", "movq mm0, qword ptr [eax]"},
    {"67660f6f00", "movdqa xmm0, xmmword ptr [eax]"},
    {"0fffc0", "ud0 eax, eax"},
    {"660f71d002", "psrlw xmm0, 0x2"},
    {"660f73d803", "psrldq xmm0, 0x3"},
    {"0fbaf803", "btc eax, 0x3"},
    {"0faef0", "mfence"},
    {"660faef0", "tpause eax"},
    {"0f01c9", "mwait"},
    {"0f01f8", "swapgs"},
    {"0f01f0", "lmsw ax"},
    {"0f01e0", "smsw eax"},
    {"0f00c1", "sldt ecx"},
    {"0fc7f0", "rdrand eax"},
    {"0fc7f8", "rdseed eax"},
    {"0f0fc09e", "pfadd mm0, mm0"},
    {"0f0f009e", "pfadd mm0, qword ptr [rax]"},
    {"0f6fc0", "movq mm0, mm0"},
    {"0f7f00", "movq qword ptr [rax], mm0"},
    {"660f7ec0", "movd eax, xmm0"},
    {"660f6ec0", "movd xmm0, eax"},
    {"480f6ec0", "movq mm0, rax"},
    {"660fc4c003", "pinsrw xmm0, eax, 0x3"},
    {"660fc5c003", "pextrw eax, xmm0, 0x3"},
    {"0fc300", "movnti [rax], eax"},
    {"d8c1", "fadd st, st(1)"},
    {"dcc9", "fmul st(1), st"},
    {"d9e0", "fchs"},
    {"dec1", "faddp st(1), st"},
    {"dfe0", "fnstsw ax"},
    {"d900", "fld dword ptr [rax]"},
    {"dd00", "fld qword ptr [rax]"},
    {"db28", "fld tbyte ptr [rax]"},
    {"db38", "fstp tbyte ptr [rax]"},
    {"da00", "fiadd dword ptr [rax]"},
    {"de18", "ficomp word ptr [rax]"},
    {"d918", "fstp dword ptr [rax]"},
    {"d930", "fnstenv [rax]"},
    {"d920", "fldenv [rax]"},
    {"dd38", "fnstsw word ptr [rax]"},
    {"c5f877", "vzeroupper"},
    {"c5fc77", "vzeroall"},
    {"c5f9efc0", "vpxor xmm0, xmm0, xmm0"},
    {"c5f892c0", "kmovw k0, eax"},
    {"7801", "js 0x140001003"},
    {"0f8801000000", "js 0x140001007"},
    {"99", "cdq"},
    {"4899", "cqo"},
    {"6699", "cwd"},
    {"98", "cwde"},
    {"4898", "cdqe"},
    {"6698", "cbw"},
    {"a90100000000", "test eax, 0x1"},
    {"a8ff", "test al, 0xff"},
    {"6a10", "push 0x10"},
    {"6811223344", "push 0x44332211"},
    {"0f20d8", "mov rax, cr3"},
    {"0f22d8", "mov cr3, rax"},
    {"440f20c0", "mov rax, cr8"},
    {"f30fbc01", "tzcnt eax, [rcx]"},
    {"f30fbd01", "lzcnt eax, [rcx]"},
    {"0f38f001", "movbe eax, [rcx]"},
    {"f20f38f001", "crc32 eax, byte ptr [rcx]"},
    {"660f38f601", "adcx eax, [rcx]"},
    {"f30f38f601", "adox eax, [rcx]"},
    {"0fba300000", "btr dword ptr [rax], 0x0"},
    {"0f1c00", "cldemote byte ptr [rax]"},
    {"0f1cc0", "nop eax"},
    {"0f1800", "prefetchnta byte ptr [rax]"},
    {"0f18c0", "nop eax"},
};

// The names a rendering must never carry. Every one of them was a placeholder in an
// opcode map rather than a name, and each reached the text of a real file at some
// point in this work: the group opcodes say "grp" followed by their number, and the
// escapes of the two and three byte maps used to say which escape they came from.
static const char *const kNoPlaceholder[] = {"grp", "esc38", "esc3a", "3dnow", "(bad)"};

static bool starts_with(const char *s, const char *t) {
    size_t n = strlen(t);
    return strncmp(s, t, n) == 0;
}

static void check_text(const re_disasm_t *dis) {
    for (size_t v = 0; v < sizeof(kText) / sizeof(kText[0]); v++) {
        re_arena_t arena;
        re_insn_t in;
        re_strbuf_t sb;
        uint8_t len = 0;
        char got[64];
        size_t n;
        re_arena_init(&arena, 0);
        re_test_count++;
        if (!decode_hex(dis, kText[v][0], &in, &len)) {
            re_test_fail++;
            printf("FAIL text %s: decode refused\n", kText[v][0]);
            fflush(stdout);
            re_arena_free(&arena);
            continue;
        }
        re_strbuf_init(&sb, &arena);
        dis->render(dis->ctx, &in, &arena, &sb);
        n = sb.len < sizeof(got) - 1u ? sb.len : sizeof(got) - 1u;
        memcpy(got, sb.p, n);
        got[n] = 0;
        if (strcmp(got, kText[v][1]) != 0) {
            re_test_fail++;
            printf("FAIL text %s: got \"%s\", want \"%s\"\n", kText[v][0], got, kText[v][1]);
            fflush(stdout);
        }
        re_arena_free(&arena);
    }
}

// The sweep: every opcode of the two byte map, under every legacy prefix, with a
// register operand and a memory one. It is what keeps a placeholder from coming back:
// the vectors above pin the encodings that were fixed, and this covers the ones that
// were never noticed because no real file happened to contain them.
static void check_no_placeholders(const re_disasm_t *dis) {
    static const uint8_t pfx[4][2] = {{0, 0}, {0x66, 0}, {0xF3, 0}, {0xF2, 0}};
    static const uint8_t modrm[2] = {0xC1, 0x00};
    re_arena_t arena;
    re_strbuf_t sb;
    re_arena_init(&arena, 0);
    re_strbuf_init(&sb, &arena);
    for (size_t p = 0; p < 4; p++) {
        for (size_t m = 0; m < 2; m++) {
            for (unsigned op = 0; op < 256u; op++) {
                uint8_t buf[8];
                re_insn_t in;
                size_t i = 0;
                if (pfx[p][0])
                    buf[i++] = pfx[p][0];
                buf[i++] = 0x0F;
                buf[i++] = (uint8_t)op;
                buf[i++] = modrm[m];
                buf[i++] = 0x00;
                buf[i++] = 0x00;
                buf[i++] = 0x00;
                if (!dis->decode(dis->ctx, 0x140001000ULL, re_span(buf, i), &in))
                    continue;
                re_strbuf_clear(&sb);
                dis->render(dis->ctx, &in, &arena, &sb);
                for (size_t k = 0; k < sizeof(kNoPlaceholder) / sizeof(kNoPlaceholder[0]); k++) {
                    re_test_count++;
                    if (starts_with(sb.p, kNoPlaceholder[k])) {
                        re_test_fail++;
                        printf("FAIL placeholder %s: op %02x pfx %u text \"%s\"\n",
                               kNoPlaceholder[k], op, pfx[p][0], sb.p);
                        fflush(stdout);
                    }
                }
            }
        }
    }
    re_arena_free(&arena);
}

// The vector runner. Called from the suite so the vectors live in one place and
// the runner in the other; the seam is the public backend.
void re_disasm_vec_run(const re_disasm_t *dis) {
    check_vectors(dis);
    check_reserved(dis);
    check_text(dis);
    check_no_placeholders(dis);
}
