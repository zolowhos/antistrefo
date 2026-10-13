// test_disasm_arm64.c - content pins for the Capstone ARM-64 backend.
// Module: test (C11).
// Owns: size, control-flow flags, targets, prologue and render checks for arm64.
// Depends: re_disasm through the vtable only. No Capstone header in this file.
#include "re_test.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "features/meta/re_disasm.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_buf.h"
#include "utils/text/re_strbuf.h"

#ifdef RE_ENABLE_CAPSTONE

static const re_disasm_t *g_arm;

static bool dec(const uint8_t *b, size_t n, uint64_t addr, re_insn_t *in) {
    return g_arm->decode(g_arm->ctx, addr, re_span(b, n), in);
}

static void test_machine_map(void) {
    RE_CHECK(strcmp(re_disasm_for_machine(0x8664), "x86-64") == 0);
    RE_CHECK(strcmp(re_disasm_for_machine(0x014c), "x86") == 0);
    RE_CHECK(strcmp(re_disasm_for_machine(0xAA64), "arm64") == 0);
    RE_CHECK(re_disasm_for_machine(0x01c4) == NULL);
}

static void test_basic(void) {
    re_insn_t in;
    static const uint8_t kRet[4] = {0xc0, 0x03, 0x5f, 0xd6};
    static const uint8_t kNop[4] = {0x1f, 0x20, 0x03, 0xd5};
    static const uint8_t kMov[4] = {0xe0, 0x03, 0x01, 0xaa}; // mov x0, x1
    RE_CHECK(dec(kRet, 4, 0x1000, &in));
    RE_CHECK_EQ_U(in.size, 4);
    RE_CHECK(in.is_return);
    RE_CHECK(!in.is_call);
    RE_CHECK(!in.is_branch);
    RE_CHECK(dec(kNop, 4, 0x1000, &in));
    RE_CHECK_EQ_U(in.size, 4);
    RE_CHECK(!in.is_return && !in.is_call && !in.is_branch);
    RE_CHECK(dec(kMov, 4, 0x1000, &in));
    RE_CHECK_EQ_U(in.size, 4);
    RE_CHECK(!in.is_branch);
}

static void test_branches(void) {
    re_insn_t in;
    static const uint8_t kBl[4] = {0x01, 0x00, 0x00, 0x94};  // bl +4
    static const uint8_t kB[4] = {0x02, 0x00, 0x00, 0x14};   // b +8
    static const uint8_t kCbz[4] = {0x40, 0x00, 0x00, 0xb4}; // cbz x0, +8
    static const uint8_t kBr[4] = {0x00, 0x00, 0x1f, 0xd6};  // br x0
    static const uint8_t kBlr[4] = {0x00, 0x00, 0x3f, 0xd6}; // blr x0
    RE_CHECK(dec(kBl, 4, 0x1000, &in));
    RE_CHECK(in.is_call);
    RE_CHECK(in.has_target);
    RE_CHECK_EQ_HEX(in.target, 0x1004ULL);
    RE_CHECK(dec(kB, 4, 0x1000, &in));
    RE_CHECK(in.is_branch);
    RE_CHECK(!in.is_conditional);
    RE_CHECK(in.has_target);
    RE_CHECK_EQ_HEX(in.target, 0x1008ULL);
    RE_CHECK(dec(kCbz, 4, 0x1000, &in));
    RE_CHECK(in.is_branch);
    RE_CHECK(in.is_conditional);
    RE_CHECK(in.has_target);
    RE_CHECK_EQ_HEX(in.target, 0x1008ULL);
    RE_CHECK(dec(kBr, 4, 0x1000, &in));
    RE_CHECK(in.is_branch);
    RE_CHECK(!in.has_target);
    RE_CHECK(dec(kBlr, 4, 0x1000, &in));
    RE_CHECK(in.is_call);
    RE_CHECK(!in.has_target);
}

static void test_truncated(void) {
    re_insn_t in;
    static const uint8_t kRet[4] = {0xc0, 0x03, 0x5f, 0xd6};
    RE_CHECK(!dec(kRet, 0, 0x1000, &in));
    RE_CHECK(!dec(kRet, 1, 0x1000, &in));
    RE_CHECK(!dec(kRet, 2, 0x1000, &in));
    RE_CHECK(!dec(kRet, 3, 0x1000, &in));
}

static void test_prologue(void) {
    static const uint8_t kStp[4] = {0xfd, 0x7b, 0xbf, 0xa9}; // stp x29,x30,[sp,#-16]!
    static const uint8_t kSub[4] = {0xff, 0x43, 0x00, 0xd1}; // sub sp,sp,#0x10
    static const uint8_t kRet[4] = {0xc0, 0x03, 0x5f, 0xd6};
    RE_CHECK(g_arm->is_prologue(g_arm->ctx, 0x1000, re_span(kStp, 4)));
    RE_CHECK(g_arm->is_prologue(g_arm->ctx, 0x1000, re_span(kSub, 4)));
    RE_CHECK(!g_arm->is_prologue(g_arm->ctx, 0x1000, re_span(kRet, 4)));
}

static void test_render_and_regs(void) {
    re_arena_t a;
    re_strbuf_t sb;
    re_insn_t in;
    static const uint8_t kRet[4] = {0xc0, 0x03, 0x5f, 0xd6};
    static const uint8_t kBl[4] = {0x01, 0x00, 0x00, 0x94};
    static const uint8_t kBr[4] = {0x00, 0x00, 0x1f, 0xd6};
    re_arena_init(&a, 0);
    RE_CHECK(dec(kRet, 4, 0x1000, &in));
    re_strbuf_init(&sb, &a);
    g_arm->render(g_arm->ctx, &in, &a, &sb);
    RE_CHECK(sb.p != NULL);
    RE_CHECK(strcmp(sb.p, "ret") == 0);
    RE_CHECK(dec(kBl, 4, 0x1000, &in));
    re_strbuf_init(&sb, &a);
    g_arm->render(g_arm->ctx, &in, &a, &sb);
    RE_CHECK(sb.p != NULL);
    RE_CHECK(strncmp(sb.p, "bl #0x", 6) == 0);
    RE_CHECK(strstr(sb.p, "1004") != NULL);
    RE_CHECK(dec(kBr, 4, 0x1000, &in));
    re_strbuf_init(&sb, &a);
    g_arm->render(g_arm->ctx, &in, &a, &sb);
    RE_CHECK(strcmp(sb.p, "br <indirect>") == 0);
    // Compact Capstone ids that fit in re_insn_t's uint8_t fields.
    RE_CHECK(strcmp(g_arm->reg_name(g_arm->ctx, 2), "fp") == 0);
    RE_CHECK(strcmp(g_arm->reg_name(g_arm->ctx, 3), "lr") == 0);
    RE_CHECK(strcmp(g_arm->reg_name(g_arm->ctx, 5), "sp") == 0);
    RE_CHECK_EQ_U(g_arm->reg_size(g_arm->ctx, 2), 8);
    RE_CHECK(g_arm->lower(g_arm->ctx, &in, NULL, &a) == 0);
    re_arena_free(&a);
}

void re_disasm_arm64_run(void) {
    g_arm = re_disasm_find("arm64");
    if (!g_arm) {
        printf("FAIL no arm64 backend in this Capstone build\n");
        re_test_fail++;
        re_test_count++;
        return;
    }
    RE_CHECK(g_arm->mode == 64);
    test_machine_map();
    test_basic();
    test_branches();
    test_truncated();
    test_prologue();
    test_render_and_regs();
}

#else

void re_disasm_arm64_run(void) {
    // Capstone-off builds still expose the PE machine map, and arm64 must be absent.
    RE_CHECK(strcmp(re_disasm_for_machine(0xAA64), "arm64") == 0);
    RE_CHECK(re_disasm_find("arm64") == NULL);
}

#endif
