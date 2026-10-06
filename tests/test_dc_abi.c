// test_dc_abi.c - a kernel PE is Microsoft x64, and a save is not a parameter.
// Module: test (C11).
// Owns: the FLTMGR force and the shadow-slot rule.
// Depends: re_stack. A PE with no kernel import keeps the scorer's answer.
#include "re_test.h"

#include <string.h>

#include "features/code/re_stack.h"
#include "utils/mem/re_arena.h"
#include "utils/text/re_str.h"

int re_test_count = 0;
int re_test_fail = 0;

static re_pe_t image(re_arena_t *a, const char *dll) {
    re_pe_t pe;
    re_pe_imp_t im;
    memset(&pe, 0, sizeof(pe));
    pe.valid = true;
    pe.pe32plus = true;
    re_vec_init(&pe.imports, sizeof(re_pe_imp_t));
    memset(&im, 0, sizeof(im));
    im.dll = re_str(dll);
    RE_VEC_PUSH(&pe.imports, a, im);
    return pe;
}

static re_stack_t saved_rbx(void) {
    re_stack_t s;
    memset(&s, 0, sizeof(s));
    s.cc = RE_CC_SYSV;
    s.n_params = 2;
    s.arg_regs[0] = 0; // rdi, callee-saved on Windows
    s.arg_regs[1] = 2; // rdx
    s.n_slots = 3;
    s.slots[0] = 8;
    s.slots[1] = 0x20;
    s.slots[2] = -16;
    s.n_locals = 3;
    return s;
}

static void check_fltmgr(void) {
    re_arena_t a;
    re_pe_t pe;
    re_arena_init(&a, 4096);
    pe = image(&a, "FLTMGR.SYS");
    re_stack_t s = saved_rbx();
    uint32_t i;
    RE_CHECK(re_stack_image_ms64(&pe));
    re_stack_apply_image(&s, &pe);
    RE_CHECK_EQ_U(s.cc, RE_CC_MS64);
    RE_CHECK(re_str_eq_cstr(re_str(re_cc_name(s.cc)), "ms64"));
    RE_CHECK(s.homed);
    RE_CHECK_EQ_U(s.n_slots, 1);
    RE_CHECK_EQ_U((uint32_t)s.slots[0], (uint32_t)-16);
    for (i = 0; i < s.n_params; i++) {
        const char *n = re_cc_arg_reg_name(s.cc, s.arg_regs[i]);
        RE_CHECK(!re_str_eq_cstr(re_str(n), "rbx"));
        RE_CHECK(!re_str_eq_cstr(re_str(n), "rdi"));
    }
    RE_CHECK_EQ_U(s.n_params, 1);
    RE_CHECK(re_str_eq_cstr(re_str(re_cc_arg_reg_name(s.cc, s.arg_regs[0])), "rdx"));
    re_arena_free(&a);
}

static void check_user_pe_unchanged(void) {
    re_arena_t a;
    re_pe_t pe;
    re_arena_init(&a, 4096);
    pe = image(&a, "KERNEL32.dll");
    pe.subsystem = 3;
    re_stack_t s = saved_rbx();
    RE_CHECK(re_stack_image_ms64(&pe));
    re_stack_apply_image(&s, &pe);
    RE_CHECK_EQ_U(s.cc, RE_CC_MS64);
    pe.subsystem = 0;
    s = saved_rbx();
    RE_CHECK(!re_stack_image_ms64(&pe));
    re_stack_apply_image(&s, &pe);
    RE_CHECK_EQ_U(s.cc, RE_CC_SYSV);
    re_arena_free(&a);
}

static void check_return(void) {
    re_stack_t s;
    memset(&s, 0, sizeof(s));
    RE_CHECK(re_str_eq_cstr(re_str(re_cc_ret_type(&s)), "uint64_t "));
    s.ret_xmm = true;
    RE_CHECK(re_str_eq_cstr(re_str(re_cc_ret_type(&s)), "double "));
}

int main(void) {
    check_fltmgr();
    check_user_pe_unchanged();
    check_return();
    return re_test_report("dc_abi");
}
