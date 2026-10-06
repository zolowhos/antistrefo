// test_dc_fold.c - the expression folder on a real prologue and a hand built add.
// Module: test (C11).
// Owns: the DriverEntry shape and the displacement fold.
// Depends: re_dc_fold, re_decompile. A missing image skips the prologue check.
#include "re_test.h"

#include <stdio.h>
#include <string.h>

#include "features/code/re_func.h"
#include "features/code/re_stack.h"
#include "features/code/re_xref.h"
#include "features/dec/re_dc_fold.h"
#include "features/dec/re_decompile.h"
#include "features/meta/re_disasm.h"
#include "features/pe/re_pe.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_buf.h"

int re_test_count = 0;
int re_test_fail = 0;

static const char *open_entry(void) {
    static const char *const kPaths[] = {"/workspace/attachments/sys.sys", "sys.sys",
                                         "tests/sys.sys"};
    unsigned i;
    for (i = 0; i < 3; i++) {
        FILE *fh = fopen(kPaths[i], "rb");
        if (fh) {
            fclose(fh);
            return kPaths[i];
        }
    }
    return NULL;
}

static void check_entry(const char *path) {
    re_arena_t a;
    re_file_t file;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_xrefset_t xs;
    re_stack_t st;
    re_decomp_t d;
    re_strbuf_t text;
    long idx;
    const re_func_t *fn;
    unsigned calls = 0;
    const char *p;
    re_arena_init(&a, 8u << 20);
    RE_CHECK(re_file_open(path, &a, &file) == RE_OK);
    RE_CHECK(re_pe_parse(file.whole, &a, &pe) == RE_OK);
    RE_CHECK(re_code_init(&code, file.whole, &pe, re_disasm_find("x86-64"), &a));
    re_func_scan(&code, &a, &scan);
    idx = re_func_index_of(&scan, 0x1402645b8ull);
    RE_CHECK(idx >= 0);
    if (idx < 0) {
        re_arena_free(&a);
        return;
    }
    fn = RE_VEC_PTR(&scan.funcs, re_func_t, (size_t)idx);
    re_xref_build(&code, &scan, &pe, &a, &xs);
    re_stack_analyze(&code, fn, &a, &st);
    d.code = &code;
    d.jtables = NULL;
    d.xrefs = &xs;
    d.arena = &a;
    re_strbuf_init(&text, &a);
    re_decompile_func(&d, fn, &st, &text);
    p = text.p ? text.p : "";
    RE_CHECK(!strstr(p, "local_p"));
    RE_CHECK(!strstr(p, "+ cf"));
    RE_CHECK(!strstr(p, "rsp -"));
    RE_CHECK(!strstr(p, "rsp +"));
    while ((p = strstr(p, "sub_140")) != NULL) {
        calls++;
        p += 7;
    }
    RE_CHECK_EQ_U(calls, 2);
    RE_CHECK(strstr(text.p, "return sub_"));
    re_file_close(&file);
    re_arena_free(&a);
}

static void check_disp(void) {
    re_ir_func_t f;
    re_ir_op_t add, load;
    re_arena_t a;
    re_arena_init(&a, 4096);
    re_ir_func_init(&f);
    re_ir_block_begin(&f, &a, 0x1000, 16);
    memset(&add, 0, sizeof(add));
    add.op = RE_OP_INTADD;
    add.out = re_ir_vn(RE_SPACE_REG, 8, 3);
    add.in[0] = re_ir_vn(RE_SPACE_REG, 8, 1);
    add.in[1] = re_ir_vn(RE_SPACE_CONST, 8, 0);
    add.const_val = 0x18;
    memset(&load, 0, sizeof(load));
    load.op = RE_OP_LOAD;
    load.out = re_ir_vn(RE_SPACE_REG, 8, 0);
    load.in[0] = add.out;
    re_ir_emit(&f, &a, add);
    re_ir_emit(&f, &a, load);
    re_dc_fold(&f);
    RE_CHECK(f.blocks[0].ops[0].op == RE_OP_NOP);
    RE_CHECK(f.blocks[0].ops[1].extra & RE_FOLD_DISP);
    RE_CHECK_EQ_U(f.blocks[0].ops[1].const_val, 0x18);
    RE_CHECK(f.blocks[0].ops[1].op == RE_OP_LOAD);
    re_arena_free(&a);
}

int main(void) {
    const char *path = open_entry();
    check_disp();
    if (path)
        check_entry(path);
    return re_test_report("dc_fold");
}
