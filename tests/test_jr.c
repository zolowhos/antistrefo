// test_jr.c - the JSON reader, which is what a protocol server trusts first.
// Module: test (C11).
// Owns: checks on parsing, escaping, and refusing malformed input.
// Depends: re_core through re_jr.h. The malformed cases matter more than the good
// ones: a reader that is lenient about a hostile frame is worse than no reader.
#include "re_test.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "features/code/re_jtable.h"
#include "features/dec/re_decompile.h"
#include "features/meta/re_disasm.h"
#include "features/pe/re_pe.h"
#include "utils/json/re_jr.h"
#include "re_pe_fixture.h"
#include "utils/mem/re_arena.h"
#include "utils/text/re_strbuf.h"

// This suite is its own binary, so it owns its counters.
int re_test_count = 0;
int re_test_fail = 0;

static re_jr_t parse(re_arena_t *a, const char *s) {
    re_jr_t v;
    memset(&v, 0, sizeof(v));
    re_jr_parse(a, s, strlen(s), &v);
    return v;
}

static void test_scalars(re_arena_t *a) {
    re_jr_t v = parse(a, "null");
    RE_CHECK_EQ_U(v.kind, RE_JR_NULL);
    v = parse(a, "true");
    RE_CHECK_EQ_U(v.kind, RE_JR_BOOL);
    RE_CHECK(v.boolean);
    v = parse(a, "false");
    RE_CHECK_EQ_U(v.kind, RE_JR_BOOL);
    RE_CHECK(!v.boolean);
    v = parse(a, "42");
    RE_CHECK_EQ_U(v.kind, RE_JR_NUM);
    RE_CHECK_EQ_U((uint64_t)re_jr_i64(&v, 0), 42);
    v = parse(a, "-7");
    RE_CHECK_EQ_U((uint64_t)re_jr_i64(&v, 0), (uint64_t)-7);
    v = parse(a, "\"text\"");
    RE_CHECK_EQ_U(v.kind, RE_JR_STR);
    RE_CHECK(re_str_eq_cstr(v.str, "text"));
}

// An address does not fit in a double exactly. Reading the raw text rather than the
// double is the whole reason raw is kept, and losing the low bits of a pointer would
// look like a data error in the file rather than a bug here.
static void test_big_int(re_arena_t *a) {
    re_jr_t v = parse(a, "18446744073709551615");
    RE_CHECK_EQ_U(v.kind, RE_JR_NUM);
    RE_CHECK_EQ_U((uint64_t)re_jr_i64(&v, 0), 18446744073709551615ull);
    v = parse(a, "1099511627776");
    RE_CHECK_EQ_U((uint64_t)re_jr_i64(&v, 0), 1099511627776ull);
}

static void test_escapes(re_arena_t *a) {
    re_jr_t v = parse(a, "\"a\\\\b\""); // the JSON text a\b
    RE_CHECK(re_str_eq_cstr(v.str, "a\\b"));
    v = parse(a, "\"a\\nb\"");
    RE_CHECK_EQ_U(v.str.n, 3);
    v = parse(a, "\"\\u0041\"");
    RE_CHECK(re_str_eq_cstr(v.str, "A"));
    // A Windows path is the case that actually comes over the wire, and the backslashes
    // are doubled there. Reading them as single separators is what would break it.
    v = parse(a, "\"C:\\\\dir\\\\f.sys\"");
    RE_CHECK(re_str_eq_cstr(v.str, "C:\\dir\\f.sys"));
}

static void test_containers(re_arena_t *a) {
    re_jr_t v = parse(a, "[1,2,3]");
    RE_CHECK_EQ_U(v.kind, RE_JR_ARR);
    RE_CHECK_EQ_U(v.count, 3);
    RE_CHECK_EQ_U((uint64_t)re_jr_i64(&v.items[2], 0), 3);
    v = parse(a, "{}");
    RE_CHECK_EQ_U(v.kind, RE_JR_OBJ);
    RE_CHECK_EQ_U(v.count, 0);
    v = parse(a, "{\"a\":1,\"b\":\"two\"}");
    RE_CHECK_EQ_U(v.count, 2);
    const re_jr_t *first = re_jr_get(&v, "a");
    RE_CHECK(first != NULL);
    RE_CHECK_EQ_U((uint64_t)re_jr_i64(first, 0), 1);
    RE_CHECK(re_str_eq_cstr(re_jr_str(re_jr_get(&v, "b"), ""), "two"));
    // A missing member and a null member are different answers.
    RE_CHECK(re_jr_get(&v, "zz") == NULL);
    v = parse(a, "{\"n\":null}");
    RE_CHECK(re_jr_has(&v, "n"));
    RE_CHECK(re_jr_get(&v, "n") != NULL);
    v = parse(a, "[[1],[2]]");
    RE_CHECK_EQ_U(v.count, 2);
    RE_CHECK_EQ_U(v.items[1].count, 1);
}

// A frame that is not exactly one value means the stream is out of step. Accepting the
// first value and ignoring the rest is how a protocol server ends up answering a
// request nobody sent.
static void test_refuses(re_arena_t *a) {
    // A single backslash before a letter is not a JSON escape. Written as bytes because
    // a C literal would eat the backslash before it ever reached the reader.
    static const char kBadEsc[] = {'"', '\\', 'q', '"'};
    re_jr_t esc;
    memset(&esc, 0, sizeof(esc));
    RE_CHECK(!re_jr_parse(a, kBadEsc, sizeof(kBadEsc), &esc));
    // The same shape with the backslash doubled is the string backslash-q, and is valid.
    static const char kOkEsc[] = {'"', '\\', '\\', 'q', '"'};
    RE_CHECK(re_jr_parse(a, kOkEsc, sizeof(kOkEsc), &esc));
    static const char *const kBad[] = {
        "",
        "{",
        "}",
        "[1,",
        "{\"a\"}",
        "{\"a\":}",
        "{a:1}",
        "{\"a\":1,}",
        "tru",
        "\"open",
        "01",
        "{}{}",
        "[1] [2]",
        "nul",
        "{\"a\":1",
        "{]",
        "{\"a\":1 \"b\":2}",
    };
    for (size_t i = 0; i < sizeof(kBad) / sizeof(kBad[0]); i++) {
        re_jr_t v;
        memset(&v, 0, sizeof(v));
        // Named rather than indexed, because a refusal that says which input was
        // accepted is the whole point of the check.
        if (re_jr_parse(a, kBad[i], strlen(kBad[i]), &v)) {
            printf("FAIL accepted a malformed frame: %zu\n", i);
            fflush(stdout);
        }
        RE_CHECK(!re_jr_parse(a, kBad[i], strlen(kBad[i]), &v));
    }
    // Depth is bounded, so a frame of open brackets is refused rather than recursing.
    re_jr_t v;
    memset(&v, 0, sizeof(v));
    char deep[128];
    for (int i = 0; i < 100; i++)
        deep[i] = '[';
    RE_CHECK(!re_jr_parse(a, deep, 100, &v));
    // The members of one object are bounded too.
    re_strbuf_t many;
    re_strbuf_init(&many, a);
    re_strbuf_puts(&many, "{\"a\":1");
    for (int i = 0; i < 100; i++)
        re_strbuf_puts(&many, ",\"a\":1");
    re_strbuf_puts(&many, "}");
    RE_CHECK(!re_jr_parse(a, many.p, many.len, &v));
}

static void test_escape_out(re_arena_t *a) {
    re_strbuf_t b;
    re_strbuf_init(&b, a);
    re_jr_escape(&b, re_str("a\"b\\c"));
    RE_CHECK(re_str_eq_cstr(re_strn(b.p, b.len), "\"a\\\"b\\\\c\""));
    re_strbuf_init(&b, a);
    re_jr_escape(&b, re_str("x\ny"));
    RE_CHECK(re_str_eq_cstr(re_strn(b.p, b.len), "\"x\\ny\""));
    re_strbuf_init(&b, a);
    re_jr_escape(&b, re_str(""));
    RE_CHECK(re_str_eq_cstr(re_strn(b.p, b.len), "\"\""));
}

static void test_switch(void) {
    uint8_t img[IMG_BYTES];
    re_arena_t a;
    re_pe_t pe;
    re_code_t code;
    re_func_t f;
    re_decomp_t d;
    re_strbuf_t out;
    re_vec_t tables;
    re_jtable_t jt;
    const char *src;
    unsigned cases = 0;
    build_pe(img);
    re_arena_init(&a, 65536);
    re_span_t span = {img, sizeof(img)};
    RE_CHECK(re_pe_parse(span, &a, &pe) == RE_OK && pe.valid);
    RE_CHECK(re_code_init(&code, span, &pe, re_disasm_find("x86-64"), &a));
    memset(&f, 0, sizeof(f));
    f.va = IMAGE_BASE + TEXT_RVA;
    f.rva = TEXT_RVA;
    f.size = 20;
    f.flags = RE_FUNC_ENTRY | RE_FUNC_RET;
    memset(&d, 0, sizeof(d));
    d.code = &code;
    d.arena = &a;
    re_strbuf_init(&out, &a);
    re_decompile_func(&d, &f, NULL, &out);
    RE_CHECK(out.p && !strstr(out.p, "switch ("));
    memset(&jt, 0, sizeof(jt));
    jt.at = IMAGE_BASE + TEXT_RVA + 0xB;
    jt.table_va = IMAGE_BASE + TEXT_RVA;
    jt.count = 2;
    jt.bound = 2;
    jt.width = 4;
    jt.encoding = 1;
    re_vec_init(&tables, sizeof(jt));
    RE_VEC_PUSH(&tables, &a, jt);
    d.jtables = &tables;
    re_strbuf_init(&out, &a);
    re_decompile_func(&d, &f, NULL, &out);
    src = out.p ? out.p : "";
    RE_CHECK(strstr(src, "switch ("));
    RE_CHECK(!strstr(src, "goto 0x"));
    while ((src = strstr(src, "case ")) != NULL) {
        cases++;
        src += 5;
    }
    RE_CHECK_EQ_U(cases, 2);
    re_arena_free(&a);
}

int main(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    test_scalars(&a);
    test_big_int(&a);
    test_escapes(&a);
    test_containers(&a);
    test_refuses(&a);
    test_escape_out(&a);
    test_switch();
    re_arena_free(&a);
    return re_test_report("jr");
}
