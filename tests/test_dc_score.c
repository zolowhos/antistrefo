// test_dc_score.c - corpus score for decompiled callees and control flow.
// Module: test (C11).
// Owns: the dc-score line and the hit rule for one fixture record.
// Depends: re_decompile, re_func, re_stack, re_xref. A missing fixture skips.
#include "re_test.h"

#include <stdio.h>
#include <string.h>

#include "features/code/re_func.h"
#include "features/code/re_stack.h"
#include "features/code/re_xref.h"
#include "features/dec/re_decompile.h"
#include "features/meta/re_disasm.h"
#include "features/pe/re_pe.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_buf.h"
#include "utils/text/re_str.h"

int re_test_count = 0;
int re_test_fail = 0;

// A hit names every required callee and does not admit the two shapes this plan
// treats as unreadability: an unbound indirect branch, or flag math on a restore.
static bool is_hit(const char *src, char callees[][64], unsigned n) {
    unsigned i;
    if (!src)
        return false;
    if (strstr(src, "goto 0x") || strstr(src, "+ cf"))
        return false;
    for (i = 0; i < n; i++) {
        if (!strstr(src, callees[i]))
            return false;
    }
    return true;
}

static void check_hit_rule(void) {
    char one[1][64];
    memcpy(one[0], "IoCompleteRequest", 18);
    RE_CHECK(is_hit("IoCompleteRequest(a, b);", one, 1));
    RE_CHECK(!is_hit("goto 0x1400 IoCompleteRequest", one, 1));
    RE_CHECK(!is_hit("v13 = v4 + 32 + cf;", one, 1));
    RE_CHECK(!is_hit("return v10;", one, 1));
}

static bool open_list(FILE **out) {
    static const char *const kPaths[] = {"tests/dc_score.txt", "dc_score.txt"};
    unsigned i;
    for (i = 0; i < 2; i++) {
        FILE *fh = fopen(kPaths[i], "rb");
        if (fh) {
            *out = fh;
            return true;
        }
    }
    return false;
}

static bool parse_va(const char *s, uint64_t *va) {
    unsigned long long v = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;
    if (!*s)
        return false;
    while (*s) {
        unsigned d;
        if (*s >= '0' && *s <= '9')
            d = (unsigned)(*s - '0');
        else if (*s >= 'a' && *s <= 'f')
            d = (unsigned)(*s - 'a' + 10);
        else if (*s >= 'A' && *s <= 'F')
            d = (unsigned)(*s - 'A' + 10);
        else
            return false;
        v = (v << 4) | d;
        s++;
    }
    *va = v;
    return true;
}

// One record's source, or NULL when the image or the function cannot be opened.
// A miss still counts in the denominator: the corpus asked and we could not name it.
static const char *decompile_at(re_arena_t *a, const char *path, uint64_t va) {
    re_file_t file;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_xrefset_t xs;
    re_stack_t st;
    re_decomp_t d;
    re_strbuf_t text;
    long idx;
    const re_disasm_t *dis = re_disasm_find("x86-64");
    if (re_file_open(path, a, &file) != RE_OK)
        return NULL;
    if (re_pe_parse(file.whole, a, &pe) != RE_OK || !pe.valid) {
        re_file_close(&file);
        return NULL;
    }
    if (!dis || !re_code_init(&code, file.whole, &pe, dis, a)) {
        re_file_close(&file);
        return NULL;
    }
    re_func_scan(&code, a, &scan);
    idx = re_func_index_of(&scan, va);
    if (idx < 0) {
        re_file_close(&file);
        return NULL;
    }
    re_xref_build(&code, &scan, &pe, a, &xs);
    re_stack_analyze(&code, RE_VEC_PTR(&scan.funcs, re_func_t, (size_t)idx), a, &st);
    d.code = &code;
    d.xrefs = &xs;
    d.arena = a;
    re_strbuf_init(&text, a);
    re_decompile_func(&d, RE_VEC_PTR(&scan.funcs, re_func_t, (size_t)idx), &st, &text);
    re_file_close(&file);
    return text.p;
}

static unsigned split_words(char *line, char **words, unsigned cap) {
    unsigned n = 0;
    char *p = line;
    while (*p && n < cap) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
            p++;
        if (!*p || *p == '#')
            break;
        words[n++] = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
            p++;
        if (*p)
            *p++ = '\0';
    }
    return n;
}

static void score_list(FILE *fh, unsigned *hits, unsigned *total) {
    char line[1024];
    while (fgets(line, sizeof(line), fh)) {
        char *words[8];
        char callees[6][64];
        unsigned n, i;
        uint64_t va = 0;
        re_arena_t a;
        const char *src;
        n = split_words(line, words, 8);
        if (n < 2 || !parse_va(words[1], &va))
            continue;
        for (i = 0; i + 2 < n && i < 6; i++) {
            snprintf(callees[i], sizeof(callees[i]), "%s", words[i + 2]);
        }
        *total += 1;
        re_arena_init(&a, 8u << 20);
        src = decompile_at(&a, words[0], va);
        if (is_hit(src, callees, n > 2 ? n - 2 : 0))
            *hits += 1;
        re_arena_free(&a);
    }
}

int main(void) {
    FILE *fh = NULL;
    unsigned hits = 0;
    unsigned total = 0;
    check_hit_rule();
    if (!open_list(&fh)) {
        printf("dc-score: 0/0\n");
        return re_test_report("dc_score");
    }
    score_list(fh, &hits, &total);
    fclose(fh);
    printf("dc-score: %u/%u\n", hits, total);
    return re_test_report("dc_score");
}
