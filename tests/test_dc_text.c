// test_dc_text.c - formatted text and condition chains are kept in full.
// Module: test (C11).
// Owns: the pins that a long value is stored whole, and a condition chain is one copy.
// Depends: re_dcx, re_arena. The quadratic copier fails the chain check.
#include "re_test.h"

#include <string.h>

#include "features/dec/core/re_dcx.h"
#include "utils/mem/re_arena.h"
#include "utils/text/re_str.h"

int re_test_count = 0;
int re_test_fail = 0;

// A value longer than a megabyte is the value itself. Replacing it with a short
// marker, or refusing to store it, fails this check.
static void check_text_kept(void) {
    re_arena_t src;
    re_arena_t out;
    char *big;
    dx_val_t v;
    size_t n = (1u << 20) + 7u;
    re_arena_init(&src, 1u << 20);
    re_arena_init(&out, 1u << 16);
    big = (char *)re_arena_alloc(&src, n + 1u);
    RE_CHECK(big != NULL);
    if (big) {
        memset(big, 'a', n);
        big[n] = 0;
    }
    v = dx_text(&out, 0, 1, "%s", big ? big : "");
    RE_CHECK(v.s != NULL && re_str(v.s).n == n);
    RE_CHECK(v.s && v.s[0] == 'a' && v.s[n - 1u] == 'a');
    RE_CHECK(out.total >= n && out.total < n * 4u);
    re_arena_free(&src);
    re_arena_free(&out);
}

static size_t count_leaf(const char *text) {
    const char *p = text;
    size_t n = 0;
    size_t leaf = re_str("x == 0").n;
    while (p && *p) {
        if (re_str(p).n >= leaf && memcmp(p, "x == 0", leaf) == 0) {
            n++;
            p += leaf;
        } else {
            p++;
        }
    }
    return n;
}

// One buffer for the whole chain. Copying each child into its own string retains
// about n squared bytes, which this bound does not allow.
static void check_cond_chain(void) {
    enum { N = 1024 };
    re_arena_t a;
    dx_fn_t fn;
    dx_cond_t node[N];
    const char *text;
    size_t i;
    size_t leaves;
    re_arena_init(&a, 1u << 16);
    memset(&fn, 0, sizeof(fn));
    fn.a = &a;
    memset(node, 0, sizeof(node));
    node[0].kind = DX_C_REL;
    node[0].l = "x";
    node[0].r = "0";
    node[0].op = DX_EQ;
    for (i = 1; i < N; i++) {
        node[i].kind = DX_C_AND;
        node[i].a = &node[i - 1];
        node[i].b = &node[0];
    }
    text = dx_cond_text(&fn, &node[N - 1], false);
    leaves = text ? count_leaf(text) : 0;
    RE_CHECK_EQ_U(leaves, (size_t)N);
    RE_CHECK(text && a.total < 256u * 1024u);
    re_arena_free(&a);
}

int main(void) {
    check_text_kept();
    check_cond_chain();
    return re_test_report("dc_text");
}
