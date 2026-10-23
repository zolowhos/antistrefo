// test_console.c - console band, ring scrollback, and wheel hit targets.
// Module: test (C11).
// Owns: the assertions for re_console.h and the layout console geometry.
// Depends: re_test, re_arena, re_strbuf, re_console, re_layout, re_screen.
#include "re_test.h"
#include "re_version.h"

#include "utils/mem/re_arena.h"
#include "utils/text/re_strbuf.h"
#include "utils/tui/re_console.h"
#include "utils/tui/re_layout.h"
#include "utils/tui/re_screen.h"

#include <stdio.h>
#include <string.h>

int re_test_count = 0;
int re_test_fail = 0;

static void test_layout_console_band(re_arena_t *a) {
    static const char *tabs[] = {"Disasm-A", "Pseudocode-A", "Hex-1"};
    static const char *rows[] = {"_fun", "_main", "_printf"};
    static const char *code[] = {"int main(void)", "{", "  return 0;", "}"};
    static const char *clog[] = {"line-a", "line-b", "line-c", "line-d"};
    re_strbuf_t out;
    re_strbuf_t dump;
    re_layout_t L;
    re_screen_t s;
    memset(&L, 0, sizeof(L));
    re_strbuf_init(&out, a);
    re_strbuf_init(&dump, a);
    L.file = "lo_world.i64";
    L.mark = "antistrefo " RE_VERSION;
    L.toolbar = tabs;
    L.n_toolbar = 3;
    L.list_title = "Functions";
    L.rows = rows;
    L.n_rows = 3;
    L.sel_row = 2;
    L.tabs = tabs;
    L.n_tabs = 3;
    L.active_tab = 1;
    L.code = code;
    L.n_code = 4;
    L.left_w = 24;
    L.console = clog;
    L.n_console = 4;
    RE_CHECK_EQ_U(re_layout_body_rows(24), 16);
    RE_CHECK(re_screen_init(&s, a, &out, 24, 100));
    RE_CHECK_EQ_U(re_layout_compose(&s, &L), 16);
    RE_CHECK(L.split > 0);
    re_screen_dump(&s, &dump);
    RE_CHECK(strstr(dump.p, "<console>") != NULL);
    RE_CHECK(strstr(dump.p, "line-a") != NULL);
    RE_CHECK(strstr(dump.p, "line-d") != NULL);
    RE_CHECK(strstr(dump.p, "return 0;") != NULL);
    RE_CHECK(re_screen_init(&s, a, &out, 11, 40));
    RE_CHECK_EQ_U(re_layout_compose(&s, &L), 0);
}

static void test_console_ring_offset(void) {
    re_console_t c;
    const char *view[RE_CONSOLE_VIEW];
    size_t n;
    char label[4];
    size_t i;
    re_console_init(&c);
    for (i = 0; i < 6; i++) {
        label[0] = (char)('0' + (int)i);
        label[1] = '\0';
        re_console_push(&c, label);
    }
    n = re_console_view(&c, view);
    RE_CHECK_EQ_U(n, 4);
    RE_CHECK_EQ_STR(view[0], "2");
    RE_CHECK_EQ_STR(view[3], "5");
    re_console_scroll(&c, 1);
    n = re_console_view(&c, view);
    RE_CHECK_EQ_U(n, 4);
    RE_CHECK_EQ_STR(view[0], "1");
    RE_CHECK_EQ_STR(view[3], "4");
    RE_CHECK_EQ_U(c.off, 1);
    re_console_scroll(&c, 10);
    RE_CHECK_EQ_U(c.off, 2);
    re_console_push(&c, "x");
    RE_CHECK_EQ_U(c.off, 0);
}

static void test_wheel_hit(void) {
    RE_CHECK(re_layout_wheel_at(24, 28, 5, 10) == RE_LAYOUT_WHEEL_LIST);
    RE_CHECK(re_layout_wheel_at(24, 28, 5, 40) == RE_LAYOUT_WHEEL_PAGE);
    RE_CHECK(re_layout_wheel_at(24, 28, 5, 28) == RE_LAYOUT_WHEEL_NONE);
    RE_CHECK(re_layout_wheel_at(24, 28, 18, 10) == RE_LAYOUT_WHEEL_CONSOLE);
    RE_CHECK(re_layout_wheel_at(24, 28, 22, 50) == RE_LAYOUT_WHEEL_CONSOLE);
    RE_CHECK(re_layout_wheel_at(24, 28, 23, 10) == RE_LAYOUT_WHEEL_NONE);
    RE_CHECK(re_layout_wheel_at(24, 28, 0, 10) == RE_LAYOUT_WHEEL_NONE);
    RE_CHECK(re_layout_wheel_at(24, 0, 18, 10) == RE_LAYOUT_WHEEL_CONSOLE);
}

int main(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    test_layout_console_band(&a);
    test_console_ring_offset();
    test_wheel_hit();
    re_arena_free(&a);
    return re_test_report("console");
}
