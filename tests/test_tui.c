// test_tui.c - the layout math of the framed report, checked without a terminal.
// Module: test (C11).
// Owns: column counts, clipping, boxes, panels, and zone hover and click.
// Depends: re_core through re_tui.h. Every case here is one where a wrong answer
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#    define _POSIX_C_SOURCE 200809L
#endif
#include "re_test.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils/mem/re_arena.h"
#include "utils/text/re_strbuf.h"
#include "utils/tui/re_layout.h"
#include "utils/tui/re_screen.h"
#include "utils/tui/re_syntax.h"
#include "utils/tui/re_tui.h"
#include "utils/tui/re_ui.h"

int re_test_count = 0;
int re_test_fail = 0;

static void test_putenv(const char *kv) {
#if defined(_WIN32)
    (void)_putenv(kv);
#else
    char name[64];
    size_t i = 0;
    for (; kv[i] && kv[i] != '=' && i + 1u < sizeof(name); i++)
        name[i] = kv[i];
    name[i] = '\0';
    if (kv[i] != '=')
        return;
    if (kv[i + 1u])
        setenv(name, kv + i + 1u, 1);
    else
        unsetenv(name);
#endif
}

#define CHECK_STR(got, want)                                                    \
    do {                                                                        \
        re_test_count++;                                                        \
        const char *g_ = (got);                                                 \
        const char *w_ = (want);                                                \
        if (!g_ || strcmp(g_, w_) != 0) {                                       \
            re_test_fail++;                                                     \
            printf("FAIL %s:%d  got \"%s\"  want \"%s\"\n", __FILE__, __LINE__, \
                   g_ ? g_ : "(null)", w_);                                     \
            fflush(stdout);                                                     \
        }                                                                       \
    } while (0)

typedef struct {
    re_strbuf_t out;
    re_strbuf_t scratch;
    re_tui_t t;
} rig_t;

static void rig_init(rig_t *r, re_arena_t *a, uint16_t width, bool color, bool unicode) {
    re_strbuf_init(&r->out, a);
    re_strbuf_init(&r->scratch, a);
    re_tui_init(&r->t, &r->out, &r->scratch, color, unicode, width);
}

static const char *out_of(const rig_t *r) {
    return r->out.p ? r->out.p : "";
}

// pinned for the cases that would otherwise shift a box silently.
static void test_cols(void) {
    RE_CHECK_EQ_U(re_tui_cols(""), 0);
    RE_CHECK_EQ_U(re_tui_cols("abc"), 3);
    RE_CHECK_EQ_U(re_tui_cols("0x1130"), 6);
    // Two, three and four byte sequences are one column each, not their byte count.
    RE_CHECK_EQ_U(re_tui_cols("\xc2\xb5"), 1);
    RE_CHECK_EQ_U(re_tui_cols("\xe2\x94\x8c"), 1);
    RE_CHECK_EQ_U(re_tui_cols("\xf0\x9f\x94\x8d"), 1);
    // A combining mark adds no column of its own.
    RE_CHECK_EQ_U(re_tui_cols("e\xcc\x81"), 1);
    RE_CHECK_EQ_U(re_tui_cols_span("abcdef", 3), 3);
    // A span cut in the middle of a sequence must not run past the end.
    RE_CHECK_EQ_U(re_tui_cols_span("\xe2\x94", 2), 1);
}

// and the whole report after it is affected.
static void test_clip(re_arena_t *a) {
    rig_t r;
    rig_init(&r, a, 40, false, true);
    re_tui_clip(r.out.p ? &r.out : &r.out, &r.t, "short", 10);
    CHECK_STR(out_of(&r), "short");
    rig_init(&r, a, 40, false, true);
    re_tui_clip(r.out.p ? &r.out : &r.out, &r.t, "abcdefghij", 5);
    RE_CHECK_EQ_U(re_tui_cols(out_of(&r)), 5);
    rig_init(&r, a, 40, false, true);
    re_tui_clip(r.out.p ? &r.out : &r.out, &r.t, "", 5);
    CHECK_STR(out_of(&r), "");
    // A multi-byte character must be cut whole, so the byte count can be less than
    // the column count requested without running past the string.
    rig_init(&r, a, 40, false, true);
    re_tui_clip(r.out.p ? &r.out : &r.out, &r.t, "\xe2\x94\x8c\xe2\x94\x8c\xe2\x94\x8c", 2);
    RE_CHECK_EQ_U(re_tui_cols(out_of(&r)), 2);
    // Padding pads to the requested columns, and clips rather than overflowing.
    rig_init(&r, a, 40, false, true);
    re_tui_pad(&r.out, &r.t, "ab", 6);
    CHECK_STR(out_of(&r), "ab    ");
    rig_init(&r, a, 40, false, true);
    re_tui_pad(&r.out, &r.t, "abcdefgh", 4);
    RE_CHECK_EQ_U(re_tui_cols(out_of(&r)), 4);
}

// invisible in a test that only checks the text.
static void test_compose_even(re_arena_t *a) {
    static const uint16_t kWidths[] = {40, 60, 80, 100, 120, 200};
    for (size_t w = 0; w < sizeof(kWidths) / sizeof(kWidths[0]); w++) {
        for (unsigned np = 1; np <= RE_TUI_MAX_PANELS; np++) {
            rig_t r;
            re_panel_t p[RE_TUI_MAX_PANELS];
            size_t tallest = 1;
            rig_init(&r, a, kWidths[w], false, true);
            for (unsigned i = 0; i < np; i++) {
                char title[16];
                size_t want = i * 2 + 1;
                snprintf(title, sizeof(title), "Panel %u", i);
                re_panel_init(&p[i], a, title, (uint16_t)(i + 1));
                for (size_t k = 0; k < want; k++)
                    re_panel_text(&r.t, &p[i], "body line");
                if (want > tallest)
                    tallest = want;
            }
            re_tui_compose(&r.t, p, np);
            const char *s = out_of(&r);
            unsigned lines = 0;
            while (*s) {
                size_t len = 0;
                while (s[len] && s[len] != '\n')
                    len++;
                RE_CHECK_EQ_U(re_tui_cols_span(s, len), kWidths[w]);
                lines++;
                s += len;
                if (*s == '\n')
                    s++;
            }
            // One top border, the tallest body, one bottom border.
            RE_CHECK_EQ_U(lines, tallest + 2);
        }
    }
}

// is uglier but it has to line up, or the fallback is not a fallback.
static void test_ascii_fallback(re_arena_t *a) {
    rig_t r;
    re_panel_t p;
    rig_init(&r, a, 60, false, false);
    re_panel_init(&p, a, "T", 1);
    re_panel_text(&r.t, &p, "hello");
    re_tui_compose(&r.t, &p, 1);
    const char *s = out_of(&r);
    RE_CHECK(strchr(s, '+') != NULL);
    RE_CHECK(strchr(s, '\xe2') == NULL); // no UTF-8 leaked into the ascii path
    while (*s) {
        size_t len = 0;
        while (s[len] && s[len] != '\n')
            len++;
        RE_CHECK_EQ_U(re_tui_cols_span(s, len), 60);
        s += len;
        if (*s == '\n')
            s++;
    }
}

static void test_color(re_arena_t *a) {
    rig_t r;
    re_panel_t p;
    rig_init(&r, a, 60, false, true);
    re_panel_init(&p, a, "T", 1);
    re_panel_kv(&r.t, &p, "key", "val", RE_ST_GOOD);
    RE_CHECK(strchr(p.body.p, '\x1b') == NULL);
    rig_init(&r, a, 60, true, true);
    re_panel_init(&p, a, "T", 1);
    re_panel_kv(&r.t, &p, "key", "val", RE_ST_GOOD);
    const char *body = p.body.p ? p.body.p : "";
    RE_CHECK(strstr(body, "val") != NULL);
    RE_CHECK(strstr(body, "\x1b[0m") != NULL);
    // The visible text survives styling: the escapes are not part of the content, so
    // the words a reader searches for are still there, in order.
    RE_CHECK(strstr(body, "key") < strstr(body, "val"));
}

// counting bytes would over-report the width threefold.
static size_t visible_cols(const char *s, size_t len) {
    char plain[256];
    size_t n = 0;
    for (size_t i = 0; i < len && n + 1 < sizeof(plain);) {
        if (s[i] == '\x1b') {
            while (i < len && s[i] != 'm')
                i++;
            if (i < len)
                i++;
            continue;
        }
        plain[n++] = s[i++];
    }
    plain[n] = '\0';
    return re_tui_cols_span(plain, n);
}

// the plain text path at all.
static void test_styled_geometry(re_arena_t *a) {
    rig_t r;
    re_panel_t p;
    rig_init(&r, a, 72, true, true);
    re_panel_init(&p, a, "Keys", 1);
    re_panel_kv(&r.t, &p, "format", "pe", RE_ST_GOOD);
    re_panel_kv(&r.t, &p, "arch", "x86-64", RE_ST_ACCENT);
    re_tui_compose(&r.t, &p, 1);
    const char *s = out_of(&r);
    while (*s) {
        size_t len = 0;
        while (s[len] && s[len] != '\n')
            len++;
        RE_CHECK_EQ_U(visible_cols(s, len), 72);
        s += len;
        if (*s == '\n')
            s++;
    }
}

static void test_env(void) {
    // The environment is consulted, not cached, so a test can set it and clear it.
    // The convention is that the variable being present at all is what counts, which
    // is why an empty value is used to clear one here rather than deleting the name.
    test_putenv("NO_COLOR=1");
    RE_CHECK(!re_tui_want_color());
    test_putenv("NO_COLOR=");
    RE_CHECK(re_tui_want_color());
    test_putenv("RE_TUI_ASCII=1");
    RE_CHECK(!re_tui_want_unicode());
    test_putenv("RE_TUI_ASCII=");
    // With no terminal and no override, the answer is no: this suite runs under a pipe,
    // and claiming the box characters would be a lie about where the output is going.
    RE_CHECK(!re_tui_want_unicode());
    // The override exists for exactly the case the automatic answer cannot cover, which
    // is a console that reports a code page it does not actually use.
    test_putenv("RE_TUI_UNICODE=1");
    RE_CHECK(re_tui_want_unicode());
    test_putenv("RE_TUI_UNICODE=");
    RE_CHECK(!re_tui_console_utf8());
    test_putenv("COLUMNS=100");
    RE_CHECK_EQ_U(re_tui_term_width(), 100);
    test_putenv("COLUMNS=5");
    RE_CHECK_EQ_U(re_tui_term_width(), RE_TUI_DEFAULT_WIDTH);
    test_putenv("COLUMNS=1000");
    RE_CHECK_EQ_U(re_tui_term_width(), 200);
    test_putenv("COLUMNS=");
    RE_CHECK_EQ_U(re_tui_term_width(), RE_TUI_DEFAULT_WIDTH);
}

static void test_header(re_arena_t *a) {
    rig_t r;
    rig_init(&r, a, 40, false, true);
    re_tui_header(&r.t, "left", "right");
    CHECK_STR(out_of(&r), "left                               right\n");
    rig_init(&r, a, 40, true, true);
    re_tui_header(&r.t, "left", "right");
    const char *s = out_of(&r);
    RE_CHECK(strstr(s, "\x1b[1;7m") < strstr(s, "right"));
    RE_CHECK(strstr(s, "right") < strstr(s, "\x1b[0m"));
    // A subject and a summary longer than the width must not underflow the padding
    // arithmetic into an enormous unsigned value and emit gigabytes of spaces.
    rig_init(&r, a, 40, false, true);
    re_tui_header(&r.t, "a very long subject indeed", "and a long summary too");
    s = out_of(&r);
    size_t len = 0;
    while (s[len] && s[len] != '\n')
        len++;
    // The subject alone is longer than the line, so the summary is dropped and
    // the subject is trimmed, leaving exactly the width. A bar that ran past the
    // edge would wrap, and every box below it would be out of step.
    RE_CHECK_EQ_U(re_tui_cols_span(s, len), 40);
}
static void test_width(void) {
    test_putenv("COLUMNS=");
    RE_CHECK_EQ_U(re_tui_term_width(), RE_TUI_DEFAULT_WIDTH);
    test_putenv("COLUMNS=120");
    RE_CHECK_EQ_U(re_tui_term_width(), 120);
    // Too narrow to lay anything out in, and far wider than anyone needs. Both clamp
    // to something usable rather than being taken at face value.
    test_putenv("COLUMNS=10");
    RE_CHECK_EQ_U(re_tui_term_width(), RE_TUI_DEFAULT_WIDTH);
    test_putenv("COLUMNS=10000");
    RE_CHECK_EQ_U(re_tui_term_width(), 200);
    test_putenv("COLUMNS=nonsense");
    RE_CHECK_EQ_U(re_tui_term_width(), RE_TUI_DEFAULT_WIDTH);
    test_putenv("COLUMNS=");
}

static void test_fits_widths(re_arena_t *a) {
    static const uint16_t kWidths[] = {40, 55, 72, 100, 160, 200};
    static const char *const kSubjects[] = {
        "info",
        "info cpqsysio64.sys 14.8 KiB (15168B) 6 sec",
        "a subject that is on its own longer than the narrowest line we lay out here",
    };
    static const char *const kSummaries[] = {
        "schema antistrefo/1",
        "pe 1 imports  0 exports",
        "",
    };
    for (size_t w = 0; w < sizeof(kWidths) / sizeof(kWidths[0]); w++) {
        for (size_t si = 0; si < 3; si++) {
            for (size_t mi = 0; mi < 3; mi++) {
                rig_t r;
                re_panel_t p[2];
                rig_init(&r, a, kWidths[w], false, true);
                re_tui_header(&r.t, kSubjects[si], kSummaries[mi]);
                re_panel_init(&p[0], a, "Left", 1);
                re_panel_init(&p[1], a, "Right", 2);
                re_panel_kv(&r.t, &p[0], "key", "a value that is fairly long here", RE_ST_NONE);
                re_panel_kv(&r.t, &p[1], "other", "another value, also long", RE_ST_NONE);
                re_tui_compose(&r.t, p, 2);
                const char *s = out_of(&r);
                while (*s) {
                    size_t len = 0;
                    while (s[len] && s[len] != '\n')
                        len++;
                    RE_CHECK(re_tui_cols_span(s, len) <= kWidths[w]);
                    s += len;
                    if (*s == '\n')
                        s++;
                }
            }
        }
    }
}

typedef struct {
    int clicks;
    int entered;
    int left;
} probe_t;

static void ui_click(void *user) {
    ((probe_t *)user)->clicks++;
}

static void ui_hover(void *user, bool over) {
    probe_t *p = user;
    if (over)
        p->entered++;
    else
        p->left++;
}

static void test_hover_and_click(re_arena_t *a) {
    re_strbuf_t out;
    re_strbuf_init(&out, a);
    re_screen_t s;
    probe_t p;
    re_ui_t u;
    memset(&p, 0, sizeof(p));
    RE_CHECK(re_screen_init(&s, a, &out, 2, 4));
    re_screen_clear(&s);
    re_screen_fill(&s, 0, 0, 2, 1, "A", (uint8_t)RE_ST_NONE, 1);
    re_screen_fill(&s, 0, 2, 2, 1, "B", (uint8_t)RE_ST_NONE, 2);

    re_ui_init(&u);
    RE_CHECK(!re_ui_bind(&u, RE_SCREEN_ZONE_NONE, ui_click, ui_hover, &p));
    RE_CHECK(re_ui_bind(&u, 1, ui_click, ui_hover, &p));
    re_ui_pointer(&u, &s, 0, 0, RE_UI_MOVE);
    RE_CHECK_EQ_U(p.entered, 1);
    RE_CHECK_EQ_U(u.hot, 1);
    re_ui_pointer(&u, &s, 0, 1, RE_UI_MOVE);
    RE_CHECK_EQ_U(p.entered, 1);

    re_ui_pointer(&u, &s, 0, 2, RE_UI_MOVE);
    RE_CHECK_EQ_U(p.left, 1);
    RE_CHECK_EQ_U(p.entered, 1);
    RE_CHECK_EQ_U(u.hot, 2);
    re_ui_mark(&u, &s, (uint8_t)RE_ST_HOVER, (uint8_t)RE_ST_PRESS);
    RE_CHECK_EQ_U(s.cell[2].style, (unsigned)RE_ST_HOVER);
    RE_CHECK_EQ_U(s.cell[0].style, (unsigned)RE_ST_NONE);

    RE_CHECK(re_ui_bind(&u, 2, ui_click, ui_hover, &p));
    re_ui_pointer(&u, &s, 0, 2, RE_UI_DOWN);
    re_ui_mark(&u, &s, (uint8_t)RE_ST_HOVER, (uint8_t)RE_ST_PRESS);
    RE_CHECK_EQ_U(s.cell[2].style, (unsigned)RE_ST_PRESS);
    re_ui_clear(&u);
    RE_CHECK_EQ_U(u.hot, 2);
    RE_CHECK(re_ui_bind(&u, 2, ui_click, ui_hover, &p));
    re_ui_pointer(&u, &s, 0, 2, RE_UI_UP);
    RE_CHECK_EQ_U(p.clicks, 1);

    re_ui_pointer(&u, &s, 0, 2, RE_UI_DOWN);
    re_ui_pointer(&u, &s, 0, 0, RE_UI_UP);
    RE_CHECK_EQ_U(p.clicks, 1);
    RE_CHECK(re_ui_click(&u, 2));
    RE_CHECK_EQ_U(p.clicks, 2);
    re_ui_clear(&u);
    RE_CHECK(!re_ui_click(&u, 2));
}

static void test_syntax_line(re_arena_t *a) {
    re_strbuf_t out;
    re_strbuf_init(&out, a);
    re_screen_t s;
    RE_CHECK(re_screen_init(&s, a, &out, 4, 64));
    re_screen_clear(&s);
    re_syntax_put(&s, 0, 0, 64, "    if (v1 == 0) goto L2");
    RE_CHECK_EQ_STR(s.cell[4].g, "i");
    RE_CHECK_EQ_U(s.cell[4].style, (unsigned)RE_ST_KW);
    RE_CHECK_EQ_STR(s.cell[14].g, "0");
    RE_CHECK_EQ_U(s.cell[14].style, (unsigned)RE_ST_NUM);
    RE_CHECK_EQ_U(s.cell[17].style, (unsigned)RE_ST_KW);
    RE_CHECK_EQ_U(s.cell[22].style, (unsigned)RE_ST_ACCENT);
    re_screen_clear(&s);
    re_syntax_put(&s, 0, 0, 64, "    uint64_t v3 = printf(v1);");
    RE_CHECK_EQ_U(s.cell[4].style, (unsigned)RE_ST_TYPE);
    RE_CHECK_EQ_STR(s.cell[18].g, "p");
    RE_CHECK_EQ_U(s.cell[18].style, (unsigned)RE_ST_CALL);
    re_screen_clear(&s);
    re_syntax_put(&s, 0, 0, 64, "    /\x2f not a return");
    RE_CHECK_EQ_U(s.cell[4].style, (unsigned)RE_ST_CMT);
    RE_CHECK_EQ_U(s.cell[13].style, (unsigned)RE_ST_CMT);
    re_screen_clear(&s);
    re_syntax_put(&s, 0, 0, 64, "v = 0x1a;");
    RE_CHECK_EQ_STR(s.cell[4].g, "0");
    RE_CHECK_EQ_U(s.cell[4].style, (unsigned)RE_ST_NUM);
    RE_CHECK_EQ_U(s.cell[7].style, (unsigned)RE_ST_NUM);
    re_screen_clear(&s);
    re_syntax_put(&s, 0, 0, 64, "name = \"hi\";");
    RE_CHECK_EQ_U(s.cell[7].style, (unsigned)RE_ST_STR);
    RE_CHECK_EQ_U(s.cell[8].style, (unsigned)RE_ST_STR);
}

static void test_syntax_pane(re_arena_t *a) {
    static const char *code[] = {"  return 0;"};
    static const char *rows[] = {"_main"};
    re_strbuf_t out;
    re_layout_t L;
    re_screen_t s;
    size_t i;
    bool kw = false;
    bool num = false;
    re_strbuf_init(&out, a);
    memset(&L, 0, sizeof(L));
    L.rows = rows;
    L.n_rows = 1;
    L.code = code;
    L.n_code = 1;
    L.syntax = true;
    L.left_w = 24;
    L.list_title = "Functions";
    RE_CHECK(re_screen_init(&s, a, &out, 12, 80));
    re_layout_compose(&s, &L);
    for (i = 0; i < (size_t)s.rows * s.cols; i++) {
        if (s.cell[i].g[0] == 'r' && s.cell[i].style == (uint8_t)RE_ST_KW)
            kw = true;
        if (s.cell[i].g[0] == '0' && s.cell[i].style == (uint8_t)RE_ST_NUM)
            num = true;
    }
    RE_CHECK(kw);
    RE_CHECK(num);
}

int main(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    test_cols();
    test_clip(&a);
    test_compose_even(&a);
    test_ascii_fallback(&a);
    test_color(&a);
    test_styled_geometry(&a);
    test_env();
    test_width();
    test_fits_widths(&a);
    test_header(&a);
    test_hover_and_click(&a);
    test_syntax_line(&a);
    test_syntax_pane(&a);
    re_arena_free(&a);
    return re_test_report("tui");
}
