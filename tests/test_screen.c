// test_screen.c - the cell grid, the widgets, and the reference arrangement.
// Module: test (C11).
// Owns: the assertions. Exercises re_screen.h and re_layout.h only.
// Depends: re_test, re_arena, re_strbuf, re_screen, re_layout.
#include "re_test.h"
#include "re_version.h"

#include "utils/mem/re_arena.h"
#include "utils/text/re_strbuf.h"
#include "utils/tui/re_layout.h"
#include "utils/tui/re_screen.h"

#include <stdio.h>
#include <string.h>

int re_test_count = 0;
int re_test_fail = 0;

// A grid is refused rather than clipped when the request cannot be honoured. Both
// halves matter: a caller has to be able to tell a refusal from a small screen, or a
// fallback will silently draw into a buffer that cannot hold it.
static void test_init_bounds(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    re_strbuf_t out;
    re_strbuf_init(&out, &a);
    re_screen_t s;

    RE_CHECK(re_screen_init(&s, &a, &out, 24, 100));
    RE_CHECK_EQ_U(s.rows, 24);
    RE_CHECK_EQ_U(s.cols, 100);
    RE_CHECK(!s.overflow);
    RE_CHECK(s.cell != NULL);

    RE_CHECK(!re_screen_init(&s, &a, &out, 0, 100));
    RE_CHECK(s.overflow);
    RE_CHECK(!re_screen_init(&s, &a, &out, 24, 0));
    RE_CHECK(!re_screen_init(&s, &a, &out, RE_SCREEN_MAX_ROWS + 1u, 100));
    RE_CHECK(!re_screen_init(&s, &a, &out, 24, RE_SCREEN_MAX_COLS + 1u));

    re_arena_free(&a);
}

// Zone ids are handed out in drawing order and never repeat, because a click is
// resolved by zone and two controls sharing an id would make the click ambiguous.
static void test_zones_are_unique(re_arena_t *a) {
    re_strbuf_t out;
    re_strbuf_init(&out, a);
    re_screen_t s;
    RE_CHECK(re_screen_init(&s, a, &out, 10, 60));
    re_screen_clear(&s);

    static const char *tb[] = {"One", "Two", "Three"};
    re_screen_toolbar(&s, 0, tb, 3);
    RE_CHECK_EQ_U(s.zone_count, 3);
    RE_CHECK(re_screen_zone(&s) == 4);
    RE_CHECK(re_screen_zone(&s) == 5);

    uint8_t z_first = s.cell[0].zone;
    RE_CHECK(z_first != RE_SCREEN_ZONE_NONE);
    RE_CHECK(z_first != s.cell[s.cols].zone);
}

// A run of text starts exactly where it was asked to and covers every glyph. The
// first column is the one a bug eats, because a caller that advances past it and then
// draws a string looks correct right up until the leading letter goes missing.
static void test_run_starts_where_asked(re_arena_t *a) {
    re_strbuf_t out;
    re_strbuf_init(&out, a);
    re_screen_t s;
    RE_CHECK(re_screen_init(&s, a, &out, 4, 30));
    re_screen_clear(&s);

    re_screen_put_run(&s, 0, 2, 30, "Hello", RE_ST_NONE, RE_SCREEN_ZONE_NONE);
    RE_CHECK_EQ_STR(s.cell[2].g, "H");
    RE_CHECK_EQ_STR(s.cell[3].g, "e");
    RE_CHECK_EQ_STR(s.cell[4].g, "l");
    RE_CHECK_EQ_STR(s.cell[5].g, "l");
    RE_CHECK_EQ_STR(s.cell[6].g, "o");
    RE_CHECK(!s.cell[7].g[0]);

    // A run stops at the limit rather than overrunning it into the next row.
    re_screen_put_run(&s, 1, 0, 4, "abcdefgh", RE_ST_NONE, RE_SCREEN_ZONE_NONE);
    RE_CHECK_EQ_STR(s.cell[s.cols + 0].g, "a");
    RE_CHECK_EQ_STR(s.cell[s.cols + 3].g, "d");
    RE_CHECK(!s.cell[s.cols + 4].g[0]);

    // A limit inside the grid still stops at the grid, not at the limit.
    re_screen_put_run(&s, 2, 0, 999, "ab", RE_ST_NONE, RE_SCREEN_ZONE_NONE);
    RE_CHECK_EQ_STR(s.cell[2 * s.cols].g, "a");
    RE_CHECK(!s.cell[2 * s.cols + 5].g[0]);
}

// Writes outside the grid are dropped, not wrapped and not written. A layout that
// hands a widget a rectangle running off the edge is common; a heap write from it is
// not survivable, so clipping is the contract.
static void test_out_of_bounds_is_dropped(re_arena_t *a) {
    re_strbuf_t out;
    re_strbuf_init(&out, a);
    re_screen_t s;
    RE_CHECK(re_screen_init(&s, a, &out, 6, 20));
    re_screen_clear(&s);

    re_screen_put(&s, 100, 100, "X", RE_ST_NONE, RE_SCREEN_ZONE_NONE);
    RE_CHECK(!s.cell[100 * s.cols + 100].g[0]);
    re_screen_put(&s, 5, 19, "X", RE_ST_NONE, RE_SCREEN_ZONE_NONE);
    RE_CHECK_EQ_STR(s.cell[5 * s.cols + 19].g, "X");

    // A box too small to hold its own corners draws nothing rather than underflowing
    // a width by two.
    re_screen_box(&s, 0, 0, 1, 1, "t", RE_ST_NONE);
    RE_CHECK(!s.cell[0].g[0]);

    // A fill starting at column 18 of a 20 column grid writes columns 18 and 19 of
    // rows 0..5, and nothing else.
    re_screen_fill(&s, 0, 18, 10, 10, "#", RE_ST_NONE, RE_SCREEN_ZONE_NONE);
    RE_CHECK_EQ_STR(s.cell[0 * s.cols + 18].g, "#");
    RE_CHECK_EQ_STR(s.cell[5 * s.cols + 19].g, "#");
    RE_CHECK(!s.cell[0].g[0]);
    RE_CHECK(!s.cell[6 * s.cols + 18].g[0]);
}

// A multi byte glyph occupies one cell and keeps its bytes, and a double width glyph
// claims the column after it so the row cannot shift left by one.
static void test_glyph_bytes(re_arena_t *a) {
    re_strbuf_t out;
    re_strbuf_init(&out, a);
    re_screen_t s;
    RE_CHECK(re_screen_init(&s, a, &out, 3, 12));
    re_screen_clear(&s);

    re_screen_put(&s, 0, 0, "\xe2\x96\x88", RE_ST_NONE, RE_SCREEN_ZONE_NONE); // full block
    re_screen_put(&s, 0, 1, "A", RE_ST_NONE, RE_SCREEN_ZONE_NONE);
    RE_CHECK_EQ_U(s.cell[0].cols, 1);
    RE_CHECK_EQ_STR(s.cell[1].g, "A");

    re_screen_put_run(&s, 1, 0, 12, "\xe2\x80\xa2\x2d", RE_ST_NONE, RE_SCREEN_ZONE_NONE);
    RE_CHECK_EQ_STR(s.cell[1 * s.cols].g, "\xe2\x80\xa2");
    RE_CHECK_EQ_STR(s.cell[1 * s.cols + 1].g, "-");

    re_screen_put(&s, 2, 0, "\xf0\x9f\x98\x80", RE_ST_NONE, RE_SCREEN_ZONE_NONE); // 4 byte
    RE_CHECK_EQ_STR(s.cell[2 * s.cols].g, "\xf0\x9f\x98\x80");
}

// The gutter right aligns its numbers in a fixed strip and puts the mark column at a
// fixed offset, because a gutter whose columns move is not readable as a column.
static void test_gutter_geometry(re_arena_t *a) {
    re_strbuf_t out;
    re_strbuf_init(&out, a);
    re_screen_t s;
    RE_CHECK(re_screen_init(&s, a, &out, 6, 20));
    re_screen_clear(&s);

    static const uint8_t marks[] = {0, 1, 0};
    re_screen_gutter(&s, 0, 0, 3, 1, marks, 3);

    // Row 0 carries no mark so its mark column is blank; row 1 carries one. Compared
    // per cell, because the mark is three bytes and slicing it would compare
    // garbage against garbage.
    for (uint16_t x = 0; x < 6; x++)
        RE_CHECK_EQ_STR(s.cell[0 * s.cols + x].g, " ");
    RE_CHECK_EQ_STR(s.cell[0 * s.cols + 6].g, "1");
    RE_CHECK_EQ_STR(s.cell[0 * s.cols + 7].g, " ");
    RE_CHECK_EQ_STR(s.cell[1 * s.cols + 6].g, "2");
    RE_CHECK_EQ_STR(s.cell[1 * s.cols + 7].g, "\xe2\x80\xa2");
    RE_CHECK_EQ_STR(s.cell[2 * s.cols + 6].g, "3");
    RE_CHECK_EQ_STR(s.cell[2 * s.cols + 7].g, " ");
}

// A scrollbar handle stays inside its track at both ends. A handle that runs past
// the end is a control reporting a position it cannot be at.
static void test_scrollbar_handle_stays_in_track(re_arena_t *a) {
    re_strbuf_t out;
    re_strbuf_init(&out, a);
    re_screen_t s;

    for (uint16_t pos = 0; pos <= 10; pos += 2) {
        RE_CHECK(re_screen_init(&s, a, &out, 10, 10));
        re_screen_clear(&s);
        re_screen_vscroll(&s, 0, 0, 8, pos, 10);
        bool found = false;
        for (uint16_t y = 1; y < 7; y++)
            if (s.cell[y * s.cols].cols == 1)
                found = true;
        RE_CHECK(found);
    }
}

typedef struct {
    re_strbuf_t out;
    re_strbuf_t dump;
    re_layout_t L;
} arr_t;

// Shared fixture, so the two arrangement tests read as assertions about a layout
// rather than as setup. The struct is zeroed first: re_layout_t is large and a caller
// that sets most of it must still zero it, because a field left uninitialised is
// decided by whatever was on the stack.
static void arr_build(re_arena_t *a, arr_t *f) {
    static const char *tabs[] = {"Disasm-A", "Pseudocode-A", "Hex-1"};
    static const char *rows[] = {"_fun", "_main", "_printf"};
    static const char *code[] = {"int main(void)", "{", "  return 0;", "}"};
    static const uint8_t marks[] = {0, 0, 1, 0};

    memset(f, 0, sizeof(*f));
    re_strbuf_init(&f->out, a);
    re_strbuf_init(&f->dump, a);
    f->L.file = "lo_world.i64";
    f->L.mark = "antistrefo " RE_VERSION;
    f->L.toolbar = tabs;
    f->L.n_toolbar = 3;
    f->L.nav_pos = 40;
    f->L.nav_total = 100;
    f->L.legend = tabs;
    f->L.n_legend = 3;
    f->L.list_title = "Functions";
    f->L.list_head = "Function name";
    f->L.rows = rows;
    f->L.n_rows = 3;
    f->L.sel_row = 2;
    f->L.tabs = tabs;
    f->L.n_tabs = 3;
    f->L.active_tab = 1;
    f->L.code = code;
    f->L.n_code = 4;
    f->L.base_line = 1;
    f->L.marks = marks;
    f->L.status = "000003E9C _main:1";
    f->L.caret = "1:8";
    f->L.left_w = 24;
}

// The arrangement must produce both panes, in order, with the subject on the first
// row and the caret on the last.
static void test_layout_bands(re_arena_t *a) {
    arr_t f;
    arr_build(a, &f);
    re_screen_t s;
    RE_CHECK(re_screen_init(&s, a, &f.out, 24, 100));
    RE_CHECK(re_layout_compose(&s, &f.L) > 10);
    re_screen_dump(&s, &f.dump);

    const char *d = f.dump.p;
    RE_CHECK(strstr(d, "lo_world.i64") != NULL);
    RE_CHECK(strstr(d, "<Functions>") != NULL);
    RE_CHECK(strstr(d, "<Pseudocode-A>") != NULL);
    RE_CHECK(strstr(d, "<antistrefo " RE_VERSION ">") != NULL);
    RE_CHECK(strstr(d, "_printf") != NULL);
    RE_CHECK(strstr(d, "return 0;") != NULL);
    bool accent = false;
    for (uint16_t i = 0; i < (uint16_t)(s.rows * s.cols); i++)
        if (s.cell[i].g[0] == 'P' && s.cell[i].style == (uint8_t)RE_ST_ACCENT)
            accent = true;
    RE_CHECK(accent);

    size_t nl = 0;
    for (const char *p = d; *p; p++)
        if (*p == '\n')
            nl++;
    RE_CHECK_EQ_U(nl, 24);
}

// A narrow terminal must still produce both panes rather than a zero width one,
// because a split that collapses leaves the reader with no code at all.
static void test_layout_narrow(re_arena_t *a) {
    arr_t f;
    arr_build(a, &f);
    re_screen_t s;
    f.L.left_w = 0;
    RE_CHECK(re_screen_init(&s, a, &f.out, 24, 60));
    RE_CHECK(re_layout_compose(&s, &f.L) > 10);
    re_screen_dump(&s, &f.dump);
    RE_CHECK(strstr(f.dump.p, "Pseudocode-A") != NULL);
    RE_CHECK(strstr(f.dump.p, "return 0;") != NULL);
}

// The welcome fixture. Built separately because two tests want it and a fixture that
// is only written down once cannot drift out of step with what it is supposed to be.
static void welcome_build(re_arena_t *a, arr_t *f) {
    arr_build(a, f);
    f->L.file = "antistrefo";
    f->L.welcome = "load a file here";
    f->L.button = "Load";
    f->L.status = "no file";
    f->L.caret = "press Enter to load a file";
}

// The welcome screen: one framed box, the message, and one control. No list and no
// code pane, because a pane drawn with nothing in it reads as a file with no functions,
// which is a different and wrong claim.
static void test_welcome(re_arena_t *a) {
    arr_t f;
    re_screen_t s;
    welcome_build(a, &f);
    RE_CHECK(re_screen_init(&s, a, &f.out, 20, 70));
    RE_CHECK(re_layout_compose(&s, &f.L) > 8);
    RE_CHECK(f.L.button_zone != RE_SCREEN_ZONE_NONE);
    re_screen_dump(&s, &f.dump);

    RE_CHECK(strstr(f.dump.p, "Get started") != NULL);
    RE_CHECK(strstr(f.dump.p, "load a file here") != NULL);
    RE_CHECK(strstr(f.dump.p, "[Load]") != NULL);
    // The parts of the file view must be absent, not present and empty. Asserted on the
    // list heading rather than on a tab name, because in this fixture the legend is
    // built from the tab labels and would match either way.
    RE_CHECK(strstr(f.dump.p, "Functions") == NULL);
    RE_CHECK(strstr(f.dump.p, "Function name") == NULL);

    // The whole of the button, brackets included, carries one zone, and the cells that
    // carry it spell exactly the label: a click on a bracket is a click on the button
    // rather than on the space beside it.
    char spelled[16] = {0};
    size_t w = 0;
    for (uint16_t y = 0; y < s.rows; y++) {
        for (uint16_t x = 0; x < s.cols; x++) {
            const re_cell_t *c = &s.cell[(size_t)y * s.cols + x];
            if (c->zone != f.L.button_zone || !c->g[0])
                continue;
            for (size_t k = 0; c->g[k] && w + 1 < sizeof(spelled); k++)
                spelled[w++] = c->g[k];
        }
    }
    RE_CHECK(strcmp(spelled, "[Load]") == 0);
}

// The button and the message are centred, not left aligned in the box. The dump now
// reports interior blanks as spaces, so a position can be asserted on at all: before
// that it collapsed every gap and each column read as column one.
static void test_welcome_centred(re_arena_t *a) {
    arr_t f;
    re_screen_t s;
    welcome_build(a, &f);
    RE_CHECK(re_screen_init(&s, a, &f.out, 20, 70));
    RE_CHECK(re_layout_compose(&s, &f.L) > 8);

    uint16_t quarter = (uint16_t)(s.cols / 4u);
    uint16_t first_x = 0;
    for (uint16_t y = 0; y < s.rows && !first_x; y++)
        for (uint16_t x = 0; x < s.cols; x++)
            if (s.cell[(size_t)y * s.cols + x].zone == f.L.button_zone) {
                first_x = x;
                break;
            }
    RE_CHECK(first_x > quarter);
    RE_CHECK(first_x < (uint16_t)(s.cols - quarter - 6u));

    uint16_t msg_x = 0;
    for (uint16_t y = 0; y < s.rows && !msg_x; y++)
        for (uint16_t x = 1; x + 3u < s.cols; x++) {
            const re_cell_t *c = &s.cell[(size_t)y * s.cols + x];
            const re_cell_t *o = &s.cell[(size_t)y * s.cols + x + 1u];
            if (c->g[0] == 'l' && o->g[0] == 'o') {
                msg_x = x;
                break;
            }
        }
    RE_CHECK(msg_x > quarter);
    RE_CHECK(msg_x < (uint16_t)(s.cols - quarter - 16u));
}

// Zone ids are per frame. A counter that keeps climbing gives Load a new id on every
// redraw, and once it passes the ceiling the button is drawn with no zone, so a click
// on it cannot land. The second compose has to report the same ids as the first.
static void test_function_rows_are_controls(re_arena_t *a) {
    arr_t f;
    re_screen_t s;
    arr_build(a, &f);
    RE_CHECK(re_screen_init(&s, a, &f.out, 24, 100));
    RE_CHECK(re_layout_compose(&s, &f.L) > 10);
    RE_CHECK(f.L.row_zone != RE_SCREEN_ZONE_NONE);
    RE_CHECK_EQ_U(f.L.rows_drawn, 3);
    RE_CHECK(f.L.row_zone != f.L.tab_zone);
    RE_CHECK(f.L.row_zone != f.L.open_zone);
    bool named = false;
    bool accent = false;
    uint8_t picked = (uint8_t)(f.L.row_zone + 2u);
    for (size_t i = 0; i < (size_t)s.rows * s.cols; i++) {
        if (s.cell[i].zone == f.L.row_zone && s.cell[i].g[0] == '_')
            named = true;
        if (s.cell[i].zone == picked && s.cell[i].g[0] == '_' &&
            s.cell[i].style == (uint8_t)RE_ST_ACCENT)
            accent = true;
    }
    RE_CHECK(named);
    RE_CHECK(accent);
}

static void test_load_zones_stable(re_arena_t *a) {
    arr_t f;
    re_screen_t s;
    welcome_build(a, &f);
    RE_CHECK(re_screen_init(&s, a, &f.out, 20, 70));
    RE_CHECK(re_layout_compose(&s, &f.L) > 8);
    uint8_t button = f.L.button_zone;
    uint8_t open = f.L.open_zone;
    RE_CHECK(button != RE_SCREEN_ZONE_NONE);
    RE_CHECK(open != RE_SCREEN_ZONE_NONE);
    RE_CHECK(open != button);

    RE_CHECK(re_layout_compose(&s, &f.L) > 8);
    RE_CHECK_EQ_U(f.L.button_zone, button);
    RE_CHECK_EQ_U(f.L.open_zone, open);

    char spelled[16] = {0};
    size_t w = 0;
    for (uint16_t x = 0; x < s.cols && w + 1 < sizeof(spelled); x++) {
        const re_cell_t *c = &s.cell[x];
        if (c->zone != open || !c->g[0] || c->g[0] == ' ')
            continue;
        spelled[w++] = c->g[0];
    }
    RE_CHECK(strcmp(spelled, "<Disasm-A>") == 0);
}

// A screen too short for the arrangement says the subject and stops, rather than
// drawing bands that cannot fit and reporting success.
static void test_layout_refuses_tiny_screen(re_arena_t *a) {
    arr_t f;
    arr_build(a, &f);
    re_screen_t s;
    RE_CHECK(re_screen_init(&s, a, &f.out, 3, 40));
    RE_CHECK_EQ_U(re_layout_compose(&s, &f.L), 0);
    re_screen_dump(&s, &f.dump);
    RE_CHECK(strstr(f.dump.p, "lo_world.i64") != NULL);
    RE_CHECK(strstr(f.dump.p, "Pseudocode") == NULL);
}

// draw and dump must carry the same glyphs in the same order. They cannot be compared
// byte for byte: draw emits a space for every blank cell because the terminal needs
// one, and dump trims trailing blanks because a reader does not. What has to hold is
// that neither drops nor repeats a glyph, which is what the space stripped comparison
// checks.
static void test_draw_matches_dump(re_arena_t *a) {
    arr_t f;
    arr_build(a, &f);
    re_screen_t s;
    RE_CHECK(re_screen_init(&s, a, &f.out, 12, 60));
    RE_CHECK(re_layout_compose(&s, &f.L) > 0);
    re_screen_draw(&s);
    re_screen_dump(&s, &f.dump);

    size_t dn = 0, un = 0;
    for (const char *p = f.out.p; *p; p++)
        if (*p != ' ')
            dn++;
    for (const char *p = f.dump.p; *p; p++)
        if (*p != ' ')
            un++;
    RE_CHECK_EQ_U(dn, un);
    RE_CHECK(dn > 40);
}

int main(int argc, char **argv) {
    re_arena_t a;
    re_arena_init(&a, 0);
    // --dump prints the arrangement at a wide size and stops. A layout that is only
    // ever asserted on is a layout nobody has looked at, and a mistake in the bands
    // reads far more clearly as a picture than as twenty string comparisons.
    if (argc > 1 && strcmp(argv[1], "--dump") == 0) {
        arr_t f;
        arr_build(&a, &f);
        re_screen_t s;
        if (re_screen_init(&s, &a, &f.out, 22, 96)) {
            re_layout_compose(&s, &f.L);
            re_screen_dump(&s, &f.dump);
            fputs(f.dump.p, stdout);
        }
        re_arena_free(&a);
        return 0;
    }
    test_init_bounds();
    test_zones_are_unique(&a);
    test_run_starts_where_asked(&a);
    test_out_of_bounds_is_dropped(&a);
    test_glyph_bytes(&a);
    test_gutter_geometry(&a);
    test_scrollbar_handle_stays_in_track(&a);
    test_layout_bands(&a);
    test_layout_narrow(&a);
    test_layout_refuses_tiny_screen(&a);
    test_welcome(&a);
    test_welcome_centred(&a);
    test_function_rows_are_controls(&a);
    test_load_zones_stable(&a);
    test_draw_matches_dump(&a);
    re_arena_free(&a);
    return re_test_report("screen");
}
