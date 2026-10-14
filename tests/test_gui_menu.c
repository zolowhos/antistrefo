// test_gui_menu.c - hover open and leave-dismiss for the top-bar menus.
// Module: test (C11).
// Owns: assertions that a dropdown closes when the pointer leaves it.
// Depends: re_test, re_gui_menu, re_layout, re_screen, re_ui, re_arena.
#include "re_test.h"

#include "utils/mem/re_arena.h"
#include "utils/text/re_strbuf.h"
#include "utils/tui/re_layout.h"
#include "utils/tui/re_screen.h"
#include "utils/tui/re_ui.h"
#include "cli/screen/re_gui_menu.h"

#include <string.h>

int re_test_count = 0;
int re_test_fail = 0;

static bool find_zone(const re_screen_t *s, uint8_t zone, uint16_t *row, uint16_t *col) {
    size_t i;
    size_t n;
    if (!s || !s->cell || zone == RE_SCREEN_ZONE_NONE)
        return false;
    n = (size_t)s->rows * s->cols;
    for (i = 0; i < n; i++) {
        if (s->cell[i].zone != zone)
            continue;
        *row = (uint16_t)(i / s->cols);
        *col = (uint16_t)(i % s->cols);
        return true;
    }
    return false;
}

static bool find_none(const re_screen_t *s, uint16_t *row, uint16_t *col) {
    size_t i;
    size_t n;
    if (!s || !s->cell)
        return false;
    n = (size_t)s->rows * s->cols;
    for (i = 0; i < n; i++) {
        if (s->cell[i].zone != RE_SCREEN_ZONE_NONE)
            continue;
        *row = (uint16_t)(i / s->cols);
        *col = (uint16_t)(i % s->cols);
        return true;
    }
    return false;
}

static void paint_and_bind(re_screen_t *s, re_layout_t *L, re_ui_t *u, re_gui_menu_ctx_t *mc) {
    re_ui_clear(u);
    (void)re_layout_compose(s, L);
    re_gui_menu_draw(s, mc);
    re_gui_menu_bind(u, mc);
}

static void fill_layout(re_layout_t *L) {
    static const char *kMenu[] = {"File", "Edit", "Jump", "Search", "Options", "Help"};
    static const char *tabs[] = {"Disasm"};
    static const char *rows[] = {"_main"};
    static const char *code[] = {"ret"};
    memset(L, 0, sizeof(*L));
    L->file = "t.bin";
    L->mark = "antistrefo";
    L->toolbar = kMenu;
    L->n_toolbar = 6;
    L->list_title = "Functions";
    L->rows = rows;
    L->n_rows = 1;
    L->tabs = tabs;
    L->n_tabs = 1;
    L->code = code;
    L->n_code = 1;
    L->left_w = 24;
}

typedef struct {
    size_t sel;
    size_t tab;
    size_t page_off;
    bool repaint;
    bool quit;
    bool syntax;
    bool color;
    int open;
    uint8_t menu_zone;
    uint8_t menu_n;
    re_gui_menu_ctx_t mc;
} menu_fix_t;

static void fill_menu_ctx(menu_fix_t *st, uint8_t bar) {
    memset(st, 0, sizeof(*st));
    st->syntax = true;
    st->color = true;
    st->open = -1;
    st->menu_zone = RE_SCREEN_ZONE_NONE;
    st->mc.sel = &st->sel;
    st->mc.nfunc = 1;
    st->mc.tab = &st->tab;
    st->mc.ntab = 1;
    st->mc.page_off = &st->page_off;
    st->mc.repaint = &st->repaint;
    st->mc.quit = &st->quit;
    st->mc.syntax = &st->syntax;
    st->mc.color = &st->color;
    st->mc.open = &st->open;
    st->mc.bar = bar;
    st->mc.zone = &st->menu_zone;
    st->mc.nitems = &st->menu_n;
}

static void hover_open_edit(re_screen_t *s, re_layout_t *L, re_ui_t *u, menu_fix_t *st, uint16_t er,
                            uint16_t ec) {
    paint_and_bind(s, L, u, &st->mc);
    re_ui_pointer(u, s, er, ec, RE_UI_MOVE);
    RE_CHECK_EQ_U((unsigned)st->open, 1u);
}

static void stay_open_on_item(re_screen_t *s, re_layout_t *L, re_ui_t *u, menu_fix_t *st) {
    uint16_t ir = 0, ic = 0;
    paint_and_bind(s, L, u, &st->mc);
    RE_CHECK(st->menu_n > 0);
    RE_CHECK(st->menu_zone != RE_SCREEN_ZONE_NONE);
    RE_CHECK(find_zone(s, st->menu_zone, &ir, &ic));
    re_ui_pointer(u, s, ir, ic, RE_UI_MOVE);
    RE_CHECK_EQ_U((unsigned)st->open, 1u);
}

static void dismiss_on_none(re_screen_t *s, re_ui_t *u, menu_fix_t *st) {
    uint16_t nr = 0, nc = 0;
    RE_CHECK(find_none(s, &nr, &nc));
    re_ui_pointer(u, s, nr, nc, RE_UI_MOVE);
    RE_CHECK_EQ_U((unsigned)st->open, (unsigned)-1);
}

static void dismiss_from_title(re_screen_t *s, re_layout_t *L, re_ui_t *u, menu_fix_t *st,
                               uint16_t er, uint16_t ec) {
    hover_open_edit(s, L, u, st, er, ec);
    paint_and_bind(s, L, u, &st->mc);
    re_ui_pointer(u, s, er, ec, RE_UI_MOVE);
    dismiss_on_none(s, u, st);
}

static void test_hover_dismiss(re_arena_t *a) {
    re_strbuf_t out;
    re_layout_t L;
    re_screen_t s;
    re_ui_t u;
    menu_fix_t st;
    uint16_t er = 0, ec = 0;
    uint8_t edit_zone;

    re_strbuf_init(&out, a);
    fill_layout(&L);
    RE_CHECK(re_screen_init(&s, a, &out, 24, 100));
    re_ui_init(&u);
    (void)re_layout_compose(&s, &L);
    RE_CHECK(L.open_zone != RE_SCREEN_ZONE_NONE);
    edit_zone = (uint8_t)(L.open_zone + 1u);
    RE_CHECK(find_zone(&s, edit_zone, &er, &ec));
    fill_menu_ctx(&st, L.open_zone);

    hover_open_edit(&s, &L, &u, &st, er, ec);
    stay_open_on_item(&s, &L, &u, &st);
    dismiss_on_none(&s, &u, &st);
    dismiss_from_title(&s, &L, &u, &st, er, ec);
}

int main(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    test_hover_dismiss(&a);
    re_arena_free(&a);
    return re_test_report("gui_menu");
}
