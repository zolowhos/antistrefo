// re_gui.c - the interactive view over an analysed file.
// Module: cli (C11).
// Owns: the loop, the selection, and the mapping from keys to state.
// Depends: re_gui.h, re_term, re_input, re_focus, re_draw, re_screen, re_layout,
//           re_analysis, re_code. Decoding and rendering are the shared backend's
//           job, reached the same way every other command reaches them.
#include "cli/screen/re_gui.h"

#include "features/analysis/re_analyze.h"
#include "features/code/re_code.h"
#include "features/code/re_stack.h"
#include "features/data/re_vtable.h"
#include "features/dec/re_decompile.h"
#include "utils/mem/re_buf.h"
#include "utils/tui/re_layout.h"
#include "utils/tui/re_screen.h"
#include "utils/tui/re_ui.h"
#include "cli/screen/re_draw.h"
#include "cli/screen/re_focus.h"
#include "cli/screen/re_gui_model.h"
#include "cli/screen/re_input.h"
#include "cli/screen/re_pseudocode.h"
#include "cli/screen/re_term.h"

#include <stdio.h>
#include <string.h>

// The pages on the body's top edge. The list of functions stays on the left for all
// of them; the right pane is what changes.
#define RE_PAGE_COUNT 6u

typedef struct gui gui_t;

typedef struct {
    gui_t *g;
    size_t index;
} page_arg_t;

typedef struct gui {
    re_analysis_t an;
    re_term_t term;
    re_draw_t draw;
    re_focus_t focus;
    size_t sel; // the selected function
    size_t tab; // which page the right pane shows
    bool quit;
    bool want_load;  // the load control was activated
    bool loaded;     // a file is open, so the body is the file view
    bool fana_ready; // the analysis arena holds a mapping
    uint8_t button_zone;
    uint8_t open_zone; // File, on the menu row
    uint8_t tab_zone;
    uint8_t tabs_drawn;
    uint8_t row_zone;
    uint8_t rows_drawn;
    page_arg_t row_arg[RE_GUI_LIST_ROWS];
    bool repaint; // the page changed, so the next frame is a full console clear
    size_t page_off;
    size_t page_rows;
    size_t page_for;
    size_t page_sel;
    bool classes_ready;
    re_vset_t classes;
    page_arg_t page_arg[RE_PAGE_COUNT];
    re_ui_t ui;
    // Remade on every load. A mapped binary lives in it, and the path is copied so the
    // title still names the file after that arena is freed.
    re_arena_t fana;
    char path[512];
    // The right pane's lines for this turn. Compose draws them and does not fill them.
    const char **body;
    const uint8_t *body_marks;
    size_t body_n;
    uint32_t body_base;
} gui_t;

// Built once per selected function. Doing it every frame would lower the same body
// again and again for the same text.
typedef struct {
    re_strbuf_t buf;
    const char *line[RE_PSEUDO_MAX];
    uint8_t mark[RE_PSEUDO_MAX];
    size_t n;
    size_t built_for;
    bool started;
    bool ok;
} pseudo_t;

static void pseudo_split(pseudo_t *ps) {
    re_strbuf_putc(&ps->buf, 0);
    ps->n = re_pseudo_split(ps->buf.p, ps->line, ps->mark, RE_PSEUDO_MAX);
}

static void pseudo_fill(pseudo_t *ps, re_arena_t *a, re_analysis_t *an, size_t sel) {
    if (!ps->started) {
        re_strbuf_init(&ps->buf, a);
        ps->started = true;
        ps->built_for = (size_t)-1;
    }
    if (ps->built_for == sel)
        return;
    ps->built_for = sel;
    re_strbuf_clear(&ps->buf);
    ps->n = 0;
    if (sel >= RE_VEC_LEN(&an->scan.funcs))
        return;
    const re_func_t *f = RE_VEC_PTR(&an->scan.funcs, re_func_t, sel);
    re_decomp_t d;
    d.jtables = NULL;
    d.code = &an->code;
    d.xrefs = &an->xs;
    d.arena = a;
    re_stack_t st;
    re_stack_analyze(d.code, f, a, &st);
    ps->ok = re_decompile_ok(&d, f);
    if (ps->ok)
        re_decompile_func(&d, f, &st, &ps->buf);
    pseudo_split(ps);
    if (!ps->n) {
        // The two slashes are written as a slash and a hex byte. A "//" inside a
        // string is eaten by the gate's comment stripper, and the function that
        // follows is then measured as part of this one.
        ps->line[0] = "/\x2f this body did not lower: no instruction was recovered from it";
        ps->mark[0] = 1;
        ps->n = 1;
    }
}

static void show_lines(gui_t *g, const char **text, const uint8_t *marks, size_t n, size_t total) {
    if (total && g->page_off >= total)
        g->page_off = total - 1u;
    g->page_rows = total;
    g->body = text;
    g->body_marks = marks;
    g->body_n = n;
    g->body_base = 0;
}

static void body_for(gui_t *g, re_arena_t *a, re_gui_listing_t *ls, pseudo_t *ps, size_t sel,
                     uint16_t rows) {
    const re_func_t *f = re_func_at(&g->an.scan, sel);
    const re_pe_t *pe = g->an.has_pe ? &g->an.pe : NULL;
    const re_vset_t *vs = NULL;
    size_t pane = re_layout_body_rows(rows);
    if (g->page_for != g->tab || g->page_sel != sel) {
        g->page_for = g->tab;
        g->page_sel = sel;
        g->page_off = 0;
    }
    if (g->tab == 1) {
        size_t off;
        pseudo_fill(ps, a, &g->an, sel);
        off = g->page_off < ps->n ? g->page_off : (ps->n ? ps->n - 1u : 0u);
        g->page_off = off;
        show_lines(g, ps->n ? ps->line + off : NULL, ps->n ? ps->mark + off : NULL,
                   ps->n > off ? ps->n - off : 0u, ps->n);
        return;
    }
    if (g->tab == 3 && !g->classes_ready && pe && g->an.has_code) {
        re_vtable_scan(pe, &g->an.code, &g->fana, &g->classes);
        g->classes_ready = true;
    }
    if (g->classes_ready)
        vs = &g->classes;
    re_gui_page_fill(ls, a, pe, vs, g->tab, f ? f->rva : 0, f ? f->size : 0, g->page_off, pane);
    show_lines(g, g->tab ? ls->text : NULL, NULL, g->tab ? ls->n : 0u, ls->total);
}

static void compose(re_screen_t *s, gui_t *g, const re_gui_funcs_t *l) {
    static const char *kPages[RE_PAGE_COUNT] = {"graph View", "pseudo-code", "hex View",
                                                "structures", "imports",     "exports"};
    static const char *kMenu[] = {"File", "Edit", "Jump", "Search", "Options", "Help"};

    re_layout_t L = {0};
    L.toolbar = kMenu;
    L.n_toolbar = 6;
    L.mark = "antistrefo 0.1.0";
    L.left_w = 28;
    g->button_zone = RE_SCREEN_ZONE_NONE;

    if (!g->loaded) {
        L.file = "antistrefo";
        L.welcome = "load a file here";
        L.button = "Load";
        re_layout_compose(s, &L);
        g->button_zone = L.button_zone;
        g->open_zone = L.open_zone;
        g->tab_zone = RE_SCREEN_ZONE_NONE;
        g->tabs_drawn = 0;
        g->row_zone = RE_SCREEN_ZONE_NONE;
        g->rows_drawn = 0;
        re_focus_build(&g->focus, s);
        return;
    }

    const char *lrows[RE_GUI_LIST_ROWS];
    re_gui_funcs_window(g->sel, l, lrows, RE_GUI_LIST_ROWS);

    L.file = g->path;
    L.list_title = "Functions";
    L.rows = lrows;
    L.n_rows = l->vis ? l->vis : 1u;
    L.sel_row = re_gui_funcs_row(g->sel, l);
    L.tabs = kPages;
    L.n_tabs = RE_PAGE_COUNT;
    L.active_tab = g->tab;
    L.code = g->body;
    L.n_code = g->body_n;
    L.base_line = g->body_base;
    L.marks = g->body_marks;
    L.syntax = g->tab == 1;
    re_layout_compose(s, &L);
    g->button_zone = L.button_zone;
    g->open_zone = L.open_zone;
    g->tab_zone = L.tab_zone;
    g->tabs_drawn = L.tabs_drawn;
    g->row_zone = L.row_zone;
    g->rows_drawn = L.rows_drawn;
    for (size_t i = 0; i < g->rows_drawn && i < RE_GUI_LIST_ROWS; i++) {
        g->row_arg[i].g = g;
        g->row_arg[i].index = re_gui_funcs_index(g->sel, l, i);
    }
    re_focus_build(&g->focus, s);
}
static bool load_file(gui_t *g, re_arena_t *a, re_gui_funcs_t *list, pseudo_t *ps,
                      const char *path) {
    g->classes_ready = false;
    g->page_off = 0;
    if (g->fana_ready) {
        re_analysis_close(&g->an);
        g->fana_ready = false;
    }
    re_arena_free(&g->fana);
    re_arena_init(&g->fana, 1u << 23);
    if (!re_analysis_open(&g->an, &g->fana, path))
        return false;
    g->fana_ready = true;
    size_t n = 0;
    while (path[n] && n + 1u < sizeof(g->path)) {
        g->path[n] = path[n];
        n++;
    }
    g->path[n] = '\0';
    g->loaded = true;
    g->sel = 0;
    g->tab = 0;
    ps->built_for = (size_t)-1;
    list->n = 0;
    re_gui_funcs_fill(list, a, &g->an);
    return true;
}

static void apply(gui_t *g, const re_ev_t *ev) {
    if (ev->kind == RE_EV_KEY) {
        switch (ev->key) {
            case 'q':
            case 'Q':
            case RE_KEY_ESCAPE:
                g->quit = true;
                return;
            case RE_KEY_ENTER:
                if (re_ui_click(&g->ui, g->focus.zone))
                    return;
                if (!g->loaded)
                    g->want_load = true;
                return;
            case 'l':
            case 'L':
                if (!g->loaded)
                    g->want_load = true;
                return;
            case RE_KEY_UP:
                if (g->sel)
                    g->sel--;
                return;
            case RE_KEY_DOWN:
                g->sel++;
                return;
            case RE_KEY_PGUP:
                g->sel = g->sel > 16u ? g->sel - 16u : 0u;
                return;
            case RE_KEY_PGDN:
                g->sel += 16u;
                return;
            case RE_KEY_HOME:
                g->sel = 0;
                return;
            case RE_KEY_TAB:
                re_focus_next(&g->focus);
                return;
            case RE_KEY_STAB:
                re_focus_prev(&g->focus);
                return;
            case RE_KEY_LEFT:
                if (g->tab) {
                    g->tab--;
                    g->repaint = true;
                }
                return;
            case RE_KEY_RIGHT:
                if (g->tab + 1u < RE_PAGE_COUNT) {
                    g->tab++;
                    g->repaint = true;
                }
                return;
            default:
                return;
        }
    }
}

static void on_load(void *user) {
    ((gui_t *)user)->want_load = true;
}

static void on_page(void *user) {
    page_arg_t *a = user;
    if (!a || !a->g || a->index == a->g->tab)
        return;
    a->g->tab = a->index;
    a->g->repaint = true;
}

static void on_menu(void *user) {
    (void)user;
}

static void on_row(void *user) {
    page_arg_t *a = user;
    if (!a || !a->g)
        return;
    a->g->sel = a->index;
}

static void bind_actions(gui_t *g) {
    re_ui_clear(&g->ui);
    re_ui_bind(&g->ui, g->button_zone, on_load, NULL, g);
    re_ui_bind(&g->ui, g->open_zone, on_load, NULL, g);
    if (g->open_zone != RE_SCREEN_ZONE_NONE)
        for (size_t i = 1; i < 6u; i++)
            re_ui_bind(&g->ui, (uint8_t)(g->open_zone + i), on_menu, NULL, g);
    for (size_t i = 0; i < g->tabs_drawn && i < RE_PAGE_COUNT; i++) {
        g->page_arg[i].g = g;
        g->page_arg[i].index = i;
        re_ui_bind(&g->ui, (uint8_t)(g->tab_zone + i), on_page, NULL, &g->page_arg[i]);
    }
    if (g->row_zone != RE_SCREEN_ZONE_NONE)
        for (size_t i = 0; i < g->rows_drawn && i < RE_GUI_LIST_ROWS; i++)
            re_ui_bind(&g->ui, (uint8_t)(g->row_zone + i), on_row, NULL, &g->row_arg[i]);
}

static void feed_pointer(gui_t *g, re_screen_t *frame, const re_ev_t *ev) {
    if (ev->button == RE_MOUSE_WHEEL_UP || ev->button == RE_MOUSE_WHEEL_DOWN) {
        if (ev->button == RE_MOUSE_WHEEL_DOWN) {
            if (g->page_rows && g->page_off + 1u < g->page_rows)
                g->page_off++;
        } else if (g->page_off) {
            g->page_off--;
        }
        return;
    }
    if ((ev->button & 64u) != 0)
        return;
    if ((ev->button & 32u) != 0) {
        re_ui_pointer(&g->ui, frame, ev->row, ev->col, RE_UI_MOVE);
        return;
    }
    if (!ev->press) {
        re_ui_pointer(&g->ui, frame, ev->row, ev->col, RE_UI_UP);
        return;
    }
    if (!re_input_is_click(ev))
        return;
    (void)re_focus_click(&g->focus, frame, ev->row, ev->col);
    re_ui_pointer(&g->ui, frame, ev->row, ev->col, RE_UI_DOWN);
}

// One turn of the loop: compose, paint, wait. Returns false to leave.
static bool turn(gui_t *g, re_arena_t *a, re_screen_t *frame, re_gui_funcs_t *list,
                 re_gui_listing_t *ls, pseudo_t *ps) {
    if (list->n && g->sel >= list->n)
        g->sel = list->n - 1u;
    // The list takes every row the body has, so a taller terminal shows more functions
    // rather than a fixed slice of them with blank rows under it.
    re_gui_funcs_fit(list, re_layout_body_rows(frame->rows));
    body_for(g, a, ls, ps, g->sel, frame->rows);
    compose(frame, g, list);
    bind_actions(g);
    // Color is off until a caller asks. The button backgrounds are the ask.
    frame->tui.color = re_tui_want_color();
    re_ui_mark(&g->ui, frame, (uint8_t)RE_ST_HOVER, (uint8_t)RE_ST_PRESS);
    // A page change clears the console and writes every cell. A diff leaves the
    // previous page in any cell the new page does not overwrite.
    if (g->repaint || !g->draw.valid)
        re_draw_full(&g->draw, frame);
    else
        re_draw_frame(&g->draw, frame);
    g->repaint = false;
    if (g->draw.out.len) {
        re_draw_home(&g->draw, 0, 0);
        re_term_write(&g->term, g->draw.out.p, g->draw.out.len);
    }

    re_ev_t ev;
    if (!re_term_wait(&g->term, &ev, 250u)) {
        // No key. Ask the terminal for its size anyway, because a resize is not always
        // an event on every terminal, and a stale frame size wraps every row.
        uint16_t nr = 0, nc = 0;
        re_term_size(&nr, &nc);
        if (nr != frame->rows || nc != frame->cols)
            return re_draw_resize(&g->draw, a, nr, nc) &&
                   re_screen_init(frame, a, &g->draw.out, nr, nc);
        return true;
    }
    if (ev.kind == RE_EV_RESIZE) {
        uint16_t nr = 0, nc = 0;
        re_term_size(&nr, &nc);
        return re_draw_resize(&g->draw, a, nr, nc) &&
               re_screen_init(frame, a, &g->draw.out, nr, nc);
    }
    if (ev.kind == RE_EV_MOUSE)
        feed_pointer(g, frame, &ev);
    apply(g, &ev);
    return !g->quit;
}

bool re_gui_wants_file(const char *arg) {
    if (!arg || !*arg)
        return false;
    // Something readable is there, not something with a known extension. A dropped
    // binary may be named anything, and refusing one over its extension would be
    // refusing the only thing the reader asked for.
    //
    // The file is read and thrown away, so opening it again costs one more read. That
    // is cheaper than a wrong answer: without a check, a mistyped command would open
    // this instead of saying the command does not exist.
    re_arena_t a;
    re_arena_init(&a, 0);
    re_file_t f;
    bool ok = re_file_open(arg, &a, &f) == RE_OK;
    re_arena_free(&a);
    return ok;
}

int re_cmd_gui(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    (void)argc;
    (void)argv;
    (void)ctx;
    gui_t g;
    memset(&g, 0, sizeof(g));
    re_ui_init(&g.ui);
    re_arena_t arena;
    re_arena_init(&arena, 1u << 23);
    re_gui_funcs_t list;
    memset(&list, 0, sizeof(list));
    re_gui_listing_t ls;
    memset(&ls, 0, sizeof(ls));
    pseudo_t ps;
    memset(&ps, 0, sizeof(ps));

    // The terminal is taken before the file is analysed. The other order puts a full
    // screen session up and then prints a failure into it, which leaves the reader with
    // escape sequences and no way back.
    if (!re_term_open(&g.term, true)) {
        fprintf(stderr, "gui needs a terminal on both ends; try the report commands\n");
        re_arena_free(&arena);
        return 2;
    }
    // A named file is loaded now. Without one the first screen is the welcome, which is
    // what opening the binary by double clicking it should produce, so this is not a
    // different code path: it is the same one with nothing to load yet.
    bool ready = !*path || load_file(&g, &arena, &list, &ps, path);
    uint16_t rows = 24, cols = 80;
    re_term_size(&rows, &cols);
    bool have_draw = re_draw_init(&g.draw, &arena, rows, cols);
    re_screen_t frame;
    bool have_frame = re_screen_init(&frame, &arena, &g.draw.out, rows, cols);
    re_focus_init(&g.focus);
    if (have_draw && have_frame) {
        while (turn(&g, &arena, &frame, &list, &ls, &ps)) {
            if (g.want_load) {
                char typed[512];
                g.want_load = false;
                if (re_term_pick_file(typed, sizeof(typed)))
                    load_file(&g, &arena, &list, &ps, typed);
                // The dialog covers the console. The diff still believes the old frame
                // is showing, so the next paint has to be a full one.
                g.draw.valid = false;
            }
        }
    }
    re_term_close(&g.term);
    if (g.fana_ready)
        re_analysis_close(&g.an);
    re_arena_free(&arena);
    return ready ? 0 : 2;
}
