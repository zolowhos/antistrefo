// re_gui.c - the interactive view over an analysed file.
// Module: cli (C11).
// Owns: the loop, the selection, and the mapping from keys to state.
// Depends: re_gui.h, term, input, focus, draw, layout, console, analysis, mcp live.
#include "cli/screen/re_gui.h"

#include "features/analysis/re_analyze.h"
#include "features/code/re_code.h"
#include "features/data/re_vtable.h"
#include "utils/mem/re_buf.h"
#include "utils/tui/re_console.h"
#include "utils/tui/re_layout.h"
#include "utils/tui/re_screen.h"
#include "utils/tui/re_ui.h"
#include "cli/screen/re_draw.h"
#include "cli/screen/re_focus.h"
#include "cli/screen/re_gui_menu.h"
#include "cli/screen/re_gui_model.h"
#include "cli/screen/re_input.h"
#include "cli/screen/re_term.h"
#include "mcp/re_mcp_live.h"
#include "mcp/re_mcp_side.h"

#include <stdio.h>
#include <string.h>

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
    size_t sel;
    size_t tab;
    bool quit;
    bool want_load;
    bool want_analyze;
    bool loaded;
    bool fana_ready;
    uint8_t button_zone;
    uint8_t open_zone;
    uint8_t tab_zone;
    uint8_t tabs_drawn;
    uint8_t row_zone;
    uint8_t rows_drawn;
    page_arg_t row_arg[RE_GUI_LIST_ROWS];
    bool repaint;
    size_t page_off;
    size_t page_rows;
    size_t page_for;
    size_t page_sel;
    bool classes_ready;
    re_vset_t classes;
    page_arg_t page_arg[RE_PAGE_COUNT];
    re_ui_t ui;
    int menu_open;
    uint8_t menu_zone;
    uint8_t menu_n;
    bool syntax;
    bool color;
    uint16_t split;
    re_console_t console;
    re_arena_t fana;
    char path[512];
    const char **body;
    const uint8_t *body_marks;
    size_t body_n;
    uint32_t body_base;
} gui_t;

static void show_lines(gui_t *g, const char **text, const uint8_t *marks, size_t n, size_t total) {
    if (total && g->page_off >= total)
        g->page_off = total - 1u;
    g->page_rows = total;
    g->body = text;
    g->body_marks = marks;
    g->body_n = n;
    g->body_base = 0;
}

static void page_scroll(gui_t *g, int down) {
    if (down > 0 && g->page_rows && g->page_off + 1u < g->page_rows)
        g->page_off++;
    else if (down < 0 && g->page_off)
        g->page_off--;
}

static bool funcs_ready(const gui_t *g) {
    return g->fana_ready && re_analysis_pass(&g->an, RE_PASS_FUNCS) != NULL;
}

static bool ensure_funcs(gui_t *g, re_arena_t *a, re_gui_funcs_t *list) {
    char msg[160];
    if (!g->fana_ready)
        return false;
    if (funcs_ready(g))
        return true;
    if (!re_analysis_ensure(&g->an, RE_PASS_SYMBOLS))
        return false;
    list->n = 0;
    re_gui_funcs_fill(list, a, &g->an);
    snprintf(msg, sizeof(msg), "recovered %zu functions%s", RE_VEC_LEN(&g->an.scan.funcs),
             g->an.scan.truncated ? " (capped)" : "");
    re_console_push(&g->console, msg);
    return true;
}

static void body_for(gui_t *g, re_arena_t *a, re_gui_listing_t *ls, re_gui_pseudo_t *ps, size_t sel,
                     uint16_t rows) {
    static const char *kMapOnly[] = {"mapped; press A to recover functions"};
    const re_func_t *f;
    const re_pe_t *pe = g->an.has_pe ? &g->an.pe : NULL;
    const re_vset_t *vs = NULL;
    size_t pane = re_layout_body_rows(rows);
    if (g->loaded && !funcs_ready(g)) {
        show_lines(g, kMapOnly, NULL, 1u, 1u);
        return;
    }
    f = re_func_at(&g->an.scan, sel);
    if (g->page_for != g->tab || g->page_sel != sel) {
        g->page_for = g->tab;
        g->page_sel = sel;
        g->page_off = 0;
    }
    if (g->tab == 1) {
        size_t off;
        re_gui_pseudo_fill(ps, a, &g->an, sel);
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

static void take_layout(gui_t *g, const re_layout_t *L) {
    g->button_zone = L->button_zone;
    g->open_zone = L->open_zone;
    g->tab_zone = L->tab_zone;
    g->tabs_drawn = L->tabs_drawn;
    g->row_zone = L->row_zone;
    g->rows_drawn = L->rows_drawn;
    g->split = L->split;
}

static void compose(re_screen_t *s, gui_t *g, const re_gui_funcs_t *l) {
    static const char *kPages[RE_PAGE_COUNT] = {"graph View", "pseudo-code", "hex View",
                                                "structures", "imports",     "exports"};
    static const char *kMenu[] = {"File", "Edit", "Jump", "Search", "Options", "Help"};
    const char *clog[RE_CONSOLE_VIEW];
    re_layout_t L = {0};
    L.toolbar = kMenu;
    L.n_toolbar = 6;
    L.mark = "antistrefo 0.1.0";
    L.left_w = 28;
    L.console = clog;
    L.n_console = re_console_view(&g->console, clog);
    g->button_zone = RE_SCREEN_ZONE_NONE;
    if (!g->loaded) {
        L.file = "antistrefo";
        L.welcome = "load a file here";
        L.button = "Load";
        re_layout_compose(s, &L);
        take_layout(g, &L);
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
    L.syntax = g->tab == 1 && g->syntax;
    re_layout_compose(s, &L);
    take_layout(g, &L);
    for (size_t i = 0; i < g->rows_drawn && i < RE_GUI_LIST_ROWS; i++) {
        g->row_arg[i].g = g;
        g->row_arg[i].index = re_gui_funcs_index(g->sel, l, i);
    }
    re_focus_build(&g->focus, s);
}

static bool load_file(gui_t *g, re_arena_t *a, re_gui_funcs_t *list, re_gui_pseudo_t *ps,
                      const char *path) {
    size_t n = 0;
    g->classes_ready = false;
    g->page_off = 0;
    if (g->fana_ready) {
        re_analysis_close(&g->an);
        g->fana_ready = false;
    }
    re_arena_free(&g->fana);
    re_arena_init(&g->fana, 1u << 23);
    // Map + PE parse only; press A to walk functions (keeps large-PE first paint lean).
    if (!re_analysis_open(&g->an, &g->fana, path)) {
        g->loaded = false;
        re_mcp_live_clear_file();
        return false;
    }
    g->fana_ready = true;
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
    re_mcp_live_note_load(&g->console, path, &g->an, g->sel);
    re_console_push(&g->console, "mapped; press A to recover functions");
    return true;
}

static void apply_nav(gui_t *g, int key) {
    if (key == RE_KEY_UP && g->sel)
        g->sel--;
    else if (key == RE_KEY_DOWN)
        g->sel++;
    else if (key == RE_KEY_PGUP)
        g->sel = g->sel > 16u ? g->sel - 16u : 0u;
    else if (key == RE_KEY_PGDN)
        g->sel += 16u;
    else if (key == RE_KEY_HOME)
        g->sel = 0;
    else if (key == RE_KEY_TAB)
        re_focus_next(&g->focus);
    else if (key == RE_KEY_STAB)
        re_focus_prev(&g->focus);
    else if (key == RE_KEY_LEFT && g->tab) {
        g->tab--;
        g->repaint = true;
    } else if (key == RE_KEY_RIGHT && g->tab + 1u < RE_PAGE_COUNT) {
        g->tab++;
        g->repaint = true;
    }
}

static void apply(gui_t *g, const re_ev_t *ev) {
    int key;
    if (ev->kind != RE_EV_KEY)
        return;
    key = ev->key;
    if (key == 'q' || key == 'Q' || key == RE_KEY_ESCAPE) {
        g->quit = true;
        return;
    }
    if (key == RE_KEY_ENTER) {
        if (!re_ui_click(&g->ui, g->focus.zone) && !g->loaded)
            g->want_load = true;
        return;
    }
    if ((key == 'l' || key == 'L') && !g->loaded)
        g->want_load = true;
    else if ((key == 'a' || key == 'A') && g->loaded)
        g->want_analyze = true;
    else
        apply_nav(g, key);
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
    for (size_t i = 0; i < g->tabs_drawn && i < RE_PAGE_COUNT; i++) {
        g->page_arg[i].g = g;
        g->page_arg[i].index = i;
        re_ui_bind(&g->ui, (uint8_t)(g->tab_zone + i), on_page, NULL, &g->page_arg[i]);
    }
    if (g->row_zone != RE_SCREEN_ZONE_NONE)
        for (size_t i = 0; i < g->rows_drawn && i < RE_GUI_LIST_ROWS; i++)
            re_ui_bind(&g->ui, (uint8_t)(g->row_zone + i), on_row, NULL, &g->row_arg[i]);
}

static void wheel_at(gui_t *g, uint16_t rows, const re_ev_t *ev) {
    int down = ev->button == RE_MOUSE_WHEEL_DOWN ? 1 : -1;
    re_layout_wheel_t w = re_layout_wheel_at(rows, g->split, ev->row, ev->col);
    if (w == RE_LAYOUT_WHEEL_LIST) {
        if (down > 0)
            g->sel++;
        else if (g->sel)
            g->sel--;
    } else if (w == RE_LAYOUT_WHEEL_PAGE) {
        page_scroll(g, down);
    } else if (w == RE_LAYOUT_WHEEL_CONSOLE) {
        re_console_scroll(&g->console, down);
    }
}

static void feed_pointer(gui_t *g, re_screen_t *frame, const re_ev_t *ev) {
    if (ev->button == RE_MOUSE_WHEEL_UP || ev->button == RE_MOUSE_WHEEL_DOWN) {
        wheel_at(g, frame->rows, ev);
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

static bool turn(gui_t *g, re_arena_t *a, re_screen_t *frame, re_gui_funcs_t *list,
                 re_gui_listing_t *ls, re_gui_pseudo_t *ps) {
    if (g->want_analyze) {
        g->want_analyze = false;
        (void)ensure_funcs(g, a, list);
        g->repaint = true;
    }
    if (list->n && g->sel >= list->n)
        g->sel = list->n - 1u;
    if (g->loaded)
        re_mcp_live_note_sel(&g->an, g->sel, true);
    re_gui_funcs_fit(list, re_layout_body_rows(frame->rows));
    body_for(g, a, ls, ps, g->sel, frame->rows);
    compose(frame, g, list);
    {
        re_gui_menu_ctx_t mc = {&g->sel,      list->n,       &g->tab,      RE_PAGE_COUNT,
                                &g->page_off, &g->repaint,   &g->quit,     &g->syntax,
                                &g->color,    &g->menu_open, g->open_zone, &g->menu_zone,
                                &g->menu_n,   &g->console};
        re_gui_menu_draw(frame, &mc);
        bind_actions(g);
        re_gui_menu_bind(&g->ui, &mc);
    }
    frame->tui.color = g->color && re_tui_want_color();
    re_ui_mark(&g->ui, frame, (uint8_t)RE_ST_HOVER, (uint8_t)RE_ST_PRESS);
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
    re_arena_t a;
    re_arena_init(&a, 0);
    re_file_t f;
    bool ok = re_file_open(arg, &a, &f) == RE_OK;
    re_arena_free(&a);
    return ok;
}

int re_cmd_gui(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    char ep[RE_MCP_LIVE_EP];
    gui_t g;
    re_arena_t arena;
    re_gui_funcs_t list;
    re_gui_listing_t ls;
    re_gui_pseudo_t ps;
    (void)argc;
    (void)argv;
    (void)ctx;
    memset(&g, 0, sizeof(g));
    re_ui_init(&g.ui);
    re_console_init(&g.console);
    g.menu_open = -1;
    g.syntax = true;
    g.color = true;
    re_arena_init(&arena, 1u << 23);
    memset(&list, 0, sizeof(list));
    memset(&ls, 0, sizeof(ls));
    memset(&ps, 0, sizeof(ps));

    if (!re_term_open(&g.term, true)) {
        fprintf(stderr, "gui needs a terminal on both ends; try the report commands\n");
        re_arena_free(&arena);
        return 2;
    }
    if (re_mcp_side_start(ep, sizeof(ep)))
        re_mcp_live_note_mcp(&g.console, ep, true);
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
                g.draw.valid = false;
            }
        }
    }
    re_term_close(&g.term);
    re_mcp_side_stop();
    re_mcp_live_clear_file();
    if (g.fana_ready)
        re_analysis_close(&g.an);
    re_arena_free(&arena);
    return ready ? 0 : 2;
}
