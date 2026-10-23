// re_gui_priv.h - the interactive view's state, shared with the deep pass worker.
// Module: cli (C11).
// Owns: gui_t, and the worker entry points the frame loop calls.
// Depends: re_gui_model, re_term, re_draw, re_focus, re_deep. Private to screen/.
#pragma once

#include "features/analysis/re_deep.h"
#include "features/data/re_vtable.h"
#include "utils/sys/re_thread.h"
#include "utils/tui/re_console.h"
#include "utils/tui/re_ui.h"
#include "cli/screen/re_draw.h"
#include "cli/screen/re_focus.h"
#include "cli/screen/re_gui_model.h"
#include "cli/screen/re_term.h"

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
    re_thread_t deep_thread; // the background deep pass, joined before the next load
    re_deep_ctrl_t deep_ctrl;
    re_analysis_t deep_an; // the worker's own context, on deep_arena
    re_arena_t deep_arena;
    bool deep_running;
    bool deep_done;      // the worker finished; swap its database in at a frame boundary
    uint8_t deep_logged; // last phase printed, 0xFF until the worker publishes one
    char path[512];
    const char **body;
    const uint8_t *body_marks;
    size_t body_n;
    uint32_t body_base;
} gui_t;

// Start, cancel, and fold in the background deep pass. pump runs once per frame.
void re_gui_arm_deep(gui_t *g);
void re_gui_stop_deep(gui_t *g);
void re_gui_pump_deep(gui_t *g, re_arena_t *a, re_gui_funcs_t *list);
