// re_gui_menu.h - the menu row's dropdowns.
// Module: cli (C11).
// Owns: Edit, Jump, Search, Options and Help, and the actions they run.
// Depends: re_screen, re_ui. The view owns the state; this only reads it.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include "utils/tui/re_screen.h"
#include "utils/tui/re_ui.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t *sel;
    size_t nfunc;
    size_t *tab;
    size_t ntab;
    size_t *page_off;
    bool *repaint;
    bool *quit;
    bool *syntax;
    bool *color;
    int *open;   // -1 closed, else the toolbar index that is open
    uint8_t bar; // zone of File, the first toolbar control
    uint8_t *zone;
    uint8_t *nitems;
    char *note;
    size_t note_n;
} re_gui_menu_ctx_t;

// Draw the open dropdown under its toolbar button. No-op when nothing is open.
void re_gui_menu_draw(re_screen_t *s, re_gui_menu_ctx_t *c);

// Bind the toolbar buttons and the dropdown rows. File stays the caller's load.
void re_gui_menu_bind(re_ui_t *u, re_gui_menu_ctx_t *c);

#ifdef __cplusplus
}
#endif
