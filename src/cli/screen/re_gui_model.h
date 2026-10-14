// re_gui_model.h - what the front end shows about a file, without knowing how.
// Module: cli (C11).
// Owns: the function list, the instruction listing, and their buffers.
// Depends: re_analyze, re_code, re_strbuf, re_arena. Builds no screen and reads no
//           terminal, so the fill functions can be reasoned about on their own.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/analysis/re_analyze.h"
#include "features/data/re_vtable.h"
#include "utils/mem/re_arena.h"
#include "utils/text/re_strbuf.h"
#include "cli/screen/re_pseudocode.h"

// A pane's worth, not a promise about the file: a function can be longer than any pane
// and a terminal has a fixed number of rows.
#define RE_GUI_CODE_MAX 48u
#define RE_GUI_LIST_MAX 256u

// Cached decompiled body for the pseudo-code tab. Lives with the model so the
// interactive loop stays under the file-size gate.
typedef struct {
    re_strbuf_t buf;
    const char *line[RE_PSEUDO_MAX];
    uint8_t mark[RE_PSEUDO_MAX];
    size_t n;
    size_t built_for;
    bool started;
    bool ok;
} re_gui_pseudo_t;

void re_gui_pseudo_fill(re_gui_pseudo_t *ps, re_arena_t *a, re_analysis_t *an, size_t sel);

// The most rows the list can be asked for at once. The screen refuses a terminal taller
// than RE_SCREEN_MAX_ROWS, so this is every pane there can be, and the view sizes the
// window to the pane it actually has instead of a fixed slice of it.
#define RE_GUI_LIST_ROWS 200u

typedef struct {
    re_strbuf_t line[RE_GUI_CODE_MAX];
    const char *text[RE_GUI_CODE_MAX];
    uint8_t mark[RE_GUI_CODE_MAX];
    size_t n;
    size_t total;
    uint32_t base;
    size_t vis;
} re_gui_listing_t;

typedef struct {
    char *name[RE_GUI_LIST_MAX];
    char addr[RE_GUI_LIST_MAX][20];
    size_t n;
    size_t vis;
} re_gui_funcs_t;

// The functions of the open file, with a name for each: an unnamed one gets one
// derived from its address, so the list never shows a blank row indistinguishable from
// any other blank row.
void re_gui_funcs_fill(re_gui_funcs_t *l, re_arena_t *a, const re_analysis_t *an);

// Size the window to the pane it is drawn in. rows is how many rows the pane has this
// frame, so a taller terminal shows more functions and a resize is answered on the next
// frame. Clamped to the list and to RE_GUI_LIST_ROWS, the bound a caller's array is
// built for.
void re_gui_funcs_fit(re_gui_funcs_t *l, size_t rows);

// The rows the list shows, anchored on sel so the reader always sees what they moved to
// and stopped at the ends rather than scrolled past the list.
void re_gui_funcs_window(size_t sel, const re_gui_funcs_t *l, const char **rows, size_t cap);

// Which function a visible row is. The window is anchored on sel, and a click has to
// name the function in that row rather than the row number itself.
size_t re_gui_funcs_index(size_t sel, const re_gui_funcs_t *l, size_t row);

// The visible row that shows sel, so the accent and a click land on the same function.
size_t re_gui_funcs_row(size_t sel, const re_gui_funcs_t *l);

// The disassembly of one function, decoded and rendered through the shared backend, so
// the listing and a report cannot disagree about an address.
void re_gui_listing_fill(re_gui_listing_t *ls, re_arena_t *a, const re_analysis_t *an, size_t sel);

// One row is sixteen bytes: the address, the hex, then the ASCII. row0 is the first
// row kept, so the wheel can move the pane a row at a time.
void re_gui_hex_fill(re_gui_listing_t *ls, re_arena_t *a, const re_pe_t *pe, uint32_t rva,
                     uint32_t size, size_t row0, size_t rows);

// One line per imported symbol, "dll!name", in file order. None is "no imports".
void re_gui_imports_fill(re_gui_listing_t *ls, re_arena_t *a, const re_pe_t *pe, size_t row0,
                         size_t rows);

// One line per export: rva, name, and code, data, or forwarder. The forwarder string
// follows the word when the export is one.
void re_gui_exports_fill(re_gui_listing_t *ls, re_arena_t *a, const re_pe_t *pe, size_t row0,
                         size_t rows);

// One line per class table from a scan already done, plus a line per base. None is
// "no class tables". The scan itself stays with the caller, so it runs once.
void re_gui_structs_fill(re_gui_listing_t *ls, re_arena_t *a, const re_vset_t *vs, size_t row0,
                         size_t rows);

// The right pane for one tab. Tab 0 leaves the listing empty. Tab 1 is not handled
// here: that page is the decompiled body, which the caller already built.
void re_gui_page_fill(re_gui_listing_t *ls, re_arena_t *a, const re_pe_t *pe, const re_vset_t *vs,
                      size_t tab, uint32_t rva, uint32_t size, size_t row0, size_t rows);

#ifdef __cplusplus
}
#endif
