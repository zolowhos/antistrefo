// re_tui_box.c - frames: the box characters, panels, and a row of panels.
// Module: util (C11).
// Owns: drawing the border, filling a panel, and composing a row of panels.
// Depends: re_tui.h.
#include "utils/tui/re_tui.h"

#include <string.h>

// The line drawing characters, as UTF-8 escapes so this file stays ASCII. Only the
// set a report actually needs is here: a frame, a horizontal rule and a divider. A
// full set of heavy, double and rounded variants would be decoration, and each would
// need its own fallback for a terminal that cannot show it.
#define B_TL "\xe2\x94\x8c"
#define B_TR "\xe2\x94\x90"
#define B_BL "\xe2\x94\x94"
#define B_BR "\xe2\x94\x98"
#define B_H "\xe2\x94\x80"
#define B_V "\xe2\x94\x82"
#define A_TL "+"
#define A_TR "+"
#define A_BL "+"
#define A_BR "+"
#define A_H "-"
#define A_V "|"

typedef struct {
    const char *tl, *tr, *bl, *br, *h, *v;
} frame_t;

static frame_t frame_of(const re_tui_t *t) {
    frame_t f = {A_TL, A_TR, A_BL, A_BR, A_H, A_V};
    if (t->unicode) {
        f.tl = B_TL;
        f.tr = B_TR;
        f.bl = B_BL;
        f.br = B_BR;
        f.h = B_H;
        f.v = B_V;
    }
    return f;
}

void re_panel_init(re_panel_t *p, re_arena_t *a, const char *title, uint16_t weight) {
    re_strbuf_init(&p->body, a);
    p->title[0] = '\0';
    if (title) {
        size_t n = strlen(title);
        if (n >= sizeof(p->title))
            n = sizeof(p->title) - 1;
        memcpy(p->title, title, n);
        p->title[n] = '\0';
    }
    p->weight = weight ? weight : 1;
}

void re_panel_close(re_panel_t *p) {
    if (p->body.len && p->body.p[p->body.len - 1] != '\n')
        re_strbuf_putc(&p->body, '\n');
}

// A view of one line inside a panel body. The body owns the bytes, so this is a span
// and never a copy: composing a row of panels walks the bodies many times over.
typedef struct {
    const char *p;
    size_t len;
} line_t;

// Advance to the next line. The newline is consumed but not reported, so a caller
// reading the last line does not have to special case a missing terminator.
static bool next_line(const char *base, size_t total, size_t at, line_t *out) {
    if (at >= total)
        return false;
    size_t eol = at;
    while (eol < total && base[eol] != '\n')
        eol++;
    out->p = base + at;
    out->len = eol - at;
    at = eol + 1;
    return true;
}

// The line at index i, or an empty line past the end. Returning an empty line rather
// than failing is what lets the row of panels be padded to a common height.
static line_t line_at(const re_panel_t *p, size_t i) {
    line_t ln = {p->body.p, 0};
    size_t at = 0;
    for (size_t k = 0; k <= i; k++) {
        if (!next_line(p->body.p, p->body.len, at, &ln))
            return (line_t){p->body.p, 0};
        at += ln.len + 1;
    }
    return ln;
}

static size_t panel_lines(const re_panel_t *p) {
    size_t n = 0;
    line_t ln;
    size_t at = 0;
    while (next_line(p->body.p, p->body.len, at, &ln)) {
        n++;
        at += ln.len + 1;
    }
    return n;
}

// The outer width of panel i. Panels are given width strictly in proportion to their
// weights, computed from a cumulative share, which is what makes the row add up to
// exactly the width available: dividing each panel on its own leaves a gap at the
// right edge, and the cumulative form is the only one that hands the rounding
// remainder somewhere visible.
//
// There is deliberately no minimum width here. A floor would have to come out of
// another panel, and a row that no longer adds up is worse than a narrow panel. A
// caller with a narrow terminal should ask re_tui_fits_panels and use fewer of them.
static size_t panel_width(const re_tui_t *t, const re_panel_t *panels, size_t n, size_t i) {
    uint32_t total = 0;
    for (size_t k = 0; k < n; k++)
        total += panels[k].weight;
    size_t avail = t->width > n ? t->width - (n - 1) : t->width;
    uint32_t before = 0;
    for (size_t k = 0; k < i; k++)
        before += panels[k].weight;
    uint32_t upto = before + panels[i].weight;
    size_t hi = (size_t)((uint64_t)avail * upto / total);
    size_t lo = (size_t)((uint64_t)avail * before / total);
    return hi > lo ? hi - lo : 1;
}

// The interior width of a panel: its outer width less the two border columns. A panel
// only two columns wide has no interior, but it still has to draw both corners, so
// this is clamped at zero rather than allowed to go negative and wrap the fill loop.
static size_t interior(size_t outer) {
    return outer >= 2 ? outer - 2 : 0;
}

// The top border of one panel, with its title in the middle of the rule.
static void panel_top(re_tui_t *t, const re_panel_t *p, size_t outer) {
    frame_t f = frame_of(t);
    size_t inner = interior(outer);
    re_strbuf_puts(t->out, f.tl);
    if (p->title[0] && inner > 4) {
        size_t tl = re_tui_cols(p->title);
        if (tl > inner - 2)
            tl = inner - 2;
        re_strbuf_puts(t->out, f.h);
        re_tui_clip_span(t->out, t, p->title, strlen(p->title), tl);
        for (size_t i = 1; i + tl < inner; i++)
            re_strbuf_puts(t->out, f.h);
    } else {
        re_tui_fill(t->out, t, inner, f.h);
    }
    re_strbuf_puts(t->out, f.tr);
    // No newline here: compose terminates the row, because a row of panels is one line
    // of the report and each panel is only part of it.
}

// One body line of one panel, between its vertical borders and padded to the
// interior. A panel with fewer lines than the tallest still gets its frame closed
// below, which is what keeps a row of panels looking like a row and not a staircase.
static void panel_body_line(re_tui_t *t, const re_panel_t *p, size_t outer, size_t row) {
    frame_t f = frame_of(t);
    size_t inner = interior(outer);
    line_t ln = row < panel_lines(p) ? line_at(p, row) : (line_t){p->body.p, 0};
    re_strbuf_puts(t->out, f.v);
    re_strbuf_putc(t->out, ' ');
    re_tui_clip_line(t->out, t, ln.p, ln.len, inner >= 2 ? inner - 1 : 0);
    for (size_t i = re_tui_cols_line(ln.p, ln.len); i + 1 < inner; i++)
        re_strbuf_putc(t->out, ' ');
    re_strbuf_puts(t->out, f.v);
}

// The bottom border of one panel, the mirror of panel_top.
static void panel_bottom(re_tui_t *t, size_t outer) {
    frame_t f = frame_of(t);
    re_strbuf_puts(t->out, f.bl);
    re_tui_fill(t->out, t, interior(outer), f.h);
    re_strbuf_puts(t->out, f.br);
}

void re_tui_compose(re_tui_t *t, re_panel_t *panels, size_t n) {
    size_t tallest = 1;
    if (n > RE_TUI_MAX_PANELS)
        n = RE_TUI_MAX_PANELS;
    if (!n)
        return;
    for (size_t i = 0; i < n; i++) {
        size_t lines = panel_lines(&panels[i]);
        if (lines > tallest)
            tallest = lines;
    }
    // Row zero is the top border, rows one through tallest are the body, and the row
    // after that closes every panel at once. Closing them together is what makes a
    // short panel sit under a tall one instead of ending early and leaving a hole.
    for (size_t row = 0; row <= tallest + 1; row++) {
        for (size_t i = 0; i < n; i++) {
            // A single space between panes, not a third border. Three vertical rules
            // in a row read as a wall, and the point of the frame is to separate the
            // panes rather than to draw as much as possible.
            if (i)
                re_strbuf_putc(t->out, ' ');
            size_t outer = panel_width(t, panels, n, i);
            if (row == 0)
                panel_top(t, &panels[i], outer);
            else if (row == tallest + 1)
                panel_bottom(t, outer);
            else
                panel_body_line(t, &panels[i], outer, row - 1);
        }
        re_strbuf_putc(t->out, '\n');
    }
}

void re_panel_kv(re_tui_t *t, re_panel_t *p, const char *key, const char *val, re_style_t style) {
    re_strbuf_putc(&p->body, ' ');
    re_tui_styled(&p->body, t, RE_ST_LABEL, key);
    re_strbuf_putc(&p->body, ' ');
    re_tui_styled(&p->body, t, style, val);
    re_strbuf_putc(&p->body, '\n');
}

void re_panel_text(re_tui_t *t, re_panel_t *p, const char *s) {
    re_strbuf_putc(&p->body, ' ');
    re_tui_styled(&p->body, t, RE_ST_NONE, s);
    re_strbuf_putc(&p->body, '\n');
}

void re_panel_rule(re_tui_t *t, re_panel_t *p) {
    // A rule inside a panel is a line of spaces, not border characters: it has to read
    // as a separator within the box rather than as another frame, and the vertical
    // borders are drawn by compose so they still line up.
    (void)t;
    re_strbuf_putc(&p->body, ' ');
    re_strbuf_putc(&p->body, '\n');
}
void re_tui_table_init(re_tui_table_t *tt, re_tui_t *t) {
    for (int i = 0; i < RE_TUI_MAX_COLS; i++)
        tt->w[i] = 0;
    tt->n = 0;
    tt->inside = t != NULL;
}

// The share of the row each column takes. The last column is given whatever is left
// over, so a table always reaches the right edge of its box rather than stopping a
// few columns short because the fixed shares did not add up to the width.
static void table_widths(const re_tui_table_t *tt, size_t avail, size_t *out) {
    size_t used = 0;
    for (size_t i = 0; i < tt->n; i++) {
        if (i + 1 == tt->n) {
            out[i] = avail > used ? avail - used : 4;
        } else {
            out[i] = tt->w[i];
            used += tt->w[i];
        }
    }
}

void re_tui_table_head(re_tui_table_t *tt, re_tui_t *t, re_panel_t *p, re_strbuf_t *scratch,
                       const char *const *cols, size_t n) {
    if (n > RE_TUI_MAX_COLS)
        n = RE_TUI_MAX_COLS;
    if (n > tt->n)
        tt->n = n;
    size_t avail = t->width - 6;
    size_t w[RE_TUI_MAX_COLS];
    table_widths(tt, avail, w);
    re_strbuf_t *line = scratch;
    re_strbuf_clear(line);
    for (size_t i = 0; i < n; i++) {
        if (i)
            re_strbuf_putc(line, ' ');
        // The last column is clipped but not padded. Trailing spaces carry nothing,
        // and a padded last column reaches the full width, which the panel then
        // clips and marks with an ellipsis, so the box appears to have run out of room
        // on every row.
        if (i + 1 == n)
            re_tui_clip(line, t, cols[i] ? cols[i] : "", w[i]);
        else
            re_tui_pad(line, t, cols[i] ? cols[i] : "", w[i]);
    }
    re_tui_styled(&p->body, t, RE_ST_HEAD, line->p ? line->p : "");
    re_strbuf_putc(&p->body, '\n');
}

void re_tui_table_row(re_tui_table_t *tt, re_tui_t *t, re_panel_t *p, re_strbuf_t *scratch,
                      const char *const *cells, size_t n) {
    if (n > RE_TUI_MAX_COLS)
        n = RE_TUI_MAX_COLS;
    if (n > tt->n)
        tt->n = n;
    size_t avail = t->width - 6;
    size_t w[RE_TUI_MAX_COLS];
    table_widths(tt, avail, w);
    re_strbuf_t *line = scratch;
    re_strbuf_clear(line);
    for (size_t i = 0; i < n; i++) {
        if (i)
            re_strbuf_putc(line, ' ');
        if (i + 1 == n)
            re_tui_clip(line, t, cells[i] ? cells[i] : "", w[i]);
        else
            re_tui_pad(line, t, cells[i] ? cells[i] : "", w[i]);
    }
    re_strbuf_puts(&p->body, line->p ? line->p : "");
    re_strbuf_putc(&p->body, '\n');
}
