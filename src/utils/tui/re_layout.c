// re_layout.c - composes the reference screen arrangement out of a description.
// Module: util (C11).
// Owns: re_layout_compose, which fixes the band order and the splitter position.
// Depends: re_screen.h, re_strbuf. Owns no data of its own and reads no input.
//           The arrangement is expressed, not hard coded per report, so a different
//           report can reuse it by filling the struct differently.
#include "utils/tui/re_layout.h"
#include "utils/tui/re_screen.h"
#include "utils/tui/re_syntax.h"

// The split is a proportion rather than a column count, because a fixed left column
// that is right on an 80 column terminal is most of the screen on a 200 column one,
// and wrong in the other direction on a 60. A proportion of the available width is
// the only thing that survives both, so the clamp is expressed the same way.
#define SPLIT_MIN 18u
#define SPLIT_MAX_FRAC 45u // percent of the body width, so the code pane never vanishes

static uint16_t left_width(uint16_t total, uint16_t want) {
    if (want < SPLIT_MIN)
        want = SPLIT_MIN;
    uint16_t cap = (uint16_t)((total * SPLIT_MAX_FRAC) / 100u);
    if (cap < SPLIT_MIN)
        cap = SPLIT_MIN;
    if (want > cap)
        want = cap;
    if (total > SPLIT_MIN + 12u && want > total - 12u)
        want = (uint16_t)(total - 12u);
    return want;
}

typedef struct {
    const char *h;
    const char *v;
    const char *tl;
    const char *tr;
    const char *bl;
    const char *br;
} frame_t;

static frame_t frame_of(const re_screen_t *s) {
    frame_t f;
    if (s->tui.unicode) {
        f.h = "\xe2\x94\x80";
        f.v = "\xe2\x94\x82";
        f.tl = "\xe2\x94\x8c";
        f.tr = "\xe2\x94\x90";
        f.bl = "\xe2\x94\x94";
        f.br = "\xe2\x94\x98";
        return f;
    }
    f.h = "-";
    f.v = "|";
    f.tl = "+";
    f.tr = "+";
    f.bl = "+";
    f.br = "+";
    return f;
}

static uint16_t dash_n(re_screen_t *s, uint16_t y, uint16_t x, uint16_t n, uint16_t limit,
                       const char *h) {
    for (uint16_t i = 0; i < n && x < limit; i++) {
        re_screen_put(s, y, x, h, (uint8_t)RE_ST_NONE, RE_SCREEN_ZONE_NONE);
        x++;
    }
    return x;
}

static uint16_t bracket_item(re_screen_t *s, uint16_t y, uint16_t x, uint16_t limit,
                             const char *label, uint8_t st, uint8_t zone) {
    if (x >= limit)
        return x;
    re_screen_put(s, y, x, "<", st, zone);
    x = re_screen_put_run(s, y, (uint16_t)(x + 1u), limit, label ? label : "", st, zone);
    if (x < limit) {
        re_screen_put(s, y, x, ">", st, zone);
        x++;
    }
    return x;
}

// The menu row. Items are <Name>, the version sits at the right, and the file name
// takes whatever gap is left between them.
static void draw_menu(re_screen_t *s, re_layout_t *L, const frame_t *f) {
    uint16_t last = (uint16_t)(s->cols - 1u);
    size_t mw = (L->mark && *L->mark) ? re_tui_cols(L->mark) + 2u : 0u;
    uint16_t mark_x = last;
    if (mw && mw + 2u < last)
        mark_x = (uint16_t)(last - 1u - mw);
    re_screen_put(s, 0, 0, f->tl, (uint8_t)RE_ST_NONE, RE_SCREEN_ZONE_NONE);
    uint16_t cx = 1;
    uint8_t first = RE_SCREEN_ZONE_NONE;
    for (size_t i = 0; i < L->n_toolbar && cx + 4u < mark_x; i++) {
        const char *label = L->toolbar && L->toolbar[i] ? L->toolbar[i] : "";
        size_t lc = re_tui_cols(label);
        if (cx + 1u + lc + 2u >= mark_x)
            break;
        cx = dash_n(s, 0, cx, 1, mark_x, f->h);
        uint8_t zone = re_screen_zone(s);
        if (first == RE_SCREEN_ZONE_NONE)
            first = zone;
        cx = bracket_item(s, 0, cx, mark_x, label, (uint8_t)RE_ST_NONE, zone);
    }
    L->open_zone = first;
    if (L->file && *L->file && cx + 2u < mark_x)
        cx =
            re_screen_put_run(s, 0, cx, mark_x, L->file, (uint8_t)RE_ST_LABEL, RE_SCREEN_ZONE_NONE);
    cx = dash_n(s, 0, cx, (uint16_t)(mark_x > cx ? (unsigned)(mark_x - cx) : 0u), mark_x, f->h);
    if (mw && mark_x < last)
        cx = bracket_item(s, 0, mark_x, last, L->mark, (uint8_t)RE_ST_NONE, RE_SCREEN_ZONE_NONE);
    cx = dash_n(s, 0, cx, (uint16_t)(last > cx ? (unsigned)(last - cx) : 0u), last, f->h);
    re_screen_put(s, 0, last, f->tr, (uint8_t)RE_ST_NONE, RE_SCREEN_ZONE_NONE);
}

// The page row. The list title fills the left pane's edge, and the pages start at the
// split so the bar under them lines up with the names.
static void draw_pages(re_screen_t *s, re_layout_t *L, uint16_t split, const frame_t *f) {
    uint16_t last = (uint16_t)(s->cols - 1u);
    if (split >= last)
        split = (uint16_t)(last / 2u);
    re_screen_put(s, 1, 0, f->tl, (uint8_t)RE_ST_NONE, RE_SCREEN_ZONE_NONE);
    uint16_t cx = dash_n(s, 1, 1, 3, split, f->h);
    if (L->list_title && *L->list_title && cx + 2u < split)
        cx = bracket_item(s, 1, cx, split, L->list_title, (uint8_t)RE_ST_NONE, RE_SCREEN_ZONE_NONE);
    cx = dash_n(s, 1, cx, (uint16_t)(split > cx ? (unsigned)(split - cx) : 0u), split, f->h);
    uint8_t first = RE_SCREEN_ZONE_NONE;
    uint8_t drawn = 0;
    for (size_t i = 0; i < L->n_tabs && cx + 4u < last; i++) {
        const char *label = L->tabs && L->tabs[i] ? L->tabs[i] : "";
        size_t lc = re_tui_cols(label);
        uint16_t gap = (i == L->active_tab) ? 3u : 1u;
        if ((size_t)cx + gap + lc + 2u >= last)
            break;
        cx = dash_n(s, 1, cx, gap, last, f->h);
        uint8_t zone = re_screen_zone(s);
        if (first == RE_SCREEN_ZONE_NONE)
            first = zone;
        uint8_t st = (i == L->active_tab) ? (uint8_t)RE_ST_ACCENT : (uint8_t)RE_ST_NONE;
        cx = bracket_item(s, 1, cx, last, label, st, zone);
        drawn++;
    }
    L->tab_zone = first;
    L->tabs_drawn = drawn;
    cx = dash_n(s, 1, cx, (uint16_t)(last > cx ? (unsigned)(last - cx) : 0u), last, f->h);
    re_screen_put(s, 1, last, f->tr, (uint8_t)RE_ST_NONE, RE_SCREEN_ZONE_NONE);
}

static void draw_bottom(re_screen_t *s, const frame_t *f) {
    uint16_t y = (uint16_t)(s->rows - 1u);
    uint16_t last = (uint16_t)(s->cols - 1u);
    re_screen_put(s, y, 0, f->bl, (uint8_t)RE_ST_NONE, RE_SCREEN_ZONE_NONE);
    (void)dash_n(s, y, 1, (uint16_t)(last - 1u), last, f->h);
    re_screen_put(s, y, last, f->br, (uint8_t)RE_ST_NONE, RE_SCREEN_ZONE_NONE);
}

static void draw_body(re_screen_t *s, re_layout_t *L, uint16_t split, const frame_t *f) {
    uint16_t last = (uint16_t)(s->cols - 1u);
    uint16_t y1 = (uint16_t)(s->rows - 1u);
    for (uint16_t y = 2; y < y1; y++) {
        uint16_t r = (uint16_t)(y - 2u);
        re_screen_put(s, y, 0, f->v, (uint8_t)RE_ST_NONE, RE_SCREEN_ZONE_NONE);
        re_screen_put(s, y, split, f->v, (uint8_t)RE_ST_NONE, RE_SCREEN_ZONE_NONE);
        re_screen_put(s, y, last, f->v, (uint8_t)RE_ST_NONE, RE_SCREEN_ZONE_NONE);
        if (L->rows && r < L->n_rows && split > 2u) {
            uint8_t st = (r == L->sel_row) ? (uint8_t)RE_ST_ACCENT : (uint8_t)RE_ST_NONE;
            uint8_t zone = re_screen_zone(s);
            if (L->rows_drawn == 0)
                L->row_zone = zone;
            if (L->rows_drawn < 255)
                L->rows_drawn++;
            re_screen_fill(s, y, 1, (uint16_t)(split - 1u), 1, " ", st, zone);
            re_screen_put_run(s, y, 2, split, L->rows[r] ? L->rows[r] : "", st, zone);
        }
        if (L->code && r < L->n_code && split + 2u < last) {
            const char *line = L->code[r] ? L->code[r] : "";
            if (L->syntax)
                re_syntax_put(s, y, (uint16_t)(split + 2u), last, line);
            else
                re_screen_put_run(s, y, (uint16_t)(split + 2u), last, line, (uint8_t)RE_ST_NONE,
                                  RE_SCREEN_ZONE_NONE);
        }
    }
}

// The body before a file is open: one framed box, the message, and the one control
// that does anything.
//
// Both are placed by a single helper rather than by arithmetic at each call site, so
// there is one answer to "where does a centred run start" and it is checkable on its
// own. A box this size has one thing in it and no need to scan, so a fixed indent would
// do; centring is because a lone control under a lone line reads as a question, and a
// question wants to be in the middle.
static void centred(re_screen_t *s, uint16_t y, uint16_t width, const char *text, uint8_t style,
                    uint8_t zone) {
    size_t n = re_tui_cols(text);
    if (!n || n + 2u >= width)
        return;
    uint16_t x = (uint16_t)(1u + (width - n) / 2u);
    re_screen_put_run(s, y, x, (uint16_t)(1u + width), text, style, zone);
}

static void draw_welcome(re_screen_t *s, re_layout_t *L, const frame_t *f) {
    uint16_t last = (uint16_t)(s->cols - 1u);
    uint16_t y1 = (uint16_t)(s->rows - 1u);
    re_screen_put(s, 1, 0, f->tl, (uint8_t)RE_ST_NONE, RE_SCREEN_ZONE_NONE);
    (void)dash_n(s, 1, 1, (uint16_t)(last - 1u), last, f->h);
    re_screen_put(s, 1, last, f->tr, (uint8_t)RE_ST_NONE, RE_SCREEN_ZONE_NONE);
    for (uint16_t y = 2; y < y1; y++) {
        re_screen_put(s, y, 0, f->v, (uint8_t)RE_ST_NONE, RE_SCREEN_ZONE_NONE);
        re_screen_put(s, y, last, f->v, (uint8_t)RE_ST_NONE, RE_SCREEN_ZONE_NONE);
    }
    uint16_t inner = (uint16_t)(y1 > 2u ? y1 - 2u : 0u);
    uint16_t mid = (uint16_t)(2u + inner / 2u);
    centred(s, (uint16_t)(mid > 2u ? mid - 2u : 2u), s->cols, "Get started", (uint8_t)RE_ST_NONE,
            RE_SCREEN_ZONE_NONE);
    centred(s, mid, s->cols, L->welcome ? L->welcome : "", (uint8_t)RE_ST_NONE,
            RE_SCREEN_ZONE_NONE);
    if (mid + 2u >= y1)
        return;
    const char *label = L->button ? L->button : "Load";
    char btn[32];
    size_t k = 0;
    btn[k++] = '[';
    for (size_t i = 0; label[i] && k + 2u < sizeof(btn); i++)
        btn[k++] = label[i];
    btn[k++] = ']';
    btn[k] = '\0';
    L->button_zone = re_screen_zone(s);
    centred(s, (uint16_t)(mid + 2u), s->cols, btn, (uint8_t)RE_ST_ACCENT, L->button_zone);
}

uint16_t re_layout_compose(re_screen_t *s, re_layout_t *L) {
    if (!s->cell || !L)
        return 0;
    L->button_zone = RE_SCREEN_ZONE_NONE;
    L->open_zone = RE_SCREEN_ZONE_NONE;
    L->tab_zone = RE_SCREEN_ZONE_NONE;
    L->tabs_drawn = 0;
    L->row_zone = RE_SCREEN_ZONE_NONE;
    L->rows_drawn = 0;
    if (s->rows < 4u || s->cols < 16u) {
        re_screen_clear(s);
        re_screen_put_run(s, 0, 0, s->cols, L->file ? L->file : "", (uint8_t)RE_ST_TITLE,
                          RE_SCREEN_ZONE_NONE);
        return 0;
    }
    re_screen_clear(s);
    frame_t f = frame_of(s);
    draw_menu(s, L, &f);
    if (L->welcome) {
        draw_welcome(s, L, &f);
        draw_bottom(s, &f);
        return (uint16_t)(s->rows - 2u);
    }
    uint16_t split = left_width(s->cols, L->left_w);
    if (split + 8u >= s->cols)
        split = (uint16_t)(s->cols / 3u);
    draw_pages(s, L, split, &f);
    draw_body(s, L, split, &f);
    draw_bottom(s, &f);
    return (uint16_t)re_layout_body_rows(s->rows);
}
