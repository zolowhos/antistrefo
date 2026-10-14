// re_console.c - fixed ring of short log lines for the GUI console band.
// Module: util (C11).
// Owns: push, scroll, and the four-line view window over the ring.
// Depends: re_console.h. No heap; every byte lives in the caller's struct.
#include "utils/tui/re_console.h"

#include <string.h>

void re_console_init(re_console_t *c) {
    if (!c)
        return;
    memset(c, 0, sizeof(*c));
}

void re_console_push(re_console_t *c, const char *text) {
    size_t n = 0;
    char *dst;
    if (!c)
        return;
    if (!text)
        text = "";
    dst = c->line[c->head % RE_CONSOLE_CAP];
    while (text[n] && n + 1u < RE_CONSOLE_LINE) {
        dst[n] = text[n];
        n++;
    }
    dst[n] = '\0';
    c->head++;
    if (c->count < RE_CONSOLE_CAP)
        c->count++;
    c->off = 0;
}

void re_console_scroll(re_console_t *c, int delta) {
    size_t max_off;
    if (!c || !c->count || !delta)
        return;
    max_off = c->count > RE_CONSOLE_VIEW ? c->count - RE_CONSOLE_VIEW : 0u;
    if (delta > 0) {
        size_t step = (size_t)delta;
        c->off = c->off + step > max_off ? max_off : c->off + step;
        return;
    }
    {
        size_t step = (size_t)(-delta);
        c->off = c->off > step ? c->off - step : 0u;
    }
}

size_t re_console_view(const re_console_t *c, const char *out[RE_CONSOLE_VIEW]) {
    size_t n;
    size_t start;
    size_t i;
    if (!c || !out || !c->count)
        return 0;
    n = c->count < RE_CONSOLE_VIEW ? c->count : RE_CONSOLE_VIEW;
    // Newest window ends at head - 1 - off; walk back n lines from there.
    start = c->head - 1u - c->off;
    for (i = 0; i < n; i++) {
        size_t idx = start - (n - 1u - i);
        out[i] = c->line[idx % RE_CONSOLE_CAP];
    }
    for (; i < RE_CONSOLE_VIEW; i++)
        out[i] = NULL;
    return n;
}
