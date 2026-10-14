// re_console.h - fixed ring of short log lines for the GUI console band.
// Module: util (C11).
// Owns: the ring, push, scrollback offset, and the four visible line pointers.
// Depends: none. No I/O, no heap; storage is inside the struct.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stddef.h>
#include <stdint.h>

// Capacity of the ring and the width of one stored line, including the NUL.
#define RE_CONSOLE_CAP 64u
#define RE_CONSOLE_LINE 96u
// How many lines the layout band shows at once.
#define RE_CONSOLE_VIEW 4u

typedef struct {
    char line[RE_CONSOLE_CAP][RE_CONSOLE_LINE];
    size_t head;  // next write slot
    size_t count; // how many slots hold a line, capped at RE_CONSOLE_CAP
    size_t off;   // scrollback: 0 shows the newest window
} re_console_t;

void re_console_init(re_console_t *c);

// Append one line. Clips to RE_CONSOLE_LINE - 1 and resets scrollback to newest.
void re_console_push(re_console_t *c, const char *text);

// Step scrollback. Positive looks older; clamped to the available history.
void re_console_scroll(re_console_t *c, int delta);

// Fill out[0..VIEW) with the visible window, oldest of the window first.
// Returns how many pointers were set (0 when the ring is empty).
size_t re_console_view(const re_console_t *c, const char *out[RE_CONSOLE_VIEW]);

#ifdef __cplusplus
}
#endif
