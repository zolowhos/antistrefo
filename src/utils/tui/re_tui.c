// re_tui.c - the environment policy and the flat parts of a report.
// Module: util (C11).
// Owns: the output policy, the width, the colour styles, and the flat report elements.
// Depends: re_tui.h. Reads the environment and asks the OS whether stdout is a terminal.
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#    define _POSIX_C_SOURCE 200809L
#endif
#include "utils/tui/re_tui.h"

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
// fcntl for the _O_TEXT and _O_BINARY modes, io for the stream handles, and
// windows.h for the console code page. The order matters: windows.h pulls in a great
// deal, and it wants these two first.
#    include <fcntl.h>
#    include <io.h>
#    include <windows.h>
#    define RE_ISATTY(fd) _isatty(fd)
#    define RE_FILENO(f) _fileno(f)
#else
#    include <stdio.h>
#    include <unistd.h>
#    include <sys/ioctl.h>
#    define RE_ISATTY(fd) isatty(fd)
#    define RE_FILENO(f) fileno(f)
#endif

// The style escapes, one table so no caller writes one. Each style resets to default
// at the end, which is what keeps a styled fragment from colouring whatever comes
// after it if the output is concatenated somewhere unexpected.
// The ceilings and the fallback for a caller that has no terminal to ask. Same
// numbers as the grid's own limits so a size read here can always be used as one.
#define TERM_H_MAX 200
#define TERM_H_DEFAULT 24

uint16_t re_tui_term_width(void);

typedef struct {
    const char *on;
    const char *off;
} style_t;

static const style_t kStyles[RE_ST_CALL + 1] = {
    {"", ""},                  // none
    {"\x1b[1;7m", "\x1b[0m"},  // title, inverted
    {"\x1b[1m", "\x1b[0m"},    // head, bold
    {"\x1b[2m", "\x1b[0m"},    // label, dim
    {"\x1b[1;36m", "\x1b[0m"}, // accent, bold cyan
    {"\x1b[32m", "\x1b[0m"},   // good, green
    {"\x1b[33m", "\x1b[0m"},   // warn, yellow
    {"\x1b[1;31m", "\x1b[0m"}, // bad, bold red
    // hover: dark text on light blue. press: light text on dark blue.
    {"\x1b[38;2;12;36;64;48;2;186;220;255m", "\x1b[0m"},
    {"\x1b[38;2;232;242;255;48;2;15;55;130m", "\x1b[0m"},
    {"\x1b[1;35m", "\x1b[0m"}, // keyword, bold magenta
    {"\x1b[36m", "\x1b[0m"},   // type, cyan
    {"\x1b[90m", "\x1b[0m"},   // comment, grey
    {"\x1b[33m", "\x1b[0m"},   // string, yellow
    {"\x1b[31m", "\x1b[0m"},   // number, red
    {"\x1b[1;32m", "\x1b[0m"}, // call, bold green
};

bool re_tui_is_tty(void) {
    return RE_ISATTY(RE_FILENO(stdout)) != 0;
}

bool re_tui_stdin_tty(void) {
    return RE_ISATTY(RE_FILENO(stdin)) != 0;
}

// The width of the window, not of the scrollback buffer. They differ whenever the
// buffer is wider than the visible area, which is what happens after a resize, and the
// buffer width would then draw a frame wider than the screen and wrap it.
#if defined(_WIN32)
static int console_width(void) {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE || !GetConsoleScreenBufferInfo(h, &csbi))
        return 0;
    int w = csbi.srWindow.Right - csbi.srWindow.Left + 1;
    return w > 0 ? w : 0;
}
#else
static int console_width(void) {
    struct winsize ws;
    // STDOUT is asked first and stderr second, because a person piping stdout to a file
    // still has a terminal, and the width of the terminal is what they are reading in.
    for (int fd = 1; fd <= 2; fd++) {
        if (ioctl(fd, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
            return (int)ws.ws_col;
    }
    return 0;
}
#endif

static int console_height(void) {
#if defined(_WIN32)
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE || !GetConsoleScreenBufferInfo(h, &csbi))
        return 0;
    int r = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
    return r > 0 ? r : 0;
#else
    return 0;
#endif
}

void re_tui_term_size(uint16_t *rows, uint16_t *cols) {
    uint16_t w = re_tui_term_width();
    int h = console_height();
#if !defined(_WIN32)
    if (h <= 0) {
        struct winsize ws;
        for (int fd = 1; fd <= 2; fd++) {
            if (ioctl(fd, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0) {
                h = (int)ws.ws_row;
                if (w < (int)RE_TUI_MIN_WIDTH && (int)ws.ws_col >= (int)RE_TUI_MIN_WIDTH)
                    w = ws.ws_col > 200 ? (uint16_t)200 : (uint16_t)ws.ws_col;
                break;
            }
        }
    }
#endif
    if (rows)
        *rows = h > 0 ? (h > TERM_H_MAX ? (uint16_t)TERM_H_MAX : (uint16_t)h)
                      : (uint16_t)TERM_H_DEFAULT;
    if (cols)
        *cols = w;
}

uint16_t re_tui_term_width(void) {
    // A real console answers for itself, and it is the only source that follows a
    // resize. COLUMNS is the fallback for a shell that exports it, which is rare, and
    // 80 is the last resort for a pipe.
    int w = console_width();
    if (w >= (int)RE_TUI_MIN_WIDTH)
        return w > 200 ? (uint16_t)200 : (uint16_t)w;
    const char *cols = getenv("COLUMNS");
    if (cols && *cols) {
        long v = strtol(cols, NULL, 10);
        if (v >= (long)RE_TUI_MIN_WIDTH)
            return v > 200 ? (uint16_t)200 : (uint16_t)v;
    }
    return RE_TUI_DEFAULT_WIDTH;
}

bool re_tui_want_color(void) {
    // NO_COLOR is a near universal expectation, so it is honoured here rather than
    // left to every caller. The variable being present at all is what counts, even
    // when empty, which is what the convention specifies.
    const char *nc = getenv("NO_COLOR");
    return !(nc != NULL);
}

bool re_tui_console_utf8(void) {
    if (!re_tui_is_tty())
        return false;
#if defined(_WIN32)
    // CP_UTF8 is 65001. Anything else means the console would decode our box
    // characters with the OEM code page, and a report drawn in those looks like
    // corruption rather than like a report.
    return GetConsoleOutputCP() == 65001u;
#else
    // A POSIX terminal takes the bytes as they are, so there is nothing to check.
    return true;
#endif
}

bool re_tui_want_unicode(void) {
    // An explicit override wins, so a user on a console that misreports its code page
    // can get the characters they want, and a log can be forced to plain ASCII.
    const char *force = getenv("RE_TUI_UNICODE");
    if (force && *force)
        return true;
    const char *legacy = getenv("RE_TUI_ASCII");
    if (legacy && *legacy)
        return false;
    return re_tui_console_utf8();
}

void re_tui_set_stream_mode(bool binary) {
#if defined(_WIN32)
    // Text mode is what a terminal needs, because it is the mode in which a newline
    // returns the cursor to column 0. Binary is what the MCP contract needs, because
    // it specifies one object and a single \n with no translation of either.
    int mode = binary ? _O_BINARY : _O_TEXT;
    _setmode(_fileno(stdout), mode);
    _setmode(_fileno(stderr), mode);
#else
    (void)binary; // POSIX streams have no text or binary mode to choose between
#endif
}

void re_tui_init(re_tui_t *t, re_strbuf_t *out, re_strbuf_t *scratch, bool color, bool unicode,
                 uint16_t width) {
    t->out = out;
    t->scratch = scratch;
    t->width = width < RE_TUI_MIN_WIDTH ? RE_TUI_DEFAULT_WIDTH : width;
    t->color = color;
    t->unicode = unicode;
}

const char *re_tui_style_on(re_style_t style) {
    if ((unsigned)style > (unsigned)RE_ST_CALL)
        return "";
    return kStyles[style].on;
}

void re_tui_styled(re_strbuf_t *dst, const re_tui_t *t, re_style_t style, const char *s) {
    if (!t->color || style == RE_ST_NONE || (unsigned)style > (unsigned)RE_ST_CALL) {
        re_strbuf_puts(dst, s ? s : "");
        return;
    }
    re_strbuf_puts(dst, kStyles[style].on);
    re_strbuf_puts(dst, s ? s : "");
    re_strbuf_puts(dst, kStyles[style].off);
}

void re_tui_fill(re_strbuf_t *dst, const re_tui_t *t, size_t n, const char *with) {
    (void)t;
    for (size_t i = 0; i < n; i++)
        re_strbuf_puts(dst, with);
}

void re_tui_rule(re_tui_t *t) {
    re_tui_fill(t->out, t, t->width, t->unicode ? "\xe2\x94\x80" : "-");
    re_strbuf_putc(t->out, '\n');
}

void re_tui_header(re_tui_t *t, const char *left, const char *right) {
    // The bar is one styled run rather than styled in pieces, so the inverse attribute
    // covers the padding and not just the text. A half inverted bar is the single most
    // visible way for this to look wrong. The scratch buffer belongs to the caller
    // because this utility keeps no state, and because a header is not reentrant with
    // one scratch buffer anyway.
    re_strbuf_t *scratch = t->scratch;
    size_t lw = re_tui_cols(left);
    size_t rw = re_tui_cols(right);
    size_t pad = 0;
    if (lw + rw + 1 <= t->width) {
        // Both fit with a column of gap between them, so fill the line exactly.
        pad = t->width - lw - rw;
    } else {
        // They do not both fit, and the summary is the half a reader can do without:
        // the file name in the subject already says which file this is. Dropping it
        // whole beats trimming it mid word, which is what a naive clip produces.
        rw = 0;
        pad = t->width > lw ? t->width - lw : 0;
    }
    re_strbuf_clear(scratch);
    re_strbuf_puts(scratch, left ? left : "");
    for (size_t i = 0; i < pad; i++)
        re_strbuf_putc(scratch, ' ');
    if (rw)
        re_strbuf_puts(scratch, right ? right : "");
    // Trim as a backstop, for a subject that is on its own longer than the line. A bar
    // that runs past the edge wraps, which leaves the cursor in the wrong column and
    // breaks every box drawn after it.
    size_t n = scratch->len;
    while (n > 0 && re_tui_cols_span(scratch->p, n) > t->width)
        n--;
    scratch->p[n] = '\0';
    scratch->len = n;
    re_tui_styled(t->out, t, RE_ST_TITLE, scratch->p ? scratch->p : "");
    re_strbuf_putc(t->out, '\n');
}

void re_tui_tabs(re_tui_t *t, const char *const *labels, size_t n, size_t active) {
    if (n > RE_TUI_MAX_PANELS * 2)
        n = RE_TUI_MAX_PANELS * 2;
    for (size_t i = 0; i < n; i++) {
        if (i)
            re_tui_styled(t->out, t, RE_ST_LABEL, " | ");
        re_tui_styled(t->out, t, i == active ? RE_ST_ACCENT : RE_ST_LABEL,
                      labels[i] ? labels[i] : "");
    }
    re_strbuf_putc(t->out, '\n');
}
