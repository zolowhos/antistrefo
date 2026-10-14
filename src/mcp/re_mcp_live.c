// re_mcp_live.c - double-buffered GUI session snapshot for MCP.
// Module: mcp (C11).
// Owns: the two snapshot slots, publish helpers, and console load lines.
// Depends: re_mcp_live.h, re_path, re_format, re_pe, re_func. No heap.
#include "mcp/re_mcp_live.h"

#include "features/code/re_func.h"
#include "features/pe/re_format.h"
#include "features/pe/re_pe.h"
#include "utils/sys/re_path.h"

#include <string.h>

static re_mcp_live_t g_slot[2];
static volatile uint32_t g_cur;
static volatile uint32_t g_gen;

static void copy_cstr(char *dst, size_t cap, const char *src) {
    size_t n = 0;
    if (!dst || !cap)
        return;
    if (!src)
        src = "";
    while (src[n] && n + 1u < cap) {
        dst[n] = src[n];
        n++;
    }
    dst[n] = '\0';
}

static void copy_str_n(char *dst, size_t cap, const char *p, size_t n) {
    size_t i = 0;
    if (!dst || !cap)
        return;
    if (!p)
        n = 0;
    while (i < n && i + 1u < cap) {
        dst[i] = p[i];
        i++;
    }
    dst[i] = '\0';
}

static void fill_from_an(re_mcp_live_t *s, const char *path, const re_analysis_t *an, size_t sel,
                         bool loaded) {
    const char *base;
    memset(s, 0, sizeof(*s));
    s->loaded = loaded && path && path[0];
    if (!s->loaded)
        return;
    copy_cstr(s->path, sizeof(s->path), path);
    base = re_path_basename_ptr(path);
    copy_cstr(s->name, sizeof(s->name), base);
    s->sel = sel;
    if (!an || !an->ok) {
        copy_cstr(s->format, sizeof(s->format), "unknown");
        return;
    }
    if (an->has_pe) {
        copy_cstr(s->format, sizeof(s->format), "pe");
        copy_cstr(s->arch, sizeof(s->arch), re_pe_machine_name(an->pe.machine));
    } else {
        re_format_t fmt = re_format_detect(an->file.whole);
        copy_cstr(s->format, sizeof(s->format), re_format_name(fmt));
        copy_cstr(s->arch, sizeof(s->arch), re_format_arch_hint(an->file.whole, fmt));
    }
    if (an->has_code) {
        const re_func_t *f = re_func_at(&an->scan, sel);
        if (f) {
            s->func_rva = f->rva;
            if (f->name.n)
                copy_str_n(s->func_name, sizeof(s->func_name), f->name.p, f->name.n);
        }
    }
}

static void publish(const re_mcp_live_t *src) {
    uint32_t next = (g_cur + 1u) & 1u;
    re_mcp_live_t *dst = &g_slot[next];
    *dst = *src;
    dst->gen = ++g_gen;
    g_cur = next;
}

static void push_line(re_console_t *console, const char *a, const char *b, const char *c) {
    char msg[RE_CONSOLE_LINE];
    size_t n = 0;
    const char *parts[3];
    size_t i;
    if (!console)
        return;
    parts[0] = a ? a : "";
    parts[1] = b ? b : "";
    parts[2] = c ? c : "";
    for (i = 0; i < 3; i++) {
        const char *p = parts[i];
        while (*p && n + 1u < RE_CONSOLE_LINE)
            msg[n++] = *p++;
    }
    msg[n] = '\0';
    re_console_push(console, msg);
}

void re_mcp_live_snapshot(re_mcp_live_t *out) {
    if (!out)
        return;
    *out = g_slot[g_cur & 1u];
}

const char *re_mcp_live_path(void) {
    const re_mcp_live_t *s = &g_slot[g_cur & 1u];
    return s->loaded && s->path[0] ? s->path : NULL;
}

void re_mcp_live_note_load(re_console_t *console, const char *path, const re_analysis_t *an,
                           size_t sel) {
    re_mcp_live_t cur;
    re_mcp_live_t next;
    re_mcp_live_snapshot(&cur);
    fill_from_an(&next, path, an, sel, true);
    copy_cstr(next.mcp_endpoint, sizeof(next.mcp_endpoint), cur.mcp_endpoint);
    next.mcp_up = cur.mcp_up;
    publish(&next);
    push_line(console, "loaded ", next.name[0] ? next.name : "file", " into antistrefo");
}

void re_mcp_live_note_sel(const re_analysis_t *an, size_t sel, bool loaded) {
    re_mcp_live_t cur;
    re_mcp_live_t next;
    re_mcp_live_snapshot(&cur);
    if (!loaded || !cur.path[0]) {
        if (!cur.loaded)
            return;
        cur.loaded = false;
        cur.sel = 0;
        cur.func_rva = 0;
        cur.func_name[0] = '\0';
        publish(&cur);
        return;
    }
    if (cur.loaded && cur.sel == sel)
        return;
    fill_from_an(&next, cur.path, an, sel, true);
    copy_cstr(next.mcp_endpoint, sizeof(next.mcp_endpoint), cur.mcp_endpoint);
    next.mcp_up = cur.mcp_up;
    publish(&next);
}

void re_mcp_live_note_mcp(re_console_t *console, const char *endpoint, bool up) {
    re_mcp_live_t cur;
    re_mcp_live_snapshot(&cur);
    copy_cstr(cur.mcp_endpoint, sizeof(cur.mcp_endpoint), endpoint ? endpoint : "");
    cur.mcp_up = up;
    publish(&cur);
    if (up && endpoint && endpoint[0])
        push_line(console, "mcp ", endpoint, "");
}

void re_mcp_live_clear_file(void) {
    re_mcp_live_t cur;
    re_mcp_live_snapshot(&cur);
    cur.loaded = false;
    cur.path[0] = '\0';
    cur.name[0] = '\0';
    cur.format[0] = '\0';
    cur.arch[0] = '\0';
    cur.func_name[0] = '\0';
    cur.func_rva = 0;
    cur.sel = 0;
    publish(&cur);
}
