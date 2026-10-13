// re_path.h - filesystem path helpers that treat both separators as equal.
// Module: util (C11).
// Owns: absolute test, extension, dirname, basename, join, normalize, path compare.
// Depends: re_arena and re_str. No I/O, never touches the filesystem, no globals.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>

#include "utils/mem/re_arena.h"
#include "utils/text/re_str.h"

#define RE_PATH_SEP '/'
#define RE_PATH_SEP_ALT '\\'
#define RE_PATH_NPOS ((size_t) - 1)

static inline bool re_path_is_sep(char c) {
    return c == RE_PATH_SEP || c == RE_PATH_SEP_ALT;
}

static inline bool re_path_is_abs(const char *p) {
    if (!p || !p[0])
        return false;
    if (p[0] == RE_PATH_SEP || p[0] == RE_PATH_SEP_ALT)
        return true;
    // Windows drive letter, C:\ or C:/
    return p[0] && p[1] == ':' && re_path_is_sep(p[2]);
}

// Offset of the extension including the dot, or RE_PATH_NPOS. A leading dot on
// the basename is a hidden file, not an extension.
static inline size_t re_path_ext_off(const char *p) {
    re_str_t s = re_str(p);
    long slash = re_str_rfind_char(s, RE_PATH_SEP, s.n);
    long alt = re_str_rfind_char(s, RE_PATH_SEP_ALT, s.n);
    long cut = slash > alt ? slash : alt;
    for (size_t i = s.n; i > 0; i--) {
        char c = s.p[i - 1];
        if (c == RE_PATH_SEP || c == RE_PATH_SEP_ALT)
            break;
        if (c == '.')
            return i - 1 > (size_t)cut + 1 ? i - 1 : RE_PATH_NPOS;
    }
    return RE_PATH_NPOS;
}

static inline bool re_path_ext_is(const char *p, const char *want) {
    size_t off = re_path_ext_off(p);
    if (off == RE_PATH_NPOS)
        return false;
    return re_str_ieq_cstr(re_strn(p + off, strlen(p + off)), want);
}

static inline const char *re_path_basename_ptr(const char *p) {
    re_str_t s = re_str(p);
    long slash = re_str_rfind_char(s, RE_PATH_SEP, s.n);
    long alt = re_str_rfind_char(s, RE_PATH_SEP_ALT, s.n);
    long cut = slash > alt ? slash : alt;
    return p + (size_t)cut + 1;
}

static inline char *re_path_basename(re_arena_t *a, const char *p) {
    return re_arena_strdup(a, re_path_basename_ptr(p));
}

// Length of the directory part including the trailing separator, 0 if none.
static inline size_t re_path_dir_len(const char *p) {
    re_str_t s = re_str(p);
    long slash = re_str_rfind_char(s, RE_PATH_SEP, s.n);
    long alt = re_str_rfind_char(s, RE_PATH_SEP_ALT, s.n);
    long cut = slash > alt ? slash : alt;
    return cut < 0 ? 0 : (size_t)cut + 1;
}

static inline char *re_path_dirname(re_arena_t *a, const char *p) {
    size_t n = re_path_dir_len(p);
    if (n == 0)
        return re_arena_strdup(a, ".");
    if (n == 1)
        return re_arena_strdup(a, "/");
    return re_arena_strndup(a, p, n - 1);
}

// Join with a single separator, skipping it when b is already absolute.
static inline char *re_path_join(re_arena_t *a, const char *dir, const char *name) {
    re_str_t d = re_str(dir);
    re_str_t n = re_str(name);
    if (d.n == 0)
        return re_arena_strndup(a, n.p, n.n);
    if (n.n == 0)
        return re_arena_strndup(a, d.p, d.n);
    if (re_path_is_abs(n.p))
        return re_arena_strndup(a, n.p, n.n);
    size_t total = d.n + 1 + n.n;
    char *out = (char *)re_arena_alloc(a, total + 1);
    if (!out)
        return NULL;
    memcpy(out, d.p, d.n);
    if (!re_path_is_sep(d.p[d.n - 1]))
        out[d.n] = RE_PATH_SEP;
    memcpy(out + d.n + 1, n.p, n.n);
    out[total] = '\0';
    return out;
}

// Collapse duplicate separators and resolve . and .. textually. Does not touch
// the filesystem, so it is safe to call on paths that do not exist.
static inline char *re_path_normalize(re_arena_t *a, const char *p) {
    re_str_t in = re_str(p);
    re_vec_t parts;
    re_vec_init(&parts, sizeof(re_str_t));
    size_t i = 0;
    while (i < in.n) {
        if (re_path_is_sep(in.p[i])) {
            i++;
            continue;
        }
        size_t start = i;
        while (i < in.n && !re_path_is_sep(in.p[i]))
            i++;
        re_str_t seg = re_strn(in.p + start, i - start);
        if (re_str_eq_cstr(seg, "."))
            continue;
        if (re_str_eq_cstr(seg, "..")) {
            if (parts.len)
                parts.len--;
            continue;
        }
        if (!RE_VEC_PUSH(&parts, a, seg))
            return NULL;
    }
    size_t total = 0;
    for (size_t k = 0; k < parts.len; k++)
        total += RE_VEC_AT(&parts, re_str_t, k).n + 1;
    char *out = (char *)re_arena_alloc(a, total + 2);
    if (!out)
        return NULL;
    size_t o = 0;
    if (re_path_is_abs(p))
        out[o++] = RE_PATH_SEP;
    for (size_t k = 0; k < parts.len; k++) {
        if (k)
            out[o++] = RE_PATH_SEP;
        re_str_t seg = RE_VEC_AT(&parts, re_str_t, k);
        memcpy(out + o, seg.p, seg.n);
        o += seg.n;
    }
    if (o == 0)
        out[o++] = '.';
    out[o] = '\0';
    return out;
}

// Case insensitive on Windows, exact elsewhere. Used to spot the same file.
static inline bool re_path_eq(const char *a, const char *b) {
#if defined(_WIN32)
    return re_str_icmp(re_str(a), re_str(b)) == 0;
#else
    return re_str_eq_cstr(re_str(a), b);
#endif
}
#ifdef __cplusplus
}
#endif
