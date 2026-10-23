// re_buf.h - bounds checked reads over an mmap'd file. The safety boundary.
// Module: util (C11).
// Owns: re_span, re_file_t, bounded reads at an offset, endian aware loads.
// Depends: none. Every byte of hostile input enters the project through here.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils/mem/re_arena.h"
#include "utils/mem/re_bits.h"
#include "utils/sys/re_err.h"

// A non owning view of bytes. Every parser takes spans, never raw pointers, so a
// length can never drift away from the memory it describes.
typedef struct {
    const uint8_t *p;
    size_t n;
} re_span_t;

typedef struct {
    re_span_t whole;
    re_span_t path;
    uint64_t size;
    void *map;     // platform mapping handle; always set for a successful open
    uint8_t *heap; // unused: files are mapped, never slurped into a heap copy
} re_file_t;

static inline re_span_t re_span(const void *p, size_t n) {
    re_span_t s;
    s.p = (const uint8_t *)p;
    s.n = p ? n : 0;
    return s;
}

static inline re_span_t re_span_none(void) {
    return re_span(NULL, 0);
}

static inline bool re_span_valid(re_span_t s) {
    return s.p != NULL;
}

static inline re_span_t re_span_sub(re_span_t s, uint64_t off, uint64_t len) {
    if (off > s.n || len > s.n - off)
        return re_span_none();
    return re_span(s.p + off, (size_t)len);
}

static inline re_span_t re_span_from(re_span_t s, uint64_t off) {
    return re_span_sub(s, off, s.n - off);
}

static inline bool re_span_eq(re_span_t a, re_span_t b) {
    return a.p == b.p && a.n == b.n;
}

// Bounded little endian load. Returns false past the end rather than reading.
static inline bool re_rd(re_span_t s, uint64_t off, uint64_t len, re_span_t *out) {
    re_span_t v = re_span_sub(s, off, len);
    if (!re_span_valid(v) && len != 0)
        return false;
    *out = v;
    return true;
}

static inline bool re_rd8(re_span_t s, uint64_t off, uint8_t *out) {
    re_span_t v;
    if (!re_rd(s, off, 1, &v))
        return false;
    *out = v.p[0];
    return true;
}

static inline bool re_rd16(re_span_t s, uint64_t off, uint16_t *out) {
    re_span_t v;
    if (!re_rd(s, off, 2, &v))
        return false;
    *out = (uint16_t)((uint16_t)v.p[0] | ((uint16_t)v.p[1] << 8));
    return true;
}

static inline bool re_rd32(re_span_t s, uint64_t off, uint32_t *out) {
    re_span_t v;
    if (!re_rd(s, off, 4, &v))
        return false;
    *out = (uint32_t)v.p[0] | ((uint32_t)v.p[1] << 8) | ((uint32_t)v.p[2] << 16) |
           ((uint32_t)v.p[3] << 24);
    return true;
}

static inline bool re_rd64(re_span_t s, uint64_t off, uint64_t *out) {
    re_span_t v;
    if (!re_rd(s, off, 8, &v))
        return false;
    uint64_t v64 = 0;
    for (int i = 7; i >= 0; i--)
        v64 = (v64 << 8) | v.p[i];
    *out = v64;
    return true;
}

// Endian aware loads. swap is false for the file's native order, which is what
// every format parser wants and what keeps the byte assembly out of the parsers.
static inline bool re_rd16_be(re_span_t s, uint64_t off, bool swap, uint16_t *out) {
    uint16_t v;
    if (!re_rd16(s, off, &v))
        return false;
    *out = swap ? re_bswap16(v) : v;
    return true;
}

static inline bool re_rd32_be(re_span_t s, uint64_t off, bool swap, uint32_t *out) {
    uint32_t v;
    if (!re_rd32(s, off, &v))
        return false;
    *out = swap ? re_bswap32(v) : v;
    return true;
}

// Little-endian stores into a caller buffer that has room, the mirror of re_rd*. A
// file this project writes is laid out byte by byte with these, never by a struct copy,
// so padding and host order cannot leak into it.
static inline void re_wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static inline void re_wr32(uint8_t *p, uint32_t v) {
    re_wr16(p, (uint16_t)v);
    re_wr16(p + 2, (uint16_t)(v >> 16));
}

static inline void re_wr64(uint8_t *p, uint64_t v) {
    re_wr32(p, (uint32_t)v);
    re_wr32(p + 4, (uint32_t)(v >> 32));
}

// NUL terminated string inside a bounded span, so a missing terminator cannot
// run off the end. Returns false when no terminator is found before max.
bool re_rd_cstr(re_span_t s, uint64_t off, uint64_t max, re_span_t *out);

// Fixed width name at off, NUL padded, the way PE section names are stored.
void re_rd_fixed_str(re_span_t s, uint64_t off, size_t width, re_span_t *out);

// Memory map a file, or fall back to reading it. Never copies more than needed
// and never trusts a length from the file itself.
re_err_code_t re_file_open(const char *path, re_arena_t *a, re_file_t *out);
void re_file_close(re_file_t *f);
#ifdef __cplusplus
}
#endif
