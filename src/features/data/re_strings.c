// re_strings.c - string, device name and PDB extraction from a mapped image.
// Module: feature (C11).
// Owns: printable run scanning in two encodings, device name finding, RSDS.
// Depends: re_strings.h, string.h. Every read is bounded, every run has a hard cap.
#include "features/data/re_strings.h"

#include <string.h>

void re_strings_init(re_strings_t *s) {
    re_vec_init(&s->hits, sizeof(re_str_hit_t));
    re_vec_init(&s->devices, sizeof(re_devname_t));
    s->pdb = re_strn(NULL, 0);
    s->pdb_off = 0;
    s->ascii_count = 0;
    s->wide_count = 0;
}

static bool is_print(uint8_t c) {
    return (c >= 0x20 && c <= 0x7e) || c == '\t' || c == '\n' || c == '\r';
}

bool re_str_is_dynamic(re_str_t s) {
    for (size_t i = 0; i + 1 < s.n; i++) {
        if (s.p[i] != '%')
            continue;
        char c = s.p[i + 1];
        if (c == 's' || c == 'S' || c == 'd' || c == 'u' || c == 'x' || c == 'p' || c == 'l' ||
            c == 'w' || c == 'c' || c == 'I' || c == 'L')
            return true;
    }
    return false;
}

// ASCII hits view the mapped image directly: copying every printable run into the
// arena doubled RSS on large PEs and is never required because the file mapping
// outlives the analysis context. Wide hits pass an already-narrowed arena buffer.
static void push_hit(re_arena_t *a, re_vec_t *v, uint64_t off, const char *p, size_t n, bool wide) {
    re_str_hit_t h;
    if (n == 0 || RE_VEC_LEN(v) >= RE_STR_HITS_MAX)
        return;
    h.off = off;
    h.wide = wide;
    h.text = re_strn(p, n);
    RE_VEC_PUSH(v, a, h);
}

// Next ASCII run at or after *i. A run may end at the file, with no terminator.
static bool next_ascii(re_span_t img, size_t *i, size_t min_len, size_t *start, size_t *n) {
    while (*i < img.n) {
        if (!is_print(img.p[*i])) {
            (*i)++;
            continue;
        }
        *start = *i;
        while (*i < img.n && is_print(img.p[*i]))
            (*i)++;
        *n = *i - *start;
        if (*n >= min_len)
            return true;
    }
    return false;
}

static bool next_wide(re_span_t img, size_t *i, size_t min_len, size_t *start, size_t *chars) {
    while (*i + 1 < img.n) {
        if (!is_print(img.p[*i]) || img.p[*i + 1] != 0) {
            (*i)++;
            continue;
        }
        *start = *i;
        *chars = 0;
        while (*i + 1 < img.n && is_print(img.p[*i]) && img.p[*i + 1] == 0) {
            (*chars)++;
            *i += 2;
        }
        if (*chars >= min_len)
            return true;
    }
    return false;
}

static void scan_ascii(re_span_t img, size_t min_len, size_t max, re_arena_t *a, re_strings_t *s) {
    size_t i = 0;
    size_t start = 0;
    size_t n = 0;
    uint64_t total = 0;
    while (next_ascii(img, &i, min_len, &start, &n)) {
        total++;
        if (max && total > max)
            continue;
        push_hit(a, &s->hits, start, (const char *)img.p + start, n, false);
    }
    s->ascii_count = total;
}

static void scan_wide(re_span_t img, size_t min_len, size_t max, re_arena_t *a, re_strings_t *s) {
    size_t i = 0;
    size_t start = 0;
    size_t chars = 0;
    uint64_t total = 0;
    while (next_wide(img, &i, min_len, &start, &chars)) {
        char *narrow;
        size_t k;
        total++;
        if (max && total > max)
            continue;
        // Narrow to the low bytes so downstream comparison and regex work on
        // one representation regardless of the source encoding.
        narrow = (char *)re_arena_alloc(a, chars);
        if (!narrow) {
            s->wide_count = total;
            return;
        }
        for (k = 0; k < chars; k++)
            narrow[k] = (char)img.p[start + k * 2];
        push_hit(a, &s->hits, start, narrow, chars, true);
    }
    s->wide_count = total;
}

void re_strings_scan(re_span_t img, size_t min_len, size_t max, re_arena_t *a, re_strings_t *out) {
    scan_ascii(img, min_len, max, a, out);
    scan_wide(img, min_len, max, a, out);
}

static void add_device(re_arena_t *a, re_vec_t *v, uint64_t off, const char *p, size_t n,
                       bool wide) {
    if (n == 0 || RE_VEC_LEN(v) >= 1024)
        return;
    for (size_t i = 0; i < RE_VEC_LEN(v); i++) {
        re_devname_t *e = RE_VEC_PTR(v, re_devname_t, i);
        if (e->off == off && e->wide == wide)
            return;
    }
    re_devname_t d;
    d.off = off;
    d.wide = wide;
    d.name = re_strn(re_arena_strndup(a, p, n), n);
    d.dynamic = re_str_is_dynamic(d.name);
    RE_VEC_PUSH(v, a, d);
}

static void find_prefixed(re_span_t img, const char *prefix, size_t plen, bool wide, re_arena_t *a,
                          re_strings_t *out) {
    size_t stride = wide ? 2u : 1u;
    for (size_t i = 0; i + (plen + 1) * stride < img.n; i++) {
        // No prefix can start where its first byte is not: jump to the next one.
        if (img.p[i] != (uint8_t)prefix[0]) {
            const uint8_t *nx = (const uint8_t *)memchr(img.p + i, prefix[0], img.n - i);
            if (!nx)
                break;
            i = (size_t)(nx - img.p) - 1;
            continue;
        }
        bool hit = true;
        for (size_t k = 0; k < plen; k++) {
            size_t at = wide ? i + k * 2 : i + k;
            uint8_t want = (uint8_t)prefix[k];
            uint8_t got = img.p[at];
            if (wide) {
                if (got != want || img.p[at + 1] != 0) {
                    hit = false;
                    break;
                }
            } else if (got != want) {
                hit = false;
                break;
            }
        }
        if (!hit)
            continue;
        size_t start = i;
        size_t chars = 0;
        while (i < img.n) {
            if (wide) {
                if (i + 1 >= img.n || !is_print(img.p[i]) || img.p[i + 1] != 0)
                    break;
                chars++;
                i += 2;
            } else {
                if (!is_print(img.p[i]) || img.p[i] == '\n' || img.p[i] == '\r')
                    break;
                chars++;
                i++;
            }
        }
        if (!wide) {
            add_device(a, &out->devices, start, (const char *)img.p + start, chars, false);
            continue;
        }
        // Narrow a wide name to one byte per character. Passing the raw byte
        // count instead would copy half the string and leave every other byte a
        // NUL, which is both a wrong name and invalid JSON once emitted.
        char *narrow = (char *)re_arena_alloc(a, chars ? chars : 1);
        if (!narrow)
            return;
        for (size_t k = 0; k < chars; k++)
            narrow[k] = (char)img.p[start + k * 2];
        add_device(a, &out->devices, start, narrow, chars, true);
    }
}

void re_strings_devices(re_span_t img, size_t max, re_arena_t *a, re_strings_t *out) {
    (void)max;
    static const char *const prefixes[] = {"\\Device\\", "\\DosDevices\\", "\\??\\", "\\Device"};
    size_t count = sizeof(prefixes) / sizeof(prefixes[0]);
    for (size_t i = 0; i < count; i++) {
        size_t plen = re_str(prefixes[i]).n;
        find_prefixed(img, prefixes[i], plen, false, a, out);
        find_prefixed(img, prefixes[i], plen, true, a, out);
    }
}

void re_strings_pdb(re_span_t img, re_arena_t *a, re_strings_t *out) {
    for (size_t i = 0; i + 24 < img.n; i++) {
        if (img.p[i] != 'R' || img.p[i + 1] != 'S' || img.p[i + 2] != 'D' || img.p[i + 3] != 'S')
            continue;
        // 4 signature, 16 byte GUID, 4 byte age, then a NUL terminated path.
        re_span_t p;
        if (!re_rd_cstr(img, i + 24, 512, &p) || p.n == 0)
            continue;
        bool looks_like_path = false;
        for (size_t k = 0; k < p.n; k++) {
            if (p.p[k] == ':' || p.p[k] == '\\' || p.p[k] == '/') {
                looks_like_path = true;
                break;
            }
        }
        if (!looks_like_path)
            continue;
        out->pdb = re_strn(re_arena_strndup(a, (const char *)p.p, p.n), p.n);
        out->pdb_off = i;
        return;
    }
}

void re_str_page_init(re_str_page_t *p) {
    re_vec_init(&p->hits, sizeof(re_str_hit_t));
    p->total = 0;
    p->truncated = false;
}

static size_t store_cap(size_t limit) {
    size_t cap = limit ? limit : (size_t)RE_STR_HITS_MAX;
    if (cap > (size_t)RE_STR_HITS_MAX)
        cap = (size_t)RE_STR_HITS_MAX;
    return cap;
}

static void consider(re_arena_t *a, re_str_page_t *page, re_rx_t *rx, size_t offset, size_t cap,
                     uint64_t off, const char *p, size_t n, bool wide) {
    size_t st = 0;
    size_t en = 0;
    char *copy;
    re_str_hit_t h;
    if (n == 0)
        return;
    if (rx && !re_rx_search(rx, re_strn(p, n), &st, &en))
        return;
    if (page->total++ < offset)
        return;
    if (RE_VEC_LEN(&page->hits) >= cap)
        return;
    copy = re_arena_strndup(a, p, n);
    if (!copy)
        return;
    h.off = off;
    h.wide = wide;
    h.text = re_strn(copy, n);
    RE_VEC_PUSH(&page->hits, a, h);
}

static void consider_wide(re_arena_t *a, re_str_page_t *page, re_rx_t *rx, size_t offset,
                          size_t cap, re_span_t img, size_t start, size_t chars) {
    char stack[512];
    char *narrow = stack;
    char *owned = NULL;
    size_t k;
    if (chars > sizeof(stack)) {
        owned = (char *)re_arena_alloc(a, chars);
        if (!owned)
            return;
        narrow = owned;
    }
    for (k = 0; k < chars; k++)
        narrow[k] = (char)img.p[start + k * 2];
    consider(a, page, rx, offset, cap, start, narrow, chars, true);
}

void re_strings_collect(re_span_t img, size_t min_len, re_rx_t *rx, size_t offset, size_t limit,
                        re_arena_t *a, re_str_page_t *out) {
    size_t cap = store_cap(limit);
    size_t i = 0;
    size_t start = 0;
    size_t n = 0;
    re_str_page_init(out);
    while (next_ascii(img, &i, min_len, &start, &n))
        consider(a, out, rx, offset, cap, start, (const char *)img.p + start, n, false);
    i = 0;
    while (next_wide(img, &i, min_len, &start, &n))
        consider_wide(a, out, rx, offset, cap, img, start, n);
    out->truncated = offset + RE_VEC_LEN(&out->hits) < out->total;
}

// Apply a regex filter, honouring offset and limit, and report how many hits
// matched in total so the caller can set the truncated flag honestly. A null filter
// matches everything: "no filter" is not "match nothing", which is what the regex
// engine answers when handed a null, and passing hits through it unfiltered turned
// the plain strings report into an empty one.
size_t re_strings_filter(re_arena_t *a, const re_strings_t *s, re_rx_t *rx, size_t offset,
                         size_t limit, re_vec_t *out_hits) {
    size_t matched = 0;
    size_t taken = 0;
    for (size_t i = 0; i < RE_VEC_LEN(&s->hits); i++) {
        const re_str_hit_t *h = RE_VEC_PTR(&s->hits, re_str_hit_t, i);
        size_t st = 0;
        size_t en = 0;
        if (rx && !re_rx_search(rx, h->text, &st, &en))
            continue;
        if (matched++ < offset)
            continue;
        if (limit && taken >= limit)
            continue;
        if (RE_VEC_PUSH(out_hits, a, *h))
            taken++;
    }
    return matched;
}
