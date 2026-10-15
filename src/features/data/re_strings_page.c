// re_strings_page.c - printable run around a hit, and the JSON for a hit list.
// Module: feature (C11).
// Owns: same-encoding neighbor windows and the JSON array of string hits.
// Depends: re_strings.h. No I/O. Walks only as far as the neighbor cap.
#include "features/data/re_strings.h"

static bool is_print(uint8_t c) {
    return (c >= 0x20 && c <= 0x7e) || c == '\t' || c == '\n' || c == '\r';
}

static re_str_t copy_cap(re_arena_t *a, const char *p, size_t n, size_t cap) {
    char *d;
    if (n > cap)
        n = cap;
    d = re_arena_strndup(a, p, n);
    return re_strn(d, d ? n : 0);
}

static re_str_t copy_wide_cap(re_arena_t *a, const uint8_t *p, size_t chars, size_t cap) {
    char *d;
    size_t k;
    if (chars > cap)
        chars = cap;
    d = (char *)re_arena_alloc(a, chars + 1);
    if (!d)
        return re_strn(NULL, 0);
    for (k = 0; k < chars; k++)
        d[k] = (char)p[k * 2];
    d[chars] = '\0';
    return re_strn(d, chars);
}

static void push_rev(re_arena_t *a, re_vec_t *out, re_str_hit_t *tmp, size_t n) {
    while (n > 0) {
        n--;
        RE_VEC_PUSH(out, a, tmp[n]);
    }
}

static bool ascii_run_at(re_span_t img, uint64_t off, size_t *start, size_t *n) {
    size_t s;
    size_t e;
    if (off >= img.n || !is_print(img.p[off]))
        return false;
    s = (size_t)off;
    while (s > 0 && is_print(img.p[s - 1]))
        s--;
    e = (size_t)off;
    while (e < img.n && is_print(img.p[e]))
        e++;
    *start = s;
    *n = e - s;
    return *n > 0;
}

static void ascii_before(re_span_t img, size_t start, size_t min_len, size_t want, re_arena_t *a,
                         re_vec_t *out) {
    re_str_hit_t tmp[RE_STR_CONTEXT_MAX];
    size_t got = 0;
    size_t i = start;
    while (got < want && i > 0) {
        size_t end;
        size_t n;
        i--;
        if (!is_print(img.p[i]))
            continue;
        end = i + 1;
        while (i > 0 && is_print(img.p[i - 1]))
            i--;
        n = end - i;
        if (n < min_len)
            continue;
        tmp[got].off = i;
        tmp[got].wide = false;
        tmp[got].text = copy_cap(a, (const char *)img.p + i, n, RE_STR_NEIGHBOR_CAP);
        got++;
    }
    push_rev(a, out, tmp, got);
}

static void ascii_after(re_span_t img, size_t i, size_t min_len, size_t want, re_arena_t *a,
                        re_vec_t *out) {
    size_t got = 0;
    while (got < want && i < img.n) {
        size_t st;
        size_t n;
        re_str_hit_t h;
        if (!is_print(img.p[i])) {
            i++;
            continue;
        }
        st = i;
        while (i < img.n && is_print(img.p[i]))
            i++;
        n = i - st;
        if (n < min_len)
            continue;
        h.off = st;
        h.wide = false;
        h.text = copy_cap(a, (const char *)img.p + st, n, RE_STR_NEIGHBOR_CAP);
        RE_VEC_PUSH(out, a, h);
        got++;
    }
}

static bool wide_run_at(re_span_t img, uint64_t off, size_t *start, size_t *chars) {
    size_t i;
    size_t s;
    size_t e;
    if (off >= img.n)
        return false;
    i = (size_t)off;
    if ((i & 1u) != 0 && i > 0)
        i--;
    if (i + 1 >= img.n || !is_print(img.p[i]) || img.p[i + 1] != 0)
        return false;
    s = i;
    while (s >= 2 && is_print(img.p[s - 2]) && img.p[s - 1] == 0)
        s -= 2;
    e = i;
    while (e + 1 < img.n && is_print(img.p[e]) && img.p[e + 1] == 0)
        e += 2;
    *start = s;
    *chars = (e - s) / 2;
    return *chars > 0;
}

static void wide_before(re_span_t img, size_t start, size_t min_len, size_t want, re_arena_t *a,
                        re_vec_t *out) {
    re_str_hit_t tmp[RE_STR_CONTEXT_MAX];
    size_t got = 0;
    size_t i = start;
    while (got < want && i >= 2) {
        size_t end;
        size_t chars;
        if (!is_print(img.p[i - 2]) || img.p[i - 1] != 0) {
            i--;
            continue;
        }
        end = i;
        while (i >= 2 && is_print(img.p[i - 2]) && img.p[i - 1] == 0)
            i -= 2;
        chars = (end - i) / 2;
        if (chars < min_len)
            continue;
        tmp[got].off = i;
        tmp[got].wide = true;
        tmp[got].text = copy_wide_cap(a, img.p + i, chars, RE_STR_NEIGHBOR_CAP);
        got++;
    }
    push_rev(a, out, tmp, got);
}

static void wide_after(re_span_t img, size_t i, size_t min_len, size_t want, re_arena_t *a,
                       re_vec_t *out) {
    size_t got = 0;
    while (got < want && i + 1 < img.n) {
        size_t st;
        size_t chars = 0;
        re_str_hit_t h;
        if (!is_print(img.p[i]) || img.p[i + 1] != 0) {
            i++;
            continue;
        }
        st = i;
        while (i + 1 < img.n && is_print(img.p[i]) && img.p[i + 1] == 0) {
            chars++;
            i += 2;
        }
        if (chars < min_len)
            continue;
        h.off = st;
        h.wide = true;
        h.text = copy_wide_cap(a, img.p + st, chars, RE_STR_NEIGHBOR_CAP);
        RE_VEC_PUSH(out, a, h);
        got++;
    }
}

static void fill_ascii(re_span_t img, uint64_t off, size_t min_len, size_t neighbors, re_arena_t *a,
                       re_str_around_t *out) {
    size_t start = 0;
    size_t n = 0;
    if (!ascii_run_at(img, off, &start, &n))
        return;
    out->found = true;
    out->run.off = start;
    out->run.wide = false;
    out->run.text = copy_cap(a, (const char *)img.p + start, n, n);
    if (!neighbors)
        return;
    ascii_before(img, start, min_len, neighbors, a, &out->before);
    ascii_after(img, start + n, min_len, neighbors, a, &out->after);
}

static void fill_wide(re_span_t img, uint64_t off, size_t min_len, size_t neighbors, re_arena_t *a,
                      re_str_around_t *out) {
    size_t start = 0;
    size_t chars = 0;
    if (!wide_run_at(img, off, &start, &chars))
        return;
    out->found = true;
    out->run.off = start;
    out->run.wide = true;
    out->run.text = copy_wide_cap(a, img.p + start, chars, chars);
    if (!neighbors)
        return;
    wide_before(img, start, min_len, neighbors, a, &out->before);
    wide_after(img, start + chars * 2, min_len, neighbors, a, &out->after);
}

void re_str_around(re_span_t img, uint64_t off, bool wide, size_t min_len, size_t neighbors,
                   re_arena_t *a, re_str_around_t *out) {
    if (neighbors > RE_STR_CONTEXT_MAX)
        neighbors = RE_STR_CONTEXT_MAX;
    out->found = false;
    out->run.off = off;
    out->run.wide = wide;
    out->run.text = re_strn(NULL, 0);
    re_vec_init(&out->before, sizeof(re_str_hit_t));
    re_vec_init(&out->after, sizeof(re_str_hit_t));
    if (wide)
        fill_wide(img, off, min_len, neighbors, a, out);
    else
        fill_ascii(img, off, min_len, neighbors, a, out);
}

void re_str_hits_json(re_jw_t *w, const char *key, const re_vec_t *hits) {
    size_t i;
    re_jw_key(w, key);
    re_jw_arr(w);
    for (i = 0; i < RE_VEC_LEN(hits); i++) {
        const re_str_hit_t *h = RE_VEC_PTR(hits, re_str_hit_t, i);
        re_jw_obj(w);
        re_jw_khex(w, "off", h->off, 8);
        re_jw_kbool(w, "wide", h->wide);
        re_jw_kstr(w, "text", h->text);
        re_jw_obj_end(w);
    }
    re_jw_arr_end(w);
}
