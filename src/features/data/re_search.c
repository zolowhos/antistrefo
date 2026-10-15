// re_search.c - the three search modes. Every scan is linear with a hard cap.
// Module: feature (C11).
// Owns: pattern parsing, the matchers, and hit reporting with offsets.
// Depends: re_search.h only. No globals, no regex reentrancy assumptions.
#include "features/data/re_search.h"

#include "utils/algo/re_regex.h"
#include "utils/text/re_hex.h"
#include "utils/text/re_strbuf.h"

void re_search_init(re_search_t *s) {
    re_vec_init(&s->hits, sizeof(re_search_hit_t));
    s->total = 0;
    s->more = false;
}

bool re_search_parse_pattern(re_arena_t *a, const char *pat, uint8_t **bytes, uint8_t **mask,
                             size_t *n, re_err_t *err) {
    re_str_t src = re_str(pat);
    uint8_t *by = (uint8_t *)re_arena_alloc(a, src.n + 1);
    uint8_t *mk = (uint8_t *)re_arena_alloc(a, src.n + 1);
    if (!by || !mk)
        return false;
    size_t k = 0;
    for (size_t i = 0; i < src.n;) {
        if (src.p[i] == '?') {
            if (i + 1 < src.n && src.p[i + 1] == '?') {
                by[k] = 0;
                mk[k] = 0;
                i += 2;
            } else {
                by[k] = 0;
                mk[k] = 0;
                i++;
            }
            k++;
            continue;
        }
        int hi = re_hex_val(src.p[i]);
        if (hi < 0 || i + 1 >= src.n) {
            re_err_setf(err, RE_E_USAGE, __FILE__, __LINE__,
                        "pattern needs hex pairs, '?' wildcards allowed, got '%c'", src.p[i]);
            return false;
        }
        int lo = re_hex_val(src.p[i + 1]);
        if (lo < 0) {
            re_err_setf(err, RE_E_USAGE, __FILE__, __LINE__, "bad hex digit '%c'", src.p[i + 1]);
            return false;
        }
        by[k] = (uint8_t)((hi << 4) | lo);
        mk[k] = 0xFFu;
        i += 2;
        k++;
    }
    if (k == 0) {
        re_err_set(err, RE_E_USAGE, __FILE__, __LINE__, "pattern is empty");
        return false;
    }
    *bytes = by;
    *mask = mk;
    *n = k;
    return true;
}

static void add_hit(re_arena_t *a, re_search_t *out, uint64_t off, const uint8_t *win, size_t wn) {
    out->total++;
    // The backstop bounds memory when no limit was asked for. Dropping a hit
    // silently is the one thing a search must never do, so it is recorded.
    if (RE_VEC_LEN(&out->hits) >= RE_SEARCH_MAX_HITS) {
        out->more = true;
        return;
    }
    re_search_hit_t h;
    h.off = off;
    h.rva = 0;
    h.has_rva = false;
    h.wide = false;
    h.text = re_strn(NULL, 0);
    re_strbuf_t sb;
    re_strbuf_init(&sb, a);
    re_strbuf_put_hex(&sb, win, wn);
    h.text = re_strn(re_arena_strndup(a, sb.p, sb.len), sb.len);
    RE_VEC_PUSH(&out->hits, a, h);
}

void re_search_bytes(re_span_t img, const uint8_t *pat, const uint8_t *mask, size_t n,
                     size_t offset, size_t limit, re_arena_t *a, re_search_t *out) {
    if (n == 0 || img.n < n)
        return;
    for (size_t i = offset; i + n <= img.n; i++) {
        if (limit && out->total >= limit) {
            // The scan stops here, so total is a floor and not the real count.
            // Saying so is the difference between a bounded answer and a lie.
            out->more = true;
            return;
        }
        size_t k = 0;
        while (k < n && (mask[k] == 0 || img.p[i + k] == pat[k]))
            k++;
        if (k == n)
            add_hit(a, out, i, img.p + i, n);
    }
}

void re_search_immediate(re_span_t img, uint64_t value, unsigned width, bool both_endians,
                         size_t offset, size_t limit, re_arena_t *a, re_search_t *out) {
    if (width != 1 && width != 2 && width != 4 && width != 8)
        return;
    uint8_t le[8];
    for (unsigned i = 0; i < width; i++)
        le[i] = (uint8_t)(value >> (i * 8));
    for (int pass = 0; pass < (both_endians ? 2 : 1); pass++) {
        uint8_t pat[8];
        for (unsigned i = 0; i < width; i++)
            pat[i] = pass == 0 ? le[i] : le[width - 1 - i];
        uint8_t mask[8];
        for (unsigned i = 0; i < width; i++)
            mask[i] = 0xFFu;
        re_search_bytes(img, pat, mask, width, offset, limit, a, out);
    }
}

void re_search_render(re_arena_t *a, re_span_t win, re_str_t *out) {
    re_strbuf_t sb;
    re_strbuf_init(&sb, a);
    re_strbuf_put_hex(&sb, win.p, win.n);
    *out = re_strn(re_arena_strndup(a, sb.p ? sb.p : "", sb.len), sb.len);
}

static bool is_word_byte(uint8_t c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' ||
           c == '.' || c == '@' || c == '?' || c == '$' || c == ':';
}

static void add_text_hit(re_arena_t *a, re_search_t *out, uint64_t off, re_str_t text, bool wide) {
    out->total++;
    if (RE_VEC_LEN(&out->hits) >= RE_SEARCH_MAX_HITS) {
        out->more = true;
        return;
    }
    re_search_hit_t h;
    h.off = off;
    h.rva = 0;
    h.has_rva = false;
    h.wide = wide;
    h.text = re_strn(re_arena_strndup(a, text.p, text.n), text.n);
    RE_VEC_PUSH(&out->hits, a, h);
}

static bool str_eq_ci(re_str_t a, re_str_t b, bool ci) {
    if (a.n != b.n)
        return false;
    for (size_t i = 0; i < a.n; i++) {
        char ca = ci ? re_char_lower(a.p[i]) : a.p[i];
        char cb = ci ? re_char_lower(b.p[i]) : b.p[i];
        if (ca != cb)
            return false;
    }
    return true;
}

// Scan the narrow byte stream for the pattern, advancing past each hit. Searching
// every offset with a substring search would be quadratic, which matters because
// the input is an untrusted file that can be megabytes long.
static void scan_narrow(re_span_t img, re_str_t pat, re_rx_t *rx, bool ci, size_t offset,
                        size_t limit, re_arena_t *a, re_search_t *out) {
    uint8_t first = (uint8_t)pat.p[0];
    uint8_t first_lo = (uint8_t)re_char_lower(pat.p[0]);
    for (size_t i = offset; i < img.n; i++) {
        if (limit && out->total >= limit) {
            // The scan stops here, so total is a floor and not the real count.
            // Saying so is the difference between a bounded answer and a lie.
            out->more = true;
            return;
        }
        uint8_t c = img.p[i];
        // Cheap pre-filter so the match only runs where the first byte can
        // possibly start one. It must fold the byte, or a case insensitive
        // search would only ever find the spelling that matches the case.
        bool pre = ci ? re_char_lower((char)c) == (char)first_lo : c == first;
        if (!pre)
            continue;
        if (rx) {
            re_str_t win = re_strn((const char *)img.p + i, img.n - i);
            size_t en = 0;
            if (re_rx_match_at(rx, win, 0, &en))
                add_text_hit(a, out, i, re_strn(pat.p, pat.n), false);
            continue;
        }
        if (i + pat.n > img.n)
            return;
        re_str_t win = re_strn((const char *)img.p + i, pat.n);
        if (!str_eq_ci(win, pat, ci))
            continue;
        add_text_hit(a, out, i, win, false);
        i += pat.n - 1;
    }
}

// Scan the UTF-16LE stream, narrowing each candidate to one byte per character.
// One maximal wide run starting at i, narrowed to one byte per character so the
// same matcher and the same reported text work for both encodings. Returns false
// only when the arena could not supply the narrowed copy.
static bool scan_wide_run(re_arena_t *a, re_search_t *out, const uint8_t *img, size_t i,
                          size_t chars, re_str_t pat, re_rx_t *rx, bool ci) {
    char *narrow = (char *)re_arena_alloc(a, chars);
    if (!narrow)
        return false;
    for (size_t k = 0; k < chars; k++)
        narrow[k] = (char)img[i + k * 2];
    if (rx) {
        re_str_t view = re_strn(narrow, chars);
        size_t en = 0;
        if (re_rx_match_at(rx, view, 0, &en))
            add_text_hit(a, out, i, view, true);
        return true;
    }
    for (size_t k = 0; k + pat.n <= chars; k++) {
        if (!str_eq_ci(re_strn(narrow + k, pat.n), pat, ci))
            continue;
        add_text_hit(a, out, i + k * 2, re_strn(narrow + k, pat.n), true);
        break;
    }
    return true;
}

// Every position whose successor byte is zero looks like the start of a wide
// run, so stepping one byte at a time rebuilt the same run once per character
// and reported the same offsets again and again. Each run is visited once and
// then stepped over entirely.
static void scan_wide(re_span_t img, re_str_t pat, re_rx_t *rx, bool ci, size_t offset,
                      size_t limit, re_arena_t *a, re_search_t *out) {
    for (size_t i = offset; i + 1 < img.n; i++) {
        if (limit && out->total >= limit) {
            out->more = true;
            return;
        }
        if (img.p[i + 1] != 0)
            continue;
        size_t chars = 0;
        for (size_t j = i; j + 1 < img.n && img.p[j + 1] == 0; j += 2)
            chars++;
        if (chars >= pat.n && !scan_wide_run(a, out, img.p, i, chars, pat, rx, ci))
            return;
        i += chars * 2 - 1;
    }
}

// One hit per offset. A wide run and the low bytes of that same run describe one
// piece of text in one place, so reporting both makes the hit count disagree
// with the number of places the text actually appears. The narrow hit is kept,
// since it is the view a reader wants. The two scans emit in separate ascending
// runs, so the repeats are not adjacent and every kept hit is compared.
static void dedupe_by_offset(re_search_t *out) {
    size_t n = RE_VEC_LEN(&out->hits);
    size_t w = 0;
    for (size_t i = 0; i < n; i++) {
        re_search_hit_t cur = RE_VEC_AT(&out->hits, re_search_hit_t, i);
        bool dup = false;
        for (size_t k = 0; k < w; k++) {
            if (RE_VEC_AT(&out->hits, re_search_hit_t, k).off == cur.off) {
                dup = true;
                break;
            }
        }
        if (dup)
            continue;
        if (w != i)
            RE_VEC_AT(&out->hits, re_search_hit_t, w) = cur;
        w++;
    }
    if (w < n)
        re_vec_truncate(&out->hits, w);
    out->total = w;
}

void re_search_text(re_span_t img, re_str_t pat, bool use_regex, bool case_insensitive,
                    bool wide_only, size_t offset, size_t limit, re_arena_t *a, re_search_t *out) {
    if (pat.n == 0)
        return;
    re_rx_t *rx = NULL;
    if (use_regex) {
        char *p = re_arena_strndup(a, pat.p, pat.n);
        rx = re_rx_compile(a, p, case_insensitive ? "i" : NULL, NULL);
        if (!rx)
            return;
    }
    if (!wide_only)
        scan_narrow(img, pat, rx, case_insensitive, offset, limit, a, out);
    scan_wide(img, pat, rx, case_insensitive, offset, limit, a, out);
    dedupe_by_offset(out);
}

void re_search_signature(re_span_t img, re_str_t pat, size_t offset, size_t limit, re_arena_t *a,
                         re_search_t *out) {
    if (pat.n == 0)
        return;
    for (size_t i = offset; i < img.n; i++) {
        if (limit && out->total >= limit) {
            // The scan stops here, so total is a floor and not the real count.
            // Saying so is the difference between a bounded answer and a lie.
            out->more = true;
            return;
        }
        if (i + pat.n > img.n)
            return;
        re_str_t win = re_strn((const char *)img.p + i, pat.n);
        if (!str_eq_ci(win, pat, true))
            continue;
        bool left_ok = i == 0 || !is_word_byte(img.p[i - 1]);
        bool right_ok = (i + pat.n >= img.n) || !is_word_byte(img.p[i + pat.n]);
        if (left_ok && right_ok)
            add_text_hit(a, out, i, win, false);
    }
}
