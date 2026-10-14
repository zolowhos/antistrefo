// re_alt.c - load, save, and apply user function renames from .alt sidecars.
// Module: feature (C11).
// Owns: the RVA-keyed map and the line format "0xRVA=name".
// Depends: re_alt.h, re_buf, re_hex, re_strbuf. No heap outside the arena.
#include "features/analysis/re_alt.h"

#include "utils/mem/re_buf.h"
#include "utils/text/re_hex.h"

#include <stdio.h>
#include <string.h>

static int cmp_ent(const void *pa, const void *pb, void *ctx) {
    const re_alt_ent_t *a = (const re_alt_ent_t *)pa;
    const re_alt_ent_t *b = (const re_alt_ent_t *)pb;
    (void)ctx;
    if (a->rva != b->rva)
        return a->rva < b->rva ? -1 : 1;
    return 0;
}

void re_alt_init(re_alt_t *m, re_arena_t *a) {
    memset(m, 0, sizeof(*m));
    m->arena = a;
    re_vec_init(&m->ents, sizeof(re_alt_ent_t));
}

char *re_alt_sidecar(re_arena_t *a, const char *bin_path) {
    re_str_t p = re_str(bin_path);
    char *out;
    if (!a || !p.n)
        return NULL;
    out = (char *)re_arena_alloc(a, p.n + 5u);
    if (!out)
        return NULL;
    memcpy(out, p.p, p.n);
    memcpy(out + p.n, ".alt", 5);
    return out;
}

static bool name_ok(re_str_t n) {
    if (n.n == 0 || n.n > RE_ALT_NAME_MAX)
        return false;
    for (size_t i = 0; i < n.n; i++) {
        unsigned char c = (unsigned char)n.p[i];
        if (c < 0x20u || c == 0x7fu || c == '=')
            return false;
    }
    return true;
}

static bool parse_u32(re_str_t s, uint32_t *out) {
    uint64_t acc = 0;
    uint64_t mul = 10;
    size_t i = 0;
    if (s.n > 2 && s.p[0] == '0' && (s.p[1] == 'x' || s.p[1] == 'X')) {
        mul = 16;
        i = 2;
    }
    if (i >= s.n)
        return false;
    for (; i < s.n; i++) {
        int d = re_hex_val(s.p[i]);
        if (d < 0 || (uint64_t)d >= mul)
            return false;
        acc = acc * mul + (uint64_t)d;
        if (acc > 0xffffffffull)
            return false;
    }
    *out = (uint32_t)acc;
    return true;
}

static long find_idx(const re_alt_t *m, uint32_t rva) {
    size_t lo = 0;
    size_t hi = RE_VEC_LEN(&m->ents);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const re_alt_ent_t *e = RE_VEC_PTR(&m->ents, re_alt_ent_t, mid);
        if (rva < e->rva)
            hi = mid;
        else if (rva > e->rva)
            lo = mid + 1;
        else
            return (long)mid;
    }
    return -1;
}

const re_alt_ent_t *re_alt_find(const re_alt_t *m, uint32_t rva) {
    long i = m ? find_idx(m, rva) : -1;
    return i < 0 ? NULL : RE_VEC_PTR(&m->ents, re_alt_ent_t, (size_t)i);
}

static void erase_at(re_alt_t *m, size_t idx) {
    size_t n = RE_VEC_LEN(&m->ents);
    size_t esz = m->ents.esz;
    if (idx + 1u < n)
        memmove(m->ents.base + idx * esz, m->ents.base + (idx + 1u) * esz, (n - idx - 1u) * esz);
    m->ents.len = n - 1u;
}

bool re_alt_set(re_alt_t *m, uint32_t rva, re_str_t name) {
    long idx;
    re_str_t trimmed;
    re_alt_ent_t e;
    if (!m || !m->arena)
        return false;
    trimmed = re_str_trim(name);
    idx = find_idx(m, rva);
    if (trimmed.n == 0) {
        if (idx >= 0)
            erase_at(m, (size_t)idx);
        return true;
    }
    if (!name_ok(trimmed))
        return false;
    e.rva = rva;
    e.name = re_strn(re_arena_strndup(m->arena, trimmed.p, trimmed.n), trimmed.n);
    if (!e.name.p)
        return false;
    if (idx >= 0) {
        *RE_VEC_PTR(&m->ents, re_alt_ent_t, (size_t)idx) = e;
        return true;
    }
    if (RE_VEC_LEN(&m->ents) >= RE_ALT_MAX_ENTS)
        return false;
    RE_VEC_PUSH(&m->ents, m->arena, e);
    re_vec_sort(&m->ents, cmp_ent, NULL);
    return true;
}

static bool parse_line(re_alt_t *m, re_str_t line) {
    size_t eq = 0;
    uint32_t rva = 0;
    line = re_str_trim(line);
    if (line.n == 0 || line.p[0] == '#')
        return true;
    while (eq < line.n && line.p[eq] != '=')
        eq++;
    if (eq >= line.n)
        return false;
    if (!parse_u32(re_str_trim(re_strn(line.p, eq)), &rva))
        return false;
    return re_alt_set(m, rva, re_str_trim(re_strn(line.p + eq + 1, line.n - eq - 1)));
}

bool re_alt_load(re_alt_t *m, const char *bin_path) {
    char *side;
    re_file_t f;
    re_str_t text;
    size_t i = 0;
    if (!m || !bin_path)
        return false;
    side = re_alt_sidecar(m->arena, bin_path);
    if (!side)
        return false;
    if (re_file_open(side, m->arena, &f) != RE_OK)
        return true;
    text = re_strn((const char *)f.whole.p, f.whole.n);
    while (i < text.n) {
        size_t start = i;
        while (i < text.n && text.p[i] != '\n' && text.p[i] != '\r')
            i++;
        if (!parse_line(m, re_strn(text.p + start, i - start))) {
            re_file_close(&f);
            return false;
        }
        if (i < text.n && text.p[i] == '\r')
            i++;
        if (i < text.n && text.p[i] == '\n')
            i++;
    }
    re_file_close(&f);
    return true;
}

bool re_alt_save(const re_alt_t *m, const char *bin_path) {
    char path[1024];
    FILE *fp;
    re_str_t p;
    if (!m || !bin_path)
        return false;
    p = re_str(bin_path);
    if (p.n + 4u >= sizeof(path))
        return false;
    memcpy(path, p.p, p.n);
    memcpy(path + p.n, ".alt", 5);
    fp = fopen(path, "wb");
    if (!fp)
        return false;
    for (size_t i = 0; i < RE_VEC_LEN(&m->ents); i++) {
        const re_alt_ent_t *e = RE_VEC_PTR(&m->ents, re_alt_ent_t, i);
        if (fprintf(fp, "0x%x=%.*s\n", e->rva, (int)e->name.n, e->name.p) < 0) {
            fclose(fp);
            return false;
        }
    }
    return fclose(fp) == 0;
}

size_t re_alt_apply(re_fscan_t *scan, const re_alt_t *m) {
    size_t n = 0;
    if (!scan || !m)
        return 0;
    for (size_t i = 0; i < RE_VEC_LEN(&scan->funcs); i++) {
        re_func_t *f = RE_VEC_PTR(&scan->funcs, re_func_t, i);
        const re_alt_ent_t *e = re_alt_find(m, f->rva);
        if (!e)
            continue;
        f->name = e->name;
        f->module = re_str("alt");
        n++;
    }
    return n;
}

static bool parse_addr_tok(re_str_t s, const re_pe_t *pe, uint64_t *va_out) {
    uint64_t acc = 0;
    uint64_t mul = 10;
    size_t i = 0;
    if (s.n > 2 && s.p[0] == '0' && (s.p[1] == 'x' || s.p[1] == 'X')) {
        mul = 16;
        i = 2;
    }
    if (i >= s.n)
        return false;
    for (; i < s.n; i++) {
        int d = re_hex_val(s.p[i]);
        if (d < 0 || (uint64_t)d >= mul)
            return false;
        acc = acc * mul + (uint64_t)d;
    }
    if (acc >= pe->image_base && (acc - pe->image_base) < pe->size_of_image)
        *va_out = acc;
    else
        *va_out = pe->image_base + acc;
    return true;
}

static void fmt_sub(char *dst, size_t cap, uint64_t va) {
    size_t n = 0;
    if (cap < 5)
        return;
    dst[n++] = 's';
    dst[n++] = 'u';
    dst[n++] = 'b';
    dst[n++] = '_';
    for (int i = 15; i >= 0 && n + 1 < cap; i--)
        dst[n++] = re_hex_nibble((uint8_t)((va >> (unsigned)(i * 4)) & 0xfu));
    dst[n] = '\0';
}

bool re_alt_resolve(const re_fscan_t *scan, const re_pe_t *pe, re_str_t target, uint32_t *rva_out) {
    uint64_t va = 0;
    long idx;
    target = re_str_trim(target);
    if (!scan || !pe || !rva_out || target.n == 0)
        return false;
    if (parse_addr_tok(target, pe, &va)) {
        idx = re_func_index_of(scan, va);
        if (idx >= 0) {
            *rva_out = re_func_at(scan, (size_t)idx)->rva;
            return true;
        }
        if (va >= pe->image_base) {
            *rva_out = (uint32_t)(va - pe->image_base);
            return true;
        }
    }
    for (size_t i = 0; i < RE_VEC_LEN(&scan->funcs); i++) {
        const re_func_t *f = re_func_at(scan, i);
        char syn[40];
        if (f->name.n && re_str_eq(f->name, target)) {
            *rva_out = f->rva;
            return true;
        }
        fmt_sub(syn, sizeof(syn), f->va);
        if (re_str_ieq_cstr(target, syn)) {
            *rva_out = f->rva;
            return true;
        }
    }
    return false;
}
