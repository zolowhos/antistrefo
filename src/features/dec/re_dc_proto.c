// re_dc_proto.c - the prototype an import name is known by.
// Module: feature (C11).
// Owns: the binary search over the prototype tables and the A/W fallback.
// Depends: re_dc_proto.h, dec/proto/re_dc_ptab.h. A name not listed has no prototype,
//           and the caller falls back to what the call site itself shows.
#include "features/dec/re_dc_proto.h"

#include "features/dec/proto/re_dc_ptab.h"

static const re_dc_ptab_t *const kTabs[] = {&re_dc_ptab_k32, &re_dc_ptab_crt, &re_dc_ptab_nt,
                                            &re_dc_ptab_win};

// Byte order comparison of the first n bytes of name against a NUL terminated row.
static int cmp_name(const char *p, size_t n, const char *row) {
    size_t i = 0;
    for (; i < n && row[i]; i++)
        if ((unsigned char)p[i] != (unsigned char)row[i])
            return (unsigned char)p[i] < (unsigned char)row[i] ? -1 : 1;
    if (i < n)
        return 1;
    return row[i] ? -1 : 0;
}

static const re_dc_pent_t *search(const re_dc_ptab_t *t, const char *p, size_t n) {
    size_t lo = 0, hi = t->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = cmp_name(p, n, t->rows[mid].name);
        if (c == 0)
            return &t->rows[mid];
        if (c < 0)
            hi = mid;
        else
            lo = mid + 1;
    }
    return NULL;
}

static const re_dc_pent_t *lookup(const char *p, size_t n) {
    for (size_t i = 0; i < sizeof(kTabs) / sizeof(kTabs[0]); i++) {
        const re_dc_pent_t *e = search(kTabs[i], p, n);
        if (e)
            return e;
    }
    return NULL;
}

bool re_dc_proto_find(re_str_t name, re_dc_proto_t *out) {
    if (!name.p || !name.n)
        return false;
    const re_dc_pent_t *e = lookup(name.p, name.n);
    char last = name.p[name.n - 1];
    if (!e && name.n > 1 && (last == 'A' || last == 'W'))
        e = lookup(name.p, name.n - 1); // CreateFileW is CreateFile
    if (!e)
        return false;
    if (out) {
        out->nargs = e->nargs;
        out->ret = e->ret;
    }
    return true;
}

// The first n comma separated arguments of args, or all of them when fewer.
static void take(const char *args, uint8_t n, char *dst, size_t cap) {
    uint32_t i = 0;
    uint8_t seen = 0;
    if (cap)
        dst[0] = 0;
    if (!args || !n || cap == 0)
        return;
    while (args[i] && seen < n && i + 1 < cap) {
        if (args[i] == ',' && args[i + 1] == ' ') {
            seen++;
            if (seen == n)
                break;
        }
        dst[i] = args[i];
        i++;
    }
    dst[i] = 0;
}

bool re_dc_proto_format(re_str_t name, const char *args, char *dst, size_t cap) {
    re_dc_proto_t pr;
    char taken[160];
    if (!dst || cap == 0 || !re_dc_proto_find(name, &pr))
        return false;
    take(args, pr.nargs, taken, sizeof(taken));
    uint32_t i = 0;
    uint32_t k = 0;
    while (i < name.n && k + 1 < cap)
        dst[k++] = name.p[i++];
    if (k + 1 < cap)
        dst[k++] = '(';
    i = 0;
    while (taken[i] && k + 1 < cap)
        dst[k++] = taken[i++];
    if (k + 1 < cap)
        dst[k++] = ')';
    dst[k] = 0;
    return true;
}

int re_dc_proto_nargs(re_str_t name) {
    re_dc_proto_t pr;
    return re_dc_proto_find(name, &pr) ? (int)pr.nargs : -1;
}
