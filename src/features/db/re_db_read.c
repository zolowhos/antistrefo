// re_db_read.c - maps an .asdb, refuses anything malformed, and loads it pass by pass.
// Module: feature (C11).
// Owns: re_db_open validation, section and record access, and re_db_load_pass.
// Depends: re_db_priv.h, re_buf, re_hash. Every byte is read through re_rd* on the mapping.
#include "features/db/re_db_priv.h"

#include <stddef.h>
#include <string.h>

char *re_db_path(re_arena_t *a, const char *bin_path) {
    re_strbuf_t sb;
    re_strbuf_init(&sb, a);
    if (!bin_path || !re_strbuf_puts(&sb, bin_path) || !re_strbuf_puts(&sb, RE_DB_SUFFIX))
        return NULL;
    return sb.p;
}

void re_db_hash_source(re_span_t src, uint8_t out[RE_SHA256_LEN]) {
    re_sha256(src.p, (size_t)src.n, out);
}

static bool fail(re_err_t *err, re_err_code_t code, const char *msg) {
    if (err)
        RE_ERR_SET(err, code, msg);
    return false;
}

// One directory entry. A section must sit after the header, inside the file, hold
// exactly count elements, and appear once.
static bool read_dirent(re_db_t *db, uint64_t at, re_err_t *err) {
    re_span_t e;
    re_db_sec_t s;
    uint64_t n = db->file.whole.n;
    if (!re_rd(db->file.whole, at, RE_DB_DIRENT, &e))
        return fail(err, RE_E_MALFORMED, "database directory runs past the end");
    s.id = re_db_f32(e, 0);
    s.elem = re_db_f32(e, 4);
    s.off = re_db_f64(e, 8);
    s.size = re_db_f64(e, 16);
    s.count = re_db_f64(e, 24);
    if (s.id == RE_DBS_NONE || s.id >= RE_DBS_COUNT || db->sec[s.id].id != 0)
        return fail(err, RE_E_MALFORMED, "database section id is unknown or repeated");
    if (s.off < RE_DB_HDR || s.off > n || s.size > n - s.off || s.elem == 0)
        return fail(err, RE_E_MALFORMED, "database section lies outside the file");
    if (s.count > s.size / s.elem || s.count * s.elem != s.size)
        return fail(err, RE_E_MALFORMED, "database section size disagrees with its count");
    db->sec[s.id] = s;
    return true;
}

static bool read_header(re_db_t *db, re_span_t src, re_err_t *err, uint32_t *n_sec,
                        uint64_t *dir_off) {
    re_span_t h;
    uint8_t want[RE_SHA256_LEN];
    if (!re_rd(db->file.whole, 0, RE_DB_HDR, &h))
        return fail(err, RE_E_MALFORMED, "database is shorter than its header");
    if (re_db_f32(h, 0) != RE_DB_MAGIC || re_db_f32(h, 4) != RE_DB_VERSION ||
        memcmp(h.p + 8, RE_DB_SCHEMA, sizeof(RE_DB_SCHEMA) - 1u) != 0)
        return fail(err, RE_E_UNSUPPORTED, "database is from another format version");
    db->src_size = re_db_f64(h, 24);
    memcpy(db->src_sha, h.p + 32, RE_SHA256_LEN);
    db->flags = re_db_f32(h, 64);
    *n_sec = re_db_f32(h, 68);
    *dir_off = re_db_f64(h, 72);
    db->user_off = re_db_f64(h, 80);
    if (db->src_size != src.n)
        return fail(err, RE_E_NOTFOUND, "database is for another version of this file");
    re_db_hash_source(src, want);
    if (memcmp(want, db->src_sha, RE_SHA256_LEN) != 0)
        return fail(err, RE_E_NOTFOUND, "database is for another version of this file");
    if (*n_sec == 0 || *n_sec >= RE_DBS_COUNT || db->user_off > db->file.whole.n)
        return fail(err, RE_E_MALFORMED, "database header is inconsistent");
    return true;
}

// The string table must end in a NUL, so a view into it is always terminated.
static bool strtab_ok(const re_db_t *db) {
    re_span_t t = re_db_section(db, RE_DBS_STRTAB);
    uint8_t last = 1;
    return t.n == 0 || (re_rd8(t, t.n - 1u, &last) && last == 0);
}

bool re_db_open(re_db_t *db, const char *path, re_span_t src, re_arena_t *a, re_err_t *err) {
    uint32_t n_sec = 0;
    uint64_t dir_off = 0;
    memset(db, 0, sizeof(*db));
    if (!path || re_file_open(path, a, &db->file) != RE_OK)
        return fail(err, RE_E_NOTFOUND, "no database");
    db->path = re_str(re_arena_strdup(a, path));
    if (!read_header(db, src, err, &n_sec, &dir_off)) {
        re_file_close(&db->file);
        return false;
    }
    for (uint32_t i = 0; i < n_sec; i++) {
        if (!read_dirent(db, dir_off + (uint64_t)i * RE_DB_DIRENT, err)) {
            re_file_close(&db->file);
            return false;
        }
    }
    if (!strtab_ok(db) || db->sec[RE_DBS_FUNCS].id == 0 || db->sec[RE_DBS_SUMMARY].id == 0) {
        re_file_close(&db->file);
        return fail(err, RE_E_MALFORMED, "database is missing a required section");
    }
    db->ok = true;
    return true;
}

void re_db_close(re_db_t *db) {
    if (!db || !db->ok)
        return;
    re_file_close(&db->file);
    db->ok = false;
}

re_span_t re_db_section(const re_db_t *db, re_dbs_t id) {
    re_span_t out = re_span(NULL, 0);
    if (!db || id <= RE_DBS_NONE || id >= RE_DBS_COUNT || db->sec[id].id == 0)
        return out;
    re_rd(db->file.whole, db->sec[id].off, db->sec[id].size, &out);
    return out;
}

bool re_db_rec(const re_db_t *db, re_dbs_t id, uint32_t elem, uint64_t i, re_span_t *out) {
    const re_db_sec_t *s;
    if (!db || id <= RE_DBS_NONE || id >= RE_DBS_COUNT)
        return false;
    s = &db->sec[id];
    if (s->id == 0 || s->elem != elem || i >= s->count)
        return false;
    return re_rd(db->file.whole, s->off + i * elem, elem, out);
}

re_str_t re_db_strref(const re_db_t *db, re_span_t rec, uint64_t off) {
    re_span_t t = re_db_section(db, RE_DBS_STRTAB);
    re_span_t v;
    uint32_t o = re_db_f32(rec, off);
    uint32_t n = re_db_f32(rec, off + 4u);
    uint8_t nul = 1;
    if (n == 0 || !re_rd(t, o, (uint64_t)n + 1u, &v) || !re_rd8(v, n, &nul) || nul != 0)
        return re_str("");
    return re_strn((const char *)v.p, n);
}

static bool load_funcs(const re_db_t *db, re_analysis_t *an) {
    uint64_t n = db->sec[RE_DBS_FUNCS].count;
    re_fscan_init(&an->scan);
    for (uint64_t i = 0; i < n; i++) {
        re_span_t r;
        re_func_t f;
        if (!re_db_rec(db, RE_DBS_FUNCS, RE_DB_FUNC_REC, i, &r))
            return false;
        f.va = re_db_f64(r, 0);
        f.dispatch = re_db_f64(r, 8);
        f.rva = re_db_f32(r, 16);
        f.size = re_db_f32(r, 20);
        f.frame_size = re_db_f32(r, 24);
        f.n_insns = re_db_f32(r, 28);
        f.n_calls = re_db_f32(r, 32);
        f.n_jumps = re_db_f32(r, 36);
        f.junk = re_db_f32(r, 40);
        f.open_edges = re_db_f32(r, 44);
        f.flags = re_db_f32(r, 48);
        f.out_edges = re_db_f32(r, 52);
        f.name = re_db_strref(db, r, 56);
        f.module = re_db_strref(db, r, 64);
        if (i && f.va <= RE_VEC_PTR(&an->scan.funcs, re_func_t, i - 1u)->va)
            return false; // lookups binary search this table; unsorted is malformed
        if (!RE_VEC_PUSH(&an->scan.funcs, an->arena, f))
            return false;
    }
    return true;
}

static bool host_le(void) {
    uint16_t one = 1;
    uint8_t lo;
    memcpy(&lo, &one, 1);
    return lo == 1;
}

// A view of the mapped records as the in-memory array, when the two layouts agree.
// The bytes are checked first: a bool field must hold 0 or 1, and an index must be
// in range, or a forged file would hand undefined values to every consumer.
static bool layout_edges(void) {
    return host_le() && sizeof(re_edge_t) == RE_DB_EDGE_REC && offsetof(re_edge_t, kind) == 16u &&
           offsetof(re_edge_t, has_to) == 17u;
}

static bool decode_edges(const re_db_t *db, re_vec_t *v, re_arena_t *a) {
    for (uint64_t i = 0; i < db->sec[RE_DBS_EDGES].count; i++) {
        re_span_t r;
        re_edge_t e;
        if (!re_db_rec(db, RE_DBS_EDGES, RE_DB_EDGE_REC, i, &r))
            return false;
        e.from = re_db_f64(r, 0);
        e.to = re_db_f64(r, 8);
        e.kind = re_db_f8(r, 16);
        e.has_to = re_db_f8(r, 17) != 0;
        if (!RE_VEC_PUSH(v, a, e))
            return false;
    }
    return true;
}

// The mapped records are the in-memory array when the layouts agree, which keeps a
// large edge list from being copied. Any other layout is decoded field by field.
static bool view_edges(const re_db_t *db, re_analysis_t *an) {
    re_span_t s = re_db_section(db, RE_DBS_EDGES);
    uint64_t n = db->sec[RE_DBS_EDGES].count;
    re_vec_t *v = &an->scan.edges;
    re_vec_init(v, sizeof(re_edge_t));
    if (db->sec[RE_DBS_EDGES].id == 0 || db->sec[RE_DBS_EDGES].elem != RE_DB_EDGE_REC)
        return db->sec[RE_DBS_EDGES].id == 0;
    if (!layout_edges())
        return decode_edges(db, v, an->arena);
    for (uint64_t i = 0; i < n; i++) {
        uint8_t b = 0xFFu;
        if (!re_rd8(s, i * RE_DB_EDGE_REC + 17u, &b) || b > 1u)
            return false;
    }
    v->base = (unsigned char *)(uintptr_t)s.p;
    v->len = (size_t)n;
    v->cap = (size_t)n;
    return true;
}

static bool load_xrefs(const re_db_t *db, re_analysis_t *an) {
    uint64_t n = db->sec[RE_DBS_XREF_FWD].count;
    uint64_t m = db->sec[RE_DBS_XREF_BACK].count;
    re_vec_init(&an->xs.fwd, sizeof(re_xref_t));
    re_vec_init(&an->xs.rev, sizeof(uint32_t));
    for (uint64_t i = 0; i < n; i++) {
        re_span_t r;
        re_xref_t x;
        if (!re_db_rec(db, RE_DBS_XREF_FWD, RE_DB_XREF_REC, i, &r))
            return false;
        x.from = re_db_f64(r, 0);
        x.to = re_db_f64(r, 8);
        x.rva = re_db_f32(r, 16);
        x.kind = re_db_f8(r, 20);
        x.flags = re_db_f8(r, 21);
        x.name = re_db_strref(db, r, 24);
        if (!RE_VEC_PUSH(&an->xs.fwd, an->arena, x))
            return false;
    }
    for (uint64_t i = 0; i < m; i++) {
        re_span_t r;
        uint32_t k;
        if (!re_db_rec(db, RE_DBS_XREF_BACK, 4u, i, &r))
            return false;
        k = re_db_f32(r, 0);
        if (k >= n || !RE_VEC_PUSH(&an->xs.rev, an->arena, k))
            return false;
    }
    return true;
}

static bool load_jtables(const re_db_t *db, re_analysis_t *an) {
    re_vec_init(&an->jtables, sizeof(re_jtable_t));
    for (uint64_t i = 0; i < db->sec[RE_DBS_JTABLES].count; i++) {
        re_span_t r;
        re_jtable_t t;
        if (!re_db_rec(db, RE_DBS_JTABLES, RE_DB_JT_REC, i, &r))
            return false;
        t.table_va = re_db_f64(r, 0);
        t.at = re_db_f64(r, 8);
        t.func_va = re_db_f64(r, 16);
        t.count = re_db_f32(r, 24);
        t.bound = re_db_f32(r, 28);
        t.width = re_db_f8(r, 32);
        t.encoding = re_db_f8(r, 33);
        if (!RE_VEC_PUSH(&an->jtables, an->arena, t))
            return false;
    }
    return true;
}

static bool load_summary(const re_db_t *db, re_analysis_t *an) {
    uint64_t v[RE_DBV_COUNT];
    re_span_t r;
    if (db->sec[RE_DBS_SUMMARY].count < RE_DBV_COUNT)
        return false;
    for (uint32_t i = 0; i < RE_DBV_COUNT; i++) {
        if (!re_db_rec(db, RE_DBS_SUMMARY, 8u, i, &r))
            return false;
        v[i] = re_db_f64(r, 0);
    }
    re_db_summary_apply(v, an);
    return true;
}

bool re_db_load_pass(const re_db_t *db, re_analysis_t *an, re_pass_t pass) {
    if (!db || !db->ok)
        return false;
    switch (pass) {
        case RE_PASS_FUNCS:
            return load_funcs(db, an) && view_edges(db, an) && load_summary(db, an) &&
                   re_db_load_notes(db, an);
        case RE_PASS_XREFS:
            return load_xrefs(db, an);
        case RE_PASS_JTABLES:
            return load_jtables(db, an);
        case RE_PASS_STRINGS:
            return re_db_load_strings(db, an);
        case RE_PASS_REGIONS:
            return re_db_load_regions(db, an);
        case RE_PASS_NAMES:
            return re_db_load_names(db, an);
        default:
            return true; // nothing stored: format is parsed live, the rest are scalars
    }
}
