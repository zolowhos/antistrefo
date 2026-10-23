// re_db_write.c - streams one analysis into "<binary>.asdb.tmp" and swaps it in.
// Module: feature (C11).
// Owns: section framing, the deduplicated string table, and every record encoder.
// Depends: re_db.h, re_fsave, re_map, re_strbuf. Output depends only on the analysis.
#include "features/db/re_db.h"

#include "features/db/re_db_priv.h"
#include "utils/mem/re_map.h"
#include "utils/sys/re_fsave.h"

#include <string.h>

typedef struct {
    re_fsave_t fs;
    re_db_sec_t dir[RE_DBS_COUNT];
    uint32_t n_dir;
    uint64_t sec_off;
    re_strbuf_t strtab;
    re_map_t seen; // string -> offset + 1 into strtab
    re_arena_t *a;
    bool ok;
} dbw_t;

static void put(dbw_t *w, const void *p, size_t n) {
    if (w->ok && !re_fsave_write(&w->fs, p, n))
        w->ok = false;
}

static void begin_sec(dbw_t *w) {
    if (w->ok && !re_fsave_align(&w->fs, RE_DB_ALIGN))
        w->ok = false;
    w->sec_off = w->fs.pos;
}

static void end_sec(dbw_t *w, re_dbs_t id, uint32_t elem, uint64_t count) {
    re_db_sec_t *s = &w->dir[w->n_dir++];
    s->id = (uint32_t)id;
    s->elem = elem;
    s->off = w->sec_off;
    s->size = w->fs.pos - w->sec_off;
    s->count = count;
}

// A string's place in the table, written once however many records name it. Offset 0
// is the empty string, so a record with no name needs no entry.
static void str_ref(dbw_t *w, re_str_t s, uint8_t *at) {
    const void *got;
    uint64_t off;
    re_wr32(at, 0);
    re_wr32(at + 4, 0);
    if (!s.p || s.n == 0 || s.n > 0xFFFFFFFFu)
        return;
    got = re_map_get(&w->seen, s.p, s.n);
    if (got) {
        off = (uint64_t)(uintptr_t)got - 1u;
    } else {
        off = w->strtab.len;
        if (off > 0xFFFFFFFFu - s.n - 1u || !re_strbuf_append(&w->strtab, s.p, s.n) ||
            !re_strbuf_putc(&w->strtab, 0) ||
            !re_map_put(&w->seen, s.p, s.n, (const void *)(uintptr_t)(off + 1u))) {
            w->ok = false;
            return;
        }
    }
    re_wr32(at, (uint32_t)off);
    re_wr32(at + 4, (uint32_t)s.n);
}

static void write_funcs(dbw_t *w, const re_fscan_t *s) {
    uint8_t r[RE_DB_FUNC_REC];
    begin_sec(w);
    for (size_t i = 0; i < RE_VEC_LEN(&s->funcs) && w->ok; i++) {
        const re_func_t *f = RE_VEC_PTR(&s->funcs, re_func_t, i);
        memset(r, 0, sizeof(r));
        re_wr64(r, f->va);
        re_wr64(r + 8, f->dispatch);
        re_wr32(r + 16, f->rva);
        re_wr32(r + 20, f->size);
        re_wr32(r + 24, f->frame_size);
        re_wr32(r + 28, f->n_insns);
        re_wr32(r + 32, f->n_calls);
        re_wr32(r + 36, f->n_jumps);
        re_wr32(r + 40, f->junk);
        re_wr32(r + 44, f->open_edges);
        re_wr32(r + 48, f->flags);
        re_wr32(r + 52, f->out_edges);
        str_ref(w, f->name, r + 56);
        str_ref(w, f->module, r + 64);
        put(w, r, sizeof(r));
    }
    end_sec(w, RE_DBS_FUNCS, RE_DB_FUNC_REC, RE_VEC_LEN(&s->funcs));
}

static void write_edges(dbw_t *w, const re_vec_t *v) {
    uint8_t r[RE_DB_EDGE_REC];
    begin_sec(w);
    for (size_t i = 0; i < RE_VEC_LEN(v) && w->ok; i++) {
        const re_edge_t *e = RE_VEC_PTR(v, re_edge_t, i);
        memset(r, 0, sizeof(r));
        re_wr64(r, e->from);
        re_wr64(r + 8, e->to);
        r[16] = e->kind;
        r[17] = e->has_to ? 1u : 0u;
        put(w, r, sizeof(r));
    }
    end_sec(w, RE_DBS_EDGES, RE_DB_EDGE_REC, RE_VEC_LEN(v));
}

static void write_xrefs(dbw_t *w, const re_xrefset_t *xs) {
    uint8_t r[RE_DB_XREF_REC];
    begin_sec(w);
    for (size_t i = 0; i < RE_VEC_LEN(&xs->fwd) && w->ok; i++) {
        const re_xref_t *x = RE_VEC_PTR(&xs->fwd, re_xref_t, i);
        memset(r, 0, sizeof(r));
        re_wr64(r, x->from);
        re_wr64(r + 8, x->to);
        re_wr32(r + 16, x->rva);
        r[20] = x->kind;
        r[21] = x->flags;
        str_ref(w, x->name, r + 24);
        put(w, r, sizeof(r));
    }
    end_sec(w, RE_DBS_XREF_FWD, RE_DB_XREF_REC, RE_VEC_LEN(&xs->fwd));
    begin_sec(w);
    for (size_t i = 0; i < RE_VEC_LEN(&xs->rev) && w->ok; i++) {
        uint8_t b[4];
        re_wr32(b, RE_VEC_AT(&xs->rev, uint32_t, i));
        put(w, b, sizeof(b));
    }
    end_sec(w, RE_DBS_XREF_BACK, 4u, RE_VEC_LEN(&xs->rev));
}

static void write_jtables(dbw_t *w, const re_vec_t *v) {
    uint8_t r[RE_DB_JT_REC];
    begin_sec(w);
    for (size_t i = 0; i < RE_VEC_LEN(v) && w->ok; i++) {
        const re_jtable_t *t = RE_VEC_PTR(v, re_jtable_t, i);
        memset(r, 0, sizeof(r));
        re_wr64(r, t->table_va);
        re_wr64(r + 8, t->at);
        re_wr64(r + 16, t->func_va);
        re_wr32(r + 24, t->count);
        re_wr32(r + 28, t->bound);
        r[32] = t->width;
        r[33] = t->encoding;
        put(w, r, sizeof(r));
    }
    end_sec(w, RE_DBS_JTABLES, RE_DB_JT_REC, RE_VEC_LEN(v));
}

static void write_strings(dbw_t *w, const re_strings_t *st) {
    uint8_t r[RE_DB_STR_REC];
    begin_sec(w);
    for (size_t i = 0; i < RE_VEC_LEN(&st->hits) && w->ok; i++) {
        const re_str_hit_t *h = RE_VEC_PTR(&st->hits, re_str_hit_t, i);
        memset(r, 0, sizeof(r));
        re_wr64(r, h->off);
        str_ref(w, h->text, r + 8);
        r[16] = h->wide ? 1u : 0u;
        put(w, r, sizeof(r));
    }
    end_sec(w, RE_DBS_STRINGS, RE_DB_STR_REC, RE_VEC_LEN(&st->hits));
    begin_sec(w);
    for (size_t i = 0; i < RE_VEC_LEN(&st->devices) && w->ok; i++) {
        const re_devname_t *d = RE_VEC_PTR(&st->devices, re_devname_t, i);
        memset(r, 0, sizeof(r));
        re_wr64(r, d->off);
        str_ref(w, d->name, r + 8);
        r[16] = d->wide ? 1u : 0u;
        r[17] = d->dynamic ? 1u : 0u;
        put(w, r, sizeof(r));
    }
    end_sec(w, RE_DBS_DEVICES, RE_DB_DEV_REC, RE_VEC_LEN(&st->devices));
}

static void write_regions(dbw_t *w, const re_vec_t *v) {
    uint8_t r[RE_DB_REGION_REC];
    begin_sec(w);
    for (size_t i = 0; i < RE_VEC_LEN(v) && w->ok; i++) {
        const re_region_t *g = RE_VEC_PTR(v, re_region_t, i);
        uint64_t bits;
        memset(r, 0, sizeof(r));
        memcpy(&bits, &g->entropy, sizeof(bits));
        re_wr64(r, g->va);
        re_wr32(r + 8, g->rva);
        re_wr32(r + 12, g->size);
        r[16] = g->kind;
        r[17] = g->confidence;
        r[18] = g->exec ? 1u : 0u;
        r[19] = g->writable ? 1u : 0u;
        r[20] = g->readable ? 1u : 0u;
        re_wr64(r + 24, bits);
        re_wr32(r + 32, g->n_funcs);
        re_wr32(r + 36, g->func_bytes);
        re_wr32(r + 40, g->n_strings);
        re_wr32(r + 44, g->n_data_refs);
        re_wr32(r + 48, g->n_jtables);
        re_wr32(r + 52, g->fill_pct);
        memcpy(r + 56, g->sec, sizeof(g->sec) < 16u ? sizeof(g->sec) : 16u);
        r[56 + 8] = 0;
        put(w, r, sizeof(r));
    }
    end_sec(w, RE_DBS_REGIONS, RE_DB_REGION_REC, RE_VEC_LEN(v));
}

static void write_notes(dbw_t *w, const re_analysis_t *an) {
    uint8_t r[RE_DB_NOTE_REC];
    begin_sec(w);
    for (size_t i = 0; i < RE_VEC_LEN(&an->notes) && w->ok; i++) {
        const re_note_t *n = RE_VEC_PTR(&an->notes, re_note_t, i);
        memset(r, 0, sizeof(r));
        re_wr64(r, n->va);
        re_wr64(r + 8, n->aux);
        re_wr32(r + 16, n->kind);
        str_ref(w, n->text, r + 24);
        put(w, r, sizeof(r));
    }
    end_sec(w, RE_DBS_NOTES, RE_DB_NOTE_REC, RE_VEC_LEN(&an->notes));
    begin_sec(w);
    for (size_t i = 0; i < RE_VEC_LEN(&an->names.vcalls) && w->ok; i++) {
        const re_vcall_t *c = RE_VEC_PTR(&an->names.vcalls, re_vcall_t, i);
        re_wr64(r, c->at);
        str_ref(w, c->method, r + 8);
        put(w, r, RE_DB_VCALL_REC);
    }
    end_sec(w, RE_DBS_VCALLS, RE_DB_VCALL_REC, RE_VEC_LEN(&an->names.vcalls));
    begin_sec(w);
    for (size_t i = 0; i < RE_VEC_LEN(&an->names.scopes) && w->ok; i++) {
        const re_eh_scope_t *s = RE_VEC_PTR(&an->names.scopes, re_eh_scope_t, i);
        re_wr64(r, s->begin);
        re_wr64(r + 8, s->end);
        put(w, r, RE_DB_SCOPE_REC);
    }
    end_sec(w, RE_DBS_SCOPES, RE_DB_SCOPE_REC, RE_VEC_LEN(&an->names.scopes));
}

static void write_passes(dbw_t *w, const re_vec_t *v) {
    uint8_t r[RE_DB_PASS_REC];
    begin_sec(w);
    for (size_t i = 0; i < RE_VEC_LEN(v) && w->ok; i++) {
        const re_pass_stat_t *p = RE_VEC_PTR(v, re_pass_stat_t, i);
        memset(r, 0, sizeof(r));
        re_wr32(r, (uint32_t)p->pass);
        r[4] = p->ran ? 1u : 0u;
        r[5] = p->skip;
        r[6] = p->partial ? 1u : 0u;
        re_wr64(r + 8, 0); // the time a pass took is not part of its result
        re_wr64(r + 16, p->count);
        put(w, r, sizeof(r));
    }
    end_sec(w, RE_DBS_PASSES, RE_DB_PASS_REC, RE_VEC_LEN(v));
}

static void write_summary(dbw_t *w, const re_analysis_t *an) {
    uint64_t v[RE_DBV_COUNT];
    uint8_t b[8];
    uint8_t pdb[8];
    re_db_summary_fill(an, v);
    str_ref(w, an->strs.pdb, pdb);
    v[RE_DBV_PDB_REF] = (uint64_t)pdb[0] | ((uint64_t)pdb[1] << 8) | ((uint64_t)pdb[2] << 16) |
                        ((uint64_t)pdb[3] << 24);
    v[RE_DBV_PDB_LEN] = an->strs.pdb.n;
    begin_sec(w);
    for (size_t i = 0; i < RE_DBV_COUNT && w->ok; i++) {
        re_wr64(b, v[i]);
        put(w, b, sizeof(b));
    }
    end_sec(w, RE_DBS_SUMMARY, 8u, RE_DBV_COUNT);
}

static void write_strtab(dbw_t *w) {
    begin_sec(w);
    put(w, w->strtab.p, w->strtab.len);
    end_sec(w, RE_DBS_STRTAB, 1u, w->strtab.len);
}

static void write_dir_and_user(dbw_t *w, const re_alt_t *user, uint64_t *dir_off,
                               uint64_t *user_off) {
    uint8_t e[RE_DB_DIRENT];
    re_strbuf_t sb;
    begin_sec(w);
    *dir_off = w->fs.pos;
    for (uint32_t i = 0; i < w->n_dir && w->ok; i++) {
        memset(e, 0, sizeof(e));
        re_wr32(e, w->dir[i].id);
        re_wr32(e + 4, w->dir[i].elem);
        re_wr64(e + 8, w->dir[i].off);
        re_wr64(e + 16, w->dir[i].size);
        re_wr64(e + 24, w->dir[i].count);
        put(w, e, sizeof(e));
    }
    begin_sec(w);
    *user_off = w->fs.pos;
    re_strbuf_init(&sb, w->a);
    re_db_user_encode(user, &sb);
    put(w, sb.p, sb.len);
}

static void write_header(dbw_t *w, const re_analysis_t *an, uint32_t flags, uint64_t dir_off,
                         uint64_t user_off) {
    uint8_t h[RE_DB_HDR];
    memset(h, 0, sizeof(h));
    re_wr32(h, RE_DB_MAGIC);
    re_wr32(h + 4, RE_DB_VERSION);
    memcpy(h + 8, RE_DB_SCHEMA, sizeof(RE_DB_SCHEMA) - 1u);
    re_wr64(h + 24, an->file.whole.n);
    re_db_hash_source(an->file.whole, h + 32);
    re_wr32(h + 64, flags);
    re_wr32(h + 68, w->n_dir);
    re_wr64(h + 72, dir_off);
    re_wr64(h + 80, user_off);
    if (w->ok && !re_fsave_patch_at(&w->fs, 0, h, sizeof(h)))
        w->ok = false;
}

static void write_body(dbw_t *w, const re_analysis_t *an, const re_db_decsrc_t *dec) {
    uint8_t zero[RE_DB_HDR];
    memset(zero, 0, sizeof(zero));
    put(w, zero, sizeof(zero));
    write_summary(w, an);
    write_passes(w, &an->passes);
    write_funcs(w, &an->scan);
    write_edges(w, &an->scan.edges);
    write_xrefs(w, &an->xs);
    write_jtables(w, &an->jtables);
    write_strings(w, &an->strs);
    write_regions(w, &an->regions);
    write_notes(w, an);
    if (dec && w->ok)
        w->ok = re_db_write_decomp(&w->fs, w->dir, &w->n_dir, an, dec, w->a);
    write_strtab(w);
}

bool re_db_write(const re_analysis_t *an, const re_db_decsrc_t *dec, const re_alt_t *user,
                 bool complete, re_arena_t *scratch) {
    dbw_t w;
    uint64_t dir_off = 0;
    uint64_t user_off = 0;
    char *path;
    uint32_t flags;
    if (!an || !an->path.n || !scratch)
        return false;
    flags = (complete ? RE_DB_COMPLETE : 0u) | (an->scan.partial ? RE_DB_PARTIAL : 0u);
    memset(&w, 0, sizeof(w));
    w.a = scratch;
    w.ok = true;
    re_strbuf_init(&w.strtab, scratch);
    re_map_init(&w.seen, scratch, 0);
    re_strbuf_putc(&w.strtab, 0);
    path = re_db_path(scratch, an->path.p);
    if (!path || !re_fsave_open(&w.fs, path))
        return false;
    write_body(&w, an, dec);
    write_dir_and_user(&w, user, &dir_off, &user_off);
    write_header(&w, an, flags, dir_off, user_off);
    if (!w.ok) {
        re_fsave_abort(&w.fs);
        return false;
    }
    return re_fsave_commit(&w.fs);
}
