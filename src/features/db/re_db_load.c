// re_db_load.c - decodes the notes, strings, regions and naming sections of an .asdb.
// Module: feature (C11).
// Owns: re_db_load_notes, re_db_load_strings, re_db_load_regions, re_db_load_names.
// Depends: re_db_priv.h. Text stays a view into the mapped string table.
#include "features/db/re_db_priv.h"

#include <string.h>

bool re_db_load_notes(const re_db_t *db, re_analysis_t *an) {
    re_vec_init(&an->notes, sizeof(re_note_t));
    for (uint64_t i = 0; i < db->sec[RE_DBS_NOTES].count; i++) {
        re_span_t r;
        re_note_t n;
        if (!re_db_rec(db, RE_DBS_NOTES, RE_DB_NOTE_REC, i, &r))
            return false;
        n.va = re_db_f64(r, 0);
        n.aux = re_db_f64(r, 8);
        n.kind = re_db_f32(r, 16);
        n.text = re_db_strref(db, r, 24);
        if (!RE_VEC_PUSH(&an->notes, an->arena, n))
            return false;
    }
    return true;
}

static bool load_devices(const re_db_t *db, re_analysis_t *an) {
    for (uint64_t i = 0; i < db->sec[RE_DBS_DEVICES].count; i++) {
        re_span_t r;
        re_devname_t d;
        if (!re_db_rec(db, RE_DBS_DEVICES, RE_DB_DEV_REC, i, &r))
            return false;
        d.off = re_db_f64(r, 0);
        d.name = re_db_strref(db, r, 8);
        d.wide = re_db_f8(r, 16) != 0;
        d.dynamic = re_db_f8(r, 17) != 0;
        if (!RE_VEC_PUSH(&an->strs.devices, an->arena, d))
            return false;
    }
    return true;
}

// The PDB path is in the summary as a string reference, which is laid out the way a
// record field is, so it is read through the same function.
static void load_pdb(const re_db_t *db, re_analysis_t *an) {
    uint8_t ref[8];
    re_span_t r;
    re_span_t lo;
    re_span_t hi;
    an->strs.pdb = re_str("");
    if (!re_db_rec(db, RE_DBS_SUMMARY, 8u, RE_DBV_PDB_REF, &lo) ||
        !re_db_rec(db, RE_DBS_SUMMARY, 8u, RE_DBV_PDB_LEN, &hi))
        return;
    re_wr32(ref, re_db_f32(lo, 0));
    re_wr32(ref + 4, re_db_f32(hi, 0));
    r = re_span(ref, sizeof(ref));
    an->strs.pdb = re_db_strref(db, r, 0);
}

bool re_db_load_strings(const re_db_t *db, re_analysis_t *an) {
    uint64_t ascii = an->strs.ascii_count;
    uint64_t wide = an->strs.wide_count;
    uint64_t pdb_off = an->strs.pdb_off;
    re_strings_init(&an->strs);
    an->strs.ascii_count = ascii;
    an->strs.wide_count = wide;
    an->strs.pdb_off = pdb_off;
    for (uint64_t i = 0; i < db->sec[RE_DBS_STRINGS].count; i++) {
        re_span_t r;
        re_str_hit_t h;
        if (!re_db_rec(db, RE_DBS_STRINGS, RE_DB_STR_REC, i, &r))
            return false;
        h.off = re_db_f64(r, 0);
        h.text = re_db_strref(db, r, 8);
        h.wide = re_db_f8(r, 16) != 0;
        if (!RE_VEC_PUSH(&an->strs.hits, an->arena, h))
            return false;
    }
    load_pdb(db, an);
    return load_devices(db, an);
}

static void region_of(re_span_t r, re_region_t *g) {
    uint64_t bits = re_db_f64(r, 24);
    memset(g, 0, sizeof(*g));
    g->va = re_db_f64(r, 0);
    g->rva = re_db_f32(r, 8);
    g->size = re_db_f32(r, 12);
    g->kind = re_db_f8(r, 16);
    g->confidence = re_db_f8(r, 17);
    g->exec = re_db_f8(r, 18) != 0;
    g->writable = re_db_f8(r, 19) != 0;
    g->readable = re_db_f8(r, 20) != 0;
    memcpy(&g->entropy, &bits, sizeof(bits));
    g->n_funcs = re_db_f32(r, 32);
    g->func_bytes = re_db_f32(r, 36);
    g->n_strings = re_db_f32(r, 40);
    g->n_data_refs = re_db_f32(r, 44);
    g->n_jtables = re_db_f32(r, 48);
    g->fill_pct = re_db_f32(r, 52);
    for (size_t k = 0; k + 1u < sizeof(g->sec); k++)
        g->sec[k] = (char)re_db_f8(r, 56u + k);
}

bool re_db_load_regions(const re_db_t *db, re_analysis_t *an) {
    re_vec_init(&an->regions, sizeof(re_region_t));
    for (uint64_t i = 0; i < db->sec[RE_DBS_REGIONS].count; i++) {
        re_span_t r;
        re_region_t g;
        if (!re_db_rec(db, RE_DBS_REGIONS, RE_DB_REGION_REC, i, &r))
            return false;
        region_of(r, &g);
        if (!RE_VEC_PUSH(&an->regions, an->arena, g))
            return false;
    }
    return true;
}

bool re_db_load_names(const re_db_t *db, re_analysis_t *an) {
    re_vec_init(&an->names.vcalls, sizeof(re_vcall_t));
    re_vec_init(&an->names.scopes, sizeof(re_eh_scope_t));
    for (uint64_t i = 0; i < db->sec[RE_DBS_VCALLS].count; i++) {
        re_span_t r;
        re_vcall_t c;
        if (!re_db_rec(db, RE_DBS_VCALLS, RE_DB_VCALL_REC, i, &r))
            return false;
        c.at = re_db_f64(r, 0);
        c.method = re_db_strref(db, r, 8);
        if (!RE_VEC_PUSH(&an->names.vcalls, an->arena, c))
            return false;
    }
    for (uint64_t i = 0; i < db->sec[RE_DBS_SCOPES].count; i++) {
        re_span_t r;
        re_eh_scope_t s;
        if (!re_db_rec(db, RE_DBS_SCOPES, RE_DB_SCOPE_REC, i, &r))
            return false;
        s.begin = re_db_f64(r, 0);
        s.end = re_db_f64(r, 8);
        if (!RE_VEC_PUSH(&an->names.scopes, an->arena, s))
            return false;
    }
    return true;
}
