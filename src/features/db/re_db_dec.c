// re_db_dec.c - the precomputed decompile: streamed text, its index, and stack frames.
// Module: feature (C11).
// Owns: re_db_write_decomp and re_db_decomp.
// Depends: re_db_priv.h, re_fsave. Text is written a chunk at a time, never held whole.
#include "features/db/re_db_priv.h"

#include <string.h>

#define RE_DB_DEC_CHUNK 1024u

static void enc_stack(const re_stack_t *s, uint8_t *r) {
    memset(r, 0, RE_DB_STACK_REC);
    r[0] = s->cc;
    r[1] = (uint8_t)((s->uses_frame_ptr ? 1u : 0u) | (s->tail_call ? 2u : 0u) |
                     (s->homed ? 4u : 0u) | (s->ret_xmm ? 8u : 0u));
    r[2] = (uint8_t)(s->n_params > 255u ? 255u : s->n_params);
    r[3] = (uint8_t)(s->n_slots > 255u ? 255u : s->n_slots);
    re_wr32(r + 4, s->frame_size);
    re_wr32(r + 8, s->n_locals);
    re_wr32(r + 12, s->n_calls);
    memcpy(r + 16, s->arg_regs, RE_CC_MAX_ARGS);
}

static bool add_dir(re_fsave_t *fs, re_db_sec_t *dir, uint32_t *n_dir, re_dbs_t id, uint32_t elem,
                    uint64_t off, uint64_t count) {
    re_db_sec_t *s = &dir[(*n_dir)++];
    s->id = (uint32_t)id;
    s->elem = elem;
    s->off = off;
    s->size = fs->pos - off;
    s->count = count;
    return true;
}

static bool write_table(re_fsave_t *fs, re_db_sec_t *dir, uint32_t *n_dir, re_dbs_t id,
                        uint32_t elem, const uint8_t *p, size_t n) {
    uint64_t off;
    if (!re_fsave_align(fs, RE_DB_ALIGN))
        return false;
    off = fs->pos;
    if (!re_fsave_write(fs, p, (size_t)elem * n))
        return false;
    return add_dir(fs, dir, n_dir, id, elem, off, n);
}

// One chunk: ask the source for its text, then append text, index and frame records.
static bool one_chunk(re_fsave_t *fs, const re_db_decsrc_t *dec, size_t first, size_t m,
                      uint64_t text_off, re_db_dec_t *out, uint8_t *idx, uint8_t *stk) {
    if (!dec->chunk(dec->ctx, first, m, out))
        return false;
    for (size_t j = 0; j < m; j++) {
        uint8_t *r = idx + (first + j) * RE_DB_DECIDX_REC;
        re_wr64(r, fs->pos - text_off);
        re_wr32(r + 8, out[j].len);
        r[12] = out[j].ok ? 1u : 0u;
        enc_stack(&out[j].st, stk + (first + j) * RE_DB_STACK_REC);
        if (out[j].len && !re_fsave_write(fs, out[j].text, out[j].len))
            return false;
    }
    return true;
}

bool re_db_write_decomp(re_fsave_t *fs, re_db_sec_t *dir, uint32_t *n_dir, const re_analysis_t *an,
                        const re_db_decsrc_t *dec, re_arena_t *a) {
    size_t n = RE_VEC_LEN(&an->scan.funcs);
    size_t chunk = dec->chunk_n ? dec->chunk_n : RE_DB_DEC_CHUNK;
    uint8_t *idx = (uint8_t *)re_arena_calloc(a, n ? n : 1u, RE_DB_DECIDX_REC);
    uint8_t *stk = (uint8_t *)re_arena_calloc(a, n ? n : 1u, RE_DB_STACK_REC);
    re_db_dec_t *out = (re_db_dec_t *)re_arena_calloc(a, chunk, sizeof(re_db_dec_t));
    uint64_t text_off;
    if (!idx || !stk || !out || !re_fsave_align(fs, RE_DB_ALIGN))
        return false;
    text_off = fs->pos;
    for (size_t first = 0; first < n; first += chunk) {
        size_t m = n - first < chunk ? n - first : chunk;
        if (!one_chunk(fs, dec, first, m, text_off, out, idx, stk))
            return false;
    }
    add_dir(fs, dir, n_dir, RE_DBS_DECOMP_TEXT, 1u, text_off, fs->pos - text_off);
    return write_table(fs, dir, n_dir, RE_DBS_DECOMP_INDEX, RE_DB_DECIDX_REC, idx, n) &&
           write_table(fs, dir, n_dir, RE_DBS_STACK, RE_DB_STACK_REC, stk, n);
}

bool re_db_decomp(const re_db_t *db, size_t i, re_str_t *text, bool *ok) {
    re_span_t r;
    re_span_t all = re_db_section(db, RE_DBS_DECOMP_TEXT);
    re_span_t v;
    uint64_t off;
    uint32_t len;
    if (!db || !db->ok || !re_db_rec(db, RE_DBS_DECOMP_INDEX, RE_DB_DECIDX_REC, i, &r))
        return false;
    off = re_db_f64(r, 0);
    len = re_db_f32(r, 8);
    if (!re_rd(all, off, len, &v))
        return false;
    *text = re_strn((const char *)v.p, len);
    *ok = re_db_f8(r, 12) != 0;
    return true;
}
