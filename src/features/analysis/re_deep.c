// re_deep.c - runs the deep tier and writes the .asdb, and attaches one on open.
// Module: feature (C11).
// Owns: re_deep_run, re_deep_attach, the decompile source, and the memory ceiling.
// Depends: re_deep.h, re_analyze, re_db, re_thread, re_log. Uses its own scratch arena.
#include "features/analysis/re_deep.h"

#include "features/analysis/re_deep_priv.h"
#include "features/db/re_db_priv.h"
#include "utils/sys/re_log.h"
#include "utils/sys/re_thread.h"

#include <stdlib.h>

static bool cancelled(re_deep_ctrl_t *c) {
    return c && re_atomic_get(&c->cancel) != 0;
}

static void phase(re_deep_ctrl_t *c, uint8_t n) {
    if (c)
        re_atomic_set(&c->progress, re_deep_progress(n, 0));
}

static void set_limits(re_analysis_t *an) {
    if (an->has_code)
        an->code.lim = re_limits_deep(re_deep_mem_ceiling());
    an->deep = true;
}

// The passes the entry tier already runs, in its order, with the deep limits set.
static void run_passes(re_analysis_t *an, re_deep_ctrl_t *c) {
    static const re_pass_t order[] = {RE_PASS_FUNCS,   RE_PASS_SYMBOLS, RE_PASS_XREFS,
                                      RE_PASS_JTABLES, RE_PASS_STRINGS, RE_PASS_REGIONS,
                                      RE_PASS_FLIRT,   RE_PASS_NAMES,   RE_PASS_SCORE};
    for (size_t i = 0; i < sizeof(order) / sizeof(order[0]) && !cancelled(c); i++) {
        phase(c, (uint8_t)(i + 1u));
        re_analysis_ensure(an, order[i]);
    }
}

static void import_renames(re_analysis_t *an, re_arena_t *scratch, re_alt_t *user) {
    re_alt_init(user, scratch);
    if (re_alt_load(user, an->path.p))
        re_alt_apply(&an->scan, user);
}

// The decompile source the writer calls a chunk at a time. Its arena is reset between
// chunks, so the text of one chunk is the most that is ever live.
typedef struct {
    re_analysis_t *an;
    re_arena_t scratch;
} dec_ctx_t;

// One function's lowering is thrown away once its text has been copied. Holding a
// thousand of them at once is what pushed Hood Warfare 2 past 40 GB. The text
// itself is kept in full; only the scratch used to build it is released.
static void decompile_one(dec_ctx_t *d, re_decomp_t *dc, const re_func_t *f, re_arena_t *work,
                          re_db_dec_t *slot) {
    re_strbuf_t sb;
    char *copy;
    re_arena_reset(work);
    memset(slot, 0, sizeof(*slot));
    slot->text = "";
    re_strbuf_init(&sb, work);
    re_stack_analyze(&d->an->code, f, work, &slot->st);
    slot->ok = re_decompile_ok(dc, f);
    if (slot->ok)
        re_decompile_func(dc, f, &slot->st, &sb);
    if (!sb.p || sb.len == 0 || sb.len > 0xFFFFFFFFu)
        return;
    copy = re_arena_memdup(&d->scratch, sb.p, sb.len);
    if (!copy)
        return;
    slot->text = copy;
    slot->len = (uint32_t)sb.len;
}

static bool dec_chunk(void *ctx, size_t first, size_t n, re_db_dec_t *out) {
    dec_ctx_t *d = (dec_ctx_t *)ctx;
    re_decomp_t dc;
    re_arena_t work;
    re_arena_reset(&d->scratch);
    re_arena_init(&work, RE_ARENA_DEFAULT_BLOCK);
    memset(&dc, 0, sizeof(dc));
    dc.code = &d->an->code;
    dc.xrefs = &d->an->xs;
    dc.jtables = &d->an->jtables;
    dc.arena = &work;
    dc.scan = &d->an->scan;
    for (size_t j = 0; j < n; j++)
        decompile_one(d, &dc, RE_VEC_PTR(&d->an->scan.funcs, re_func_t, first + j), &work, &out[j]);
    re_arena_free(&work);
    return true;
}

static bool write_db(re_analysis_t *an, re_arena_t *scratch, const re_alt_t *user, bool done) {
    dec_ctx_t ctx;
    re_db_decsrc_t src;
    bool ok;
    ctx.an = an;
    re_arena_init(&ctx.scratch, RE_ARENA_DEFAULT_BLOCK);
    src.chunk = dec_chunk;
    src.ctx = &ctx;
    src.chunk_n = 1024u;
    ok = re_db_write(an, &src, user, done, scratch);
    re_arena_free(&ctx.scratch);
    return ok;
}

bool re_deep_run(re_analysis_t *out, re_deep_ctrl_t *ctrl) {
    re_arena_t scratch;
    re_alt_t user;
    bool done;
    bool fresh;
    if (!out || !out->ok || !out->has_code)
        return false;
    fresh = !out->deep && !out->db;
    re_arena_init(&scratch, RE_ARENA_DEFAULT_BLOCK);
    set_limits(out);
    phase(ctrl, 0);
    if (fresh)
        re_deep_hostile(out, &scratch); // before the walk, so ciphertext is never decoded
    run_passes(out, ctrl);
    if (fresh && !cancelled(ctrl)) {
        re_deep_flatten(out);
        re_deep_vm(out);
        re_deep_data(out, &scratch);
    }
    import_renames(out, &scratch, &user);
    done = !cancelled(ctrl) && !out->scan.truncated;
    phase(ctrl, RE_DEEP_PHASES);
    if (!write_db(out, &scratch, &user, done))
        RE_LOGW("deep pass finished but the database could not be written");
    re_arena_free(&scratch);
    return true;
}

uint64_t re_deep_mem_ceiling(void) {
    const char *env = getenv("RE_MEM_MAX");
    uint64_t phys;
    if (env && env[0])
        return (uint64_t)strtoull(env, NULL, 10);
    phys = re_thread_phys_mem();
    return phys ? phys / 4u : RE_LIM_NONE;
}

static bool record_pass(re_analysis_t *an, const re_db_t *db) {
    re_pass_stat_t st;
    re_span_t r;
    for (uint64_t i = 0; i < db->sec[RE_DBS_PASSES].count; i++) {
        if (!re_db_rec(db, RE_DBS_PASSES, RE_DB_PASS_REC, i, &r))
            return false;
        st.pass = (re_pass_t)re_db_f32(r, 0);
        st.ran = re_db_f8(r, 4) != 0;
        st.skip = re_db_f8(r, 5);
        st.partial = re_db_f8(r, 6) != 0;
        st.ms = 0;
        st.count = re_db_f64(r, 16);
        if (!RE_VEC_PUSH(&an->passes, an->arena, st))
            return false;
    }
    return true;
}

static void mark_done(re_analysis_t *an) {
    for (int i = 0; i < (int)RE_PASS_COUNT; i++) {
        if (re_analysis_pass(an, (re_pass_t)i))
            continue;
        re_pass_stat_t st;
        st.pass = (re_pass_t)i;
        st.ms = 0;
        st.count = 0;
        st.ran = true;
        st.skip = RE_PASS_RAISED_NONE;
        st.partial = false;
        RE_VEC_PUSH(&an->passes, an->arena, st);
    }
}

bool re_deep_attach(re_analysis_t *an) {
    re_db_t *db;
    re_err_t err;
    char *path;
    if (!an || !an->ok || !an->path.n)
        return false;
    db = (re_db_t *)re_arena_alloc(an->arena, sizeof(*db));
    path = re_db_path(an->arena, an->path.p);
    if (!db || !path || !re_db_open(db, path, an->file.whole, an->arena, &err))
        return false;
    if ((db->flags & RE_DB_COMPLETE) == 0) {
        re_db_close(db);
        return false;
    }
    re_vec_clear(&an->passes); // open recorded format; the database has that row already
    for (int i = 0; i < (int)RE_PASS_COUNT; i++) {
        if (!re_db_load_pass(db, an, (re_pass_t)i)) {
            re_db_close(db);
            return false;
        }
    }
    if (!record_pass(an, db)) {
        re_db_close(db);
        return false;
    }
    mark_done(an);
    an->db = db;
    an->deep = true;
    return true;
}
