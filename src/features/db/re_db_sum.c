// re_db_sum.c - the SUMMARY vector: every scalar of an analysis that is not a list.
// Module: feature (C11).
// Owns: re_db_summary_fill and re_db_summary_apply, kept in one place so they agree.
// Depends: re_db_priv.h. No I/O.
#include "features/db/re_db_priv.h"

#include <string.h>

static uint64_t dbits(double d) {
    uint64_t b;
    memcpy(&b, &d, sizeof(b));
    return b;
}

static double bitsd(uint64_t b) {
    double d;
    memcpy(&d, &b, sizeof(d));
    return d;
}

static void fill_score(const re_score_t *s, uint64_t *v) {
    v[RE_DBV_SC_FUNCS] = s->n_funcs;
    v[RE_DBV_SC_PDATA] = s->n_pdata;
    v[RE_DBV_SC_PDATA_HIT] = s->n_pdata_hit;
    v[RE_DBV_SC_EDGES] = s->n_edges;
    v[RE_DBV_SC_EDGES_OK] = s->n_edges_ok;
    v[RE_DBV_SC_CALLS] = s->n_calls;
    v[RE_DBV_SC_CALLS_NAMED] = s->n_calls_named;
    v[RE_DBV_SC_INSNS] = s->n_insns;
    v[RE_DBV_SC_LOWERED] = s->n_lowered;
    v[RE_DBV_SC_INDIRECT] = s->n_indirect;
    v[RE_DBV_SC_INDIRECT_OK] = s->n_indirect_ok;
    v[RE_DBV_SC_SCORE] = dbits(s->score);
}

static void apply_score(const uint64_t *v, re_score_t *s) {
    s->n_funcs = (size_t)v[RE_DBV_SC_FUNCS];
    s->n_pdata = (size_t)v[RE_DBV_SC_PDATA];
    s->n_pdata_hit = (size_t)v[RE_DBV_SC_PDATA_HIT];
    s->n_edges = (size_t)v[RE_DBV_SC_EDGES];
    s->n_edges_ok = (size_t)v[RE_DBV_SC_EDGES_OK];
    s->n_calls = (size_t)v[RE_DBV_SC_CALLS];
    s->n_calls_named = (size_t)v[RE_DBV_SC_CALLS_NAMED];
    s->n_insns = (size_t)v[RE_DBV_SC_INSNS];
    s->n_lowered = (size_t)v[RE_DBV_SC_LOWERED];
    s->n_indirect = (size_t)v[RE_DBV_SC_INDIRECT];
    s->n_indirect_ok = (size_t)v[RE_DBV_SC_INDIRECT_OK];
    s->score = bitsd(v[RE_DBV_SC_SCORE]);
}

static void fill_scan(const re_analysis_t *an, uint64_t *v) {
    v[RE_DBV_DEEP] = an->deep ? 1u : 0u;
    v[RE_DBV_SCAN_TRUNC] = an->scan.truncated ? 1u : 0u;
    v[RE_DBV_SCAN_PARTIAL] = an->scan.partial ? 1u : 0u;
    v[RE_DBV_PDATA_WALKED] = an->scan.stat.pdata_walked;
    v[RE_DBV_PDATA_REJECTED] = an->scan.stat.pdata_rejected;
    v[RE_DBV_GAP_FOUND] = an->scan.stat.gap_found;
    v[RE_DBV_GAP_ROUNDS] = an->scan.stat.gap_rounds;
    v[RE_DBV_TRICKS] = an->scan.stat.tricks;
    v[RE_DBV_XS_INDIRECT] = an->xs.n_indirect;
    v[RE_DBV_PDB_OFF] = an->strs.pdb_off;
    v[RE_DBV_ASCII] = an->strs.ascii_count;
    v[RE_DBV_WIDE] = an->strs.wide_count;
}

static void apply_scan(const uint64_t *v, re_analysis_t *an) {
    an->deep = v[RE_DBV_DEEP] != 0;
    an->scan.truncated = v[RE_DBV_SCAN_TRUNC] != 0;
    an->scan.partial = v[RE_DBV_SCAN_PARTIAL] != 0;
    an->scan.stat.pdata_walked = (size_t)v[RE_DBV_PDATA_WALKED];
    an->scan.stat.pdata_rejected = (size_t)v[RE_DBV_PDATA_REJECTED];
    an->scan.stat.gap_found = (size_t)v[RE_DBV_GAP_FOUND];
    an->scan.stat.gap_rounds = (size_t)v[RE_DBV_GAP_ROUNDS];
    an->scan.stat.tricks = (size_t)v[RE_DBV_TRICKS];
    an->xs.n_indirect = (size_t)v[RE_DBV_XS_INDIRECT];
    an->strs.pdb_off = v[RE_DBV_PDB_OFF];
    an->strs.ascii_count = v[RE_DBV_ASCII];
    an->strs.wide_count = v[RE_DBV_WIDE];
}

static void fill_names(const re_analysis_t *an, uint64_t *v) {
    v[RE_DBV_GO_VERSION] = an->go.version;
    v[RE_DBV_GO_PTR] = an->go.ptr_size;
    v[RE_DBV_GO_NFUNCS] = an->go.n_funcs;
    v[RE_DBV_GO_NNAMED] = an->go.n_named;
    v[RE_DBV_GO_TEXT] = an->go.text_start;
    v[RE_DBV_GO_TRUNC] = an->go.truncated ? 1u : 0u;
    v[RE_DBV_GO_NAMED] = an->go_named;
    v[RE_DBV_SIG_BEFORE] = an->sigstat.before;
    v[RE_DBV_SIG_LOADED] = an->sigstat.loaded;
    v[RE_DBV_SIG_REJECTED] = an->sigstat.rejected;
    v[RE_DBV_SIG_SKIPPED] = an->sigstat.skipped;
    v[RE_DBV_NAMED] = an->named;
    v[RE_DBV_NM_SLOTS] = an->names.n_slots;
    v[RE_DBV_NM_FUNCS] = an->names.n_funcs;
    v[RE_DBV_NM_SCOPES] = an->names.n_scopes;
    v[RE_DBV_NM_VCALLS] = an->names.n_vcalls;
}

static void apply_names(const uint64_t *v, re_analysis_t *an) {
    an->go.version = (uint32_t)v[RE_DBV_GO_VERSION];
    an->go.ptr_size = (uint32_t)v[RE_DBV_GO_PTR];
    an->go.n_funcs = (size_t)v[RE_DBV_GO_NFUNCS];
    an->go.n_named = (size_t)v[RE_DBV_GO_NNAMED];
    an->go.text_start = v[RE_DBV_GO_TEXT];
    an->go.truncated = v[RE_DBV_GO_TRUNC] != 0;
    an->go_named = (size_t)v[RE_DBV_GO_NAMED];
    an->sigstat.before = (size_t)v[RE_DBV_SIG_BEFORE];
    an->sigstat.loaded = (size_t)v[RE_DBV_SIG_LOADED];
    an->sigstat.rejected = (size_t)v[RE_DBV_SIG_REJECTED];
    an->sigstat.skipped = (size_t)v[RE_DBV_SIG_SKIPPED];
    an->named = (size_t)v[RE_DBV_NAMED];
    an->names.n_slots = (size_t)v[RE_DBV_NM_SLOTS];
    an->names.n_funcs = (size_t)v[RE_DBV_NM_FUNCS];
    an->names.n_scopes = (size_t)v[RE_DBV_NM_SCOPES];
    an->names.n_vcalls = (size_t)v[RE_DBV_NM_VCALLS];
}

void re_db_summary_fill(const re_analysis_t *an, uint64_t v[RE_DBV_COUNT]) {
    memset(v, 0, sizeof(uint64_t) * RE_DBV_COUNT);
    fill_scan(an, v);
    fill_names(an, v);
    fill_score(&an->score, v);
}

void re_db_summary_apply(const uint64_t v[RE_DBV_COUNT], re_analysis_t *an) {
    apply_scan(v, an);
    apply_names(v, an);
    apply_score(v, &an->score);
}
