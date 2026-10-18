// re_analyze_cmd.c - the analyze command and its framed report.
// Module: cli (C11).
// Owns: the combined JSON and the framed report for one analysed file.
// Depends: re_analyze, re_report, re_render3, re_pe, re_func. Reads the shared
//           context; never re-runs a pass to produce a field.
#include "cli/cmds/re_analyze_cmd.h"

#include "features/analysis/re_analyze.h"
#include "features/code/re_stack.h"
#include "utils/json/re_json.h"
#include "utils/mem/re_vec.h"
#include "utils/sys/re_path.h"
#include "utils/text/re_strbuf.h"
#include "cli/cmds/re_prep.h"
#include "cli/render/re_render3.h"
#include "cli/render/re_report.h"

// The scan is bounded so a large image reports a sample rather than taking minutes
// to say the same thing about every function.
static size_t ctx_limit(const re_analysis_t *an) {
    size_t n = RE_VEC_LEN(&an->scan.funcs);
    return n < 64u ? n : 64u;
}

// The passes, in the order they ran, with what each one found or why it did not run.
// The timing is reported next to the result rather than in a separate block, because
// a slow pass is only interesting next to what it was slow doing.
static void pass_rows(re_jw_t *w, const re_analysis_t *an) {
    re_jw_key(w, "passes");
    re_jw_arr(w);
    for (size_t i = 0; i < RE_VEC_LEN(&an->passes); i++) {
        const re_pass_stat_t *st = RE_VEC_PTR(&an->passes, re_pass_stat_t, i);
        re_jw_obj(w);
        re_jw_kcstr(w, "pass", re_analysis_pass_name(st->pass));
        re_jw_ku64(w, "ms", st->ms);
        re_jw_ku64(w, "count", st->count);
        re_jw_kbool(w, "ran", st->ran);
        re_jw_kbool(w, "partial", st->partial);
        // The reason is written whether or not it is empty, so a caller can tell
        // "skipped for a reason" from "not attempted" without knowing the field set.
        re_jw_kcstr(w, "skipped", re_analysis_skip_name(st->skip));
        re_jw_obj_end(w);
    }
    re_jw_arr_end(w);
}

// What the analysis could not determine. Kept as its own object because it is the
// half of the answer a reader needs most and the half a summary usually drops.
static void unknowns(re_jw_t *w, const re_analysis_t *an) {
    uint32_t skipped = 0;
    uint32_t partial = 0;
    for (size_t i = 0; i < RE_VEC_LEN(&an->passes); i++) {
        const re_pass_stat_t *st = RE_VEC_PTR(&an->passes, re_pass_stat_t, i);
        if (st->skip != RE_PASS_RAISED_NONE)
            skipped++;
        if (st->partial)
            partial++;
    }
    re_jw_key(w, "not_determined");
    re_jw_obj(w);
    re_jw_ku64(w, "passes_skipped", skipped);
    re_jw_ku64(w, "passes_partial", partial);
    re_jw_ku64(w, "indirect_transfers", an->xs.n_indirect);
    re_jw_ku64(w, "unresolved_regions", (uint32_t)(an->xs.n_indirect ? 1u : 0u) + skipped);
    re_jw_obj_end(w);
}

// The functions worth looking at first: the ones with the most inbound references,
// the largest frames, and anything a signature named. Ranked rather than listed,
// because a 150,000 function image has no useful full listing.
static void notable(re_jw_t *w, re_analysis_t *an) {
    re_jw_key(w, "notable");
    re_jw_arr(w);
    for (size_t i = 0; i < RE_VEC_LEN(&an->scan.funcs) && i < ctx_limit(an); i++) {
        const re_func_t *f = RE_VEC_PTR(&an->scan.funcs, re_func_t, i);
        re_stack_t st;
        size_t refs = re_xref_to_count(&an->xs, f->va);
        if (!refs && !f->name.n && f->frame_size < 128u)
            continue;
        if (!re_analysis_stack_of(an, i, &st))
            continue;
        re_jw_obj(w);
        re_jw_khex(w, "va", f->va, 16);
        re_jw_ku64(w, "rva", f->rva);
        re_jw_ku64(w, "size", f->size);
        re_jw_ku64(w, "insns", f->n_insns);
        re_jw_ku64(w, "xrefs_to", refs);
        re_jw_ku64(w, "frame", st.frame_size);
        re_jw_ku64(w, "args", st.n_params);
        if (f->name.n)
            re_jw_kstr(w, "name", f->name);
        re_jw_obj_end(w);
    }
    re_jw_arr_end(w);
}

// Packer and obfuscation indicators. Each is a fact about the file, not a verdict
// about it, and the count is reported so a reader can weigh them.
static void indicators(re_jw_t *w, const re_analysis_t *an) {
    uint32_t high = 0;
    uint32_t exec_unread = 0;
    uint32_t writable_exec = 0;
    for (uint32_t i = 0; i < an->pe.n_sec; i++) {
        const re_pe_section_t *s = &an->pe.sec[i];
        if (s->entropy >= 7.2)
            high++;
        if ((s->chars & 0x20000000u) && !(s->chars & 0x40000000u))
            exec_unread++;
        if ((s->chars & 0x20000000u) && (s->chars & 0x80000000u))
            writable_exec++;
    }
    re_jw_key(w, "indicators");
    re_jw_obj(w);
    re_jw_ku64(w, "high_entropy_sections", high);
    re_jw_ku64(w, "exec_not_read_sections", exec_unread);
    re_jw_ku64(w, "write_exec_sections", writable_exec);
    re_jw_ku64(w, "sections", an->pe.n_sec);
    re_jw_obj_end(w);
}

// The quality scoreboard: the six axes a decompiler depends on, each with its own
// denominator so a reader can see how much evidence stands behind the composite.
static void quality(re_jw_t *w, const re_analysis_t *an) {
    const re_score_t *s = &an->score;
    re_jw_key(w, "quality");
    re_jw_obj(w);
    re_jw_kf64(w, "score", s->score);
    re_jw_ku64(w, "funcs", s->n_funcs);
    re_jw_ku64(w, "pdata", s->n_pdata);
    re_jw_ku64(w, "pdata_hit", s->n_pdata_hit);
    re_jw_ku64(w, "edges", s->n_edges);
    re_jw_ku64(w, "edges_resolved", s->n_edges_ok);
    re_jw_ku64(w, "calls", s->n_calls);
    re_jw_ku64(w, "calls_named", s->n_calls_named);
    re_jw_ku64(w, "insns_sampled", s->n_insns);
    re_jw_ku64(w, "insns_lowered", s->n_lowered);
    re_jw_ku64(w, "indirect", s->n_indirect);
    re_jw_ku64(w, "indirect_resolved", s->n_indirect_ok);
    re_jw_obj_end(w);
}

int re_cmd_analyze(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_analysis_t local;
    re_analysis_t *an = NULL;
    re_arena_t *a = ctx->arena;
    bool reused = false;
    (void)argc;
    (void)argv;
    if (re_report_wanted(ctx))
        return re_render_analyze(ctx, path);
    // The session cache, when there is one, is only used if it is the file that was
    // asked about. A stale cache would answer about the wrong binary, which is worse
    // than doing the work again.
    if (ctx->session && re_str_eq_cstr(ctx->session->path, path)) {
        if (re_analysis_run_all(ctx->session)) {
            an = ctx->session;
            reused = true;
        }
    } else if (re_analysis_open(&local, a, path)) {
        if (re_analysis_run_all(&local))
            an = &local;
        else
            re_analysis_close(&local);
    }
    if (!an) {
        RE_ERR_SETF(ctx->err, RE_E_NOTBIN, "%s is not a recognized binary", path);
        return re_err_exit_code(ctx->err->code);
    }
    re_jw_t w;
    re_jw_init(&w, a);
    re_envelope(&w, "analyze", an->file.whole, &an->pe);
    re_jw_kbool(&w, "cached", reused);
    re_jw_ku64(&w, "functions", RE_VEC_LEN(&an->scan.funcs));
    re_jw_ku64(&w, "edges", RE_VEC_LEN(&an->scan.edges));
    re_jw_ku64(&w, "xrefs", RE_VEC_LEN(&an->xs.fwd));
    re_jw_ku64(&w, "jtables", RE_VEC_LEN(&an->jtables));
    re_jw_ku64(&w, "strings", RE_VEC_LEN(&an->strs.hits));
    re_jw_ku64(&w, "regions", RE_VEC_LEN(&an->regions));
    re_jw_ku64(&w, "imports", RE_VEC_LEN(&an->pe.imports));
    re_jw_ku64(&w, "exports", RE_VEC_LEN(&an->pe.exports));
    re_jw_ku64(&w, "signatures", RE_VEC_LEN(&an->sigs));
    indicators(&w, an);
    quality(&w, an);
    pass_rows(&w, an);
    unknowns(&w, an);
    notable(&w, an);
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
    if (!reused)
        re_analysis_close(an);
    return 0;
}
