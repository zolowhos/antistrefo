// re_render3.c - the framed report for the analyze command.
// Module: cli (C11).
// Owns: the text rendering of analyze.
// Depends: re_render3.h, re_analyze, re_report, re_tui. Reads the shared context the
//           driver already built; never re-runs a pass to fill in a cell.
#include "cli/render/re_render3.h"

#include "features/analysis/re_analyze.h"
#include "features/code/re_stack.h"
#include "utils/mem/re_vec.h"
#include "utils/sys/re_path.h"
#include "utils/text/re_strbuf.h"
#include "utils/tui/re_tui.h"
#include "cli/render/re_report.h"

// The pass table. A skipped or partial pass is shown as such in its own row, because
// a reader who sees eight rows and assumes all eight succeeded will believe a
// result that was never computed.
static void pass_table(re_report_t *r, const re_analysis_t *an) {
    re_table_t tt;
    static const size_t kWidths[5] = {12, 9, 12, 11, 0};
    const char *cols[5] = {"pass", "ms", "found", "state", ""};
    const char *cells[5];
    re_table_begin(&tt, r, "Passes", kWidths, 5);
    re_table_head(&tt, cols);
    for (size_t i = 0; i < RE_VEC_LEN(&an->passes); i++) {
        const re_pass_stat_t *st = RE_VEC_PTR(&an->passes, re_pass_stat_t, i);
        cells[0] = re_analysis_pass_name(st->pass);
        cells[1] = re_report_tmp(r, "%llu", (unsigned long long)st->ms);
        cells[2] = st->ran ? re_report_tmp(r, "%llu", (unsigned long long)st->count) : "-";
        if (st->skip != RE_PASS_RAISED_NONE)
            cells[3] = re_analysis_skip_name(st->skip);
        else if (st->partial)
            cells[3] = "partial";
        else
            cells[3] = "ok";
        cells[4] = "";
        re_table_row(&tt, cells);
    }
    re_table_end(&tt);
}

// The headline numbers, in three panes: what the file is, what was found, and what
// the analysis could not settle.
static void summary_panes(re_report_t *r, const re_analysis_t *an, const char *path) {
    re_panel_t p[3];
    uint32_t skipped = 0;
    uint32_t partial = 0;
    for (size_t i = 0; i < RE_VEC_LEN(&an->passes); i++) {
        const re_pass_stat_t *st = RE_VEC_PTR(&an->passes, re_pass_stat_t, i);
        if (st->skip != RE_PASS_RAISED_NONE)
            skipped++;
        if (st->partial)
            partial++;
    }
    const char *titles[3] = {"Image", "Found", "Not determined"};
    uint16_t weights[3] = {3, 4, 4};
    for (size_t i = 0; i < 3; i++)
        re_panel_init(&p[i], r->scratch.arena, titles[i], weights[i]);
    re_panel_kv(&r->tui, &p[0], "file", re_path_basename_ptr(path), RE_ST_NONE);
    re_panel_kv(&r->tui, &p[0], "sections", re_report_tmp(r, "%u", an->pe.n_sec), RE_ST_NONE);
    re_panel_kv(&r->tui, &p[0], "imports", re_report_tmp(r, "%zu", RE_VEC_LEN(&an->pe.imports)),
                RE_ST_NONE);
    re_panel_kv(&r->tui, &p[0], "exports", re_report_tmp(r, "%zu", RE_VEC_LEN(&an->pe.exports)),
                RE_ST_NONE);
    re_panel_kv(&r->tui, &p[1], "functions", re_report_tmp(r, "%zu", RE_VEC_LEN(&an->scan.funcs)),
                RE_ST_ACCENT);
    re_panel_kv(&r->tui, &p[1], "xrefs", re_report_tmp(r, "%zu", RE_VEC_LEN(&an->xs.fwd)),
                RE_ST_NONE);
    re_panel_kv(&r->tui, &p[1], "jump tables", re_report_tmp(r, "%zu", RE_VEC_LEN(&an->jtables)),
                RE_ST_NONE);
    re_panel_kv(&r->tui, &p[1], "strings", re_report_tmp(r, "%zu", RE_VEC_LEN(&an->strs.hits)),
                RE_ST_NONE);
    re_panel_kv(&r->tui, &p[1], "regions", re_report_tmp(r, "%zu", RE_VEC_LEN(&an->regions)),
                RE_ST_NONE);
    // The counts are the answer to "what does this tool not know", so they get the
    // same weight as the findings rather than a closing line.
    re_panel_kv(&r->tui, &p[2], "passes skipped", re_report_tmp(r, "%u", skipped),
                skipped ? RE_ST_WARN : RE_ST_NONE);
    re_panel_kv(&r->tui, &p[2], "passes partial", re_report_tmp(r, "%u", partial),
                partial ? RE_ST_WARN : RE_ST_NONE);
    re_panel_kv(&r->tui, &p[2], "indirect transfers", re_report_tmp(r, "%zu", an->xs.n_indirect),
                an->xs.n_indirect ? RE_ST_WARN : RE_ST_NONE);
    re_panel_kv(&r->tui, &p[2], "functions named", re_report_tmp(r, "%zu", RE_VEC_LEN(&an->sigs)),
                RE_ST_NONE);
    re_tui_compose(&r->tui, p, 3);
}

int re_render_analyze(re_ctx_t *ctx, const char *path) {
    re_analysis_t an;
    re_report_t r;
    re_strbuf_t subj;
    re_strbuf_t sum;
    const char *tabs[1] = {"analysis"};
    if (!re_analysis_open(&an, ctx->arena, path) || !re_analysis_run_all(&an)) {
        RE_ERR_SETF(ctx->err, RE_E_NOTBIN, "%s is not a recognized binary", path);
        re_analysis_close(&an);
        return re_err_exit_code(ctx->err->code);
    }
    re_report_open(&r, ctx->arena, ctx, tabs, 1);
    re_strbuf_init(&subj, ctx->arena);
    re_strbuf_init(&sum, ctx->arena);
    re_strbuf_puts(&subj, "analyze ");
    re_strbuf_puts(&subj, re_path_basename_ptr(path));
    re_strbuf_appendf(&sum, "%zu functions  %zu xrefs", RE_VEC_LEN(&an.scan.funcs),
                      RE_VEC_LEN(&an.xs.fwd));
    re_report_head(&r, subj.p, sum.p);
    summary_panes(&r, &an, path);
    pass_table(&r, &an);
    re_report_end(&r);
    re_analysis_close(&an);
    return 0;
}
