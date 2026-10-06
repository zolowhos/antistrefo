// re_render.c - the framed report for the file level commands.
// Module: cli (C11).
// Owns: the text rendering of info, triage, sections, imports and exports.
// Depends: re_render.h, re_prep, re_report, re_tui, re_pe, re_format, re_features.
#include "cli/render/re_render.h"

#include "features/code/re_func.h"
#include "features/code/re_stack.h"
#include "features/meta/re_features.h"
#include "features/pe/re_format.h"
#include "features/pe/re_pe.h"
#include "utils/mem/re_vec.h"
#include "utils/sys/re_path.h"
#include "utils/text/re_fmt.h"
#include "utils/tui/re_tui.h"
#include "cli/cmds/re_prep.h"
#include "cli/render/re_report.h"

// The subject line: the tool, the file, and the three facts that decide whether to
// keep reading. This is the row a reader scans first, so it carries format and size
// rather than making them hunt for a second line.
static void subject(re_strbuf_t *out, const char *path, const char *tool, const re_file_t *f,
                    const re_pe_t *pe) {
    re_strbuf_puts(out, tool);
    re_strbuf_putc(out, ' ');
    re_strbuf_puts(out, re_path_basename_ptr(path));
    re_strbuf_putc(out, ' ');
    re_fmt_size_human(out, f->whole.n);
    re_strbuf_putc(out, ' ');
    re_strbuf_appendf(out, "%u sec", pe->n_sec);
}

// info: the facts about the file, in three panes. A pane per question is the point of
// the frame: what the file is, where things sit, and what it pulls in are three
// things a reader looks up separately, and one flat list makes all three look equally
// important.
static void info_panes(re_report_t *r, const re_file_t *f, const re_pe_t *pe) {
    re_panel_t p[3];
    const char *titles[3] = {"Image", "Layout", "Imports"};
    uint16_t weights[3] = {3, 3, 4};
    for (size_t i = 0; i < 3; i++)
        re_panel_init(&p[i], r->scratch.arena, titles[i], weights[i]);
    re_panel_kv(&r->tui, &p[0], "format", re_format_name(re_format_detect(f->whole)), RE_ST_NONE);
    re_panel_kv(&r->tui, &p[0], "machine", re_pe_machine_name(pe->machine),
                pe->machine == 0x8664u ? RE_ST_ACCENT : RE_ST_NONE);
    re_panel_kv(&r->tui, &p[0], "pe32+", pe->pe32plus ? "yes" : "no", RE_ST_NONE);
    re_panel_kv(&r->tui, &p[0], "subsystem", re_pe_subsystem_name(pe->subsystem), RE_ST_NONE);
    re_panel_kv(&r->tui, &p[0], "dll", pe->is_dll ? "yes" : "no", RE_ST_NONE);
    re_panel_kv(&r->tui, &p[0], "timestamp",
                re_report_tmp(r, "%llu", (unsigned long long)pe->timestamp), RE_ST_NONE);
    re_panel_kv(&r->tui, &p[0], "image base",
                re_report_tmp(r, "0x%llx", (unsigned long long)pe->image_base), RE_ST_NONE);
    re_panel_kv(&r->tui, &p[1], "entry rva",
                re_report_tmp(r, "0x%llx", (unsigned long long)pe->entry_rva), RE_ST_ACCENT);
    re_panel_kv(&r->tui, &p[1], "entry va",
                re_report_tmp(r, "0x%llx", (unsigned long long)(pe->image_base + pe->entry_rva)),
                RE_ST_NONE);
    re_panel_kv(&r->tui, &p[1], "image size",
                re_report_tmp(r, "%llu", (unsigned long long)pe->size_of_image), RE_ST_NONE);
    re_panel_kv(&r->tui, &p[1], "file size",
                re_report_tmp(r, "%llu", (unsigned long long)f->whole.n), RE_ST_NONE);
    re_panel_kv(&r->tui, &p[1], "sections", re_report_tmp(r, "%u", pe->n_sec), RE_ST_NONE);
    re_panel_kv(&r->tui, &p[2], "modules", re_report_tmp(r, "%zu", RE_VEC_LEN(&pe->imports)),
                RE_ST_NONE);
    re_panel_kv(&r->tui, &p[2], "symbols", re_report_tmp(r, "%zu", RE_VEC_LEN(&pe->syms)),
                RE_ST_NONE);
    re_panel_kv(&r->tui, &p[2], "exports", re_report_tmp(r, "%zu", RE_VEC_LEN(&pe->exports)),
                RE_ST_NONE);
    re_panel_rule(&r->tui, &p[2]);
    re_panel_head(&r->tui, &p[2], "detected");
    for (size_t i = 0; i < re_features_count(); i++) {
        const char *feat = re_features_name(i);
        if (feat)
            re_panel_text(&r->tui, &p[2], feat);
    }
    re_tui_compose(&r->tui, p, 3);
}

int re_render_info(re_ctx_t *ctx, const char *path) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_report_t r;
    re_strbuf_t subj;
    re_strbuf_t sum;
    const char *sections[3] = {"image", "layout", "imports"};
    // Layout only. A missing decoder is not an answer to a question about the header.
    if (!re_prepare_loose(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_report_open(&r, ctx->arena, ctx, sections, 3);
    re_strbuf_init(&subj, ctx->arena);
    re_strbuf_init(&sum, ctx->arena);
    subject(&subj, path, "info", &f, &pe);
    re_strbuf_puts(&sum, re_format_name(re_format_detect(f.whole)));
    re_strbuf_putc(&sum, ' ');
    re_strbuf_appendf(&sum, "%zu imports  %zu exports", RE_VEC_LEN(&pe.imports),
                      RE_VEC_LEN(&pe.exports));
    re_report_head(&r, subj.p, sum.p);
    info_panes(&r, &f, &pe);
    re_report_end(&r);
    re_file_close(&f);
    return 0;
}

// sections: the one place a report is almost entirely a table, so it is a table with
// a header rather than panes. The entropy column is the reason to look here at all,
// so it carries a bar as well as the number: the bar is what shows that one section
// dominates, which is the question this table is usually asked to answer.
int re_render_sections(re_ctx_t *ctx, const char *path) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_report_t r;
    re_table_t tt;
    re_strbuf_t subj;
    re_strbuf_t sum;
    static const size_t kWidths[6] = {9, 11, 13, 13, 9, 0};
    const char *tabs[1] = {"sections"};
    const char *cols[6] = {"name", "vaddr", "vsize", "raw", "entropy", ""};
    const char *cells[6];
    if (!re_prepare_loose(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_report_open(&r, ctx->arena, ctx, tabs, 1);
    re_strbuf_init(&subj, ctx->arena);
    re_strbuf_init(&sum, ctx->arena);
    re_strbuf_puts(&subj, "sections ");
    re_strbuf_puts(&subj, re_path_basename_ptr(path));
    re_strbuf_appendf(&sum, "%u sections", pe.n_sec);
    re_report_head(&r, subj.p, sum.p);
    re_table_begin(&tt, &r, "Sections", kWidths, 6);
    re_table_head(&tt, cols);
    for (size_t i = 0; i < pe.n_sec; i++) {
        const re_pe_section_t *s = &pe.sec[i];
        re_strbuf_t bar;
        re_strbuf_init(&bar, ctx->arena);
        re_tui_bar(&bar, &r.tui, s->entropy / 8.0, 10);
        cells[0] = s->name;
        cells[1] = re_report_tmp(&r, "0x%08x", s->vaddr);
        cells[2] = re_report_tmp(&r, "%u", s->vsize);
        cells[3] = re_report_tmp(&r, "%u", s->rsize);
        cells[4] = re_report_tmp(&r, "%.3f", s->entropy);
        cells[5] = bar.p ? bar.p : "";
        re_table_row(&tt, cells);
    }
    re_table_end(&tt);
    re_report_end(&r);
    re_file_close(&f);
    return 0;
}

// imports: one row per symbol, grouped by module. A module heading inside the table
// keeps the grouping visible without a second column full of repeated names.
int re_render_imports(re_ctx_t *ctx, const char *path) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_report_t r;
    re_table_t tt;
    re_strbuf_t subj;
    re_strbuf_t sum;
    static const size_t kWidths[4] = {10, 12, 12, 0};
    const char *tabs[1] = {"imports"};
    const char *cols[4] = {"rva", "hint", "ordinal", "symbol"};
    const char *cells[4];
    size_t shown = 0;
    if (!re_prepare_loose(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_report_open(&r, ctx->arena, ctx, tabs, 1);
    re_strbuf_init(&subj, ctx->arena);
    re_strbuf_init(&sum, ctx->arena);
    re_strbuf_puts(&subj, "imports ");
    re_strbuf_puts(&subj, re_path_basename_ptr(path));
    re_strbuf_appendf(&sum, "%zu modules  %zu symbols", RE_VEC_LEN(&pe.imports),
                      RE_VEC_LEN(&pe.syms));
    re_report_head(&r, subj.p, sum.p);
    re_table_begin(&tt, &r, "Imported symbols", kWidths, 4);
    re_table_head(&tt, cols);
    for (size_t m = 0; m < RE_VEC_LEN(&pe.imports) && shown < ctx->limit; m++) {
        const re_pe_imp_t *im = RE_VEC_PTR(&pe.imports, re_pe_imp_t, m);
        re_panel_head(&r.tui, &tt.p, re_report_tmp(&r, "%s", im->dll.p ? im->dll.p : "?"));
        for (uint32_t k = 0; k < im->n_syms && shown < ctx->limit; k++, shown++) {
            re_str_t sym = RE_VEC_AT(&pe.syms, re_str_t, im->first_sym + k);
            cells[0] = re_report_tmp(&r, "0x%08x", im->first_thunk + k * 8u);
            cells[1] = "";
            cells[2] = "";
            cells[3] = sym.p ? sym.p : "";
            re_table_row(&tt, cells);
        }
    }
    re_table_end(&tt);
    re_report_end(&r);
    re_file_close(&f);
    return 0;
}

// The argument registers a function was called with, as a comma separated list. This
// is the column that makes the row useful: "2" says how many arguments there are,
// "rcx,rdx" says where they came from.
static const char *arg_names(re_report_t *r, const re_stack_t *st) {
    re_strbuf_t sb;
    bool first = true;
    re_strbuf_init(&sb, r->scratch.arena);
    for (uint32_t i = 0; i < st->n_params && i < RE_CC_MAX_ARGS; i++) {
        if (!first)
            re_strbuf_puts(&sb, ",");
        first = false;
        re_strbuf_puts(&sb, re_cc_arg_reg_name(st->cc, st->arg_regs[i]));
    }
    if (first)
        re_strbuf_puts(&sb, "-");
    return re_report_tmp(r, "%s", sb.p ? sb.p : "-");
}

// funcs: the command a shell session spends most of its time in, so it gets the widest
// table and a column for the calling convention, which is the fact that makes a
// recovered function's signature readable. Sizes are human formatted here and exact in
// the JSON.
// Not every export is a function, and a table that says nothing about which is which
// invites calling a GPU preference dword. The kind column is the whole point, so it
// comes before the address, and a forwarder names its module rather than pretending
// to have code here.
int re_render_exports(re_ctx_t *ctx, const char *path) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_report_t r;
    re_table_t tt;
    re_strbuf_t subj;
    re_strbuf_t sum;
    static const size_t kWidths[5] = {10, 10, 28, 8, 0};
    const char *tabs[1] = {"exports"};
    const char *cols[5] = {"kind", "rva", "name", "section", "forwards to"};
    const char *cells[5];
    size_t shown = 0, fwd = 0, data = 0;
    if (!re_prepare_loose(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_report_open(&r, ctx->arena, ctx, tabs, 1);
    re_strbuf_init(&subj, ctx->arena);
    re_strbuf_init(&sum, ctx->arena);
    for (size_t i = 0; i < RE_VEC_LEN(&pe.exports); i++) {
        const re_pe_exp_t *x = RE_VEC_PTR(&pe.exports, re_pe_exp_t, i);
        re_str_t f2 = re_pe_export_forwarder(&pe, x->rva);
        if (f2.n)
            fwd++;
        else if (!re_str_eq_cstr(re_str(re_pe_region_kind(re_pe_section_at_rva(&pe, x->rva))),
                                 "code"))
            data++;
    }
    re_strbuf_puts(&subj, "exports ");
    re_strbuf_puts(&subj, re_path_basename_ptr(path));
    re_strbuf_appendf(&sum, "%zu exports  %zu forward  %zu not code", RE_VEC_LEN(&pe.exports), fwd,
                      data);
    re_report_head(&r, subj.p, sum.p);
    re_table_begin(&tt, &r, "Exported symbols", kWidths, 5);
    re_table_head(&tt, cols);
    for (size_t i = 0; i < RE_VEC_LEN(&pe.exports) && shown < ctx->limit; i++, shown++) {
        const re_pe_exp_t *x = RE_VEC_PTR(&pe.exports, re_pe_exp_t, i);
        const re_pe_section_t *sec = re_pe_section_at_rva(&pe, x->rva);
        re_str_t f2 = re_pe_export_forwarder(&pe, x->rva);
        cells[0] = f2.n ? "forwarder" : re_pe_region_kind(sec);
        cells[1] = re_report_tmp(&r, "0x%08x", x->rva);
        cells[2] = x->name.p ? x->name.p : "?";
        cells[3] = sec ? sec->name : "";
        cells[4] = f2.n ? f2.p : "";
        re_table_row(&tt, cells);
    }
    re_table_end(&tt);
    re_report_end(&r);
    re_file_close(&f);
    return 0;
}

int re_render_funcs(re_ctx_t *ctx, const char *path) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_report_t r;
    re_table_t tt;
    re_strbuf_t subj;
    re_strbuf_t sum;
    static const size_t kWidths[10] = {15, 6, 6, 5, 4, 4, 6, 9, 6, 0};
    const char *tabs[1] = {"functions"};
    const char *cols[10] = {"va",  "size",  "insns",   "edges", "args",
                            "loc", "frame", "argregs", "conv",  "name"};
    const char *cells[10];
    size_t shown = 0;
    size_t named;
    if (!re_prepare(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_func_scan(&code, ctx->arena, &scan);
    named = re_prep_names(ctx, NULL, &code, &scan, NULL);
    re_report_open(&r, ctx->arena, ctx, tabs, 1);
    re_strbuf_init(&subj, ctx->arena);
    re_strbuf_init(&sum, ctx->arena);
    re_strbuf_puts(&subj, "funcs ");
    re_strbuf_puts(&subj, re_path_basename_ptr(path));
    re_strbuf_appendf(&sum, "%zu functions  %zu named  %zu edges", RE_VEC_LEN(&scan.funcs), named,
                      RE_VEC_LEN(&scan.edges));
    re_report_head(&r, subj.p, sum.p);
    re_table_begin(&tt, &r, "Recovered functions", kWidths, 10);
    re_table_head(&tt, cols);
    for (size_t i = 0; i < RE_VEC_LEN(&scan.funcs) && shown < ctx->limit; i++, shown++) {
        const re_func_t *fn = RE_VEC_PTR(&scan.funcs, re_func_t, i);
        re_stack_t st;
        re_stack_analyze(&code, fn, ctx->arena, &st);
        cells[0] = re_report_tmp(&r, "0x%llx", (unsigned long long)fn->va);
        cells[1] = re_report_tmp(&r, "%u", fn->size);
        cells[2] = re_report_tmp(&r, "%u", fn->n_insns);
        cells[3] = re_report_tmp(&r, "%zu", re_func_edge_count(&scan, fn));
        cells[4] = re_report_tmp(&r, "%u", st.n_params);
        cells[5] = re_report_tmp(&r, "%u", st.n_locals);
        cells[6] = re_report_tmp(&r, "%u", st.frame_size);
        cells[7] = arg_names(&r, &st);
        cells[8] = re_cc_name(st.cc);
        // A function nothing named is labelled by its address rather than left blank,
        // so a row is never indistinguishable from a row that failed to render.
        cells[9] =
            fn->name.n ? fn->name.p : re_report_tmp(&r, "sub_%llx", (unsigned long long)fn->va);
        re_table_row(&tt, cells);
    }
    re_table_end(&tt);
    re_report_end(&r);
    re_file_close(&f);
    return 0;
}
