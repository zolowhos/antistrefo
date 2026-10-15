// re_cmds4.c - the decompiler command.
// Module: cli (C11).
// Owns: the decompile command, which renders one function as C-like source.
// Depends: re_prep, re_decompile, re_dc_walk, re_func, re_stack, re_xref, re_json.
// Depends: re_decompile, re_dc_walk, re_func, re_stack, re_xref, re_prep, re_names.
#include "cli/cmds/re_cmds3.h"

#include "features/code/re_func.h"
#include "features/code/re_jtable.h"
#include "features/code/re_stack.h"
#include "features/code/re_xref.h"
#include "features/data/re_regions.h"
#include "features/data/re_vtable.h"
#include "features/dec/re_cfg.h"
#include "features/dec/re_dc_print.h"
#include "features/dec/re_decompile.h"
#include "features/flow/re_names.h"
#include "utils/json/re_json.h"
#include "utils/text/re_strbuf.h"
#include "cli/cmds/re_prep.h"
#include "cli/render/re_render2.h"
#include "cli/render/re_report.h"

#include <stdio.h>

static bool pick_func(re_ctx_t *ctx, const re_fscan_t *scan, const re_pe_t *pe, const char *pos,
                      const re_func_t **out) {
    return re_pick_func_at(ctx, scan, pe, pos, NULL, out);
}

// The xref set is what turns a call target into an imported name, so the emitter
// gets it. Without it every call would print as a bare address. The class table
// scan feeds the naming pass, whose names land in the function table before the
// emitter reads it, and whose recovered virtual calls annotate the text below.
static void build_xrefs_and_names(re_ctx_t *ctx, re_pe_t *pe, re_code_t *code, re_fscan_t *scan,
                                  re_xrefset_t *xs, re_names_stat_t *nm) {
    re_vset_t vs;
    re_xref_build(code, scan, pe, ctx->arena, xs);
    re_vtable_scan(pe, code, ctx->arena, &vs);
    re_names_apply(pe, code, scan, &vs, ctx->arena, nm);
}

static void write_edge(re_jw_t *w, const re_xref_t *x) {
    re_jw_obj(w);
    re_jw_khex(w, "from", x->from, 16);
    re_jw_khex(w, "to", x->to, 16);
    re_jw_ku64(w, "kind", x->kind);
    re_jw_ku64(w, "flags", x->flags);
    if (x->name.n)
        re_jw_kstr(w, "name", x->name);
    re_jw_obj_end(w);
}

static void write_refs(re_jw_t *w, const char *key, const re_xrefset_t *xs, re_arena_t *a,
                       uint64_t va, uint64_t size, bool into) {
    re_vec_t idx;
    size_t i, n;
    re_vec_init(&idx, sizeof(uint32_t));
    n = into ? re_xref_into(xs, a, va, size, 32, &idx) : re_xref_out_of(xs, a, va, size, 32, &idx);
    re_jw_key(w, key);
    re_jw_arr(w);
    for (i = 0; i < n; i++) {
        uint32_t at = *RE_VEC_PTR(&idx, uint32_t, i);
        write_edge(w, RE_VEC_PTR(&xs->fwd, re_xref_t, at));
    }
    re_jw_arr_end(w);
}

static void write_map(re_jw_t *w, const re_vec_t *sites, const re_xrefset_t *xs) {
    size_t i;
    re_jw_key(w, "map");
    re_jw_arr(w);
    for (i = 0; sites && i < RE_VEC_LEN(sites); i++) {
        const re_dc_site_t *s = RE_VEC_PTR(sites, re_dc_site_t, i);
        size_t k, c = re_xref_from_count(xs, s->va);
        re_jw_obj(w);
        re_jw_ku64(w, "line", s->line);
        re_jw_khex(w, "va", s->va, 16);
        re_jw_key(w, "to");
        re_jw_arr(w);
        for (k = 0; k < c; k++)
            write_edge(w, re_xref_from_at(xs, s->va, k));
        re_jw_arr_end(w);
        re_jw_obj_end(w);
    }
    re_jw_arr_end(w);
}

static void write_disps(re_jw_t *w, const re_stack_t *st) {
    size_t i;
    re_jw_key(w, "displacements");
    re_jw_arr(w);
    for (i = 0; i < st->n_slots; i++) {
        int32_t d = st->slots[i];
        char name[24];
        unsigned m = d < 0 ? (unsigned)(-d) : (unsigned)d;
        snprintf(name, sizeof(name), "%s%u", d < 0 ? "local_m" : "local_p", m);
        re_jw_obj(w);
        re_jw_kcstr(w, "name", name);
        re_jw_ki64(w, "disp", d);
        re_jw_khex(w, "disp_hex", (uint64_t)(uint32_t)d, 8);
        re_jw_obj_end(w);
    }
    re_jw_arr_end(w);
}

static const char *mem_op_kind(const re_insn_t *in) {
    unsigned map = RE_INSN_MAP(in);
    unsigned op = RE_INSN_OPCODE(in);
    if (map == 0 && (op == 0x89 || op == 0x88 || op == 0xC6 || op == 0xC7))
        return "store";
    return "load";
}

// Paginated index of every [reg+/-disp] load/store in the walked function body.
static void write_mem_ops(re_jw_t *w, re_code_t *code, const re_func_t *fn, size_t limit) {
    uint64_t va = fn->va;
    size_t shown = 0;
    size_t total = 0;
    re_jw_key(w, "mem_ops");
    re_jw_arr(w);
    while (va < fn->va + fn->size) {
        re_insn_t in;
        const char *reg;
        if (!re_code_insn(code, va, &in) || in.size == 0)
            break;
        if (in.is_mem && in.base != RE_REG_NONE && in.base != RE_REG_RIP) {
            total++;
            if (shown < limit) {
                reg = (code->dis && code->dis->reg_name)
                          ? code->dis->reg_name(code->dis->ctx, in.base)
                          : "?";
                re_jw_obj(w);
                re_jw_khex(w, "va", va, 16);
                re_jw_kcstr(w, "reg", reg ? reg : "?");
                re_jw_ki64(w, "disp", in.disp);
                re_jw_ku64(w, "size", in.opsize ? in.opsize : 8);
                re_jw_kcstr(w, "op", mem_op_kind(&in));
                re_jw_obj_end(w);
                shown++;
            }
        }
        va += in.size;
    }
    re_jw_arr_end(w);
    re_jw_ku64(w, "mem_ops_total", total);
    re_jw_kbool(w, "mem_ops_truncated", shown < total);
}

static void write_decomp(re_ctx_t *ctx, re_span_t img, re_pe_t *pe, re_code_t *code,
                         const re_func_t *fn, uint64_t at, const re_stack_t *st, bool ok,
                         const re_strbuf_t *text, const re_names_stat_t *nm, re_vec_t *sites,
                         re_xrefset_t *xs) {
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    re_envelope(&w, "decompile", img, pe);
    re_jw_khex(&w, "at", at, 16);
    re_emit_func_bounds(&w, fn);
    re_jw_khex(&w, "va", fn->va, 16);
    re_jw_ku64(&w, "rva", fn->rva);
    re_jw_ku64(&w, "size", fn->size);
    re_jw_kcstr(&w, "cc", re_cc_name(st->cc));
    re_jw_ku64(&w, "params", st->n_params);
    re_jw_ku64(&w, "locals", st->n_locals);
    write_disps(&w, st);
    write_mem_ops(&w, code, fn, ctx->limit ? ctx->limit : 200);
    re_jw_kbool(&w, "ok", ok);
    if (fn->name.n)
        re_jw_kstr(&w, "name", fn->name);
    re_jw_ku64(&w, "vtable_slots_named", nm->n_slots);
    re_jw_ku64(&w, "virtual_calls", nm->n_vcalls);
    re_jw_ku64(&w, "eh_scopes", nm->n_scopes);
    re_jw_kstr(&w, "source", re_str(text->p ? text->p : ""));
    write_map(&w, sites, xs);
    write_refs(&w, "callers", xs, ctx->arena, fn->va, fn->size, true);
    write_refs(&w, "callees", xs, ctx->arena, fn->va, fn->size, false);
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
}

int re_cmd_decompile(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_xrefset_t xs;
    re_decomp_t d;
    re_stack_t st;
    re_strbuf_t text;
    re_names_stat_t nm;
    re_vec_t tables;
    re_vec_t sites;
    const re_func_t *fn = NULL;
    uint64_t at = 0;
    bool ok;
    if (!re_prepare(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_func_scan(&code, ctx->arena, &scan);
    re_prep_names(ctx, path, NULL, &code, &scan, NULL);
    if (!re_pick_func_at(ctx, &scan, &pe, re_cmd_positional(argc, argv, 1), &at, &fn)) {
        re_file_close(&f);
        return re_err_exit_code(ctx->err->code);
    }
    build_xrefs_and_names(ctx, &pe, &code, &scan, &xs, &nm);
    re_stack_analyze(&code, fn, ctx->arena, &st);
    re_stack_apply_image(&st, &pe);
    re_vec_init(&tables, sizeof(re_jtable_t));
    re_jtable_scan(&code, &scan, ctx->arena, &tables);
    re_vec_init(&sites, sizeof(re_dc_site_t));
    d.code = &code;
    d.jtables = &tables;
    d.xrefs = &xs;
    d.arena = ctx->arena;
    d.sites = &sites;
    re_strbuf_init(&text, ctx->arena);
    ok = re_decompile_ok(&d, fn);
    if (ok)
        re_decompile_func(&d, fn, &st, &text);
    write_decomp(ctx, f.whole, &pe, &code, fn, at, &st, ok, &text, &nm, &sites, &xs);
    re_file_close(&f);
    return 0;
}

// Every jump table found, with its case targets. The count is only reported when
// the run of targets ended, so this never invents a case number.
int re_cmd_jtables(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_vec_t tables;
    (void)argc;
    (void)argv;
    if (!re_prepare(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_vec_init(&tables, sizeof(re_jtable_t));
    re_func_scan(&code, ctx->arena, &scan);
    size_t total = re_jtable_scan(&code, &scan, ctx->arena, &tables);
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    re_envelope(&w, "jtables", f.whole, &pe);
    re_jw_key(&w, "tables");
    re_jw_arr(&w);
    size_t shown = 0;
    for (size_t i = 0; i < total && shown < ctx->limit; i++, shown++) {
        const re_jtable_t *t = RE_VEC_PTR(&tables, re_jtable_t, i);
        re_jw_obj(&w);
        re_jw_khex(&w, "table", t->table_va, 16);
        re_jw_ku64(&w, "table_rva", t->table_va - code.base);
        re_jw_khex(&w, "dispatch", t->at, 16);
        re_jw_khex(&w, "func", t->func_va, 16);
        re_jw_ku64(&w, "entries", t->count);
        re_jw_ku64(&w, "entry_width", t->width);
        re_jw_ku64(&w, "encoding", t->encoding);
        re_jw_ku64(&w, "case_max", t->bound);
        re_jw_key(&w, "targets");
        re_jw_arr(&w);
        for (uint32_t k = 0; k < t->count && k < 64; k++)
            re_jw_hex(&w, re_jtable_target(&code, t, k), 16);
        re_jw_arr_end(&w);
        re_jw_obj_end(&w);
    }
    re_jw_arr_end(&w);
    re_jw_ku64(&w, "total", total);
    re_jw_kbool(&w, "truncated", shown < total);
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
    re_file_close(&f);
    return 0;
}

// One block of the graph. The terminator is named rather than numbered, and the
// unresolved case is carried through as a null destination instead of being
// dropped, because a branch whose target was not decoded is a real finding.
static void cfg_block(re_jw_t *w, const re_cfg_block_t *b, const re_func_t *fn, size_t index) {
    re_jw_obj(w);
    re_jw_ku64(w, "index", index);
    re_jw_khex(w, "va", b->va, 16);
    re_jw_ku64(w, "rva", b->va - fn->va + fn->rva);
    re_jw_ku64(w, "size", b->size);
    re_jw_ku64(w, "insns", b->n_insns);
    re_jw_kcstr(w, "term", re_cfg_term_name(b->term));
    if (b->has_target) {
        re_jw_khex(w, "target", b->target, 16);
        re_jw_kbool(w, "target_external", b->external);
    }
    re_jw_obj_end(w);
}

// The edges of one block, as successor indices. A tail call names no destination
// because there is none inside the function, which is the whole point of it.
static void cfg_edges(re_jw_t *w, const re_cfg_t *g, size_t from) {
    for (size_t i = 0; i < RE_VEC_LEN(&g->edges); i++) {
        const re_cfg_edge_t *e = RE_VEC_PTR(&g->edges, re_cfg_edge_t, i);
        if (e->from != from)
            continue;
        re_jw_obj(w);
        re_jw_kcstr(w, "kind", re_cfg_edge_name(e->kind));
        if (e->to >= 0)
            re_jw_ku64(w, "to", (uint64_t)e->to);
        re_jw_obj_end(w);
    }
}

// One region and the evidence behind it. The evidence fields are reported even when
// the verdict is unknown, because "we could not tell, and here is what we saw" is the
// useful answer on a protected binary and a bare unknown is not.
static void region_row(re_jw_t *w, const re_region_t *r) {
    re_jw_obj(w);
    re_jw_khex(w, "va", r->va, 16);
    re_jw_ku64(w, "rva", r->rva);
    re_jw_ku64(w, "size", r->size);
    re_jw_kcstr(w, "kind", re_reg_kind_name(r->kind));
    re_jw_kcstr(w, "confidence", re_reg_conf_name(r->confidence));
    re_jw_kcstr(w, "section", r->sec[0] ? r->sec : "");
    re_jw_kf64(w, "entropy", r->entropy);
    re_jw_kbool(w, "exec", r->exec);
    re_jw_kbool(w, "writable", r->writable);
    re_jw_ku64(w, "fill_pct", r->fill_pct);
    re_jw_ku64(w, "funcs", r->n_funcs);
    re_jw_ku64(w, "func_bytes", r->func_bytes);
    re_jw_ku64(w, "strings", r->n_strings);
    re_jw_ku64(w, "data_refs", r->n_data_refs);
    re_jw_ku64(w, "jtables", r->n_jtables);
    re_jw_obj_end(w);
}

// Classify the image into windows and say what each one is. Every row carries the
// counts the verdict came from, so a reader can disagree with the rule and still use
// the evidence.
int re_cmd_regions(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_xrefset_t xs;
    re_vec_t out;
    bool truncated = false;
    // A fixed window rather than a flag: the region boundaries have to line up with
    // the sections to be worth anything, and a caller-supplied size would move them
    // for no reason. The window is reported in the output so it is never a mystery.
    const size_t win = 4096u;
    (void)argc;
    (void)argv;
    if (re_report_wanted(ctx))
        return re_render_regions(ctx, path);
    if (!re_prepare(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_func_scan(&code, ctx->arena, &scan);
    re_xref_build(&code, &scan, &pe, ctx->arena, &xs);
    re_vec_init(&out, sizeof(re_region_t));
    re_region_scan(&code, &scan, &xs, &pe, win, &out, &truncated, ctx->arena);
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    re_envelope(&w, "regions", f.whole, &pe);
    re_jw_ku64(&w, "window", win);
    re_jw_ku64(&w, "count", RE_VEC_LEN(&out));
    re_jw_kbool(&w, "truncated", truncated);
    re_jw_key(&w, "regions");
    re_jw_arr(&w);
    for (size_t i = 0; i < RE_VEC_LEN(&out); i++)
        region_row(&w, RE_VEC_PTR(&out, re_region_t, i));
    re_jw_arr_end(&w);
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
    re_file_close(&f);
    return 0;
}

// One function's basic blocks and terminators. The blocks come from the decompiler's
// own walk, so this graph and the decompiled C always describe the same basic blocks
// rather than two walkers disagreeing about where a function branches.
int re_cmd_cfg(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_cfg_t g;
    const re_func_t *fn = NULL;
    if (re_report_wanted(ctx))
        return re_render_cfg(ctx, path, re_cmd_positional(argc, argv, 1));
    if (!re_prepare(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_func_scan(&code, ctx->arena, &scan);
    re_prep_names(ctx, path, NULL, &code, &scan, NULL);
    if (!pick_func(ctx, &scan, &pe, re_cmd_positional(argc, argv, 1), &fn)) {
        re_file_close(&f);
        return re_err_exit_code(ctx->err->code);
    }
    bool ok = re_cfg_build(&code, fn, &g, ctx->arena);
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    re_envelope(&w, "cfg", f.whole, &pe);
    re_jw_khex(&w, "va", fn->va, 16);
    re_jw_ku64(&w, "rva", fn->rva);
    re_jw_ku64(&w, "size", fn->size);
    if (fn->name.n)
        re_jw_kstr(&w, "name", fn->name);
    re_jw_kbool(&w, "ok", ok);
    re_jw_ku64(&w, "blocks", RE_VEC_LEN(&g.blocks));
    re_jw_ku64(&w, "edges", RE_VEC_LEN(&g.edges));
    re_jw_ku64(&w, "unknown_terminators", g.n_unknown);
    re_jw_ku64(&w, "unresolved_edges", g.n_unresolved);
    re_jw_kbool(&w, "truncated", g.truncated);
    re_jw_key(&w, "block_list");
    re_jw_arr(&w);
    for (size_t i = 0; i < RE_VEC_LEN(&g.blocks); i++)
        cfg_block(&w, RE_VEC_PTR(&g.blocks, re_cfg_block_t, i), fn, i);
    re_jw_arr_end(&w);
    re_jw_key(&w, "succ");
    re_jw_arr(&w);
    for (size_t i = 0; i < RE_VEC_LEN(&g.blocks); i++) {
        re_jw_obj(&w);
        re_jw_ku64(&w, "from", i);
        re_jw_key(&w, "to");
        re_jw_arr(&w);
        cfg_edges(&w, &g, i);
        re_jw_arr_end(&w);
        re_jw_obj_end(&w);
    }
    re_jw_arr_end(&w);
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
    re_file_close(&f);
    return 0;
}
