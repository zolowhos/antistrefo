// re_cmds4.c - the decompiler command.
// Module: cli (C11).
// Owns: the decompile command, which renders one function as C-like source.
// Depends: re_prep, re_decompile, re_dc_walk, re_func, re_stack, re_xref, re_json.
// Depends: re_decompile, re_dc_walk, re_func, re_stack, re_xref, re_prep, re_names.
#include "cli/cmds/re_cmds3.h"

#include "features/code/re_func.h"
#include "features/code/re_stack.h"
#include "features/code/re_xref.h"
#include "features/data/re_regions.h"
#include "features/data/re_vtable.h"
#include "features/dec/re_cfg.h"
#include "features/dec/re_decompile.h"
#include "features/flow/re_names.h"
#include "utils/json/re_json.h"
#include "utils/text/re_strbuf.h"
#include "cli/cmds/re_prep.h"
#include "cli/render/re_render2.h"
#include "cli/render/re_report.h"

// The function the command works on: the one containing the address given, or the
// function at the entry point when no address was given. A function subject is
// resolved here so the command answers the question a reader actually asked, which
// is "show me this function", not "show me these bytes".
static bool pick_func(re_ctx_t *ctx, const re_fscan_t *scan, const re_pe_t *pe, const char *pos,
                      const re_func_t **out) {
    uint64_t at = 0;
    long fi;
    if (pos) {
        if (!re_parse_addr(ctx, re_str(pos), pe, &at))
            return false;
    } else {
        if (!pe->entry_rva) {
            RE_ERR_SET(ctx->err, RE_E_MALFORMED, "no entry point, pass an address");
            return false;
        }
        at = pe->image_base + pe->entry_rva;
    }
    fi = re_func_index_of(scan, at);
    if (fi < 0) {
        RE_ERR_SETF(ctx->err, RE_E_USAGE, "no function at 0x%llx", (unsigned long long)at);
        return false;
    }
    *out = re_func_at(scan, (size_t)fi);
    return true;
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

int re_cmd_decompile(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_xrefset_t xs;
    re_decomp_t d;
    re_stack_t st;
    re_strbuf_t text;
    const re_func_t *fn = NULL;
    if (!re_prepare(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_func_scan(&code, ctx->arena, &scan);
    // Named before the function is picked, so the report, the graph and the view all
    // call the same function by the same name.
    re_prep_names(ctx, NULL, &code, &scan, NULL);
    if (!pick_func(ctx, &scan, &pe, re_cmd_positional(argc, argv, 1), &fn)) {
        re_file_close(&f);
        return re_err_exit_code(ctx->err->code);
    }
    re_names_stat_t nm;
    build_xrefs_and_names(ctx, &pe, &code, &scan, &xs, &nm);
    re_stack_analyze(&code, fn, ctx->arena, &st);
    re_stack_apply_image(&st, &pe);
    d.code = &code;
    d.xrefs = &xs;
    d.arena = ctx->arena;
    re_strbuf_init(&text, ctx->arena);
    bool ok = re_decompile_ok(&d, fn);
    if (ok)
        re_decompile_func(&d, fn, &st, &text);
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    re_envelope(&w, "decompile", f.whole, &pe);
    re_jw_khex(&w, "va", fn->va, 16);
    re_jw_ku64(&w, "rva", fn->rva);
    re_jw_ku64(&w, "size", fn->size);
    re_jw_kcstr(&w, "cc", re_cc_name(st.cc));
    re_jw_ku64(&w, "params", st.n_params);
    re_jw_ku64(&w, "locals", st.n_locals);
    re_jw_kbool(&w, "ok", ok);
    if (fn->name.n)
        re_jw_kstr(&w, "name", fn->name);
    // The class recoveries, in the unit each reader acts on: a slot name is a
    // function that learned its class, a virtual call is an indirect transfer
    // that learned its target, and a scope is a try region the image states.
    re_jw_ku64(&w, "vtable_slots_named", nm.n_slots);
    re_jw_ku64(&w, "virtual_calls", nm.n_vcalls);
    re_jw_ku64(&w, "eh_scopes", nm.n_scopes);
    // Only the fields a reader acts on: the source, and the strings it touches,
    // which name the function far better than the source alone does.
    re_jw_kstr(&w, "source", re_str(text.p ? text.p : ""));
    re_vec_t strs;
    re_vec_init(&strs, sizeof(uint32_t));
    re_jw_ku64(&w, "strings", re_xref_func_strings(&xs, fn, ctx->arena, &strs));
    re_vec_truncate(&strs, 0);
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
    re_prep_names(ctx, NULL, &code, &scan, NULL);
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
