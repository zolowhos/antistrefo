// re_alt_cmd.c - rename and list_names commands for persistent .alt mappings.
// Module: cli (C11).
// Owns: re_cmd_rename and re_cmd_list_names. Saves on every successful rename.
// Depends: re_alt, re_prep, re_func, re_json. Unified argv and MCP surface.
#include "cli/cmds/re_cmds.h"

#include "cli/cmds/re_prep.h"
#include "features/analysis/re_alt.h"
#include "features/code/re_func.h"
#include "utils/json/re_json.h"

static void touch_session(re_ctx_t *ctx, const char *path, uint32_t rva, re_str_t name) {
    re_fscan_t *scan;
    if (!ctx->session || !re_str_eq_cstr(ctx->session->path, path))
        return;
    scan = &ctx->session->scan;
    for (size_t i = 0; i < RE_VEC_LEN(&scan->funcs); i++) {
        re_func_t *f = RE_VEC_PTR(&scan->funcs, re_func_t, i);
        if (f->rva != rva)
            continue;
        f->name = re_strn(re_arena_strndup(ctx->session->arena, name.p, name.n), name.n);
        f->module = re_str("alt");
        return;
    }
}

int re_cmd_rename(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_alt_t alt;
    const char *target;
    const char *new_name;
    uint32_t rva = 0;
    re_jw_t w;
    target = re_cmd_positional(argc, argv, 1);
    new_name = re_cmd_positional(argc, argv, 2);
    if (!target || !new_name) {
        RE_ERR_SET(ctx->err, RE_E_USAGE, "rename <file> <addr|name> <newname>");
        return re_err_exit_code(ctx->err->code);
    }
    if (!re_prepare(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_func_scan(&code, ctx->arena, &scan);
    re_prep_names(ctx, path, NULL, &code, &scan, NULL);
    if (!re_alt_resolve(&scan, &pe, re_str(target), &rva)) {
        RE_ERR_SETF(ctx->err, RE_E_USAGE, "no function matches %s", target);
        re_file_close(&f);
        return re_err_exit_code(ctx->err->code);
    }
    re_alt_init(&alt, ctx->arena);
    if (!re_alt_load(&alt, path)) {
        RE_ERR_SET(ctx->err, RE_E_IO, "cannot read .alt mapping");
        re_file_close(&f);
        return re_err_exit_code(ctx->err->code);
    }
    if (!re_alt_set(&alt, rva, re_str(new_name))) {
        RE_ERR_SET(ctx->err, RE_E_USAGE, "invalid rename name");
        re_file_close(&f);
        return re_err_exit_code(ctx->err->code);
    }
    if (!re_alt_save(&alt, path)) {
        RE_ERR_SET(ctx->err, RE_E_IO, "cannot write .alt mapping");
        re_file_close(&f);
        return re_err_exit_code(ctx->err->code);
    }
    re_alt_apply(&scan, &alt);
    touch_session(ctx, path, rva, re_str(new_name));
    re_jw_init(&w, ctx->arena);
    re_envelope(&w, "rename", f.whole, &pe);
    re_jw_ku64(&w, "rva", rva);
    re_jw_khex(&w, "va", pe.image_base + rva, 16);
    re_jw_kcstr(&w, "name", new_name);
    re_jw_kcstr(&w, "alt", re_alt_sidecar(ctx->arena, path));
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
    re_file_close(&f);
    return 0;
}

int re_cmd_list_names(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_alt_t alt;
    re_jw_t w;
    size_t shown = 0;
    size_t total;
    (void)argc;
    (void)argv;
    if (!re_prepare_loose(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_alt_init(&alt, ctx->arena);
    if (!re_alt_load(&alt, path)) {
        RE_ERR_SET(ctx->err, RE_E_IO, "cannot read .alt mapping");
        re_file_close(&f);
        return re_err_exit_code(ctx->err->code);
    }
    total = RE_VEC_LEN(&alt.ents);
    re_jw_init(&w, ctx->arena);
    re_envelope(&w, "list_names", f.whole, &pe);
    re_jw_kcstr(&w, "alt", re_alt_sidecar(ctx->arena, path));
    re_jw_key(&w, "names");
    re_jw_arr(&w);
    for (size_t i = ctx->offset; i < total && shown < ctx->limit; i++, shown++) {
        const re_alt_ent_t *e = RE_VEC_PTR(&alt.ents, re_alt_ent_t, i);
        re_jw_obj(&w);
        re_jw_ku64(&w, "rva", e->rva);
        re_jw_khex(&w, "va", pe.image_base + e->rva, 16);
        re_jw_kstr(&w, "name", e->name);
        re_jw_obj_end(&w);
    }
    re_jw_arr_end(&w);
    re_jw_ku64(&w, "count", shown);
    re_jw_ku64(&w, "total", total);
    re_jw_kbool(&w, "truncated", shown < total);
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
    re_file_close(&f);
    return 0;
}
