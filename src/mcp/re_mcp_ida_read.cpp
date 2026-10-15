// re_mcp_ida_read.cpp - Tier A discrete ida-pro-mcp read tool wrappers.
// Module: mcp (C++17).
// Owns: connection, lookup, memory, stack, and call-graph reshape helpers.
// Depends: re_mcp_ida.h, re_prep, re_func, re_stack, re_xref, re_alt, re_jw.
#include "mcp/re_mcp_ida.h"

#include "features/analysis/re_alt.h"
#include "features/code/re_func.h"
#include "features/code/re_stack.h"
#include "features/code/re_xref.h"
#include "utils/json/re_json.h"
#include "utils/mem/re_buf.h"
#include "utils/mem/re_vec.h"
#include "utils/sys/re_err.h"
#include "utils/text/re_hex.h"
#include "utils/text/re_str.h"
#include "utils/text/re_strbuf.h"
#include "cli/cmds/re_cmds.h"
#include "cli/cmds/re_prep.h"
#include "mcp/re_mcp_live.h"

#include <cstdio>

namespace {

void begin_out(re_ctx_t *ctx, re_jw_t *w, const char *tool) {
    re_jw_init(w, ctx->arena);
    re_jw_obj(w);
    if (!ctx->ida_shape) {
        re_jw_kcstr(w, "schema", "antistrefo/1");
        re_jw_kcstr(w, "tool", tool);
    }
}

void end_out(re_ctx_t *ctx, re_jw_t *w) {
    re_jw_obj_end(w);
    re_jw_flush(w, re_ctx_out(ctx));
}

const char *pos1(int argc, char **argv) {
    return re_cmd_positional(argc, argv, 1);
}

bool va_off(const re_pe_t *pe, uint64_t va, uint64_t *off) {
    return va >= pe->image_base && re_pe_rva2off(pe, (uint32_t)(va - pe->image_base), off);
}

void emit_func(re_jw_t *w, const re_func_t *fn) {
    re_jw_khex(w, "address", fn->va, 16);
    re_jw_ku64(w, "rva", fn->rva);
    re_jw_ku64(w, "size", fn->size);
    re_jw_khex(w, "end", fn->va + fn->size, 16);
    if (fn->flags & RE_FUNC_UNWIND)
        re_jw_kbool(w, "unwind", true);
    re_jw_kstr(w, "name", fn->name.n ? fn->name : re_str(""));
}

bool load_fn(re_ctx_t *ctx, const char *path, int argc, char **argv, bool by_name, re_file_t *f,
             re_pe_t *pe, re_code_t *code, re_fscan_t *scan, const re_func_t **out) {
    const char *tok = pos1(argc, argv);
    uint32_t rva = 0;
    if (!re_prepare(ctx, path, f, pe, code))
        return false;
    re_func_scan(code, ctx->arena, scan);
    re_prep_names(ctx, path, NULL, code, scan, NULL);
    if (by_name) {
        if (!tok || !re_alt_resolve(scan, pe, re_str(tok), &rva)) {
            RE_ERR_SETF(ctx->err, RE_E_USAGE, "no function named %s", tok ? tok : "");
            re_file_close(f);
            return false;
        }
        {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "0x%x", rva);
            if (!re_pick_func_at(ctx, scan, pe, buf, NULL, out)) {
                re_file_close(f);
                return false;
            }
        }
        return true;
    }
    if (!tok) {
        RE_ERR_SET(ctx->err, RE_E_USAGE, "address required");
        re_file_close(f);
        return false;
    }
    if (!re_pick_func_at(ctx, scan, pe, tok, NULL, out)) {
        re_file_close(f);
        return false;
    }
    return true;
}

void write_edges(re_jw_t *w, const char *key, const re_xrefset_t *xs, re_arena_t *a, uint64_t va,
                 uint64_t size, bool into) {
    re_vec_t idx;
    size_t n, i;
    re_vec_init(&idx, sizeof(uint32_t));
    n = into ? re_xref_into(xs, a, va, size, 64, &idx) : re_xref_out_of(xs, a, va, size, 64, &idx);
    re_jw_key(w, key);
    re_jw_arr(w);
    for (i = 0; i < n; i++) {
        const re_xref_t *x = RE_VEC_PTR(&xs->fwd, re_xref_t, *RE_VEC_PTR(&idx, uint32_t, i));
        re_jw_obj(w);
        re_jw_khex(w, "from", x->from, 16);
        re_jw_khex(w, "to", x->to, 16);
        if (x->name.n)
            re_jw_kstr(w, "name", x->name);
        re_jw_obj_end(w);
    }
    re_jw_arr_end(w);
}

int call_edges(re_ctx_t *ctx, const char *path, int argc, char **argv, bool callers) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_xrefset_t xs;
    const re_func_t *fn = NULL;
    re_jw_t w;
    if (!load_fn(ctx, path, argc, argv, false, &f, &pe, &code, &scan, &fn))
        return re_err_exit_code(ctx->err->code);
    re_xref_build(&code, &scan, &pe, ctx->arena, &xs);
    begin_out(ctx, &w, callers ? "get_callers" : "get_callees");
    emit_func(&w, fn);
    write_edges(&w, callers ? "callers" : "callees", &xs, ctx->arena, fn->va, fn->size, callers);
    end_out(ctx, &w);
    re_file_close(&f);
    return 0;
}

bool parse_u64_any(re_str_t s, uint64_t *out) {
    size_t i = 0;
    uint64_t base = 10, acc = 0;
    if (s.n > 2 && s.p[0] == '0' && (s.p[1] == 'x' || s.p[1] == 'X')) {
        base = 16;
        i = 2;
    } else if (s.n > 2 && s.p[0] == '0' && (s.p[1] == 'b' || s.p[1] == 'B')) {
        base = 2;
        i = 2;
    }
    if (i >= s.n)
        return false;
    for (; i < s.n; i++) {
        int d = re_hex_val(s.p[i]);
        if (d < 0 || (uint64_t)d >= base)
            return false;
        acc = acc * base + (uint64_t)d;
    }
    *out = acc;
    return true;
}

int data_read_n(re_ctx_t *ctx, const char *path, int argc, char **argv, size_t nbytes,
                const char *tool) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    uint64_t va = 0, off = 0, value = 0;
    re_span_t view;
    re_jw_t w;
    const char *a = pos1(argc, argv);
    if (!re_prepare_loose(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    if (!a || !re_parse_addr(ctx, re_str(a), &pe, &va) || !va_off(&pe, va, &off) ||
        !re_rd(pe.img, off, nbytes, &view) || view.n < nbytes) {
        if (ctx->err->code == RE_OK)
            RE_ERR_SET(ctx->err, RE_E_USAGE, "cannot read at address");
        re_file_close(&f);
        return re_err_exit_code(ctx->err->code);
    }
    if (nbytes == 1)
        value = view.p[0];
    else if (nbytes == 2) {
        uint16_t v = 0;
        re_rd16(view, 0, &v);
        value = v;
    } else if (nbytes == 4) {
        uint32_t v = 0;
        re_rd32(view, 0, &v);
        value = v;
    } else {
        re_rd64(view, 0, &value);
    }
    begin_out(ctx, &w, tool);
    re_jw_khex(&w, "address", va, 16);
    re_jw_ku64(&w, "value", value);
    end_out(ctx, &w);
    re_file_close(&f);
    return 0;
}

int one_fn(re_ctx_t *ctx, const char *path, int argc, char **argv, bool by_name, const char *tool) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    const re_func_t *fn = NULL;
    re_jw_t w;
    if (!load_fn(ctx, path, argc, argv, by_name, &f, &pe, &code, &scan, &fn))
        return re_err_exit_code(ctx->err->code);
    begin_out(ctx, &w, tool);
    emit_func(&w, fn);
    end_out(ctx, &w);
    re_file_close(&f);
    return 0;
}

} // namespace

extern "C" int re_cmd_check_connection(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_jw_t w;
    (void)path;
    (void)argc;
    (void)argv;
    begin_out(ctx, &w, "check_connection");
    re_jw_kbool(&w, "ok", true);
    end_out(ctx, &w);
    return 0;
}

extern "C" int re_cmd_get_metadata(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    return re_cmd_info(ctx, path, argc, argv);
}

extern "C" int re_cmd_convert_number(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    const char *tok = re_cmd_positional(argc, argv, 0);
    uint64_t v = 0;
    re_jw_t w;
    re_strbuf_t bin;
    char hex[32];
    int bit;
    (void)path;
    if (!tok)
        tok = pos1(argc, argv);
    if (!tok || !parse_u64_any(re_str(tok), &v)) {
        RE_ERR_SET(ctx->err, RE_E_USAGE, "convert_number needs a number");
        return 2;
    }
    begin_out(ctx, &w, "convert_number");
    re_jw_ku64(&w, "decimal", v);
    std::snprintf(hex, sizeof(hex), "0x%llx", (unsigned long long)v);
    re_jw_kcstr(&w, "hexadecimal", hex);
    re_strbuf_init(&bin, ctx->arena);
    re_strbuf_puts(&bin, "0b");
    if (v == 0)
        re_strbuf_putc(&bin, '0');
    else {
        for (bit = 63; bit >= 0 && ((v >> bit) & 1ull) == 0; bit--) {
        }
        for (; bit >= 0; bit--)
            re_strbuf_putc(&bin, ((v >> bit) & 1ull) ? '1' : '0');
    }
    re_jw_kcstr(&w, "binary", bin.p ? bin.p : "0b0");
    end_out(ctx, &w);
    return 0;
}

extern "C" int re_cmd_get_current_address(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_mcp_live_t live;
    re_jw_t w;
    (void)path;
    (void)argc;
    (void)argv;
    re_mcp_live_snapshot(&live);
    begin_out(ctx, &w, "get_current_address");
    re_jw_khex(&w, "address", live.sel, 16);
    re_jw_kbool(&w, "loaded", live.loaded);
    end_out(ctx, &w);
    return 0;
}

extern "C" int re_cmd_get_current_function(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_mcp_live_t live;
    re_jw_t w;
    (void)path;
    (void)argc;
    (void)argv;
    re_mcp_live_snapshot(&live);
    begin_out(ctx, &w, "get_current_function");
    re_jw_khex(&w, "address", live.func_rva, 8);
    re_jw_kcstr(&w, "name", live.func_name);
    re_jw_kbool(&w, "loaded", live.loaded);
    end_out(ctx, &w);
    return 0;
}

extern "C" int re_cmd_get_entry_points(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_jw_t w;
    (void)argc;
    (void)argv;
    if (!re_prepare_loose(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    begin_out(ctx, &w, "get_entry_points");
    re_jw_key(&w, "entries");
    re_jw_arr(&w);
    re_jw_obj(&w);
    re_jw_khex(&w, "address", pe.image_base + pe.entry_rva, 16);
    re_jw_ku64(&w, "rva", pe.entry_rva);
    re_jw_kcstr(&w, "name", "entry");
    re_jw_obj_end(&w);
    re_jw_arr_end(&w);
    re_jw_ku64(&w, "count", 1);
    end_out(ctx, &w);
    re_file_close(&f);
    return 0;
}

extern "C" int re_cmd_get_function_by_name(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    return one_fn(ctx, path, argc, argv, true, "get_function_by_name");
}

extern "C" int re_cmd_get_function_by_address(re_ctx_t *ctx, const char *path, int argc,
                                              char **argv) {
    return one_fn(ctx, path, argc, argv, false, "get_function_by_address");
}

extern "C" int re_cmd_get_callees(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    return call_edges(ctx, path, argc, argv, false);
}

extern "C" int re_cmd_get_callers(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    return call_edges(ctx, path, argc, argv, true);
}

extern "C" int re_cmd_get_stack_frame_variables(re_ctx_t *ctx, const char *path, int argc,
                                                char **argv) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_stack_t st;
    const re_func_t *fn = NULL;
    re_jw_t w;
    size_t i;
    if (!load_fn(ctx, path, argc, argv, false, &f, &pe, &code, &scan, &fn))
        return re_err_exit_code(ctx->err->code);
    re_stack_analyze(&code, fn, ctx->arena, &st);
    re_stack_apply_image(&st, &pe);
    begin_out(ctx, &w, "get_stack_frame_variables");
    emit_func(&w, fn);
    re_jw_kcstr(&w, "cc", re_cc_name(st.cc));
    re_jw_ku64(&w, "frame_size", st.frame_size);
    re_jw_ku64(&w, "params", st.n_params);
    re_jw_key(&w, "variables");
    re_jw_arr(&w);
    for (i = 0; i < st.n_slots; i++) {
        char name[24];
        std::snprintf(name, sizeof(name), "slot_%zu", i);
        re_jw_obj(&w);
        re_jw_kcstr(&w, "name", name);
        re_jw_ki64(&w, "offset", st.slots[i]);
        re_jw_obj_end(&w);
    }
    re_jw_arr_end(&w);
    re_jw_ku64(&w, "count", st.n_slots);
    end_out(ctx, &w);
    re_file_close(&f);
    return 0;
}

extern "C" int re_cmd_read_memory_bytes(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    uint64_t va = 0, off = 0, len = ctx->len ? ctx->len : 16;
    re_span_t view;
    re_jw_t w;
    re_strbuf_t hex;
    const char *a = pos1(argc, argv);
    const char *len_tok = re_cmd_positional(argc, argv, 2);
    if (!re_prepare_loose(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    if (len_tok) {
        uint64_t n = 0;
        if (parse_u64_any(re_str(len_tok), &n) && n > 0)
            len = n;
    }
    if (!a || !re_parse_addr(ctx, re_str(a), &pe, &va) || !va_off(&pe, va, &off) ||
        !re_rd(pe.img, off, len, &view)) {
        if (ctx->err->code == RE_OK)
            RE_ERR_SET(ctx->err, RE_E_USAGE, "cannot read memory");
        re_file_close(&f);
        return re_err_exit_code(ctx->err->code);
    }
    re_strbuf_init(&hex, ctx->arena);
    re_strbuf_put_hex(&hex, view.p, view.n);
    begin_out(ctx, &w, "read_memory_bytes");
    re_jw_khex(&w, "address", va, 16);
    re_jw_ku64(&w, "size", view.n);
    re_jw_kcstr(&w, "data", hex.p ? hex.p : "");
    end_out(ctx, &w);
    re_file_close(&f);
    return 0;
}

extern "C" int re_cmd_data_read_byte(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    return data_read_n(ctx, path, argc, argv, 1, "data_read_byte");
}
extern "C" int re_cmd_data_read_word(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    return data_read_n(ctx, path, argc, argv, 2, "data_read_word");
}
extern "C" int re_cmd_data_read_dword(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    return data_read_n(ctx, path, argc, argv, 4, "data_read_dword");
}
extern "C" int re_cmd_data_read_qword(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    return data_read_n(ctx, path, argc, argv, 8, "data_read_qword");
}

extern "C" int re_cmd_data_read_string(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    uint64_t va = 0, off = 0;
    re_span_t s;
    re_jw_t w;
    const char *a = pos1(argc, argv);
    if (!re_prepare_loose(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    if (!a || !re_parse_addr(ctx, re_str(a), &pe, &va) || !va_off(&pe, va, &off) ||
        !re_rd_cstr(pe.img, off, 4096, &s)) {
        if (ctx->err->code == RE_OK)
            RE_ERR_SET(ctx->err, RE_E_MALFORMED, "no C string at address");
        re_file_close(&f);
        return re_err_exit_code(ctx->err->code);
    }
    begin_out(ctx, &w, "data_read_string");
    re_jw_khex(&w, "address", va, 16);
    re_jw_kstr(&w, "value", re_strn((const char *)s.p, s.n));
    end_out(ctx, &w);
    re_file_close(&f);
    return 0;
}

extern "C" int re_cmd_get_global_variable_value_at_address(re_ctx_t *ctx, const char *path,
                                                           int argc, char **argv) {
    return data_read_n(ctx, path, argc, argv, 8, "get_global_variable_value_at_address");
}

extern "C" int re_cmd_get_global_variable_value_by_name(re_ctx_t *ctx, const char *path, int argc,
                                                        char **argv) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    const char *name = pos1(argc, argv);
    size_t i;
    uint64_t off = 0, value = 0;
    re_span_t view;
    re_jw_t w;
    if (!re_prepare_loose(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    if (!name) {
        RE_ERR_SET(ctx->err, RE_E_USAGE, "name required");
        re_file_close(&f);
        return 2;
    }
    for (i = 0; i < RE_VEC_LEN(&pe.exports); i++) {
        const re_pe_exp_t *e = RE_VEC_PTR(&pe.exports, re_pe_exp_t, i);
        if (!e->name.n || !re_str_eq_cstr(e->name, name))
            continue;
        if (!re_pe_rva2off(&pe, e->rva, &off) || !re_rd(pe.img, off, 8, &view)) {
            RE_ERR_SET(ctx->err, RE_E_MALFORMED, "cannot read export");
            re_file_close(&f);
            return re_err_exit_code(ctx->err->code);
        }
        re_rd64(view, 0, &value);
        begin_out(ctx, &w, "get_global_variable_value_by_name");
        re_jw_kcstr(&w, "name", name);
        re_jw_khex(&w, "address", pe.image_base + e->rva, 16);
        re_jw_ku64(&w, "value", value);
        end_out(ctx, &w);
        re_file_close(&f);
        return 0;
    }
    RE_ERR_SETF(ctx->err, RE_E_USAGE, "no export named %s", name);
    re_file_close(&f);
    return 2;
}
