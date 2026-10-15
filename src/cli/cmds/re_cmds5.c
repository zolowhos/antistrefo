// re_cmds5.c - strings, class tables, and ordered name references.
// Module: cli (C11).
// Owns: re_cmd_strings, re_cmd_vtables and re_cmd_namerefs.
// Depends: re_prep, re_strings, re_regex, re_vtable, re_nameref. Any file.
#include "features/data/re_strings.h"
#include "features/data/re_vtable.h"
#include "features/pe/re_pe.h"
#include "features/resolve/re_nameref.h"
#include "utils/algo/re_regex.h"
#include "utils/json/re_json.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_buf.h"
#include "utils/mem/re_vec.h"
#include "utils/text/re_str.h"
#include "utils/text/re_text.h"
#include "cli/app/re_table.h"
#include "cli/cmds/re_prep.h"

#include <string.h>

static void string_row(re_jw_t *w, re_ctx_t *ctx, re_span_t img, const re_str_hit_t *h,
                       const re_pe_t *pe) {
    uint32_t rva = 0;
    re_str_around_t ar;
    re_jw_obj(w);
    re_jw_khex(w, "off", h->off, 8);
    if (pe && re_pe_off2rva(pe, h->off, &rva)) {
        re_jw_khex(w, "va", pe->image_base + rva, 16);
        re_jw_ku64(w, "rva", rva);
    }
    re_jw_kbool(w, "wide", h->wide);
    re_jw_kstr(w, "text", h->text);
    if (ctx->context) {
        re_str_around(img, h->off, h->wide, 4, ctx->context, ctx->arena, &ar);
        re_str_hits_json(w, "before", &ar.before);
        re_str_hits_json(w, "after", &ar.after);
    }
    re_jw_obj_end(w);
}

// The plain text form: the same rows the JSON carries, as one aligned table. The
// string stays the last column so only it can run past its measured width.
static void strings_text(re_ctx_t *ctx, const re_pe_t *pe, const re_vec_t *hits) {
    re_strbuf_t sb;
    re_strbuf_init(&sb, ctx->arena);
    re_text_t t;
    re_text_init(&t, &sb);
    char off[16], va[24], rva[16], wide[8];
    const char *row[5];
    const char *hdr[5] = {"off", "va", "rva", "enc", "text"};
    for (size_t i = 0; i < RE_VEC_LEN(hits); i++) {
        const re_str_hit_t *h = RE_VEC_PTR(hits, re_str_hit_t, i);
        snprintf(off, sizeof(off), "0x%08llx", (unsigned long long)h->off);
        uint32_t r = 0;
        if (re_pe_off2rva(pe, h->off, &r)) {
            snprintf(va, sizeof(va), "0x%llx", (unsigned long long)(pe->image_base + r));
            snprintf(rva, sizeof(rva), "0x%x", r);
        } else {
            snprintf(va, sizeof(va), "-");
            snprintf(rva, sizeof(rva), "-");
        }
        snprintf(wide, sizeof(wide), "%s", h->wide ? "wide" : "ascii");
        row[0] = off;
        row[1] = va;
        row[2] = rva;
        row[3] = wide;
        row[4] = h->text.p ? h->text.p : "";
        re_text_measure(&t, row, 5);
    }
    re_text_header(&t, hdr, 5);
    for (size_t i = 0; i < RE_VEC_LEN(hits); i++) {
        const re_str_hit_t *h = RE_VEC_PTR(hits, re_str_hit_t, i);
        snprintf(off, sizeof(off), "0x%08llx", (unsigned long long)h->off);
        uint32_t r = 0;
        if (re_pe_off2rva(pe, h->off, &r)) {
            snprintf(va, sizeof(va), "0x%llx", (unsigned long long)(pe->image_base + r));
            snprintf(rva, sizeof(rva), "0x%x", r);
        } else {
            snprintf(va, sizeof(va), "-");
            snprintf(rva, sizeof(rva), "-");
        }
        snprintf(wide, sizeof(wide), "%s", h->wide ? "wide" : "ascii");
        row[0] = off;
        row[1] = va;
        row[2] = rva;
        row[3] = wide;
        row[4] = h->text.p ? h->text.p : "";
        re_text_row(&t, row, 5);
    }
    fputs(sb.p ? sb.p : "", stdout);
}

static re_rx_t *compile_rx(re_ctx_t *ctx) {
    char *pat;
    if (!ctx->has_regex)
        return NULL;
    pat = re_arena_strndup(ctx->arena, ctx->regex.p, ctx->regex.n);
    return re_rx_compile(ctx->arena, pat, "i", ctx->err);
}

int re_cmd_strings(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_file_t f;
    re_pe_t pe;
    re_str_page_t page;
    re_rx_t *rx;
    re_err_code_t e;
    re_jw_t w;
    size_t i;
    (void)argc;
    (void)argv;
    e = re_file_open(path, ctx->arena, &f);
    if (e != RE_OK) {
        RE_ERR_SETF(ctx->err, e, "cannot open %s", path);
        return re_err_exit_code(e);
    }
    memset(&pe, 0, sizeof(pe));
    (void)re_pe_parse(f.whole, ctx->arena, &pe);
    rx = compile_rx(ctx);
    if (ctx->has_regex && !rx) {
        re_file_close(&f);
        return re_err_exit_code(ctx->err->code);
    }
    re_strings_collect(f.whole, 4, rx, ctx->offset, ctx->limit, ctx->arena, &page);
    if (ctx->out == RE_FMT_OUT_TEXT) {
        strings_text(ctx, &pe, &page.hits);
        re_file_close(&f);
        return 0;
    }
    re_jw_init(&w, ctx->arena);
    re_envelope(&w, "strings", f.whole, &pe);
    re_jw_ku64(&w, "total", page.total);
    re_jw_ku64(&w, "count", RE_VEC_LEN(&page.hits));
    re_jw_kbool(&w, "truncated", page.truncated);
    re_jw_key(&w, "strings");
    re_jw_arr(&w);
    for (i = 0; i < RE_VEC_LEN(&page.hits); i++)
        string_row(&w, ctx, f.whole, RE_VEC_PTR(&page.hits, re_str_hit_t, i), &pe);
    re_jw_arr_end(&w);
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
    re_file_close(&f);
    return 0;
}

// One vtable: where it is, which class it is for, and the functions it can dispatch
// to. A vtable with no name is still reported, because the file has RTTI for some
// classes and not others and hiding the unnamed ones would understate how much of the
// image is C++.
static void vtable_row(re_jw_t *w, const re_vtable_t *v, const re_pe_t *pe) {
    re_jw_obj(w);
    re_jw_khex(w, "va", pe->image_base + v->rva, 16);
    re_jw_ku64(w, "rva", v->rva);
    if (v->name.n)
        re_jw_kstr(w, "class", v->name);
    re_jw_kbool(w, "demangled", v->demangled);
    re_jw_ku64(w, "entries", v->n_entries);
    re_jw_ku64(w, "bases", v->n_bases);
    re_jw_key(w, "targets");
    re_jw_arr(w);
    for (uint32_t i = 0; i < v->n_entries; i++) {
        uint32_t t = 0;
        if (re_vtable_entry(pe, v, i, &t))
            re_jw_hex(w, pe->image_base + t, 16);
    }
    re_jw_arr_end(w);
    re_jw_obj_end(w);
}

// The C++ class tables. Every name here came out of the file's own RTTI: a locator's
// pSelf field has to equal the locator's own address before the entry is believed, so
// a coincidence in a data section cannot produce a class name.
int re_cmd_vtables(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    (void)argc;
    (void)argv;
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    if (!re_prepare(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_vset_t vs;
    re_vtable_scan(&pe, &code, ctx->arena, &vs);
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    re_envelope(&w, "vtables", f.whole, &pe);
    re_jw_ku64(&w, "vtables", RE_VEC_LEN(&vs.vtables));
    re_jw_ku64(&w, "locators", vs.n_col);
    re_jw_ku64(&w, "named", vs.n_named);
    re_jw_key(&w, "classes");
    re_jw_arr(&w);
    for (size_t i = 0; i < RE_VEC_LEN(&vs.vtables) && i < ctx->limit; i++)
        vtable_row(&w, RE_VEC_PTR(&vs.vtables, re_vtable_t, i), &pe);
    re_jw_arr_end(&w);
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
    re_file_close(&f);
    return 0;
}

static bool push_owned(re_arena_t *a, re_vec_t *out, re_str_t text) {
    char *dup;
    re_str_t owned;
    if (text.n == 0)
        return true;
    dup = re_arena_strndup(a, text.p, text.n);
    if (!dup)
        return false;
    owned = re_strn(dup, text.n);
    return RE_VEC_PUSH(out, a, owned);
}

static bool read_lines(re_ctx_t *ctx, const char *path, re_vec_t *out) {
    re_file_t f;
    re_vec_t lines;
    re_err_code_t e = re_file_open(path, ctx->arena, &f);
    if (e != RE_OK) {
        RE_ERR_SETF(ctx->err, e, "cannot open %s", path);
        return false;
    }
    lines = re_str_split(ctx->arena, re_strn((const char *)f.whole.p, f.whole.n), '\n');
    for (size_t i = 0; i < RE_VEC_LEN(&lines); i++) {
        re_str_t line = re_str_trim(RE_VEC_AT(&lines, re_str_t, i));
        if (!push_owned(ctx->arena, out, line)) {
            re_file_close(&f);
            RE_ERR_SET(ctx->err, RE_E_NOMEM, "out of memory reading names");
            return false;
        }
    }
    re_file_close(&f);
    return true;
}

static bool names_from_file(re_ctx_t *ctx, re_vec_t *out) {
    re_vec_t lines;
    re_vec_init(&lines, sizeof(re_str_t));
    if (!read_lines(ctx, ctx->names_path.p, &lines))
        return false;
    for (size_t i = 0; i < RE_VEC_LEN(&lines); i++) {
        re_nameref_in_t in;
        in.name = RE_VEC_AT(&lines, re_str_t, i);
        in.rva = 0;
        in.has_rva = false;
        if (!RE_VEC_PUSH(out, ctx->arena, in)) {
            RE_ERR_SET(ctx->err, RE_E_NOMEM, "out of memory reading names");
            return false;
        }
    }
    return true;
}

static bool push_export(re_ctx_t *ctx, re_vec_t *out, const re_pe_exp_t *x) {
    re_nameref_in_t in;
    char *dup;
    if (x->name.n == 0)
        return true;
    dup = re_arena_strndup(ctx->arena, x->name.p, x->name.n);
    if (!dup) {
        RE_ERR_SET(ctx->err, RE_E_NOMEM, "out of memory reading exports");
        return false;
    }
    in.name = re_strn(dup, x->name.n);
    in.rva = x->rva;
    in.has_rva = true;
    if (!RE_VEC_PUSH(out, ctx->arena, in)) {
        RE_ERR_SET(ctx->err, RE_E_NOMEM, "out of memory reading exports");
        return false;
    }
    return true;
}

static bool names_from_exports(re_ctx_t *ctx, re_vec_t *out) {
    re_file_t f;
    re_pe_t pe;
    re_err_code_t e = re_file_open(ctx->exports_path.p, ctx->arena, &f);
    if (e != RE_OK) {
        RE_ERR_SETF(ctx->err, e, "cannot open %s", ctx->exports_path.p);
        return false;
    }
    e = re_pe_parse(f.whole, ctx->arena, &pe);
    if (e != RE_OK || !pe.valid) {
        re_file_close(&f);
        RE_ERR_SETF(ctx->err, e != RE_OK ? e : RE_E_MALFORMED, "cannot parse %s",
                    ctx->exports_path.p);
        return false;
    }
    for (size_t i = 0; i < RE_VEC_LEN(&pe.exports); i++) {
        if (!push_export(ctx, out, RE_VEC_PTR(&pe.exports, re_pe_exp_t, i))) {
            re_file_close(&f);
            return false;
        }
    }
    re_file_close(&f);
    return true;
}

static bool load_inputs(re_ctx_t *ctx, re_vec_t *names, re_vec_t *order) {
    if (ctx->exports_path.n && ctx->names_path.n) {
        RE_ERR_SET(ctx->err, RE_E_USAGE, "pass one of --exports or --names");
        return false;
    }
    if (!ctx->exports_path.n && !ctx->names_path.n) {
        RE_ERR_SET(ctx->err, RE_E_USAGE, "namerefs needs --exports or --names");
        return false;
    }
    if (ctx->exports_path.n && !names_from_exports(ctx, names))
        return false;
    if (ctx->names_path.n && !names_from_file(ctx, names))
        return false;
    if (ctx->order_path.n && !read_lines(ctx, ctx->order_path.p, order))
        return false;
    return true;
}

static void emit_hit(re_jw_t *w, const re_nameref_hit_t *h) {
    re_jw_obj(w);
    re_jw_ku64(w, "index", h->index);
    re_jw_khex(w, "from", h->from, 16);
    re_jw_khex(w, "to", h->to, 16);
    re_jw_kstr(w, "name", h->name);
    if (h->order_index >= 0) {
        re_jw_ki64(w, "order_index", h->order_index);
        re_jw_kstr(w, "order_name", h->order_name);
    }
    re_jw_obj_end(w);
}

static void emit_refs(re_jw_t *w, const re_nameref_t *nr, size_t off, size_t limit) {
    size_t shown = 0;
    size_t total = RE_VEC_LEN(&nr->hits);
    re_jw_key(w, "refs");
    re_jw_arr(w);
    for (size_t i = off; i < total && shown < limit; i++, shown++)
        emit_hit(w, RE_VEC_PTR(&nr->hits, re_nameref_hit_t, i));
    re_jw_arr_end(w);
    re_jw_ku64(w, "count", total);
    re_jw_kbool(w, "truncated", off + shown < total);
}

static void emit_miss(re_jw_t *w, const re_nameref_miss_t *m) {
    re_jw_obj(w);
    re_jw_kstr(w, "name", m->name);
    if (m->has_rva)
        re_jw_khex(w, "rva", m->rva, 8);
    if (m->order_index >= 0) {
        re_jw_ki64(w, "order_index", m->order_index);
        re_jw_kstr(w, "order_name", m->order_name);
    }
    re_jw_obj_end(w);
}

static void emit_gap(re_jw_t *w, const re_nameref_gap_t *g) {
    re_jw_obj(w);
    re_jw_ki64(w, "order_index", g->order_index);
    re_jw_kstr(w, "order_name", g->order_name);
    if (g->name.n)
        re_jw_kstr(w, "name", g->name);
    re_jw_obj_end(w);
}

static void emit_side(re_jw_t *w, const char *key, const re_vec_t *v, bool gaps) {
    re_jw_key(w, key);
    re_jw_arr(w);
    for (size_t i = 0; i < RE_VEC_LEN(v); i++) {
        if (gaps)
            emit_gap(w, RE_VEC_PTR(v, re_nameref_gap_t, i));
        else
            emit_miss(w, RE_VEC_PTR(v, re_nameref_miss_t, i));
    }
    re_jw_arr_end(w);
}

int re_cmd_namerefs(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_vec_t names;
    re_vec_t order;
    re_nameref_t nr;
    re_jw_t w;
    const re_nameref_in_t *in = NULL;
    const re_str_t *ord = NULL;
    (void)argc;
    (void)argv;
    if (!re_prepare_loose(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_vec_init(&names, sizeof(re_nameref_in_t));
    re_vec_init(&order, sizeof(re_str_t));
    if (!load_inputs(ctx, &names, &order)) {
        re_file_close(&f);
        return re_err_exit_code(ctx->err->code);
    }
    if (RE_VEC_LEN(&names))
        in = RE_VEC_PTR(&names, re_nameref_in_t, 0);
    if (RE_VEC_LEN(&order))
        ord = RE_VEC_PTR(&order, re_str_t, 0);
    if (!re_nameref_scan(&pe, in, RE_VEC_LEN(&names), ord, RE_VEC_LEN(&order), ctx->arena, &nr)) {
        re_file_close(&f);
        RE_ERR_SET(ctx->err, RE_E_NOMEM, "out of memory");
        return re_err_exit_code(RE_E_NOMEM);
    }
    re_jw_init(&w, ctx->arena);
    re_envelope(&w, "namerefs", f.whole, &pe);
    emit_refs(&w, &nr, ctx->offset, ctx->limit);
    emit_side(&w, "unreferenced", &nr.unreferenced, false);
    re_jw_ku64(&w, "unreferenced_count", RE_VEC_LEN(&nr.unreferenced));
    emit_side(&w, "absent", &nr.absent, true);
    re_jw_ku64(&w, "absent_count", RE_VEC_LEN(&nr.absent));
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
    re_file_close(&f);
    return 0;
}
