// re_cmds2.c - the step two commands: search, rules, entropy, demangle.
// Module: cli (C11).
// Owns: those four commands and their output shapes.
// Depends: re_cmds.h, re_search, re_rules, re_demangle, re_entropy, re_json.

#include "cli/cmds/re_cmds.h"

#include <stdio.h>

#include "features/data/re_rules.h"
#include "features/data/re_search.h"
#include "features/data/re_strings.h"
#include "features/lib/re_demangle.h"
#include "features/pe/re_format.h"
#include "features/pe/re_pe.h"
#include "utils/json/re_json.h"
#include "utils/mem/re_buf.h"
#include "utils/sys/re_entropy.h"
#include "utils/text/re_util.h"

#define SCHEMA2 "antistrefo/1"

static void envelope(re_jw_t *w, const char *tool, re_span_t img, re_format_t fmt) {
    re_jw_obj(w);
    re_jw_kcstr(w, "schema", SCHEMA2);
    re_jw_kcstr(w, "tool", tool);
    re_jw_kcstr(w, "format", re_format_name(fmt));
    re_jw_ku64(w, "size", img.n);
}

// The pattern prefix selects the kind and the rest of the pattern is the body.
// The skip is carried per prefix because text: is five characters and the other
// two are four, so a single fixed offset silently eats a digit.
static re_search_kind_t search_kind(re_str_t pat, re_str_t *body) {
    size_t skip = 0;
    re_search_kind_t kind = RE_SEARCH_BYTES;
    if (re_str_starts_cstr(pat, "text:"))
        kind = RE_SEARCH_TEXT, skip = 5;
    else if (re_str_starts_cstr(pat, "imm:"))
        kind = RE_SEARCH_IMMEDIATE, skip = 4;
    else if (re_str_starts_cstr(pat, "sym:"))
        kind = RE_SEARCH_SIGNATURE, skip = 4;
    *body = skip ? re_strn(pat.p + skip, pat.n - skip) : pat;
    return kind;
}

// A literal integer immediate. The width is taken from the digit count, which is
// what the user meant by typing 2 digits versus 8, and both byte orders run.
static bool run_immediate(re_ctx_t *ctx, re_span_t img, re_str_t pat, re_search_t *s) {
    uint64_t v = 0;
    for (size_t i = 0; i < pat.n; i++) {
        int d = re_hex_val(pat.p[i]);
        if (d < 0) {
            RE_ERR_SET(ctx->err, RE_E_USAGE, "imm: needs a hex value");
            return false;
        }
        v = v * 16u + (uint64_t)d;
    }
    unsigned width = (pat.n <= 2) ? 1u : (pat.n <= 4) ? 2u : (pat.n <= 8) ? 4u : 8u;
    re_search_immediate(img, v, width, true, ctx->offset, ctx->limit, ctx->arena, s);
    return true;
}

static void emit_hits(re_ctx_t *ctx, re_span_t img, re_format_t fmt, re_search_t *s) {
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    envelope(&w, "search", img, fmt);
    re_jw_key(&w, "hits");
    re_jw_arr(&w);
    for (size_t i = 0; i < RE_VEC_LEN(&s->hits); i++) {
        const re_search_hit_t *h = RE_VEC_PTR(&s->hits, re_search_hit_t, i);
        re_jw_obj(&w);
        re_jw_khex(&w, "off", h->off, 8);
        re_jw_kstr(&w, "text", h->text);
        re_jw_obj_end(&w);
    }
    re_jw_arr_end(&w);
    re_jw_ku64(&w, "total", s->total);
    re_jw_kbool(&w, "truncated", s->more);
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
}

int re_cmd_search(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    // argv[0] is the file, which main already passed as path, so the pattern is
    // the second argument. Reading argv[0] here searched for the file name.
    const char *pat_arg = re_cmd_positional(argc, argv, 1);
    if (!pat_arg) {
        RE_ERR_SET(ctx->err, RE_E_USAGE, "search needs a pattern, usage: search <file> <pattern>");
        return re_err_exit_code(RE_E_USAGE);
    }
    re_file_t f;
    re_err_code_t e = re_file_open(path, ctx->arena, &f);
    if (e != RE_OK) {
        RE_ERR_SETF(ctx->err, e, "cannot open %s", path);
        return re_err_exit_code(e);
    }
    re_span_t img = f.whole;
    re_format_t fmt = re_format_detect(img);
    re_str_t pat;
    re_search_kind_t kind = search_kind(re_str(pat_arg), &pat);
    re_search_t s;
    re_search_init(&s);
    uint8_t *by = NULL;
    uint8_t *mk = NULL;
    size_t n = 0;
    if (kind == RE_SEARCH_BYTES &&
        !re_search_parse_pattern(ctx->arena, pat.p, &by, &mk, &n, ctx->err)) {
        // A bare pattern that cannot be hex pairs is searched as text: the docs
        // promise text without asking for a prefix, and a pattern holding a non hex
        // byte could never have been hex anyway. The text: prefix still forces text
        // for a pattern that looks like hex, and a non usage failure is an error.
        if (ctx->err->code != RE_E_USAGE) {
            re_file_close(&f);
            return re_err_exit_code(ctx->err->code);
        }
        kind = RE_SEARCH_TEXT;
        RE_ERR_OK(ctx->err);
    }
    if (kind == RE_SEARCH_BYTES) {
        re_search_bytes(img, by, mk, n, ctx->offset, ctx->limit, ctx->arena, &s);
    } else if (kind == RE_SEARCH_IMMEDIATE) {
        if (!run_immediate(ctx, img, pat, &s)) {
            re_file_close(&f);
            return re_err_exit_code(ctx->err->code);
        }
    } else if (kind == RE_SEARCH_TEXT) {
        re_search_text(img, pat, false, true, false, ctx->offset, ctx->limit, ctx->arena, &s);
    } else {
        re_search_signature(img, pat, ctx->offset, ctx->limit, ctx->arena, &s);
    }
    emit_hits(ctx, img, fmt, &s);
    re_file_close(&f);
    return 0;
}

int re_cmd_rules(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    (void)argc;
    (void)argv;
    re_file_t f;
    re_err_code_t e = re_file_open(path, ctx->arena, &f);
    if (e != RE_OK) {
        RE_ERR_SETF(ctx->err, e, "cannot open %s", path);
        return re_err_exit_code(e);
    }
    re_span_t img = f.whole;
    re_format_t fmt = re_format_detect(img);
    re_pe_t pe;
    re_strings_t st;
    re_strings_init(&st);
    e = re_pe_parse(img, ctx->arena, &pe);
    if (e != RE_OK) {
        re_file_close(&f);
        return re_err_exit_code(e);
    }
    re_strings_scan(img, 4, 20000, ctx->arena, &st);
    re_strings_devices(img, 1024, ctx->arena, &st);
    re_strings_pdb(img, ctx->arena, &st);
    re_vec_t findings;
    re_rules_eval(img, &pe, &st, ctx->arena, &findings);
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    envelope(&w, "rules", img, fmt);
    re_rules_emit(&w, &findings, true);
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
    re_file_close(&f);
    return 0;
}

int re_cmd_entropy(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    (void)argc;
    (void)argv;
    re_file_t f;
    re_err_code_t e = re_file_open(path, ctx->arena, &f);
    if (e != RE_OK) {
        RE_ERR_SETF(ctx->err, e, "cannot open %s", path);
        return re_err_exit_code(e);
    }
    re_span_t img = f.whole;
    size_t win = 1024;
    size_t step = 1024;
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    envelope(&w, "entropy", img, re_format_detect(img));
    re_jw_ku64(&w, "window", win);
    re_jw_ku64(&w, "step", step);
    re_jw_kf64(&w, "whole_file", re_entropy(img));
    re_jw_key(&w, "windows");
    re_jw_arr(&w);
    for (size_t off = 0; off + win <= img.n && off < 1u << 20; off += step) {
        double h = re_entropy(re_span_sub(img, off, win));
        re_jw_obj(&w);
        re_jw_khex(&w, "off", off, 8);
        re_jw_kf64(&w, "entropy", h);
        re_jw_kbool(&w, "hot", h > 7.0);
        re_jw_obj_end(&w);
    }
    re_jw_arr_end(&w);
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
    re_file_close(&f);
    return 0;
}

int re_cmd_demangle(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    (void)path;
    if (argc < 1) {
        RE_ERR_SET(ctx->err, RE_E_USAGE, "demangle needs a symbol");
        return re_err_exit_code(RE_E_USAGE);
    }
    re_str_t sym = re_str(argv[0]);
    re_str_t out;
    bool ok = re_demangle(ctx->arena, sym.p, sym.n, &out);
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    re_jw_obj(&w);
    re_jw_kcstr(&w, "schema", SCHEMA2);
    re_jw_kcstr(&w, "tool", "demangle");
    re_jw_kstr(&w, "symbol", sym);
    re_jw_kcstr(&w, "mangling", re_mangle_name(re_mangle_kind(sym.p, sym.n)));
    re_jw_kbool(&w, "ok", ok);
    if (ok)
        re_jw_kstr(&w, "demangled", out);
    else
        re_jw_knull(&w, "demangled");
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
    return 0;
}
