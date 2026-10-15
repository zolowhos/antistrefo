// re_cmds2.c - the step two commands: search, rules, entropy, demangle.
// Module: cli (C11).
// Owns: those four commands and their output shapes.
// Depends: re_cmds.h, re_search, re_rules, re_demangle, re_entropy, re_json.

#include "cli/cmds/re_cmds.h"

#include <stdio.h>
#include <string.h>

#include "features/code/re_code.h"
#include "features/data/re_rules.h"
#include "features/data/re_search.h"
#include "features/data/re_strings.h"
#include "features/lib/re_demangle.h"
#include "features/meta/re_disasm.h"
#include "features/pe/re_format.h"
#include "features/pe/re_pe.h"
#include "utils/json/re_json.h"
#include "utils/mem/re_buf.h"
#include "utils/sys/re_entropy.h"
#include "utils/text/re_strbuf.h"
#include "utils/text/re_util.h"
#include "cli/cmds/re_prep.h"

#define SCHEMA2 "antistrefo/1"

static void envelope(re_jw_t *w, const char *tool, re_span_t img, re_format_t fmt) {
    re_jw_obj(w);
    re_jw_kcstr(w, "schema", SCHEMA2);
    re_jw_kcstr(w, "tool", tool);
    re_jw_kcstr(w, "format", re_format_name(fmt));
    re_jw_ku64(w, "size", img.n);
}

// Prefix selects the kind. text: is five chars; imm:/raw:/sym: are four.
static re_search_kind_t search_kind(re_str_t pat, re_str_t *body) {
    size_t skip = 0;
    re_search_kind_t kind = RE_SEARCH_BYTES;
    if (re_str_starts_cstr(pat, "text:"))
        kind = RE_SEARCH_TEXT, skip = 5;
    else if (re_str_starts_cstr(pat, "imm:"))
        kind = RE_SEARCH_IMMEDIATE, skip = 4;
    else if (re_str_starts_cstr(pat, "raw:"))
        kind = RE_SEARCH_BYTES, skip = 4;
    else if (re_str_starts_cstr(pat, "sym:"))
        kind = RE_SEARCH_SIGNATURE, skip = 4;
    *body = skip ? re_strn(pat.p + skip, pat.n - skip) : pat;
    return kind;
}

// Covering instruction for a hit in executable bytes: walk back a short window.
static bool insn_covering(re_code_t *code, uint64_t va, uint64_t *insn_va, re_str_t *text,
                          re_arena_t *a) {
    uint64_t try_va;
    uint64_t best = 0;
    bool found = false;
    re_strbuf_t line;
    if (!code || !code->dis || !re_code_in_code(code, va))
        return false;
    for (uint64_t back = 0; back < 16; back++) {
        re_insn_t in;
        try_va = va - back;
        if (!re_code_in_code(code, try_va) || !re_code_insn(code, try_va, &in))
            continue;
        if (va >= try_va && va < try_va + in.size) {
            best = try_va;
            found = true;
            break;
        }
    }
    if (!found)
        return false;
    {
        re_insn_t in;
        if (!re_code_insn(code, best, &in))
            return false;
        re_strbuf_init(&line, a);
        code->dis->render(code->dis->ctx, &in, a, &line);
        *insn_va = best;
        *text = re_str(line.p ? line.p : "");
        return true;
    }
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

static void emit_text_extra(re_jw_t *w, re_ctx_t *ctx, re_span_t img, const re_search_hit_t *h) {
    re_str_around_t ar;
    re_str_around(img, h->off, h->wide, 4, ctx->context, ctx->arena, &ar);
    if (ar.found)
        re_jw_kstr(w, "run", ar.run.text);
    re_jw_kbool(w, "wide", h->wide);
    if (!ctx->context)
        return;
    re_str_hits_json(w, "before", &ar.before);
    re_str_hits_json(w, "after", &ar.after);
}

static void emit_hits(re_ctx_t *ctx, re_span_t img, re_format_t fmt, const re_pe_t *pe,
                      re_code_t *code, re_search_t *s, bool as_text) {
    re_jw_t w;
    size_t i;
    re_jw_init(&w, ctx->arena);
    envelope(&w, "search", img, fmt);
    re_jw_key(&w, "hits");
    re_jw_arr(&w);
    for (i = 0; i < RE_VEC_LEN(&s->hits); i++) {
        const re_search_hit_t *h = RE_VEC_PTR(&s->hits, re_search_hit_t, i);
        uint32_t rva = 0;
        uint64_t insn_va = 0;
        re_str_t insn_text;
        re_jw_obj(&w);
        re_jw_khex(&w, "off", h->off, 8);
        if (pe && pe->valid && re_pe_off2rva(pe, h->off, &rva)) {
            re_jw_ku64(&w, "rva", rva);
            re_jw_khex(&w, "va", pe->image_base + rva, 16);
            if (code &&
                insn_covering(code, pe->image_base + rva, &insn_va, &insn_text, ctx->arena)) {
                re_jw_khex(&w, "insn_va", insn_va, 16);
                re_jw_kstr(&w, "insn_text", insn_text);
            }
        }
        re_jw_kstr(&w, "text", h->text);
        if (as_text)
            emit_text_extra(&w, ctx, img, h);
        re_jw_obj_end(&w);
    }
    re_jw_arr_end(&w);
    re_jw_ku64(&w, "total", s->total);
    re_jw_kbool(&w, "truncated", s->more);
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
}

static bool bind_search_code(re_span_t img, re_arena_t *a, re_pe_t *pe, re_code_t *code) {
    const char *want;
    const re_disasm_t *d;
    memset(pe, 0, sizeof(*pe));
    memset(code, 0, sizeof(*code));
    if (re_pe_parse(img, a, pe) != RE_OK || !pe->valid)
        return false;
    want = re_disasm_for_machine(pe->machine);
    d = want ? re_disasm_find(want) : NULL;
    return re_code_init(code, img, pe, d, a);
}

static bool run_search(re_ctx_t *ctx, re_span_t img, re_search_kind_t *kind, re_str_t pat,
                       re_search_t *s) {
    uint8_t *by = NULL;
    uint8_t *mk = NULL;
    size_t n = 0;
    if (*kind == RE_SEARCH_BYTES &&
        !re_search_parse_pattern(ctx->arena, pat.p, &by, &mk, &n, ctx->err)) {
        if (ctx->err->code != RE_E_USAGE)
            return false;
        *kind = RE_SEARCH_TEXT;
        RE_ERR_OK(ctx->err);
    }
    if (*kind == RE_SEARCH_BYTES)
        re_search_bytes(img, by, mk, n, ctx->offset, ctx->limit, ctx->arena, s);
    else if (*kind == RE_SEARCH_IMMEDIATE)
        return run_immediate(ctx, img, pat, s);
    else if (*kind == RE_SEARCH_TEXT)
        re_search_text(img, pat, false, true, false, ctx->offset, ctx->limit, ctx->arena, s);
    else
        re_search_signature(img, pat, ctx->offset, ctx->limit, ctx->arena, s);
    return true;
}

int re_cmd_search(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    const char *pat_arg = re_cmd_positional(argc, argv, 1);
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_err_code_t e;
    re_str_t pat;
    re_search_kind_t kind;
    re_search_t s;
    bool have_code;
    if (!pat_arg) {
        RE_ERR_SET(ctx->err, RE_E_USAGE,
                   "search needs a pattern: text:<pat> imm:<hex> raw:<hex> sym:<name>");
        return re_err_exit_code(RE_E_USAGE);
    }
    e = re_file_open(path, ctx->arena, &f);
    if (e != RE_OK) {
        RE_ERR_SETF(ctx->err, e, "cannot open %s", path);
        return re_err_exit_code(e);
    }
    have_code = bind_search_code(f.whole, ctx->arena, &pe, &code);
    kind = search_kind(re_str(pat_arg), &pat);
    re_search_init(&s);
    if (!run_search(ctx, f.whole, &kind, pat, &s)) {
        re_file_close(&f);
        return re_err_exit_code(ctx->err->code);
    }
    emit_hits(ctx, f.whole, re_format_detect(f.whole), &pe, have_code ? &code : NULL, &s,
              kind == RE_SEARCH_TEXT || kind == RE_SEARCH_SIGNATURE);
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
