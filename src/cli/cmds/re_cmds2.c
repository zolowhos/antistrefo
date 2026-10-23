// re_cmds2.c - the step two commands: search, rules, entropy, demangle.
// Module: cli (C11).
// Owns: those four commands and their output shapes.
// Depends: re_cmds.h, re_search, re_rules, re_demangle, re_entropy, re_json.

#include "cli/cmds/re_cmds.h"

#include <stdio.h>
#include <string.h>

#include "features/code/re_code.h"
#include "features/code/re_func.h"
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

static bool render_at(re_code_t *code, uint64_t va, re_str_t *text, re_arena_t *a) {
    re_insn_t in;
    re_strbuf_t line;
    if (!re_code_insn(code, va, &in))
        return false;
    re_strbuf_init(&line, a);
    code->dis->render(code->dis->ctx, &in, a, &line);
    *text = re_str(line.p ? line.p : "");
    return true;
}

// True when the decoded instruction carries v as an immediate or a displacement.
static bool insn_carries_value(const re_insn_t *in, uint64_t v) {
    unsigned w;
    for (w = 1; w <= 8; w *= 2) {
        uint64_t mask = w == 8 ? ~(uint64_t)0 : ((uint64_t)1 << (w * 8)) - 1u;
        if (v > mask)
            continue;
        if (((uint64_t)in->imm & mask) == v)
            return true;
        if (((uint64_t)in->disp & mask) == v)
            return true;
    }
    return (uint64_t)in->imm == v || (uint64_t)in->disp == v;
}

// Prefer function-linear snap so a mid-immediate payload is never the decode site.
// When check_val is set, reject a covering decode that does not carry want.
static bool insn_covering(re_code_t *code, const re_fscan_t *scan, uint64_t va, bool check_val,
                          uint64_t want, uint64_t *insn_va, re_str_t *text, re_arena_t *a) {
    uint64_t best = 0;
    bool found = false;
    re_insn_t in;
    if (!code || !code->dis || !re_code_in_code(code, va))
        return false;
    if (scan) {
        long fi = re_func_index_of(scan, va);
        if (fi >= 0) {
            const re_func_t *f = re_func_at(scan, (size_t)fi);
            if (f && re_snap_insn_va(code, f->va, va, &best))
                found = true;
        }
    }
    for (uint64_t back = 1; !found && back < 16; back++) {
        uint64_t try_va = va - back;
        if (!re_code_in_code(code, try_va) || !re_code_insn(code, try_va, &in))
            continue;
        if (va >= try_va && va < try_va + in.size) {
            best = try_va;
            found = true;
        }
    }
    if (!found && re_code_insn(code, va, &in) && in.size > 0) {
        best = va;
        found = true;
    }
    if (!found || !re_code_insn(code, best, &in))
        return false;
    if (check_val && !insn_carries_value(&in, want))
        return false;
    if (!render_at(code, best, text, a))
        return false;
    *insn_va = best;
    return true;
}

// Optional 0x/0X prefix, then every width that can hold the value (LE and BE).
// Digit count does not pin width: imm:1E78 is still searched as 16/32/64. Prefer
// zero-padded dword forms (imm:00001E78) when the agent means a 32-bit field.
static bool parse_imm_value(re_ctx_t *ctx, re_str_t pat, uint64_t *out) {
    uint64_t v = 0;
    size_t i = 0;
    if (pat.n >= 2 && pat.p[0] == '0' && (pat.p[1] == 'x' || pat.p[1] == 'X'))
        i = 2;
    if (i >= pat.n) {
        RE_ERR_SET(ctx->err, RE_E_USAGE, "imm: needs a hex value");
        return false;
    }
    for (; i < pat.n; i++) {
        int d = re_hex_val(pat.p[i]);
        if (d < 0) {
            RE_ERR_SET(ctx->err, RE_E_USAGE, "imm: needs a hex value");
            return false;
        }
        v = v * 16u + (uint64_t)d;
    }
    *out = v;
    return true;
}

static bool run_immediate(re_ctx_t *ctx, re_span_t img, re_str_t pat, re_search_t *s, uint64_t *v) {
    if (!parse_imm_value(ctx, pat, v))
        return false;
    re_search_immediate_all(img, *v, 0, 0, ctx->arena, s);
    return true;
}

static bool hit_in_code(const re_pe_t *pe, re_code_t *code, uint64_t off) {
    uint32_t rva = 0;
    if (!pe || !pe->valid || !code || !re_pe_off2rva(pe, off, &rva))
        return false;
    return re_code_in_code(code, pe->image_base + rva);
}

// Page imm hits with executable matches first so header noise does not bury them.
static void page_imm_hits(re_search_t *s, const re_pe_t *pe, re_code_t *code, size_t offset,
                          size_t limit, re_arena_t *a) {
    re_vec_t ranked;
    size_t i, n, pass;
    re_vec_init(&ranked, sizeof(re_search_hit_t));
    for (pass = 0; pass < 2; pass++) {
        for (i = 0; i < RE_VEC_LEN(&s->hits); i++) {
            re_search_hit_t h = RE_VEC_AT(&s->hits, re_search_hit_t, i);
            bool code_hit = hit_in_code(pe, code, h.off);
            if (pass == 0 ? code_hit : !code_hit)
                RE_VEC_PUSH(&ranked, a, h);
        }
    }
    re_vec_truncate(&s->hits, 0);
    n = RE_VEC_LEN(&ranked);
    s->total = n > offset ? n - offset : 0;
    s->more = false;
    for (i = offset; i < n; i++) {
        if (limit && RE_VEC_LEN(&s->hits) >= limit) {
            s->more = true;
            break;
        }
        RE_VEC_PUSH(&s->hits, a, RE_VEC_AT(&ranked, re_search_hit_t, i));
    }
    if (!limit)
        s->total = RE_VEC_LEN(&s->hits);
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
                      re_code_t *code, const re_fscan_t *scan, re_search_t *s, bool as_text,
                      bool filter_imm, uint64_t imm_v) {
    re_jw_t w;
    size_t i, shown = 0;
    re_jw_init(&w, ctx->arena);
    envelope(&w, "search", img, fmt);
    re_jw_key(&w, "hits");
    re_jw_arr(&w);
    for (i = 0; i < RE_VEC_LEN(&s->hits); i++) {
        const re_search_hit_t *h = RE_VEC_PTR(&s->hits, re_search_hit_t, i);
        uint32_t rva = 0;
        uint64_t hit_va = 0, insn_va = 0;
        re_str_t insn_text = re_strn(NULL, 0);
        bool have_insn = false;
        if (pe && pe->valid && re_pe_off2rva(pe, h->off, &rva))
            hit_va = pe->image_base + rva;
        if (code && hit_va) {
            have_insn = insn_covering(code, scan, hit_va, filter_imm, imm_v, &insn_va, &insn_text,
                                      ctx->arena);
            if (filter_imm && re_code_in_code(code, hit_va) && !have_insn)
                continue;
        }
        re_jw_obj(&w);
        re_jw_khex(&w, "off", h->off, 8);
        if (hit_va) {
            re_jw_ku64(&w, "rva", rva);
            re_jw_khex(&w, "va", hit_va, 16);
            if (have_insn) {
                re_jw_khex(&w, "insn_va", insn_va, 16);
                re_jw_kstr(&w, "insn_text", insn_text);
                if (insn_va != hit_va)
                    re_jw_kbool(&w, "mid_imm", true);
            }
        }
        re_jw_kstr(&w, "text", h->text);
        if (as_text)
            emit_text_extra(&w, ctx, img, h);
        re_jw_obj_end(&w);
        shown++;
    }
    re_jw_arr_end(&w);
    // Imm pages through page_imm_hits first; truncated must still follow s->more
    // so a full page is not reported as complete when more matches remain.
    re_jw_ku64(&w, "total", filter_imm ? shown : s->total);
    re_jw_kbool(&w, "truncated", s->more);
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
}

static bool bind_search_code(re_span_t img, re_arena_t *a, re_pe_t *pe, re_code_t *code,
                             re_fscan_t *scan) {
    const char *want;
    const re_disasm_t *d;
    memset(pe, 0, sizeof(*pe));
    memset(code, 0, sizeof(*code));
    if (re_pe_parse(img, a, pe) != RE_OK || !pe->valid)
        return false;
    want = re_disasm_for_machine(pe->machine);
    d = want ? re_disasm_find(want) : NULL;
    if (!re_code_init(code, img, pe, d, a))
        return false;
    re_func_scan(code, a, scan);
    return true;
}

static bool run_search(re_ctx_t *ctx, re_span_t img, re_search_kind_t *kind, re_str_t pat,
                       re_search_t *s, uint64_t *imm_v) {
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
        return run_immediate(ctx, img, pat, s, imm_v);
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
    re_fscan_t scan;
    re_err_code_t e;
    re_str_t pat;
    re_search_kind_t kind;
    re_search_t s;
    uint64_t imm_v = 0;
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
    have_code = bind_search_code(f.whole, ctx->arena, &pe, &code, &scan);
    kind = search_kind(re_str(pat_arg), &pat);
    re_search_init(&s);
    if (!run_search(ctx, f.whole, &kind, pat, &s, &imm_v)) {
        re_file_close(&f);
        return re_err_exit_code(ctx->err->code);
    }
    if (kind == RE_SEARCH_IMMEDIATE)
        page_imm_hits(&s, have_code ? &pe : NULL, have_code ? &code : NULL, ctx->offset, ctx->limit,
                      ctx->arena);
    emit_hits(ctx, f.whole, re_format_detect(f.whole), &pe, have_code ? &code : NULL,
              have_code ? &scan : NULL, &s, kind == RE_SEARCH_TEXT || kind == RE_SEARCH_SIGNATURE,
              kind == RE_SEARCH_IMMEDIATE, imm_v);
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
