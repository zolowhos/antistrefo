// re_prep.c - the shared preamble of the code reading commands.
// Module: cli (C11).
// Owns: opening, parsing, and the JSON envelope. Nothing here knows a command.
// Depends: re_prep.h.
#include "cli/cmds/re_prep.h"

#include "features/analysis/re_alt.h"
#include "features/analysis/re_analyze.h"
#include "features/code/re_func.h"
#include "features/data/re_gopath.h"
#include "features/lib/re_sigfile.h"
#include "features/pe/re_format.h"
#include "features/pe/re_pe.h"
#include "utils/text/re_hex.h"
#include "utils/text/re_strbuf.h"

// Which registered backend an image's machine field asks for. Mapping lives in
// re_disasm_for_machine so analyze and the commands cannot drift apart.
static const char *backend_for(uint16_t machine) {
    return re_disasm_for_machine(machine);
}

// The shared body of the two preps. need_decoder is the line between them: a command
// that decodes instructions refuses to run without a backend for the image's machine,
// because decoding with the wrong one produced confident nonsense (SysV calling
// conventions on a stdcall binary). A command that only reads the parser's output and
// the raw bytes continues instead, because re_code_init binds the image, the machine
// and the base before it reports that it cannot decode, and that is everything address
// translation needs.
static bool prepare(re_ctx_t *ctx, const char *path, re_file_t *f, re_pe_t *pe, re_code_t *code,
                    bool need_decoder) {
    re_err_code_t e = re_file_open(path, ctx->arena, f);
    if (e != RE_OK) {
        RE_ERR_SETF(ctx->err, e, "cannot open %s", path);
        return false;
    }
    e = re_pe_parse(f->whole, ctx->arena, pe);
    if (e != RE_OK) {
        RE_ERR_SETF(ctx->err, e, "cannot parse %s", path);
        return false;
    }
    const char *want = backend_for(pe->machine);
    const re_disasm_t *d = want ? re_disasm_find(want) : NULL;
    if (!re_code_init(code, f->whole, pe, d, ctx->arena) && (need_decoder || d || !pe->valid)) {
        // The backend either does not exist for this machine or declined the image;
        // with no backend the context above is still bound, so only a decoder consumer
        // has to stop here.
        RE_ERR_SETF(ctx->err, RE_E_UNSUPPORTED, "no disassembler for %s in this build",
                    re_pe_machine_name(pe->machine));
        return false;
    }
    return true;
}

re_analysis_t *re_prep_analysis(re_ctx_t *ctx, const char *path, re_arena_t *own) {
    re_analysis_t *an;
    if (ctx->session && re_str_eq_cstr(ctx->session->path, path))
        return re_analysis_run_all(ctx->session) ? ctx->session : NULL;
    an = (re_analysis_t *)re_arena_alloc(own, sizeof(*an));
    if (!an || !re_analysis_open(an, own, path) || !re_analysis_run_all(an))
        return NULL;
    return an;
}

bool re_prepare(re_ctx_t *ctx, const char *path, re_file_t *f, re_pe_t *pe, re_code_t *code) {
    return prepare(ctx, path, f, pe, code, true);
}

bool re_prepare_loose(re_ctx_t *ctx, const char *path, re_file_t *f, re_pe_t *pe, re_code_t *code) {
    return prepare(ctx, path, f, pe, code, false);
}

void re_envelope(re_jw_t *w, const char *tool, re_span_t img, const re_pe_t *pe) {
    // `arch` is the image's own machine field, the same answer info and triage
    // give, so every report agrees on what it opened. The backend is the one that
    // can decode that machine in this build, or none: naming the compiled-in
    // x86-64 decoder on an x86 image is the same lie the prep split exists to stop.
    const char *want = backend_for(pe->machine);
    const char *backend = (want && re_disasm_find(want)) ? want : "none";
    re_jw_obj(w);
    re_jw_kcstr(w, "schema", RE_SCHEMA);
    re_jw_kcstr(w, "tool", tool);
    re_jw_kcstr(w, "format", re_format_name(re_format_detect(img)));
    re_jw_kcstr(w, "arch", re_pe_machine_name(pe->machine));
    re_jw_kcstr(w, "disasm_backend", backend);
    re_jw_ku64(w, "size", img.n);
    re_jw_ku64(w, "image_base", pe->image_base);
}

// The names the image states about itself, before any pattern is consulted. A Go binary
// lists every function it contains and what each is called, which is evidence a signature
// cannot produce, and the signature pass below leaves those functions alone. A file with
// no such table costs one search and no names.
static size_t name_from_image(re_ctx_t *ctx, re_code_t *code, re_fscan_t *scan) {
    re_vec_t syms;
    re_goinfo_t info;
    uint64_t lo = 0;
    uint64_t hi = 0;
    re_vec_init(&syms, sizeof(re_gosym_t));
    re_code_window(code, &lo, &hi);
    if (!re_gopath_scan(code->img, lo, hi, code->base + code->pe->entry_rva, ctx->arena, &syms,
                        &info))
        return 0;
    return re_symbols_apply(scan, &syms);
}

size_t re_prep_names(re_ctx_t *ctx, const char *path, const char *sigfile, re_code_t *code,
                     re_fscan_t *scan, re_flirt_load_stat_t *stat) {
    re_vec_t sigs;
    re_sigdb_t db;
    re_alt_t alt;
    size_t named = name_from_image(ctx, code, scan);
    if (stat) {
        stat->before = 0;
        stat->loaded = 0;
        stat->rejected = 0;
        stat->skipped = 0;
    }
    re_vec_init(&sigs, sizeof(re_sig_t));
    re_flirt_builtin(ctx->arena, &sigs);
    if (sigfile)
        re_sigfile_load(ctx->arena, sigfile, &sigs, stat);
    re_sigdb_build(ctx->arena, &sigs, &db);
    named += re_flirt_name_all(&db, code, scan);
    // User renames in "<path>.alt" win over image and signature names.
    re_alt_init(&alt, ctx->arena);
    if (path && re_alt_load(&alt, path))
        named += re_alt_apply(scan, &alt);
    return named;
}

bool re_parse_addr(re_ctx_t *ctx, re_str_t s, const re_pe_t *pe, uint64_t *out) {
    uint64_t acc = 0;
    uint64_t mul = 10;
    size_t i = 0;
    if (s.n > 2 && s.p[0] == '0' && (s.p[1] == 'x' || s.p[1] == 'X')) {
        mul = 16;
        i = 2;
    }
    if (i >= s.n) {
        RE_ERR_SET(ctx->err, RE_E_USAGE, "expected an address");
        return false;
    }
    for (; i < s.n; i++) {
        int d = re_hex_val(s.p[i]);
        if (d < 0 || (uint64_t)d >= mul) {
            RE_ERR_SETF(ctx->err, RE_E_USAGE, "cannot read an address from %s", s.p);
            return false;
        }
        acc = acc * mul + (uint64_t)d;
    }
    // Image-base window => VA; otherwise treat the value as an RVA.
    bool in_image = acc >= pe->image_base && (acc - pe->image_base) < pe->size_of_image;
    *out = in_image ? acc : pe->image_base + acc;
    return true;
}

bool re_str_looks_like_addr(re_str_t s) {
    size_t i = 0;
    if (s.n == 0)
        return false;
    if (s.n > 2 && s.p[0] == '0' && (s.p[1] == 'x' || s.p[1] == 'X'))
        i = 2;
    if (i >= s.n)
        return false;
    for (; i < s.n; i++) {
        if (re_hex_val(s.p[i]) < 0)
            return false;
    }
    return true;
}

void re_emit_func_bounds(re_jw_t *w, const re_func_t *f) {
    re_jw_khex(w, "func_va", f->va, 16);
    re_jw_ku64(w, "func_rva", f->rva);
    re_jw_ku64(w, "func_size", f->size);
    re_jw_khex(w, "func_end", f->va + f->size, 16);
    if (f->flags & RE_FUNC_UNWIND)
        re_jw_kbool(w, "unwind", true);
}

bool re_snap_insn_va(re_code_t *code, uint64_t fn_va, uint64_t at, uint64_t *insn_va) {
    uint64_t va = fn_va;
    if (!insn_va || at < fn_va)
        return false;
    *insn_va = at;
    while (va <= at) {
        re_insn_t in;
        if (!re_code_insn(code, va, &in) || in.size == 0)
            return false;
        if (at < va + in.size) {
            *insn_va = va;
            return true;
        }
        va += in.size;
        if (va - fn_va > 65536u)
            return false;
    }
    return false;
}

bool re_render_insn_at(re_ctx_t *ctx, re_code_t *code, uint64_t va, re_str_t *text, uint32_t *len) {
    re_insn_t in;
    re_strbuf_t line;
    if (!code || !code->dis || !re_code_insn(code, va, &in))
        return false;
    re_strbuf_init(&line, ctx->arena);
    code->dis->render(code->dis->ctx, &in, ctx->arena, &line);
    if (text)
        *text = re_str(line.p ? line.p : "");
    if (len)
        *len = in.size;
    return true;
}

bool re_pick_func_at(re_ctx_t *ctx, const re_fscan_t *scan, const re_pe_t *pe, const char *pos,
                     uint64_t *at_out, const re_func_t **out) {
    uint64_t at = 0;
    long fi;
    re_pe_unwind_t u;
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
    if (at_out)
        *at_out = at;
    if (at >= pe->image_base && (at - pe->image_base) < pe->size_of_image &&
        re_pe_unwind_covering(pe, (uint32_t)(at - pe->image_base), &u)) {
        uint64_t begin = pe->image_base + u.begin;
        fi = re_func_index_of(scan, begin);
        if (fi >= 0) {
            const re_func_t *f = re_func_at(scan, (size_t)fi);
            if (f && f->va == begin) {
                *out = f;
                return true;
            }
        }
    }
    fi = re_func_index_of(scan, at);
    if (fi < 0) {
        RE_ERR_SETF(ctx->err, RE_E_USAGE, "no function at 0x%llx", (unsigned long long)at);
        return false;
    }
    *out = re_func_at(scan, (size_t)fi);
    return true;
}
