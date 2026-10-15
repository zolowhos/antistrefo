// re_cmds.c - the command implementations behind the table. All read only.
// Module: cli (C11).
// Owns: per command JSON or text output, file loading, and the shared preamble.
// Depends: re_cmds.h, re_pe, re_format, re_strings, re_triage, re_json, re_text.
#include "cli/cmds/re_cmds.h"

#include <stdio.h>

#include "features/data/re_strings.h"
#include "features/data/re_triage.h"
#include "features/meta/re_features.h"
#include "features/pe/re_format.h"
#include "features/pe/re_pe.h"
#include "utils/algo/re_hash.h"
#include "utils/json/re_json.h"
#include "utils/mem/re_buf.h"
#include "utils/text/re_fmt.h"
#include "utils/text/re_hex.h"
#include "utils/text/re_text.h"
#include "utils/text/re_util.h"
#include "cli/render/re_render.h"
#include "cli/render/re_report.h"

#define SCHEMA "antistrefo/1"

typedef struct {
    re_file_t file;
    re_span_t img;
    re_format_t fmt;
    re_pe_t pe;
    bool has_pe;
    re_strings_t strs;
} re_loaded_t;

// Returns a code, and records the human message in ctx->err. The split keeps the
// caller from having to copy a 200 byte record just to test success.
static re_err_code_t load(re_loaded_t *l, re_ctx_t *ctx, const char *path, bool need_pe,
                          bool need_str) {
    memset(l, 0, sizeof(*l));
    re_strings_init(&l->strs);
    re_err_code_t e = re_file_open(path, ctx->arena, &l->file);
    if (e != RE_OK) {
        RE_ERR_SETF(ctx->err, e, "cannot open %s", path);
        return e;
    }
    l->img = l->file.whole;
    l->fmt = re_format_detect(l->img);
    // A file offset does not need a parsed image. RVA still does, so only a
    // caller that requires a PE refuses an unrecognized file here.
    if (l->fmt == RE_FMT_UNKNOWN) {
        if (!need_pe)
            return RE_OK;
        RE_ERR_SETF(ctx->err, RE_E_NOTBIN, "%s is not a recognized binary", path);
        return RE_E_NOTBIN;
    }
    if (l->fmt != RE_FMT_PE) {
        if (!need_pe)
            return RE_OK;
        RE_ERR_SETF(ctx->err, RE_E_UNSUPPORTED, "%s is %s, only pe is parsed in this build", path,
                    re_format_name(l->fmt));
        return RE_E_UNSUPPORTED;
    }
    e = re_pe_parse(l->img, ctx->arena, &l->pe);
    if (e != RE_OK)
        return e;
    l->has_pe = true;
    if (need_str) {
        re_strings_scan(l->img, 4, 20000, ctx->arena, &l->strs);
        re_strings_devices(l->img, 1024, ctx->arena, &l->strs);
        re_strings_pdb(l->img, ctx->arena, &l->strs);
    }
    return RE_OK;
}

static void unload(re_loaded_t *l) {
    re_file_close(&l->file);
}

static void preamble(re_jw_t *w, const char *tool, re_loaded_t *l) {
    re_jw_obj(w);
    re_jw_kcstr(w, "schema", SCHEMA);
    re_jw_kcstr(w, "tool", tool);
    re_jw_kcstr(w, "format", re_format_name(l->fmt));
    re_jw_ku64(w, "size", l->img.n);
}

static void finish(re_ctx_t *ctx, re_jw_t *w, re_loaded_t *l) {
    (void)ctx;
    (void)l;
    re_jw_obj_end(w);
    re_jw_flush(w, re_ctx_out(ctx));
}

int re_cmd_info(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    (void)argc;
    (void)argv;
    if (re_report_wanted(ctx))
        return re_render_info(ctx, path);
    re_loaded_t l;
    re_err_code_t e = load(&l, ctx, path, true, false);
    if (e != RE_OK) {
        unload(&l);
        return re_err_exit_code(e);
    }
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    preamble(&w, "info", &l);
    re_jw_kcstr(&w, "arch", re_pe_machine_name(l.pe.machine));
    re_jw_kcstr(&w, "arch_hint", re_format_arch_hint(l.img, l.fmt));
    re_jw_kbool(&w, "pe32plus", l.pe.pe32plus);
    re_jw_kbool(&w, "is_dll", l.pe.is_dll);
    re_jw_kcstr(&w, "subsystem", re_pe_subsystem_name(l.pe.subsystem));
    re_jw_khex(&w, "image_base", l.pe.image_base, l.pe.pe32plus ? 16 : 8);
    re_jw_khex(&w, "entry_rva", l.pe.entry_rva, 8);
    re_jw_khex(&w, "entry_va", l.pe.image_base + l.pe.entry_rva, l.pe.pe32plus ? 16 : 8);
    re_jw_khex(&w, "timestamp", l.pe.timestamp, 8);
    re_jw_ku64(&w, "section_count", l.pe.n_sec);
    re_jw_ku64(&w, "import_modules", RE_VEC_LEN(&l.pe.imports));
    re_jw_ku64(&w, "import_symbols", RE_VEC_LEN(&l.pe.syms));
    re_jw_ku64(&w, "export_count", RE_VEC_LEN(&l.pe.exports));
    re_jw_key(&w, "features");
    re_jw_arr(&w);
    for (size_t i = 0; i < re_features_count(); i++) {
        const char *f = re_features_name(i);
        if (f)
            re_jw_cstr(&w, f);
    }
    re_jw_arr_end(&w);
    finish(ctx, &w, &l);
    unload(&l);
    return 0;
}

int re_cmd_triage(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    (void)argc;
    (void)argv;
    re_loaded_t l;
    re_err_code_t e = load(&l, ctx, path, true, true);
    if (e != RE_OK) {
        unload(&l);
        return re_err_exit_code(e);
    }
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    preamble(&w, "triage", &l);
    re_jw_key(&w, "triage");
    re_jw_obj(&w);
    re_triage_emit(&w, l.img, &l.pe, &l.strs, ctx->arena);
    re_jw_obj_end(&w);
    finish(ctx, &w, &l);
    unload(&l);
    return 0;
}

// Build one section row into caller supplied scratch, so the measure pass and the
// print pass share exactly the same cells and the columns line up.
static size_t section_cells(const re_pe_section_t *s, re_strbuf_t *flags, char va[16], char vs[24],
                            char rs[24], char en[16], const char *row[6]) {
    snprintf(va, 16, "0x%08x", s->vaddr);
    snprintf(vs, 24, "%llu", (unsigned long long)s->vsize);
    snprintf(rs, 24, "%llu", (unsigned long long)s->rsize);
    snprintf(en, 16, "%.3f", s->entropy);
    re_pe_section_flags(s->chars, flags);
    row[0] = s->name;
    row[1] = va;
    row[2] = vs;
    row[3] = rs;
    row[4] = en;
    row[5] = flags->p ? flags->p : "";
    return 6;
}

// The --format text path for sections. Split out so the command body stays under
// the function cap, and so the measure pass and the print pass share one helper.
static int sections_text(re_loaded_t *l, re_ctx_t *ctx) {
    re_strbuf_t sb;
    re_strbuf_init(&sb, ctx->arena);
    // The flags go in their own buffer. Writing them into the accumulator would
    // leave row[] pointing into memory the row writer appends to, and the arena
    // reallocating under it, which is a dangling read and a hang.
    re_strbuf_t flags;
    re_strbuf_init(&flags, ctx->arena);
    char va[16];
    char vs[24];
    char rs[24];
    char en[16];
    const char *row[6];
    re_text_t t;
    re_text_init(&t, &sb);
    for (uint16_t i = 0; i < l->pe.n_sec; i++) {
        size_t n = section_cells(&l->pe.sec[i], &flags, va, vs, rs, en, row);
        re_text_measure(&t, row, n);
    }
    const char *hdr[6] = {"name", "vaddr", "vsize", "raw", "entropy", "flags"};
    re_text_header(&t, hdr, 6);
    for (uint16_t i = 0; i < l->pe.n_sec; i++) {
        size_t n = section_cells(&l->pe.sec[i], &flags, va, vs, rs, en, row);
        re_text_row(&t, row, n);
    }
    fputs(sb.p ? sb.p : "", stdout);
    return 0;
}

int re_cmd_sections(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    if (re_report_wanted(ctx))
        return re_render_sections(ctx, path);
    (void)argc;
    (void)argv;
    re_loaded_t l;
    re_err_code_t e = load(&l, ctx, path, true, false);
    if (e != RE_OK) {
        unload(&l);
        return re_err_exit_code(e);
    }
    re_strbuf_t sb;
    re_strbuf_init(&sb, ctx->arena);
    if (ctx->out == RE_FMT_OUT_TEXT) {
        sections_text(&l, ctx);
        unload(&l);
        return 0;
    }
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    preamble(&w, "sections", &l);
    re_jw_ku64(&w, "count", l.pe.n_sec);
    re_jw_key(&w, "sections");
    re_jw_arr(&w);
    for (uint16_t i = 0; i < l.pe.n_sec; i++) {
        const re_pe_section_t *s = &l.pe.sec[i];
        re_jw_obj(&w);
        re_jw_kcstr(&w, "name", s->name);
        re_jw_khex(&w, "vaddr", s->vaddr, 8);
        re_jw_ku64(&w, "vsize", s->vsize);
        re_jw_ku64(&w, "raw_size", s->rsize);
        re_jw_khex(&w, "raw_ptr", s->rptr, 8);
        re_jw_kf64(&w, "entropy", s->entropy);
        re_jw_kbool(&w, "packed", s->entropy > 7.0);
        re_jw_obj_end(&w);
    }
    re_jw_arr_end(&w);
    finish(ctx, &w, &l);
    unload(&l);
    return 0;
}

int re_cmd_imports(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    if (re_report_wanted(ctx))
        return re_render_imports(ctx, path);
    (void)argc;
    (void)argv;
    re_loaded_t l;
    re_err_code_t e = load(&l, ctx, path, true, false);
    if (e != RE_OK) {
        unload(&l);
        return re_err_exit_code(e);
    }
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    preamble(&w, "imports", &l);
    re_jw_ku64(&w, "module_count", RE_VEC_LEN(&l.pe.imports));
    re_jw_ku64(&w, "symbol_count", RE_VEC_LEN(&l.pe.syms));
    re_jw_key(&w, "modules");
    re_jw_arr(&w);
    size_t seen = 0;
    for (size_t i = 0; i < RE_VEC_LEN(&l.pe.imports); i++) {
        const re_pe_imp_t *im = RE_VEC_PTR(&l.pe.imports, re_pe_imp_t, i);
        re_jw_obj(&w);
        re_jw_kstr(&w, "module", im->dll);
        re_jw_key(&w, "symbols");
        re_jw_arr(&w);
        for (uint32_t k = 0; k < im->n_syms; k++) {
            if (ctx->offset && seen++ < ctx->offset)
                continue;
            if (ctx->limit && seen - ctx->offset >= ctx->limit)
                break;
            const re_str_t *s = RE_VEC_PTR(&l.pe.syms, re_str_t, im->first_sym + k);
            re_jw_str(&w, *s);
        }
        re_jw_arr_end(&w);
        re_jw_obj_end(&w);
    }
    re_jw_arr_end(&w);
    finish(ctx, &w, &l);
    unload(&l);
    return 0;
}

int re_cmd_exports(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    if (re_report_wanted(ctx))
        return re_render_exports(ctx, path);
    (void)argc, (void)argv;
    re_loaded_t l;
    re_err_code_t e = load(&l, ctx, path, true, false);
    if (e != RE_OK) {
        unload(&l);
        return re_err_exit_code(e);
    }
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    preamble(&w, "exports", &l);
    re_jw_ku64(&w, "count", RE_VEC_LEN(&l.pe.exports));
    re_jw_key(&w, "exports");
    re_jw_arr(&w);
    size_t seen = 0;
    for (size_t i = 0; i < RE_VEC_LEN(&l.pe.exports); i++) {
        const re_pe_exp_t *x = RE_VEC_PTR(&l.pe.exports, re_pe_exp_t, i);
        if (ctx->offset && seen++ < ctx->offset)
            continue;
        if (ctx->limit && seen - ctx->offset >= ctx->limit)
            break;
        re_jw_obj(&w);
        re_jw_kstr(&w, "name", x->name);
        re_jw_ku64(&w, "ordinal", x->ordinal);
        re_jw_ku64(&w, "rva", x->rva);
        // Whether an export is callable. Two exports in a real binary are not
        // functions at all: AmdPowerXpressRequestHighPerformance and
        // NvOptimusEnablement are dwords a GPU driver reads out of the image, and
        // listing them beside real code with nothing to say so invites treating them
        // as addresses to call.
        const re_pe_section_t *sec = re_pe_section_at_rva(&l.pe, x->rva);
        re_str_t fwd = re_pe_export_forwarder(&l.pe, x->rva);
        const char *kind = fwd.n ? "forwarder" : re_pe_region_kind(sec);
        re_jw_kcstr(&w, "kind", kind);
        re_jw_kcstr(&w, "section", sec ? sec->name : "");
        // When set, the real code is in another module and this is its address
        // there. Without it a forwarder is indistinguishable from a function.
        if (fwd.n)
            re_jw_kstr(&w, "forwarder", fwd);
        re_jw_obj_end(&w);
    }
    re_jw_arr_end(&w);
    finish(ctx, &w, &l);
    unload(&l);
    return 0;
}

// One string, with its RVA and virtual address as well as its file offset, so it can
// be handed straight to xrefs or disasm. An offset alone is not an address the rest
// of the tool accepts, and converting it by hand is where the chain breaks. Strings
// outside any section, such as the ones in the DOS stub, have no RVA and are reported
// without one rather than with a fabricated zero.
// Why an rva has no bytes on disk. The two cases look identical from the outside and
// mean opposite things: an rva outside every section is a mistake, while an rva inside
// a section that declares no raw data is a packed image, where the code is written at
// run time rather than stored. Reporting the first for the second would tell a reader
// their address was wrong when the file is the thing that is unusual.
static void rva_diagnostic(re_err_t *err, const re_pe_t *pe, uint32_t rva) {
    for (uint16_t i = 0; i < pe->n_sec; i++) {
        const re_pe_section_t *s = &pe->sec[i];
        if (rva < s->vaddr || rva - s->vaddr >= s->vsize)
            continue;
        if (s->rsize == 0) {
            RE_ERR_SETF(err, RE_E_UNSUPPORTED,
                        "rva 0x%llx is in section '%s', which declares no raw data on "
                        "disk; this image is packed and its code exists only in memory",
                        (unsigned long long)rva, s->name);
        } else {
            RE_ERR_SETF(err, RE_E_USAGE,
                        "rva 0x%llx is in the virtual tail of section '%s', past the "
                        "bytes stored in the file",
                        (unsigned long long)rva, s->name);
        }
        return;
    }
    RE_ERR_SETF(err, RE_E_USAGE, "rva 0x%llx is not in any section", (unsigned long long)rva);
}

// --off is a file offset and --rva is a relative virtual address, and they are not
// interchangeable: an RVA handed to --off silently returns whatever is at that byte
// in the file, which for a small RVA is the MZ header. Rather than guess, the two are
// told apart here and an unrecognised one is an error, because a hexdump of the wrong
// bytes is worse than no hexdump at all. Returns false with the diagnostic set.
static bool hexdump_start(re_ctx_t *ctx, int argc, char **argv, const re_pe_t *pe) {
    bool by_rva = false;
    bool named = false;
    for (int i = 0; i < argc; i++) {
        if (re_str_starts_cstr(re_str(argv[i]), "--rva")) {
            by_rva = true;
            named = true;
        } else if (re_str_starts_cstr(re_str(argv[i]), "--off")) {
            named = true;
        }
    }
    if (!named) {
        RE_ERR_SET(ctx->err, RE_E_USAGE,
                   "hexdump needs --off <file offset> or --rva <relative address>, "
                   "and they are not the same number");
        return false;
    }
    if (!by_rva)
        return true;
    uint64_t off = 0;
    uint32_t rva = (uint32_t)ctx->off;
    if (!re_pe_rva2off(pe, rva, &off)) {
        rva_diagnostic(ctx->err, pe, rva);
        return false;
    }
    ctx->off = off;
    return true;
}

int re_cmd_hexdump(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_loaded_t l;
    re_err_code_t e = load(&l, ctx, path, false, false);
    if (e != RE_OK) {
        unload(&l);
        return re_err_exit_code(e);
    }
    if (!hexdump_start(ctx, argc, argv, &l.pe)) {
        unload(&l);
        return re_err_exit_code(ctx->err->code);
    }
    re_span_t view = re_span_sub(l.img, ctx->off, ctx->len);
    if (!re_span_valid(view))
        view = re_span_sub(l.img, ctx->off, l.img.n - ctx->off);
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    preamble(&w, "hexdump", &l);
    re_jw_khex(&w, "off", ctx->off, 8);
    re_jw_ku64(&w, "len", view.n);
    re_jw_key(&w, "bytes");
    re_jw_arr(&w);
    for (size_t i = 0; i < view.n; i += 16) {
        re_strbuf_t line;
        re_strbuf_init(&line, ctx->arena);
        re_strbuf_put_hex(&line, view.p + i, view.n - i > 16 ? 16 : view.n - i);
        re_jw_str(&w, re_strn(line.p, line.len));
    }
    re_jw_arr_end(&w);
    finish(ctx, &w, &l);
    unload(&l);
    return 0;
}

// Where a command's response goes. NULL in the context means stdout, which is every
// caller except the MCP server. The indirection exists so the server can capture a
// response instead of printing it, without every command learning about protocols.
void *re_ctx_out(const re_ctx_t *ctx) {
    return ctx->stream ? ctx->stream : stdout;
}
