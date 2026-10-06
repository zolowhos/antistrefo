// re_cmds5.c - the string search and the C++ class tables.
// Module: cli (C11).
// Owns: re_cmd_strings and re_cmd_vtables.
// Depends: re_prep, re_strings, re_regex, re_vtable. Loads through the shared
//           re_prepare rather than a private loader, so every command agrees on what a
//           file is and what an address in it means.
#include "features/data/re_strings.h"
#include "features/data/re_vtable.h"
#include "features/pe/re_pe.h"
#include "utils/algo/re_regex.h"
#include "utils/json/re_json.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_buf.h"
#include "utils/mem/re_vec.h"
#include "utils/text/re_str.h"
#include "utils/text/re_text.h"
#include "cli/app/re_table.h"
#include "cli/cmds/re_prep.h"

static void string_row(re_jw_t *w, const re_str_hit_t *h, const re_pe_t *pe) {
    re_jw_obj(w);
    re_jw_khex(w, "off", h->off, 8);
    uint32_t rva = 0;
    if (re_pe_off2rva(pe, h->off, &rva)) {
        re_jw_khex(w, "va", pe->image_base + rva, 16);
        re_jw_ku64(w, "rva", rva);
    }
    re_jw_kbool(w, "wide", h->wide);
    re_jw_kstr(w, "text", h->text);
    re_jw_obj_end(w);
}

// A filtered search has to see every string, not the first page of them. The shared
// loader caps its scan so that an unfiltered report of a 200 MB image does not build a
// list nobody asked for, and filtering that capped list reported "0 matches, not
// truncated" for strings that are in the file. A search therefore rescans at the limit.
static re_rx_t *compile_filter(re_ctx_t *ctx, re_span_t img, re_strings_t *full) {
    char *pat = re_arena_strndup(ctx->arena, ctx->regex.p, ctx->regex.n);
    re_rx_t *rx = re_rx_compile(ctx->arena, pat, "i", ctx->err);
    if (rx)
        re_strings_scan(img, 4, RE_STR_HITS_MAX, ctx->arena, full);
    return rx;
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

int re_cmd_strings(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    (void)argc;
    (void)argv;
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    // A string scan reads bytes. "no disassembler for x86" is not a string report.
    if (!re_prepare_loose(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_rx_t *rx = NULL;
    re_strings_t full, scanned;
    // Both are initialised: `scanned` feeds the unfiltered report, and an
    // uninitialised vec here meant a crash or an all zero report depending on what
    // the caller's stack happened to hold.
    re_strings_init(&full);
    re_strings_init(&scanned);
    re_strings_scan(f.whole, 4, 20000, ctx->arena, &scanned);
    if (ctx->has_regex) {
        rx = compile_filter(ctx, f.whole, &full);
        if (!rx) {
            re_file_close(&f);
            return re_err_exit_code(ctx->err->code);
        }
    }
    re_vec_t hits;
    re_vec_init(&hits, sizeof(re_str_hit_t));
    const re_strings_t *src = rx ? &full : &scanned;
    size_t matched = re_strings_filter(ctx->arena, src, rx, ctx->offset, ctx->limit, &hits);
    if (ctx->out == RE_FMT_OUT_TEXT) {
        strings_text(ctx, &pe, &hits);
        re_file_close(&f);
        return 0;
    }
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    re_envelope(&w, "strings", f.whole, &pe);
    re_jw_ku64(&w, "total", matched);
    re_jw_ku64(&w, "count", RE_VEC_LEN(&hits));
    // The page the caller asked for, or the scan itself stopping at its cap. Reporting
    // only the first made a capped scan look like a complete one.
    bool scan_capped = rx && RE_VEC_LEN(&full.hits) >= RE_STR_HITS_MAX;
    re_jw_kbool(&w, "truncated", matched > RE_VEC_LEN(&hits) || scan_capped);
    re_jw_key(&w, "strings");
    re_jw_arr(&w);
    for (size_t i = 0; i < RE_VEC_LEN(&hits); i++)
        string_row(&w, RE_VEC_PTR(&hits, re_str_hit_t, i), &pe);
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
