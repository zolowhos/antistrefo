// re_gui_model.c - the list and the listing, built from the analysis.
// Module: cli (C11).
// Owns: re_gui_model.h's fill functions.
// Depends: re_gui_model.h, re_code, re_strbuf, re_arena, re_disasm. No screen, no
//           terminal, no input.
#include "cli/screen/re_gui_model.h"

#include "features/code/re_code.h"
#include "features/code/re_stack.h"
#include "features/db/re_db.h"
#include "features/dec/re_decompile.h"
#include "utils/mem/re_buf.h"
#include "utils/text/re_hex.h"
#include "utils/text/re_strbuf.h"

#include <string.h>

void re_gui_pseudo_fill(re_gui_pseudo_t *ps, re_arena_t *a, re_analysis_t *an, size_t sel) {
    if (!ps->started) {
        re_strbuf_init(&ps->buf, a);
        ps->started = true;
        ps->built_for = (size_t)-1;
    }
    if (ps->built_for == sel)
        return;
    ps->built_for = sel;
    re_strbuf_clear(&ps->buf);
    ps->n = 0;
    if (sel >= RE_VEC_LEN(&an->scan.funcs))
        return;
    const re_func_t *f = RE_VEC_PTR(&an->scan.funcs, re_func_t, sel);
    re_str_t pre;
    bool pre_ok = false;
    // The deep tier already decompiled every function into the database, so the pane
    // reads that text instead of decompiling again. A function without one falls
    // through to the live decompiler, which is what the entry tier always does.
    if (an->db && re_db_decomp(an->db, sel, &pre, &pre_ok) && pre_ok && pre.n) {
        re_strbuf_append(&ps->buf, pre.p, pre.n);
        re_strbuf_putc(&ps->buf, 0);
        ps->n = re_pseudo_split(ps->buf.p, ps->line, ps->mark, RE_PSEUDO_MAX);
        return;
    }
    re_decomp_t d;
    re_stack_t st;
    memset(&d, 0, sizeof(d));
    d.jtables = &an->jtables;
    d.scan = &an->scan;
    d.code = &an->code;
    d.xrefs = &an->xs;
    d.arena = a;
    re_stack_analyze(d.code, f, a, &st);
    ps->ok = re_decompile_ok(&d, f);
    if (ps->ok)
        re_decompile_func(&d, f, &st, &ps->buf);
    re_strbuf_putc(&ps->buf, 0);
    ps->n = re_pseudo_split(ps->buf.p, ps->line, ps->mark, RE_PSEUDO_MAX);
    if (!ps->n) {
        ps->line[0] = "/\x2f this body did not lower: no instruction was recovered from it";
        ps->mark[0] = 1;
        ps->n = 1;
    }
}

void re_gui_funcs_fill(re_gui_funcs_t *l, re_arena_t *a, const re_analysis_t *an) {
    l->n = 0;
    size_t total = RE_VEC_LEN(&an->scan.funcs);
    for (size_t i = 0; i < total && l->n < RE_GUI_LIST_MAX; i++) {
        const re_func_t *f = RE_VEC_PTR(&an->scan.funcs, re_func_t, i);
        re_strbuf_t sb;
        re_strbuf_init(&sb, a);
        re_strbuf_put_hex64(&sb, f->va, 16);
        re_strbuf_putc(&sb, 0);
        size_t n = sb.len < 19u ? sb.len : 19u;
        for (size_t k = 0; k < n; k++)
            l->addr[l->n][k] = sb.p[k];
        l->addr[l->n][n] = '\0';
        re_strbuf_t fb;
        re_strbuf_init(&fb, a);
        re_strbuf_puts(&fb, "sub_");
        re_strbuf_put_hex64(&fb, f->va, 16);
        re_strbuf_putc(&fb, 0);
        const char *nm = (f->name.p && f->name.n) ? f->name.p : fb.p;
        l->name[l->n] = re_arena_strdup(a, nm);
        l->n++;
    }
    re_gui_funcs_fit(l, RE_GUI_LIST_ROWS);
}

void re_gui_funcs_fit(re_gui_funcs_t *l, size_t rows) {
    if (rows > RE_GUI_LIST_ROWS)
        rows = RE_GUI_LIST_ROWS;
    if (rows > l->n)
        rows = l->n;
    l->vis = rows;
}

// Where the window starts. It follows the selection down to the middle of the pane and
// then stops at the last window that still holds it, so the last function lands on the
// last row instead of the list scrolling past its end. A pane the whole list fits in
// never moves at all.
static size_t window_base(size_t sel, const re_gui_funcs_t *l) {
    if (!l->vis || l->vis >= l->n)
        return 0;
    size_t half = l->vis > 2u ? l->vis / 2u : 0u;
    size_t base = sel > half ? sel - half : 0u;
    size_t last = l->n - l->vis;
    return base > last ? last : base;
}

size_t re_gui_funcs_row(size_t sel, const re_gui_funcs_t *l) {
    size_t base = window_base(sel, l);
    return sel > base ? sel - base : 0u;
}

size_t re_gui_funcs_index(size_t sel, const re_gui_funcs_t *l, size_t row) {
    size_t idx = window_base(sel, l) + row;
    if (l->n && idx >= l->n)
        return l->n - 1u;
    return idx;
}

void re_gui_funcs_window(size_t sel, const re_gui_funcs_t *l, const char **rows, size_t cap) {
    // A list with no rows to show still has one row to draw, and it is the row that says
    // so, so a caller is never handed an array with a hole in its first slot.
    size_t n = l->vis ? l->vis : 1u;
    for (size_t i = 0; i < n && i < cap; i++) {
        size_t idx = re_gui_funcs_index(sel, l, i);
        rows[i] = l->n ? l->name[idx] : "(no functions)";
    }
}

void re_gui_listing_fill(re_gui_listing_t *ls, re_arena_t *a, const re_analysis_t *an, size_t sel) {
    ls->n = 0;
    ls->base = 0;
    for (size_t i = 0; i < RE_GUI_CODE_MAX; i++)
        re_strbuf_init(&ls->line[i], a);
    if (sel >= RE_VEC_LEN(&an->scan.funcs))
        return;
    const re_func_t *f = RE_VEC_PTR(&an->scan.funcs, re_func_t, sel);
    ls->base = (uint32_t)f->va;
    if (!an->code.dis)
        return;
    uint64_t end = f->va + (f->size ? f->size : 1u);
    for (uint64_t va = f->va; va < end && ls->n < RE_GUI_CODE_MAX;) {
        re_insn_t in;
        if (!re_code_insn(&an->code, va, &in))
            break;
        re_strbuf_clear(&ls->line[ls->n]);
        an->code.dis->render(an->code.dis->ctx, &in, a, &ls->line[ls->n]);
        // A call or a branch is where the flow goes, and it is the one thing worth
        // noticing in a listing a reader has not read yet.
        ls->mark[ls->n] = (uint8_t)(in.is_call || in.is_branch);
        ls->text[ls->n] = ls->line[ls->n].p ? ls->line[ls->n].p : "";
        ls->n++;
        if (!in.size)
            break; // a zero length instruction would loop for ever
        va += in.size;
    }
    ls->total = ls->n;
}

static size_t row_cap(size_t rows) {
    if (!rows || rows > RE_GUI_CODE_MAX)
        return RE_GUI_CODE_MAX;
    return rows;
}

static void listing_open(re_gui_listing_t *ls, re_arena_t *a) {
    if (ls->line[0].arena != a) {
        for (size_t i = 0; i < RE_GUI_CODE_MAX; i++)
            re_strbuf_init(&ls->line[i], a);
    }
    ls->n = 0;
    ls->base = 0;
    ls->total = 0;
}

static re_strbuf_t *listing_slot(re_gui_listing_t *ls) {
    if (ls->n >= RE_GUI_CODE_MAX)
        return NULL;
    re_strbuf_clear(&ls->line[ls->n]);
    return &ls->line[ls->n];
}

static void listing_commit(re_gui_listing_t *ls) {
    ls->text[ls->n] = ls->line[ls->n].p ? ls->line[ls->n].p : "";
    ls->mark[ls->n] = 0;
    ls->n++;
}

static void listing_note(re_gui_listing_t *ls, const char *s) {
    re_strbuf_t *b = listing_slot(ls);
    if (!b)
        return;
    re_strbuf_puts(b, s);
    listing_commit(ls);
}

static bool read_at(const re_pe_t *pe, uint32_t rva, uint8_t *v) {
    uint64_t off = 0;
    if (!pe || !re_pe_rva2off(pe, rva, &off))
        return false;
    return re_rd8(pe->img, off, v);
}

static void put_hex_row(re_strbuf_t *b, const re_pe_t *pe, uint64_t va, uint32_t rva, uint32_t n) {
    uint8_t raw[16];
    re_strbuf_put_hex64(b, va, 16);
    re_strbuf_puts(b, "  ");
    for (uint32_t i = 0; i < 16u; i++) {
        uint8_t v = 0;
        bool ok = i < n && read_at(pe, rva + i, &v);
        raw[i] = ok ? v : 0;
        if (i)
            re_strbuf_putc(b, ' ');
        if (ok) {
            re_strbuf_putc(b, re_hex_nibble((uint8_t)(v >> 4)));
            re_strbuf_putc(b, re_hex_nibble(v));
        } else {
            re_strbuf_puts(b, "  ");
        }
    }
    re_strbuf_puts(b, "  ");
    for (uint32_t i = 0; i < n && i < 16u; i++) {
        uint8_t v = raw[i];
        re_strbuf_putc(b, (v >= 0x20 && v < 0x7f) ? (char)v : '.');
    }
}

void re_gui_hex_fill(re_gui_listing_t *ls, re_arena_t *a, const re_pe_t *pe, uint32_t rva,
                     uint32_t size, size_t row0, size_t rows) {
    size_t cap = row_cap(rows);
    listing_open(ls, a);
    if (!pe || !size) {
        ls->total = 1;
        if (!row0)
            listing_note(ls, "no bytes");
        return;
    }
    ls->total = ((size_t)size + 15u) / 16u;
    for (size_t row = row0; row < ls->total && ls->n < cap; row++) {
        uint32_t at = rva + (uint32_t)(row * 16u);
        uint32_t n = size - (uint32_t)(row * 16u);
        re_strbuf_t *b = listing_slot(ls);
        if (!b)
            return;
        if (n > 16u)
            n = 16u;
        put_hex_row(b, pe, pe->image_base + at, at, n);
        listing_commit(ls);
    }
}

static size_t import_total(const re_pe_t *pe) {
    size_t n = 0;
    if (!pe)
        return 0;
    for (size_t m = 0; m < RE_VEC_LEN(&pe->imports); m++)
        n += RE_VEC_PTR(&pe->imports, re_pe_imp_t, m)->n_syms;
    return n;
}

void re_gui_imports_fill(re_gui_listing_t *ls, re_arena_t *a, const re_pe_t *pe, size_t row0,
                         size_t rows) {
    size_t cap = row_cap(rows);
    size_t seen = 0;
    listing_open(ls, a);
    ls->total = import_total(pe);
    if (!ls->total) {
        ls->total = 1;
        if (!row0)
            listing_note(ls, "no imports");
        return;
    }
    for (size_t m = 0; m < RE_VEC_LEN(&pe->imports) && ls->n < cap; m++) {
        const re_pe_imp_t *im = RE_VEC_PTR(&pe->imports, re_pe_imp_t, m);
        for (uint32_t s = 0; s < im->n_syms && ls->n < cap; s++) {
            re_str_t nm = {NULL, 0};
            re_strbuf_t *b;
            if (seen++ < row0)
                continue;
            b = listing_slot(ls);
            if (!b)
                return;
            if (im->dll.n)
                re_strbuf_put_re_str(b, im->dll);
            re_strbuf_putc(b, '!');
            if (im->first_sym + s < RE_VEC_LEN(&pe->syms))
                nm = *RE_VEC_PTR(&pe->syms, re_str_t, im->first_sym + s);
            if (nm.n)
                re_strbuf_put_re_str(b, nm);
            listing_commit(ls);
        }
    }
}

void re_gui_exports_fill(re_gui_listing_t *ls, re_arena_t *a, const re_pe_t *pe, size_t row0,
                         size_t rows) {
    size_t cap = row_cap(rows);
    size_t total = pe ? RE_VEC_LEN(&pe->exports) : 0;
    listing_open(ls, a);
    if (!total) {
        ls->total = 1;
        if (!row0)
            listing_note(ls, "no exports");
        return;
    }
    ls->total = total;
    for (size_t i = row0; i < total && ls->n < cap; i++) {
        const re_pe_exp_t *x = RE_VEC_PTR(&pe->exports, re_pe_exp_t, i);
        re_str_t fwd = re_pe_export_forwarder(pe, x->rva);
        re_strbuf_t *b = listing_slot(ls);
        if (!b)
            return;
        re_strbuf_put_hex64(b, x->rva, 8);
        re_strbuf_putc(b, ' ');
        if (x->name.n)
            re_strbuf_put_re_str(b, x->name);
        re_strbuf_putc(b, ' ');
        if (fwd.n) {
            re_strbuf_puts(b, "forwarder ");
            re_strbuf_put_re_str(b, fwd);
        } else {
            re_strbuf_puts(b, re_pe_region_kind(re_pe_section_at_rva(pe, x->rva)));
        }
        listing_commit(ls);
    }
}

static size_t struct_total(const re_vset_t *vs) {
    size_t n = 0;
    if (!vs)
        return 0;
    for (size_t i = 0; i < RE_VEC_LEN(&vs->vtables); i++)
        n += 1u + RE_VEC_PTR(&vs->vtables, re_vtable_t, i)->n_bases;
    return n;
}

static void put_class(re_strbuf_t *b, const re_vtable_t *v) {
    if (v->name.n)
        re_strbuf_put_re_str(b, v->name);
    else
        re_strbuf_puts(b, "(unnamed)");
    re_strbuf_putc(b, ' ');
    re_strbuf_put_hex64(b, v->rva, 8);
    re_strbuf_putc(b, ' ');
    re_strbuf_put_u64(b, v->n_entries);
}

void re_gui_structs_fill(re_gui_listing_t *ls, re_arena_t *a, const re_vset_t *vs, size_t row0,
                         size_t rows) {
    size_t cap = row_cap(rows);
    size_t seen = 0;
    listing_open(ls, a);
    ls->total = struct_total(vs);
    if (!ls->total) {
        ls->total = 1;
        if (!row0)
            listing_note(ls, "no class tables");
        return;
    }
    for (size_t i = 0; i < RE_VEC_LEN(&vs->vtables) && ls->n < cap; i++) {
        const re_vtable_t *v = RE_VEC_PTR(&vs->vtables, re_vtable_t, i);
        if (seen >= row0) {
            re_strbuf_t *b = listing_slot(ls);
            if (!b)
                return;
            put_class(b, v);
            listing_commit(ls);
        }
        seen++;
        for (uint32_t k = 0; k < v->n_bases && ls->n < cap; k++) {
            re_strbuf_t *b;
            if (seen++ < row0)
                continue;
            b = listing_slot(ls);
            if (!b)
                return;
            int32_t off = v->bases[k].this_off;
            re_strbuf_puts(b, "  ");
            if (v->bases[k].name.n)
                re_strbuf_put_re_str(b, v->bases[k].name);
            re_strbuf_puts(b, " +");
            if (off < 0) {
                re_strbuf_putc(b, '-');
                re_strbuf_put_u64(b, (uint64_t)(-(int64_t)off));
            } else {
                re_strbuf_put_u64(b, (uint64_t)off);
            }
            listing_commit(ls);
        }
    }
}

void re_gui_page_fill(re_gui_listing_t *ls, re_arena_t *a, const re_pe_t *pe, const re_vset_t *vs,
                      size_t tab, uint32_t rva, uint32_t size, size_t row0, size_t rows) {
    switch (tab) {
        case 2:
            re_gui_hex_fill(ls, a, pe, rva, size, row0, rows);
            return;
        case 3:
            re_gui_structs_fill(ls, a, vs, row0, rows);
            return;
        case 4:
            re_gui_imports_fill(ls, a, pe, row0, rows);
            return;
        case 5:
            re_gui_exports_fill(ls, a, pe, row0, rows);
            return;
        default:
            ls->n = 0;
            ls->total = 0;
            return;
    }
}
