// re_pe.c - PE and COFF parsing. Every field is bounds checked before it is used.
// Module: feature (C11).
// Owns: header decoding, sections, data directories, imports, exports, rva maps.
// Depends: re_pe.h and the utils. No I/O, no globals, never trusts a file count.
#include "features/pe/re_pe.h"

#include <stdlib.h>
#include <string.h>

#define PE_FILE_EXECUTABLE 0x0002u
#define PE_FILE_DLL 0x2000u
#define PE_FILE_32BIT 0x0100u

static re_err_code_t fail(re_pe_t *pe, re_err_code_t code, const char *msg) {
    RE_ERR_SET(&pe->err, code, msg);
    return pe->err.code;
}

static bool rd16(re_span_t s, uint64_t o, uint16_t *v) {
    return re_rd16(s, o, v);
}

static bool rd32(re_span_t s, uint64_t o, uint32_t *v) {
    return re_rd32(s, o, v);
}

static re_err_code_t parse_headers(re_span_t img, re_pe_t *pe) {
    uint16_t magic;
    if (img.n < 0x40)
        return fail(pe, RE_E_MALFORMED, "file is smaller than a DOS header");
    if (!re_rd16(img, 0, &magic) || magic != 0x5A4Du)
        return fail(pe, RE_E_NOTBIN, "missing MZ signature");
    uint32_t lfanew;
    if (!rd32(img, 0x3C, &lfanew))
        return fail(pe, RE_E_MALFORMED, "truncated before e_lfanew");
    uint32_t sig;
    if (!rd32(img, lfanew, &sig) || sig != 0x00004550u)
        return fail(pe, RE_E_MALFORMED, "missing PE signature");
    uint64_t coff = lfanew + 4;
    if (!rd16(img, coff, &pe->machine) || !rd16(img, coff + 2, &pe->n_sec_field) ||
        !rd32(img, coff + 4, &pe->timestamp) || !rd16(img, coff + 16, &pe->opt_size) ||
        !rd16(img, coff + 18, &pe->chars))
        return fail(pe, RE_E_MALFORMED, "truncated COFF header");
    pe->has_ascii = (pe->chars & PE_FILE_EXECUTABLE) != 0;
    pe->is_dll = (pe->chars & PE_FILE_DLL) != 0;
    uint64_t opt = coff + 20;
    uint16_t omagic;
    if (!rd16(img, opt, &omagic))
        return fail(pe, RE_E_MALFORMED, "truncated optional header");
    if (omagic == 0x20B) {
        pe->pe32plus = true;
    } else if (omagic != 0x10B) {
        return fail(pe, RE_E_UNSUPPORTED, "optional header magic is neither PE32 nor PE32+");
    }
    uint64_t dd_at = opt + (pe->pe32plus ? 112u : 96u);
    if (!rd32(img, opt + 16, &pe->entry_rva) || !rd32(img, opt + 56, &pe->size_of_image) ||
        !rd16(img, opt + 68, &pe->subsystem) || !rd16(img, opt + 70, &pe->dll_chars) ||
        !rd32(img, opt + (pe->pe32plus ? 108u : 92u), &pe->n_dirs))
        return fail(pe, RE_E_MALFORMED, "truncated optional header fields");
    if (pe->pe32plus) {
        if (!re_rd64(img, opt + 24, &pe->image_base))
            return fail(pe, RE_E_MALFORMED, "truncated image base");
    } else {
        uint32_t b32;
        if (!rd32(img, opt + 28, &b32))
            return fail(pe, RE_E_MALFORMED, "truncated image base");
        pe->image_base = b32;
    }
    pe->signed_hdr = (pe->dll_chars & 0x4000u) != 0; // IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
    pe->n_dirs = pe->n_dirs > RE_PE_MAX_DIRS ? RE_PE_MAX_DIRS : pe->n_dirs;
    for (uint32_t i = 0; i < pe->n_dirs; i++) {
        if (!rd32(img, dd_at + i * 8, &pe->dd_rva[i]) ||
            !rd32(img, dd_at + i * 8 + 4, &pe->dd_size[i]))
            break;
    }
    pe->valid = true;
    return RE_OK;
}

static re_err_code_t parse_sections(re_span_t img, re_pe_t *pe, uint64_t sec_at) {
    if (pe->n_sec_field == 0)
        return fail(pe, RE_E_MALFORMED, "image declares no sections");
    uint16_t want = pe->n_sec_field;
    if (want > RE_PE_MAX_SECTIONS)
        want = RE_PE_MAX_SECTIONS;
    for (uint16_t i = 0; i < want; i++) {
        uint64_t o = sec_at + (uint64_t)i * 40u;
        re_pe_section_t *s = &pe->sec[i];
        re_span_t nm;
        re_rd_fixed_str(img, o, 8, &nm);
        for (size_t k = 0; k < nm.n && k < 8; k++)
            s->name[k] = nm.p[k];
        s->name[8] = '\0';
        if (!rd32(img, o + 8, &s->vsize) || !rd32(img, o + 12, &s->vaddr) ||
            !rd32(img, o + 16, &s->rsize) || !rd32(img, o + 20, &s->rptr) ||
            !rd32(img, o + 36, &s->chars))
            return fail(pe, RE_E_MALFORMED, "truncated section table");
        s->entropy = re_entropy(re_span_sub(img, s->rptr, s->rsize));
    }
    pe->n_sec = want;
    return RE_OK;
}

bool re_pe_rva2off(const re_pe_t *pe, uint32_t rva, uint64_t *out) {
    if (!pe || !out)
        return false;
    for (uint16_t i = 0; i < pe->n_sec; i++) {
        const re_pe_section_t *s = &pe->sec[i];
        uint32_t span = s->vsize > s->rsize ? s->vsize : s->rsize;
        if (rva >= s->vaddr && rva - s->vaddr < span) {
            uint64_t delta = rva - s->vaddr;
            if (delta >= s->rsize)
                return false; // in the virtual tail, no bytes on disk
            *out = s->rptr + delta;
            return true;
        }
    }
    return false;
}

const re_pe_section_t *re_pe_section_at_rva(const re_pe_t *pe, uint32_t rva) {
    for (uint16_t i = 0; i < pe->n_sec; i++) {
        const re_pe_section_t *s = &pe->sec[i];
        uint32_t span = s->vsize > s->rsize ? s->vsize : s->rsize;
        if (rva >= s->vaddr && rva - s->vaddr < span)
            return s;
    }
    return NULL;
}

const char *re_pe_region_kind(const re_pe_section_t *s) {
    if (!s)
        return "unmapped";
    // Either flag counts. A protected image can have MEM_EXECUTE stripped from its
    // .text, and a section carrying only CNT_CODE is still where the code is.
    if (s->chars & (RE_SEC_EXEC | RE_SEC_CODE))
        return "code";
    return "data";
}

re_str_t re_pe_export_forwarder(const re_pe_t *pe, uint32_t rva) {
    re_str_t none = {NULL, 0};
    uint32_t ed = pe->dd_rva[RE_PE_DD_EXPORT], es = pe->dd_size[RE_PE_DD_EXPORT];
    if (!es || rva < ed || rva - ed >= es)
        return none;
    uint64_t off = 0;
    if (!re_pe_rva2off(pe, rva, &off) || off >= pe->img.n)
        return none;
    const char *p = (const char *)pe->img.p + off;
    size_t room = pe->img.n - off, i = 0;
    while (i < room && p[i] >= 0x20 && p[i] < 0x7f)
        i++;
    // A forwarder string is NUL terminated. Running to the end of the image without
    // finding one means this is not a forwarder, and guessing here would invent an
    // implementation module that the file never named.
    if (i == 0 || i == room)
        return none;
    re_str_t s = {p, i};
    return s;
}

bool re_pe_off2rva(const re_pe_t *pe, uint64_t off, uint32_t *out) {
    for (uint16_t i = 0; i < pe->n_sec; i++) {
        const re_pe_section_t *s = &pe->sec[i];
        if (off >= s->rptr && off - s->rptr < s->rsize) {
            *out = s->vaddr + (uint32_t)(off - s->rptr);
            return true;
        }
    }
    return false;
}

static re_err_code_t parse_thunks(re_span_t img, re_pe_t *pe, re_arena_t *a, uint32_t thunk_rva,
                                  re_pe_imp_t *imp) {
    uint64_t toff;
    if (!re_pe_rva2off(pe, thunk_rva, &toff))
        return RE_OK; // a directory we cannot map is not fatal
    size_t step = pe->pe32plus ? 8u : 4u;
    imp->first_sym = (uint32_t)pe->syms.len;
    for (size_t i = 0; i < RE_PE_IMPORT_LIMIT; i++) {
        uint64_t o = toff + i * step;
        uint64_t val = 0;
        if (step == 8) {
            if (!re_rd64(img, o, &val))
                break;
        } else {
            uint32_t v32;
            if (!rd32(img, o, &v32))
                break;
            val = v32;
        }
        if (val == 0)
            break;
        uint64_t ordinal_bit = step == 8 ? (1ULL << 63) : (1ULL << 31);
        re_str_t sym;
        if (val & ordinal_bit) {
            char buf[24];
            re_strbuf_t sb;
            re_strbuf_init(&sb, a);
            re_strbuf_appendf(&sb, "#%u", (unsigned)(val & 0xffffu));
            sym = re_strn(re_arena_strndup(a, sb.p, sb.len), sb.len);
            (void)buf;
        } else {
            uint64_t noff;
            re_span_t name;
            if (!re_pe_rva2off(pe, (uint32_t)(val & 0x7fffffffu), &noff) ||
                !re_rd_cstr(img, noff + 2, 512, &name)) {
                sym = re_strn(re_arena_strdup(a, "?"), 1);
            } else {
                sym = re_strn(re_arena_strndup(a, (const char *)name.p, name.n), name.n);
            }
        }
        if (!RE_VEC_PUSH(&pe->syms, a, sym))
            return fail(pe, RE_E_NOMEM, "out of arena memory walking imports");
    }
    imp->n_syms = (uint32_t)(pe->syms.len - imp->first_sym);
    return RE_OK;
}

static re_err_code_t parse_imports(re_span_t img, re_pe_t *pe, re_arena_t *a) {
    if (pe->n_dirs <= RE_PE_DD_IMPORT || pe->dd_rva[RE_PE_DD_IMPORT] == 0)
        return RE_OK;
    uint64_t off;
    if (!re_pe_rva2off(pe, pe->dd_rva[RE_PE_DD_IMPORT], &off))
        return RE_OK;
    for (size_t d = 0; d < RE_PE_IMPORT_LIMIT; d++) {
        uint64_t o = off + d * 20u;
        uint32_t oft = 0, name_rva = 0, ft = 0;
        if (!rd32(img, o, &oft) || !rd32(img, o + 12, &name_rva) || !rd32(img, o + 16, &ft))
            break;
        if (name_rva == 0 && ft == 0)
            break;
        re_pe_imp_t imp;
        imp.first_sym = 0;
        imp.n_syms = 0;
        imp.first_thunk = ft;
        uint64_t noff;
        re_span_t dll;
        if (re_pe_rva2off(pe, name_rva, &noff) && re_rd_cstr(img, noff, 256, &dll)) {
            imp.dll = re_strn(re_arena_strndup(a, (const char *)dll.p, dll.n), dll.n);
        } else {
            imp.dll = re_strn(re_arena_strdup(a, "?"), 1);
        }
        re_err_code_t e = parse_thunks(img, pe, a, oft ? oft : ft, &imp);
        if (e != RE_OK)
            return e;
        if (!RE_VEC_PUSH(&pe->imports, a, imp))
            return fail(pe, RE_E_NOMEM, "out of arena memory walking imports");
    }
    return RE_OK;
}

static re_err_code_t parse_exports(re_span_t img, re_pe_t *pe, re_arena_t *a) {
    if (pe->n_dirs <= RE_PE_DD_EXPORT || pe->dd_rva[RE_PE_DD_EXPORT] == 0)
        return RE_OK;
    uint64_t off;
    if (!re_pe_rva2off(pe, pe->dd_rva[RE_PE_DD_EXPORT], &off))
        return RE_OK;
    uint32_t base = 0, n_names = 0, addr_funcs = 0, addr_names = 0, addr_ords = 0;
    if (!rd32(img, off + 16, &base) || !rd32(img, off + 24, &n_names) ||
        !rd32(img, off + 28, &addr_funcs) || !rd32(img, off + 32, &addr_names) ||
        !rd32(img, off + 36, &addr_ords))
        return RE_OK;
    if (n_names > 8192)
        n_names = 8192;
    uint64_t funcs_off, names_off, ords_off;
    if (!re_pe_rva2off(pe, addr_names, &names_off) || !re_pe_rva2off(pe, addr_ords, &ords_off) ||
        !re_pe_rva2off(pe, addr_funcs, &funcs_off))
        return RE_OK;
    for (uint32_t i = 0; i < n_names; i++) {
        uint32_t name_rva = 0;
        uint16_t ord = 0;
        if (!rd32(img, names_off + (uint64_t)i * 4u, &name_rva) ||
            !rd16(img, ords_off + (uint64_t)i * 2u, &ord))
            break;
        uint64_t noff;
        re_span_t name;
        re_pe_exp_t e;
        e.ordinal = base + ord;
        e.rva = 0;
        uint32_t func_rva = 0;
        if (rd32(img, funcs_off + (uint64_t)ord * 4u, &func_rva))
            e.rva = func_rva;
        if (re_pe_rva2off(pe, name_rva, &noff) && re_rd_cstr(img, noff, 512, &name)) {
            e.name = re_strn(re_arena_strndup(a, (const char *)name.p, name.n), name.n);
        } else {
            e.name = re_strn(re_arena_strdup(a, "?"), 1);
        }
        if (!RE_VEC_PUSH(&pe->exports, a, e))
            return fail(pe, RE_E_NOMEM, "out of arena memory walking exports");
    }
    return RE_OK;
}

static int unwind_cmp(const void *l, const void *r) {
    uint32_t a = ((const re_pe_unwind_t *)l)->begin, b = ((const re_pe_unwind_t *)r)->begin;
    return a < b ? -1 : (a > b ? 1 : 0);
}

// The exception directory, which on x64 is a flat array of RUNTIME_FUNCTION records:
// a begin, an exclusive end, and a pointer to the unwind data. The compiler writes
// one per function that can throw, so this is a function list the author of the code
// stated rather than one inferred from bytes. Entries with a zero begin are chained
// padding and are skipped, and a count that does not fit the directory is not trusted.
static re_err_code_t parse_unwind(re_span_t img, re_pe_t *pe, re_arena_t *a) {
    if (pe->n_dirs <= RE_PE_DD_EXCEPTION || pe->dd_rva[RE_PE_DD_EXCEPTION] == 0)
        return RE_OK;
    uint64_t off, size = pe->dd_size[RE_PE_DD_EXCEPTION];
    if (!re_pe_rva2off(pe, pe->dd_rva[RE_PE_DD_EXCEPTION], &off))
        return RE_OK;
    if (size < 12)
        return RE_OK;
    uint32_t n = (uint32_t)(size / 12u);
    if (n > RE_PE_UNWIND_LIMIT)
        n = RE_PE_UNWIND_LIMIT;
    for (uint32_t i = 0; i < n; i++) {
        re_pe_unwind_t u;
        if (!rd32(img, off + (uint64_t)i * 12u, &u.begin) ||
            !rd32(img, off + (uint64_t)i * 12u + 4u, &u.end) ||
            !rd32(img, off + (uint64_t)i * 12u + 8u, &u.unwind))
            break;
        if (u.begin == 0 || u.end <= u.begin)
            continue;
        if (!RE_VEC_PUSH(&pe->unwind, a, u))
            return fail(pe, RE_E_NOMEM, "out of arena memory reading the exception table");
    }
    if (RE_VEC_LEN(&pe->unwind) > 1)
        qsort(pe->unwind.base, RE_VEC_LEN(&pe->unwind), sizeof(re_pe_unwind_t), unwind_cmp);
    return RE_OK;
}

// The exception table is sorted by begin address in every linker that emits it, so a
// binary search answers "is this address inside a known function" in a dozen steps.
// A linear scan would be a hundred thousand times that on the largest binary in the
// corpus, called once per candidate function start.
bool re_pe_unwind_covering(const re_pe_t *pe, uint32_t rva, re_pe_unwind_t *out) {
    size_t lo = 0, hi = RE_VEC_LEN(&pe->unwind);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        const re_pe_unwind_t *u = RE_VEC_PTR(&pe->unwind, re_pe_unwind_t, mid);
        if (rva < u->begin)
            hi = mid;
        else if (rva >= u->end)
            lo = mid + 1u;
        else {
            *out = *u;
            return true;
        }
    }
    return false;
}

re_err_code_t re_pe_parse(re_span_t img, re_arena_t *a, re_pe_t *out) {
    memset(out, 0, sizeof(*out));
    out->img = img;
    re_vec_init(&out->imports, sizeof(re_pe_imp_t));
    re_vec_init(&out->syms, sizeof(re_str_t));
    re_vec_init(&out->exports, sizeof(re_pe_exp_t));
    re_vec_init(&out->unwind, sizeof(re_pe_unwind_t));
    out->err.code = RE_OK;
    re_err_code_t e = parse_headers(img, out);
    if (e != RE_OK)
        return e;
    uint32_t lfanew = 0;
    if (!rd32(img, 0x3C, &lfanew))
        return fail(out, RE_E_MALFORMED, "truncated before e_lfanew");
    uint64_t sec_at = (uint64_t)lfanew + 4u + 20u + out->opt_size;
    e = parse_sections(img, out, sec_at);
    if (e != RE_OK)
        return e;
    e = parse_imports(img, out, a);
    if (e != RE_OK)
        return e;
    e = parse_exports(img, out, a);
    if (e != RE_OK)
        return e;
    return parse_unwind(img, out, a);
}

const char *re_pe_machine_name(uint16_t m) {
    switch (m) {
        case 0x014c:
            return "x86";
        case 0x8664:
            return "x64";
        case 0xAA64:
            return "arm64";
        case 0x01c0:
            return "arm";
        case 0x01c4:
            return "armv7";
        case 0x0200:
            return "ia64";
        case 0x5032:
            return "riscv32";
        case 0x5064:
            return "riscv64";
        default:
            return "unknown";
    }
}

const char *re_pe_subsystem_name(uint16_t s) {
    switch (s) {
        case 1:
            return "native";
        case 2:
            return "windows_gui";
        case 3:
            return "windows_console";
        case 5:
            return "os2_console";
        case 7:
            return "posix_console";
        case 9:
            return "windows_ce_gui";
        case 10:
            return "efi_application";
        case 14:
            return "xbox";
        default:
            return "unknown";
    }
}

const char *re_pe_section_flags(uint32_t c, re_strbuf_t *out) {
    re_strbuf_clear(out);
    if (c & 0x00000020u)
        re_strbuf_puts(out, "C");
    if (c & 0x00000040u)
        re_strbuf_puts(out, "I");
    if (c & 0x00000080u)
        re_strbuf_puts(out, "U");
    if (c & 0x02000000u)
        re_strbuf_puts(out, "D");
    if (c & 0x04000000u)
        re_strbuf_puts(out, "L");
    if (c & 0x20000000u)
        re_strbuf_puts(out, "X");
    if (c & 0x40000000u)
        re_strbuf_puts(out, "R");
    if (c & 0x80000000u)
        re_strbuf_puts(out, "W");
    return out->p ? out->p : "";
}
