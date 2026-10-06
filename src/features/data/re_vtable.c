// re_vtable.c - vtable and RTTI discovery, judged by each record's own claims.
// Module: feature (C11).
// Owns: the scan, the Complete Object Locator check and the class name lookup.
// Depends: re_pe, re_code, re_demangle. No allocation outside the caller's arena.
#include "features/data/re_vtable.h"

#include <string.h>

#include "features/lib/re_demangle.h"
#include "features/lib/re_demangle_rtti.h"
#include "utils/text/re_str.h"

// The Complete Object Locator, as MSVC lays it out on x64. Everything in it is an
// rva rather than a pointer, which is why a relocated image still parses.
#define COL_SIGNATURE 0u
#define COL_SIGNATURE32 1u // the 32 bit form, which exists and looks the same
#define COL_SIZE 24u

static bool rd32(const re_pe_t *pe, uint32_t rva, uint32_t *v) {
    uint64_t off = 0;
    if (!re_pe_rva2off(pe, rva, &off))
        return false;
    const re_pe_section_t *s = re_pe_section_at_rva(pe, rva);
    if (!s)
        return false;
    uint64_t so = 0;
    if (!re_pe_rva2off(pe, s->vaddr, &so) || off + 4u > pe->img.n)
        return false;
    *v = (uint32_t)pe->img.p[off] | ((uint32_t)pe->img.p[off + 1] << 8) |
         ((uint32_t)pe->img.p[off + 2] << 16) | ((uint32_t)pe->img.p[off + 3] << 24);
    return true;
}

// The eight byte form, for the locator pointer the slot before a vtable holds.
static bool rd64(const re_pe_t *pe, uint32_t rva, uint64_t *v) {
    uint32_t lo = 0, hi = 0;
    if (!rd32(pe, rva, &lo) || !rd32(pe, rva + 4u, &hi))
        return false;
    *v = (uint64_t)lo | ((uint64_t)hi << 32);
    return true;
}

// One 8 byte slot, normalised to an rva. A relocated image carries a full virtual
// address, which the image base turns back; a file whose table was written as base
// relative rvas reads as a small number and is used as it stands. Both forms exist
// in the wild, and the image base is what tells them apart.
static bool slot_ptr(const re_pe_t *pe, uint32_t rva, uint32_t *out) {
    uint64_t ptr = 0;
    if (!rd64(pe, rva, &ptr))
        return false;
    if (ptr >= pe->image_base && ptr - pe->image_base < pe->size_of_image)
        ptr -= pe->image_base;
    if (ptr > 0xFFFFFFFFu)
        return false;
    *out = (uint32_t)ptr;
    return true;
}

// A vtable's own address is written inside its locator. Nothing else in the file
// repeats an address like that, so this is the check that keeps a run of coincidental
// code pointers from being reported as a class.
bool re_vtable_col_at(const re_pe_t *pe, uint32_t rva, uint32_t *td_rva, uint32_t *bcd_rva) {
    uint32_t sig = 0, self = 0, td = 0, bcd = 0;
    // Rva zero is the headers, never a locator. Zero filled data offers this
    // candidate on every scan, and the pSelf check cannot refuse it, because zero
    // reads back as zero and self == rva holds for free.
    if (rva == 0)
        return false;
    if (rva > 0xFFFFFF00u || rva + COL_SIZE > 0x100000000u)
        return false;
    if (!rd32(pe, rva, &sig) || !rd32(pe, rva + 12u, &td) || !rd32(pe, rva + 16u, &bcd) ||
        !rd32(pe, rva + 20u, &self))
        return false;
    if (sig != COL_SIGNATURE && sig != COL_SIGNATURE32)
        return false;
    if (self != rva)
        return false;
    if (td_rva)
        *td_rva = td;
    if (bcd_rva)
        *bcd_rva = bcd;
    return true;
}

// A TypeDescriptor ends with the mangled class name, and the two pointers before
// that name are the type_info vtable the runtime uses for its own comparisons and
// the spare it compares it against. Requiring the name to start with one of the four
// mangling prefixes is what separates a real type descriptor from any other structure
// that happens to sit in the data section.
static bool td_name(const re_pe_t *pe, uint32_t td_rva, re_str_t *out) {
    // A TypeDescriptor is two 64-bit pointers and then the name. The spare is null
    // in every real image, which is a fact about the runtime and not a defect, so
    // only the first pointer is required to name something; two identical pointers
    // would be a copy of the same word twice, which no real descriptor is.
    uint32_t lo1 = 0, hi1 = 0, lo2 = 0, hi2 = 0;
    if (!rd32(pe, td_rva, &lo1) || !rd32(pe, td_rva + 4u, &hi1) || !rd32(pe, td_rva + 8u, &lo2) ||
        !rd32(pe, td_rva + 12u, &hi2))
        return false;
    if (lo1 == 0 || (lo1 == lo2 && hi1 == hi2))
        return false;
    uint32_t name_rva = td_rva + 16u;
    uint64_t off = 0;
    if (!re_pe_rva2off(pe, name_rva, &off) || off >= pe->img.n)
        return false;
    const char *p = (const char *)pe->img.p + off;
    size_t room = pe->img.n - off, i = 0;
    while (i < room && p[i] != 0)
        i++;
    if (i < 5 || i == room)
        return false;
    if (p[0] != '.' || p[1] != '?' || p[2] != 'A')
        return false;
    if (p[3] != 'V' && p[3] != 'U' && p[3] != 'T' && p[3] != 'W')
        return false;
    out->p = p;
    out->n = i;
    return true;
}

// The class name. A type descriptor's name is not a function symbol, it is ".?AVFoo@@"
// with the class inside it, so the wrapper is stripped before anything else is tried.
// Two flags come back and they are not the same: got says there is a name to report at
// all, demangled says the demangler understood it. Reporting the raw mangled text as
// though it were a demangled name is how a class ends up called something it is not.
static re_str_t class_name(re_arena_t *a, const re_pe_t *pe, uint32_t td_rva, bool *demangled,
                           bool *got) {
    re_str_t raw;
    *demangled = false;
    *got = false;
    if (!td_name(pe, td_rva, &raw))
        return re_str("");
    re_str_t out;
    // The descriptor name is its own format, not a function symbol: the generic
    // demangler refuses ".?AVFoo@@" on sight, and the wrapper must go through the
    // reader that knows it. Falling back to the raw text keeps a name where a
    // template descriptor defeated the reader, still marked undemangled.
    if (re_demangle_rtti(a, raw.p, raw.n, &out) && out.n) {
        *demangled = true;
        *got = true;
        return out;
    }
    *got = true;
    return raw;
}

// The base class chain a locator carries, walked through the Base Class Descriptor.
// pmd[1] holds the this-pointer adjustment, which is what tells a multiple inheritance
// offset apart from a single base at zero.
static uint32_t read_bases(re_arena_t *a, const re_pe_t *pe, uint32_t bcd_rva, re_base_t **out) {
    uint32_t n = 0;
    *out = NULL;
    uint32_t first_td = 0, count = 0;
    if (!rd32(pe, bcd_rva, &first_td) || !rd32(pe, bcd_rva + 4u, &count))
        return 0;
    if (count == 0 || count > 64u)
        return 0;
    re_base_t *b = (re_base_t *)re_arena_alloc(a, sizeof(re_base_t) * count);
    if (!b)
        return 0;
    for (uint32_t i = 0; i < count; i++) {
        // Each pmd is three 32 bit fields, and the second is the mdisp.
        uint32_t mdisp = 0;
        uint32_t pmd_rva = bcd_rva + 8u + i * 12u + 4u;
        if (!rd32(pe, pmd_rva, &mdisp))
            break;
        uint32_t td = first_td;
        bool dm = false, got = false;
        b[n].type_rva = td;
        b[n].this_off = (int32_t)mdisp;
        b[n].name = class_name(a, pe, td, &dm, &got);
        n++;
    }
    *out = b;
    return n;
}

// How many code pointers start at this rva, which is the length of the table. The run
// stops at the first slot that is not a pointer into an executable section, so a
// vtable that is followed by other data ends where it really does.
static uint32_t vtable_len(const re_pe_t *pe, const re_code_t *code, uint32_t rva, uint32_t max) {
    uint32_t n = 0;
    while (n < max) {
        uint32_t v = 0;
        if (!slot_ptr(pe, rva + n * 8u, &v))
            break;
        const re_pe_section_t *s = re_pe_section_at_rva(pe, v);
        if (!s || !re_code_in_code(code, pe->image_base + v))
            break;
        n++;
    }
    return n;
}

bool re_vtable_entry(const re_pe_t *pe, const re_vtable_t *v, uint32_t i, uint32_t *out) {
    if (i >= v->n_entries)
        return false;
    return slot_ptr(pe, v->rva + i * 8u, out);
}

void re_vtable_scan(const re_pe_t *pe, const re_code_t *code, re_arena_t *a, re_vset_t *out) {
    memset(out, 0, sizeof(*out));
    re_vec_init(&out->vtables, sizeof(re_vtable_t));
    for (uint16_t si = 0; si < pe->n_sec; si++) {
        const re_pe_section_t *sec = &pe->sec[si];
        if (sec->chars & (RE_SEC_CODE | RE_SEC_EXEC))
            continue;
        uint32_t nslots = sec->rsize / 8u;
        if (nslots > 1u << 20u)
            nslots = 1u << 20u;
        for (uint32_t i = 0; i + 1u < nslots; i++) {
            // The slot before a vtable's first entry points at its locator.
            uint32_t col_rva = sec->vaddr + i * 8u;
            uint32_t td = 0, bcd = 0;
            uint32_t target = 0;
            if (!slot_ptr(pe, col_rva, &target))
                continue;
            if (!re_vtable_col_at(pe, target, &td, &bcd))
                continue;
            out->n_col++;
            uint32_t first = col_rva + 8u;
            uint32_t n = vtable_len(pe, code, first, 256u);
            if (n == 0)
                continue;
            re_vtable_t v;
            memset(&v, 0, sizeof(v));
            v.rva = first;
            v.col_rva = target;
            v.td_rva = td;
            v.n_entries = n;
            bool dm = false, got = false;
            re_str_t nm = class_name(a, pe, td, &dm, &got);
            if (got) {
                v.name = re_strn(re_arena_strndup(a, nm.p, nm.n), nm.n);
                v.demangled = dm;
                out->n_named++;
            }
            v.n_bases = read_bases(a, pe, bcd, &v.bases);
            RE_VEC_PUSH(&out->vtables, a, v);
        }
    }
}
