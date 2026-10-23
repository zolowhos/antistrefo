// re_regions.c - classifies regions of an image as code, data, rdata or padding.
// Module: feature (C11).
// Owns: the evidence counters and the rules that turn them into a classification.
// Depends: re_regions, re_code, re_func, re_xref, re_pe, re_entropy, re_str.
#include "features/data/re_regions.h"

#include <stdlib.h>
#include <string.h>

#include "features/code/re_jtable.h"
#include "features/data/re_strings.h"
#include "utils/sys/re_entropy.h"
#include "utils/text/re_str.h"

// The section a range sits in, or NULL when it is outside every one of them. A
// packed file routinely has code the section table does not describe, so a miss here
// is normal and is reported as unknown rather than as an error.
static const re_pe_section_t *sec_of(const re_pe_t *pe, uint64_t va) {
    for (uint16_t i = 0; i < pe->n_sec; i++) {
        const re_pe_section_t *s = &pe->sec[i];
        uint64_t lo = pe->image_base + s->vaddr;
        uint64_t span = s->vsize > s->rsize ? s->vsize : s->rsize;
        if (va >= lo && va - lo < span)
            return s;
    }
    return NULL;
}

// Both vectors lead with the address they sort on, so one comparator orders either.
static int cmp_u64(const void *a, const void *b) {
    uint64_t x = 0;
    uint64_t y = 0;
    memcpy(&x, a, sizeof(x));
    memcpy(&y, b, sizeof(y));
    return (x < y) ? -1 : (x > y);
}

static void sort_u64(uint64_t *v, size_t n) {
    if (n > 1)
        qsort(v, n, sizeof(*v), cmp_u64);
}

// Functions overlapping the region. The scan's table is sorted by address, so the
// first candidate is found by binary search rather than by walking the table from the
// start: the regions are visited in ascending order and the table can hold six
// figures of functions, so rescanning it per region is quadratic in the image and
// turns a large binary into a minute of waiting.
static void tally_funcs(const re_fscan_t *scan, uint64_t va, uint64_t size, re_region_t *r) {
    size_t n = scan ? RE_VEC_LEN(&scan->funcs) : 0;
    if (!n)
        return;
    // The first function starting after the region ends is the upper bound.
    size_t lo = 0;
    size_t hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (RE_VEC_AT(&scan->funcs, re_func_t, mid).va <= va + size)
            lo = mid + 1;
        else
            hi = mid;
    }
    // Walk back over the functions that begin before the region but reach into it.
    // They do not overlap each other, so this is a couple of steps, not a scan.
    size_t i = lo;
    while (i > 0) {
        const re_func_t *f = RE_VEC_PTR(&scan->funcs, re_func_t, i - 1);
        if (f->va + f->size <= va)
            break;
        i--;
    }
    for (; i < lo; i++) {
        const re_func_t *f = RE_VEC_PTR(&scan->funcs, re_func_t, i);
        if (f->va >= va + size)
            break;
        if (f->va + f->size <= va)
            continue;
        r->n_funcs++;
        // Only the part inside the region counts, so a function straddling a window
        // boundary does not claim bytes in both windows twice.
        uint64_t blo = f->va > va ? f->va : va;
        uint64_t bhi = f->va + f->size < va + size ? f->va + f->size : va + size;
        r->func_bytes += (uint32_t)(bhi - blo);
    }
}

// The share of the region's bytes that are filler: a run of zeroes, of int3 padding,
// or of nops. A region that is nearly all of one of those is alignment, not content,
// and calling it data would put the reader in the wrong place entirely.
static uint32_t fill_share(re_span_t bytes) {
    if (!bytes.n)
        return 0;
    uint32_t fill = 0;
    for (size_t i = 0; i < bytes.n; i++) {
        uint8_t b = bytes.p[i];
        if (b == 0x00u || b == 0xCCu || b == 0x90u || b == 0xFFu)
            fill++;
    }
    return (uint32_t)((fill * 100u) / bytes.n);
}

// References from anywhere in the image into the region. Count only: materialising
// a hit vector per window allocated O(windows) arena junk on a large SizeOfImage
// and was the main multi-GB blow-up on open of a ~200MB PE.
static void tally_refs(const re_xrefset_t *xs, re_arena_t *a, uint64_t va, uint64_t size,
                       re_region_t *r) {
    (void)a;
    if (!xs)
        return;
    r->n_data_refs = (uint32_t)re_xref_into_count(xs, va, size, 4096);
}

// How many entries of an ascending address list land in [va, va+size). Used for both
// jump tables and strings: each is a whole-image pass that is expensive to run and
// trivial to search, so both are done once and indexed here.
static uint32_t count_in(const re_vec_t *v, uint64_t va, uint64_t size) {
    size_t n = v ? RE_VEC_LEN(v) : 0;
    size_t i = 0;
    while (i < n && RE_VEC_AT(v, uint64_t, i) < va)
        i++;
    uint32_t got = 0;
    for (; i < n; i++) {
        uint64_t t = RE_VEC_AT(v, uint64_t, i);
        if (t >= va + size)
            break;
        got++;
    }
    return got;
}

const char *re_reg_kind_name(uint8_t kind) {
    static const char *const kNames[] = {"code", "data", "rdata", "pad", "unknown"};
    return kind < 5 ? kNames[kind] : "unknown";
}

const char *re_reg_conf_name(uint8_t conf) {
    static const char *const kNames[] = {"none", "low", "medium", "high"};
    return conf < 4 ? kNames[conf] : "none";
}

// The rules. Each one is a claim the evidence can support on its own, and the
// confidence counts how many of them agree, so a region claimed only by one weak
// signal stays low rather than being promoted to a verdict.
static void decide(re_region_t *r) {
    uint32_t agree = 0;
    bool claimed_code = r->func_bytes > 0;
    uint32_t code_share = r->size ? (r->func_bytes * 100u) / r->size : 0u;

    if (claimed_code && code_share >= 50u) {
        r->kind = RE_REG_CODE;
        agree += r->exec ? 2u : 0u;
        agree += code_share >= 90u ? 1u : 0u;
    } else if (r->fill_pct >= 90u) {
        r->kind = RE_REG_PAD;
        agree += 1u;
        agree += r->fill_pct == 100u ? 1u : 0u;
    } else if (claimed_code) {
        // Instructions that decode are code, whatever the section's permissions say.
        // A driver's INIT section is writable and holds code, and calling it data
        // because of the write flag would send the reader to the wrong place. The
        // share and the flags are both reported, so a reader who wants to treat a
        // writable region as self modifying can say so from the evidence.
        r->kind = RE_REG_CODE;
        // Two signals agree here, not one: the section says executable and functions
        // really do decode in it. Scoring only the second would report every text
        // section as low confidence, which is not what the evidence says.
        agree += 1u;
        agree += r->exec ? 1u : 0u;
    } else if (r->n_strings || r->n_jtables) {
        // Content, in a section whose permissions then decide whether it is data or
        // rdata. A string in a read only section is rdata and a string in a writable
        // one is data, and the two signals are counted separately because they are
        // independent: plenty of regions hold a jump table or a string and nothing else.
        r->kind = r->writable ? RE_REG_DATA : RE_REG_RDATA;
        agree += r->n_strings ? 1u : 0u;
        agree += r->n_jtables ? 1u : 0u;
    } else if (r->n_data_refs) {
        r->kind = r->writable ? RE_REG_DATA : RE_REG_RDATA;
        agree += 1u;
    } else if (r->writable) {
        r->kind = RE_REG_DATA;
        agree += r->fill_pct >= 50u ? 0u : 1u;
    } else {
        r->kind = RE_REG_UNKNOWN;
    }
    // Without a containing section there is no flag evidence to agree with, so a
    // region outside every section can never be more than low confidence.
    uint32_t cap = (r->sec[0] == '\0') ? RE_REG_CONF_LOW : RE_REG_CONF_HIGH;
    if (r->kind == RE_REG_UNKNOWN)
        cap = RE_REG_CONF_NONE;
    r->confidence = (uint8_t)(agree < cap ? agree : cap);
}

bool re_region_classify(re_code_t *c, const re_fscan_t *scan, const re_xrefset_t *xs,
                        const re_pe_t *pe, const re_region_ev_t *ev, uint64_t va, uint64_t size,
                        re_region_t *out, re_arena_t *a) {
    if (!c || !pe || !out || !size)
        return false;
    memset(out, 0, sizeof(*out));
    out->va = va;
    out->size = (uint32_t)size;
    out->rva = (uint32_t)(va - pe->image_base);
    const re_pe_section_t *s = sec_of(pe, va);
    if (s) {
        for (size_t i = 0; i < sizeof(out->sec) - 1 && s->name[i]; i++)
            out->sec[i] = s->name[i];
        out->exec = (s->chars & 0x20000000u) != 0; // IMAGE_SCN_MEM_EXECUTE
        out->writable = (s->chars & 0x80000000u) != 0;
        out->readable = (s->chars & 0x40000000u) != 0;
    }
    // Only bytes actually present on disk are measured. The virtual tail of a section
    // has no entropy and no filler share, and folding it in would make a section look
    // emptier than the file actually is.
    re_span_t bytes = {NULL, 0};
    uint64_t off = 0;
    if (re_code_offset(c, va, &off)) {
        uint64_t avail = c->img.n > off ? c->img.n - off : 0;
        uint64_t n = size < avail ? size : avail;
        bytes.p = c->img.p + off;
        bytes.n = (size_t)n;
    }
    if (bytes.n) {
        out->entropy = re_entropy(bytes);
        out->fill_pct = fill_share(bytes);
    }
    tally_funcs(scan, va, size, out);
    tally_refs(xs, a, va, size, out);
    // Jump tables and strings are counted separately from other data references
    // because they mean different things to a reader: a jump table is a structured
    // artefact of code, a string is content, and a plain reference is usually a
    // constant. All three point into the region and none of them implies the others.
    out->n_jtables = count_in(ev ? ev->jtables : NULL, va, size);
    out->n_strings = count_in(ev ? ev->strings : NULL, va, size);
    decide(out);
    return true;
}

// Both whole-image passes, done once and reduced to sorted address lists so the per
// window count is a search rather than a rescan. Strings are found as file offsets
// and have to be translated before they can be compared against a window.
static void gather_evidence(re_code_t *c, const re_fscan_t *scan, const re_pe_t *pe, re_arena_t *a,
                            re_vec_t *jt, re_vec_t *strs) {
    re_vec_t found;
    re_vec_init(&found, sizeof(re_jtable_t));
    re_vec_init(jt, sizeof(uint64_t));
    re_vec_init(strs, sizeof(uint64_t));
    re_jtable_scan(c, scan, a, &found);
    for (size_t i = 0; i < RE_VEC_LEN(&found); i++)
        RE_VEC_PUSH(jt, a, RE_VEC_AT(&found, re_jtable_t, i).table_va);
    sort_u64(RE_VEC_PTR(jt, uint64_t, 0), RE_VEC_LEN(jt));
    re_strings_t s;
    re_strings_init(&s);
    re_strings_scan(c->img, 4, re_lim_size(c->lim.str_hits), a, &s);
    for (size_t i = 0; i < RE_VEC_LEN(&s.hits); i++) {
        uint32_t rva = 0;
        if (!re_pe_off2rva(pe, RE_VEC_AT(&s.hits, re_str_hit_t, i).off, &rva))
            continue;
        // Into a local first: the push macro takes the address of its value, and
        // image_base + rva is not something that can be addressed.
        uint64_t at = pe->image_base + rva;
        RE_VEC_PUSH(strs, a, at);
    }
    sort_u64(RE_VEC_PTR(strs, uint64_t, 0), RE_VEC_LEN(strs));
}

size_t re_region_scan(re_code_t *c, const re_fscan_t *scan, const re_xrefset_t *xs,
                      const re_pe_t *pe, size_t win, re_vec_t *out, bool *truncated,
                      re_arena_t *a) {
    re_vec_t jt;
    re_vec_t strs;
    re_region_ev_t ev;
    *truncated = false;
    if (!c || !pe || !win)
        return 0;
    gather_evidence(c, scan, pe, a, &jt, &strs);
    ev.jtables = &jt;
    ev.strings = &strs;
    uint64_t base = pe->image_base;
    // The virtual extent, not the file length. A section can sit at an RVA far beyond
    // the last byte in the file, so walking img.n would stop before reaching it and
    // every window over the sections would silently go unreported. Windows past the
    // end of the file measure no bytes, which the classifier reports as unknown.
    uint64_t span = pe->size_of_image ? pe->size_of_image : (c->img.n ? c->img.n : 1);
    uint64_t end = base + span;
    for (uint64_t va = base; va < end; va += win) {
        uint64_t left = end - va;
        uint64_t n = left < (uint64_t)win ? left : (uint64_t)win;
        re_region_t r;
        if ((uint64_t)RE_VEC_LEN(out) >= c->lim.regions) {
            *truncated = true;
            break;
        }
        if (!re_region_classify(c, scan, xs, pe, &ev, va, n, &r, a))
            break;
        if (!RE_VEC_PUSH(out, a, r)) {
            *truncated = true;
            break;
        }
    }
    return RE_VEC_LEN(out);
}
