// re_code.c - address translation and the covered bitmap for one image.
// Module: feature (C11).
// Owns: section selection, virtual address to span, and coverage bookkeeping.
// Depends: re_code.h only. Every access is bounds checked against the image.
#include "features/code/re_code.h"

#include "utils/mem/re_bits.h"

// The bitset is sized by the total executable span rather than by the image, so a
// file with a large overlay does not pay for the overlay.
static bool init_bits(re_code_t *c) {
    size_t words = (size_t)((c->n_code + 63u) / 64u);
    if (words == 0)
        return false;
    c->bits = (uint64_t *)re_arena_calloc(c->arena, words, sizeof(uint64_t));
    if (!c->bits)
        return false;
    c->n_words = words;
    return true;
}

bool re_code_init(re_code_t *c, re_span_t img, const re_pe_t *pe, const re_disasm_t *dis,
                  re_arena_t *a) {
    uint64_t total = 0;
    c->img = img;
    c->pe = pe;
    c->dis = dis;
    c->arena = a;
    c->base = pe->image_base;
    c->bits = NULL;
    c->n_words = 0;
    c->n_code = 0;
    if (!dis || !pe->valid)
        return false;
    for (uint16_t i = 0; i < pe->n_sec; i++) {
        const re_pe_section_t *s = &pe->sec[i];
        uint64_t bytes = s->rsize < s->vsize ? s->rsize : s->vsize;
        if ((s->chars & (RE_SEC_EXEC | RE_SEC_CODE)) == (RE_SEC_EXEC | RE_SEC_CODE))
            total += bytes;
    }
    c->n_code = total;
    return init_bits(c);
}

// Walk the sections to find the one holding a virtual address. The comparison is
// against the image base plus the section RVA, because the caller works in
// absolute addresses while the section table stores RVAs. A section whose raw
// data is absent contributes nothing, so an address past the end of the file is
// not decodable even though the section claims the virtual range.
static const re_pe_section_t *find(const re_code_t *c, uint64_t va, uint64_t *base) {
    for (uint16_t i = 0; i < c->pe->n_sec; i++) {
        const re_pe_section_t *s = &c->pe->sec[i];
        uint64_t bytes = s->rsize < s->vsize ? s->rsize : s->vsize;
        uint64_t start = c->base + s->vaddr;
        // Either flag on its own is taken as evidence of code. Requiring both is
        // stricter than the format guarantees and it is not safe: a protected image
        // can have MEM_EXECUTE stripped from its .text and wrongly set on .rodata,
        // and then a test for both misses the code section entirely and finds nothing
        // at all. One of the two is what a linker sets; the other can be mangled.
        if ((s->chars & (RE_SEC_EXEC | RE_SEC_CODE)) == 0)
            continue;
        if (va >= start && va - start < bytes) {
            *base = s->vaddr;
            return s;
        }
    }
    return NULL;
}

bool re_code_in_code(const re_code_t *c, uint64_t va) {
    uint64_t base = 0;
    return find(c, va, &base) != NULL;
}

void re_code_window(const re_code_t *c, uint64_t *lo, uint64_t *hi) {
    uint64_t min = 0;
    uint64_t max = 0;
    bool any = false;
    for (uint16_t i = 0; i < c->pe->n_sec; i++) {
        const re_pe_section_t *s = &c->pe->sec[i];
        uint64_t bytes = s->rsize < s->vsize ? s->rsize : s->vsize;
        uint64_t start;
        if (bytes == 0 || (s->chars & (RE_SEC_EXEC | RE_SEC_CODE)) == 0)
            continue;
        start = c->base + s->vaddr;
        if (!any || start < min)
            min = start;
        if (!any || start + bytes > max)
            max = start + bytes;
        any = true;
    }
    *lo = any ? min : 0;
    *hi = any ? max : 0;
}

bool re_code_at(const re_code_t *c, uint64_t va, re_span_t *bytes) {
    uint64_t base = 0;
    const re_pe_section_t *s = find(c, va, &base);
    if (!s)
        return false;
    uint64_t off = 0;
    if (!re_pe_rva2off(c->pe, (uint32_t)(va - c->base), &off))
        return false;
    // The span ends where the section's raw data ends, measured from the image
    // base like the address itself, so the two can never be subtracted apart.
    uint64_t span = s->rsize < s->vsize ? s->rsize : s->vsize;
    uint64_t left = (c->base + s->vaddr + span) - va;
    re_span_t v = re_span_sub(c->img, off, left);
    if (!re_span_valid(v))
        return false;
    *bytes = v;
    return true;
}

bool re_code_insn(const re_code_t *c, uint64_t va, re_insn_t *out) {
    re_span_t b;
    if (!re_code_at(c, va, &b))
        return false;
    // Cap the span at the longest instruction the architecture allows, so the
    // decoder never sees bytes from the next function as part of this one.
    if (b.n > RE_MAX_INSN_LEN)
        b = re_span_sub(b, 0, RE_MAX_INSN_LEN);
    return c->dis->decode(c->dis->ctx, va, b, out);
}

// The bitmap is indexed by the distance from the start of the concatenated
// executable space, so an address always lands on the same bit whichever section
// holds it. Summing the sections that come first keeps that mapping stable.
static bool code_index(const re_code_t *c, uint64_t va, uint64_t *idx) {
    uint64_t acc = 0;
    for (uint16_t i = 0; i < c->pe->n_sec; i++) {
        const re_pe_section_t *s = &c->pe->sec[i];
        uint64_t bytes = s->rsize < s->vsize ? s->rsize : s->vsize;
        uint64_t start = c->base + s->vaddr;
        if ((s->chars & (RE_SEC_EXEC | RE_SEC_CODE)) != (RE_SEC_EXEC | RE_SEC_CODE))
            continue;
        if (va >= start && va - start < bytes) {
            *idx = acc + (va - start);
            return true;
        }
        acc += bytes;
    }
    return false;
}

static bool in_bits(const re_code_t *c, uint64_t idx) {
    return (c->bits[idx >> 6] >> (idx & 63u)) & 1u;
}

bool re_code_mark(re_code_t *c, uint64_t va, size_t n) {
    uint64_t idx;
    if (!code_index(c, va, &idx) || idx + (uint64_t)n > c->n_code)
        return false;
    for (size_t k = 0; k < n; k++) {
        uint64_t b = idx + (uint64_t)k;
        c->bits[b >> 6] |= (uint64_t)1 << (b & 63u);
    }
    return true;
}

// True only when every byte of the range is already marked, which is what stops
// the walk from treating a jump into the middle of a known function as a new one.
bool re_code_covered(const re_code_t *c, uint64_t va, size_t n) {
    uint64_t idx;
    if (!code_index(c, va, &idx) || idx + (uint64_t)n > c->n_code)
        return false;
    for (size_t k = 0; k < n; k++) {
        if (!in_bits(c, idx + (uint64_t)k))
            return false;
    }
    return n > 0;
}

// True when any byte of the range is marked, so a candidate that overlaps a
// function already found is reported rather than silently merged.
bool re_code_overlaps(const re_code_t *c, uint64_t va, size_t n) {
    uint64_t idx;
    if (!code_index(c, va, &idx) || idx + (uint64_t)n > c->n_code)
        return false;
    for (size_t k = 0; k < n; k++) {
        if (in_bits(c, idx + (uint64_t)k))
            return true;
    }
    return false;
}

bool re_code_offset(const re_code_t *c, uint64_t va, uint64_t *off) {
    // A context that was never bound has pe == NULL. Translating through it is
    // how analyze died on an x86 image; refuse rather than dereference.
    if (!c || !c->pe || !off)
        return false;
    return re_pe_rva2off(c->pe, (uint32_t)(va - c->base), off);
}

bool re_code_range(const re_code_t *c, uint16_t index, uint64_t *va, uint64_t *len) {
    uint16_t seen = 0;
    for (uint16_t i = 0; i < c->pe->n_sec; i++) {
        const re_pe_section_t *s = &c->pe->sec[i];
        uint64_t bytes = s->rsize < s->vsize ? s->rsize : s->vsize;
        if ((s->chars & (RE_SEC_EXEC | RE_SEC_CODE)) != (RE_SEC_EXEC | RE_SEC_CODE))
            continue;
        if (seen++ != index)
            continue;
        *va = c->base + s->vaddr;
        *len = bytes;
        return true;
    }
    return false;
}
