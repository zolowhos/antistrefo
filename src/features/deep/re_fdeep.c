// re_fdeep.c - the deep tier's function passes: trust scored pdata and the gap sweep.
// Module: feature (C11).
// Owns: re_fdeep_pdata, re_fdeep_gaps, and the plausibility tests both apply.
// Depends: re_func_priv.h, re_code, re_pe. Never claims bytes a walk did not decode.
#include "features/code/re_func_priv.h"

#include "features/pe/re_pe.h"

// A real function is rarely larger than this. An unwind entry claiming more is a
// forged one, and walking it would hand a hostile table the instruction budget.
#define RE_PDATA_MAX_SPAN (16u * 1024u * 1024u)
#define RE_GAP_PROBE 6u // instructions decoded linearly before a gap start is believed

// The UNWIND_INFO an entry points at must exist and carry version 1 or 2. A table
// forged to look like pdata usually fails this before anything else.
static bool unwind_info_ok(const re_pe_t *pe, uint32_t rva) {
    uint64_t off = 0;
    uint8_t ver = 0;
    if (!rva || !re_pe_rva2off(pe, rva & ~1u, &off) || !re_rd8(pe->img, off, &ver))
        return false;
    ver &= 7u;
    return ver == 1u || ver == 2u;
}

// Trust for one entry, given the previous one. The format requires the table sorted
// and non overlapping, so an entry out of order or inside its predecessor is forged.
static bool pdata_trusted(walk_t *w, const re_pe_unwind_t *u, const re_pe_unwind_t *prev) {
    const re_pe_t *pe = w->code->pe;
    uint64_t start = w->code->base + u->begin;
    re_insn_t in;
    if (u->end <= u->begin || u->end - u->begin > RE_PDATA_MAX_SPAN)
        return false;
    if (prev && (u->begin < prev->end || u->begin <= prev->begin))
        return false;
    if (!re_code_in_code(w->code, start) || re_code_hostile(w->code, start))
        return false;
    if (!re_code_in_code(w->code, w->code->base + u->end - 1u))
        return false;
    if (!unwind_info_ok(pe, u->unwind))
        return false;
    return re_code_insn(w->code, start, &in);
}

size_t re_fdeep_pdata(walk_t *w) {
    const re_pe_t *pe = w->code->pe;
    const re_pe_unwind_t *prev = NULL;
    size_t walked = 0;
    for (size_t i = 0; i < RE_VEC_LEN(&pe->unwind) && !w->truncated; i++) {
        const re_pe_unwind_t *u = RE_VEC_PTR(&pe->unwind, re_pe_unwind_t, i);
        uint64_t start = w->code->base + u->begin;
        re_func_t f;
        if (re_walk_over_budget(w))
            break;
        if (!pdata_trusted(w, u, prev)) {
            w->rejected++;
            continue; // a refused entry does not become the order reference either
        }
        prev = u;
        if (re_code_covered(w->code, start, 1))
            continue;
        re_walk_func(w, start, &f);
        if (f.n_insns == 0)
            continue;
        f.flags |= RE_FUNC_UNWIND;
        if (f.rva + f.size < u->end)
            f.size = u->end - u->begin;
        if (re_walk_keep(w, &f))
            walked++;
    }
    return walked;
}

static bool is_pad(uint8_t b) {
    return b == 0xCCu || b == 0x90u || b == 0x00u;
}

// A gap start is believed when a short linear decode succeeds and does not open with
// the zero bytes data decodes as. A transfer or a return inside the probe ends it early.
static bool plausible(walk_t *w, uint64_t at) {
    uint64_t va = at;
    for (uint32_t k = 0; k < RE_GAP_PROBE; k++) {
        re_insn_t in;
        if (re_code_covered(w->code, va, 1) || re_code_hostile(w->code, va))
            return false;
        if (!re_code_insn(w->code, va, &in))
            return false;
        if (k == 0 && in.raw[0] == 0x00u)
            return false;
        if (in.is_return || (in.is_branch && !in.is_conditional))
            return k >= 1u;
        va += in.size;
    }
    return true;
}

// The first non padding byte at or after at, within the range, or end.
static uint64_t skip_pad(const re_code_t *c, uint64_t at, uint64_t end) {
    while (at < end) {
        re_span_t b;
        if (!re_code_at(c, at, &b) || b.n == 0 || !is_pad(b.p[0]))
            break;
        at++;
    }
    return at;
}

// One sweep: every uncovered run in the code, tried once at its first non padding
// byte. Not every byte, because a run of data inside .text would then cost a decode
// per byte; a run's head is where the linker put a function if it put one there.
static size_t gap_round(walk_t *w) {
    uint64_t va = 0;
    uint64_t len = 0;
    size_t found = 0;
    for (uint16_t r = 0; re_code_range(w->code, r, &va, &len) && !w->truncated; r++) {
        uint64_t end = va + len;
        uint64_t at = va;
        while (at < end && !w->truncated && !re_walk_over_budget(w)) {
            re_func_t f;
            if (re_code_covered(w->code, at, 1)) {
                at++;
                continue;
            }
            at = skip_pad(w->code, at, end);
            if (at >= end)
                break;
            if (!plausible(w, at)) {
                while (at < end && !re_code_covered(w->code, at, 1))
                    at++; // the rest of this run is not a function head
                continue;
            }
            re_walk_func(w, at, &f);
            if (f.n_insns >= 2u) {
                f.flags |= RE_FUNC_GAP;
                found += re_walk_keep(w, &f) ? 1u : 0u;
                found += re_walk_drain(w, RE_FUNC_GAP);
            }
            at += f.size ? f.size : 1u;
        }
    }
    return found;
}

size_t re_fdeep_gaps(walk_t *w) {
    size_t total = 0;
    for (uint32_t round = 0; round < w->code->lim.gap_rounds; round++) {
        size_t n = gap_round(w);
        w->rounds++;
        total += n;
        if (n == 0)
            break;
    }
    return total;
}
