// re_code.h - the walkable code map: address translation, decode, and coverage.
// Module: feature (C11).
// Owns: which bytes may be executed, decoding at an address, and the covered bitmap.
// Depends: re_disasm, re_pe, re_buf, re_vec. Never reads outside the image span.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/code/re_limits.h"
#include "features/meta/re_disasm.h"
#include "features/pe/re_pe.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_buf.h"

#define RE_CODE_PAGE 4096u

typedef struct {
    re_span_t img;          // the whole mapped file
    const re_pe_t *pe;      // for section and address translation
    const re_disasm_t *dis; // the backend, NULL when the build has none
    re_arena_t *arena;
    uint64_t base;   // image base, so a virtual address is absolute
    uint64_t n_code; // executable bytes, the size of the covered bitmap
    uint64_t *bits;  // one bit per code byte, arena backed
    size_t n_words;
    re_limits_t lim; // the tier's caps; re_code_init sets the entry tier
    // Deep tier only, NULL in the entry tier. hostile has one byte per RE_CODE_PAGE of
    // the code space, nonzero where the bytes are packed or encrypted and must not be
    // walked. starts has one bit per code byte, set where an instruction was decoded,
    // so a jump into the middle of one is seen as overlapping code.
    const uint8_t *hostile;
    uint64_t n_pages;
    uint64_t *starts;
} re_code_t;

// Prepare the map. The image, the parser and the base are written before this
// returns, including when it returns false: address translation does not need a
// decoder. False means no backend, an invalid image, or no executable section.
// A caller that decodes must treat false as "do not decode".
bool re_code_init(re_code_t *c, re_span_t img, const re_pe_t *pe, const re_disasm_t *dis,
                  re_arena_t *a);

// True when the address falls inside an executable, mapped section.
bool re_code_in_code(const re_code_t *c, uint64_t va);

// The image's code window in absolute addresses: the lowest and the highest address its
// executable sections cover. A table that states its entries relative to the start of the
// code needs this window to turn them into addresses, and the test for what counts as
// code is the one the walk uses, so the build has one answer rather than two.
void re_code_window(const re_code_t *c, uint64_t *lo, uint64_t *hi);

// The bytes at a virtual address, for handing to the decoder. False when the
// address is not executable or only part of the span is mapped.
bool re_code_at(const re_code_t *c, uint64_t va, re_span_t *bytes);

// Decode one instruction at a virtual address. False on a decode failure, and
// that is a normal stopping condition rather than a fault.
bool re_code_insn(const re_code_t *c, uint64_t va, re_insn_t *out);

// Mark n bytes as covered. Returns false when the range leaves the code section.
bool re_code_mark(re_code_t *c, uint64_t va, size_t n);

// True when every byte of the instruction at va is already covered, which is how
// the walk avoids descending into a function twice.
bool re_code_covered(const re_code_t *c, uint64_t va, size_t n);

// True when any byte of the range is already covered, so a new function that
// overlaps an old one is suspicious and worth reporting.
bool re_code_overlaps(const re_code_t *c, uint64_t va, size_t n);

// The file offset for a virtual address, for reading a jump table or a string.
bool re_code_offset(const re_code_t *c, uint64_t va, uint64_t *off);

// The executable ranges in section order, for a sweep over the whole code area.
// Returns false once index is past the last executable section.
bool re_code_range(const re_code_t *c, uint16_t index, uint64_t *va, uint64_t *len);

// The bit an address has in the covered bitmap: its distance into the concatenated
// executable space. False outside every executable section.
bool re_code_index(const re_code_t *c, uint64_t va, uint64_t *idx);

// True when va is on a page the deep tier classified as packed or encrypted.
bool re_code_hostile(const re_code_t *c, uint64_t va);

// Record, and ask about, a decoded instruction start. Both are no-ops without starts.
void re_code_set_start(re_code_t *c, uint64_t va);
bool re_code_is_start(const re_code_t *c, uint64_t va);
#ifdef __cplusplus
}
#endif
