// re_xref.h - cross references in both directions, with the target named.
// Module: feature (C11).
// Owns: the forward and reverse indexes, and the classification of each target.
// Depends: re_code, re_func, re_pe, re_strings. Read only, arena backed.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/code/re_code.h"
#include "features/code/re_func.h"
#include "features/data/re_strings.h"
#include "features/pe/re_pe.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_vec.h"
#include "utils/text/re_str.h"

typedef enum {
    RE_XR_NONE = 0,
    RE_XR_CALL, // a direct or indirect call
    RE_XR_JUMP, // an unconditional transfer, including a tail call
    RE_XR_COND, // a conditional branch
    RE_XR_DATA, // a memory or immediate reference, not a transfer
} re_xr_kind_t;

// What the target is. This is the question a caller actually has, and answering
// it here keeps every consumer from re-deriving it.
#define RE_XRF_CODE 0x01u        // lands in a function we recovered
#define RE_XRF_IMPORT 0x02u      // lands in an IAT slot, so it is an imported symbol
#define RE_XRF_EXPORT 0x04u      // lands on a named export
#define RE_XRF_STRING 0x08u      // lands on a printable string
#define RE_XRF_DATA 0x10u        // lands in a data section
#define RE_XRF_OUTSIDE 0x20u     // not mapped in this image at all
#define RE_XRF_JTABLE 0x40u      // lands on a jump table
#define RE_XRF_GLOBAL_SLOT 0x80u // pointer cell whose target is BSS/common

typedef struct {
    uint64_t from; // the referencing instruction
    uint64_t to;   // the address it references
    uint32_t rva;
    uint8_t kind;  // re_xr_kind_t
    uint8_t flags; // RE_XRF_*
    re_str_t name; // import or export name, or the string itself
} re_xref_t;

typedef struct {
    re_vec_t fwd;      // re_xref_t, sorted by from
    re_vec_t rev;      // uint32_t indices into fwd, sorted by to
    size_t n_indirect; // transfers with no resolvable target
} re_xrefset_t;

// Build both directions. The scan supplies the edges already discovered, so this
// classifies and indexes rather than re-walking, which keeps it linear.
void re_xref_build(re_code_t *c, const re_fscan_t *scan, const re_pe_t *pe, re_arena_t *a,
                   re_xrefset_t *out);

// Number of references made from a given address.
size_t re_xref_from_count(const re_xrefset_t *s, uint64_t va);

// The i-th reference made from va, or NULL when there is no such reference.
const re_xref_t *re_xref_from_at(const re_xrefset_t *s, uint64_t va, size_t i);

// Number of references made to a given address.
size_t re_xref_to_count(const re_xrefset_t *s, uint64_t va);

// The i-th reference made to va, or NULL when there is no such reference.
const re_xref_t *re_xref_to_at(const re_xrefset_t *s, uint64_t va, size_t i);

// Every distinct string a function touches, in address order. This is the single
// most useful question about a function, so it gets its own accessor.
size_t re_xref_func_strings(const re_xrefset_t *s, const re_func_t *f, re_arena_t *a,
                            re_vec_t *out);

// Every distinct call target of a function, as indices into fwd.
size_t re_xref_func_calls(const re_xrefset_t *s, const re_func_t *f);

// Refs whose source instruction lies in [va, va+size), as indices into fwd. A
// function has to be asked about by its body, not by its entry, because the
// instructions that make references are spread through it. A max of 0 means all.
size_t re_xref_out_of(const re_xrefset_t *s, re_arena_t *a, uint64_t va, uint64_t size, size_t max,
                      re_vec_t *out);

// Refs whose target lies in [va, va+size), as indices into fwd. This is the
// caller query for a function, and it counts a call into a shared tail as well
// as one to the entry.
size_t re_xref_into(const re_xrefset_t *s, re_arena_t *a, uint64_t va, uint64_t size, size_t max,
                    re_vec_t *out);

// How many refs target [va, va+size), without allocating. max 0 means unbounded.
size_t re_xref_into_count(const re_xrefset_t *s, uint64_t va, uint64_t size, size_t max);
#ifdef __cplusplus
}
#endif
