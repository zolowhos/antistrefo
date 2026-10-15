// re_nameref.h - ordered references to an exact set of names.
// Module: feature (C11).
// Owns: the hit list, the names never referenced, and an optional order alignment.
// Depends: re_pe, re_vec, re_str, re_arena. No I/O, no decoder, x86-64 RIP only.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/pe/re_pe.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_vec.h"
#include "utils/text/re_str.h"

// One name to look for. rva is the provider address used to order the names the
// consumer never loads. has_rva is false for a name that came from a text list.
typedef struct {
    re_str_t name;
    uint32_t rva;
    bool has_rva;
} re_nameref_in_t;

// One RIP-relative load, in the order the instruction appears. order_index is -1
// until an order list claims this name. The string address is the identity: two
// names that share an export rva stay two hits.
typedef struct {
    uint64_t from;
    uint64_t to;
    uint32_t index;
    re_str_t name;
    int32_t order_index;
    re_str_t order_name;
} re_nameref_hit_t;

// A provider name no instruction loads. order_name is set only when a single
// contiguous hole in the order list has exactly this many unreferenced names.
typedef struct {
    re_str_t name;
    uint32_t rva;
    uint32_t ord;
    bool has_rva;
    int32_t order_index;
    re_str_t order_name;
} re_nameref_miss_t;

// An order-list entry the reference sequence skipped. name is the unreferenced
// provider name filled into this hole, or empty when the hole was not filled.
typedef struct {
    re_str_t name;
    re_str_t order_name;
    int32_t order_index;
    uint32_t rva;
    bool has_rva;
} re_nameref_gap_t;

typedef struct {
    re_vec_t hits;         // re_nameref_hit_t
    re_vec_t unreferenced; // re_nameref_miss_t
    re_vec_t absent;       // re_nameref_gap_t
} re_nameref_t;

// Walk the consumer's executable sections for RIP-relative LEA and MOV whose
// target is the start of one of names. order may be NULL when norder is 0.
bool re_nameref_scan(const re_pe_t *pe, const re_nameref_in_t *names, size_t nnames,
                     const re_str_t *order, size_t norder, re_arena_t *a, re_nameref_t *out);
#ifdef __cplusplus
}
#endif
