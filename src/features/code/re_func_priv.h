// re_func_priv.h - the walk state shared by the seeding pass and the block walk.
// Module: feature (C11).
// Owns: the walk context and the two walk entry points the scan calls.
// Depends: re_func.h and re_code.h. Private to src/features/code; not a seam.
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "features/code/re_func.h"

// What a walk needs beyond the function it is filling in: the code map, the arena
// everything is allocated from, and the two lists it records into. `blocks` is
// reused across every function so each walk does not abandon a grow-array in the
// arena (that was the multi-GB RSS on large game DLLs).
typedef struct {
    re_code_t *code;
    re_arena_t *a;
    re_vec_t *edges; // re_edge_t
    re_vec_t *queue; // uint64_t, candidate function starts still to walk
    re_vec_t *out;   // re_func_t
    re_vec_t blocks; // uint64_t, pending block VAs for the current function
    bool truncated;  // an arena push failed (OOM); stop seeding further
} walk_t;

// Append one address to a vector, through the arena the walk was given.
void re_walk_push(re_arena_t *a, re_vec_t *v, uint64_t x);

// Walk one function from start, filling the record. Every instruction in the record
// was decoded by this call and marked covered, which is what stops a second walk
// from reporting another function's body as its own.
void re_walk_func(walk_t *w, uint64_t start, re_func_t *f);

// The cheap byte test the prologue sweep uses to find functions nothing points at.
// It never calls the decoder, because that sweep probes every byte of a section.
bool re_walk_looks_like_start(const re_code_t *c, uint64_t va);
