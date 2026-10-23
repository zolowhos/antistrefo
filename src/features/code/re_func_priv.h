// re_func_priv.h - the walk state shared by the seeding pass and the block walk.
// Module: feature (C11).
// Owns: the walk context, the walk entry points, and the deep tier's trick hooks.
// Depends: re_func.h, re_code.h. Private to features/code and features/deep; not a seam.
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "features/code/re_func.h"

// What the instruction before an address left behind, as far as the deep tier's
// trick recognisers care. Kept per fall-through address in a small direct mapped
// table, so the facts survive the walk taking pending blocks in queue order.
typedef struct {
    uint64_t next;     // the address this record is the predecessor state of, 0 empty
    uint64_t jcc_to;   // target of a conditional branch that ended here
    uint64_t reg_val;  // value of reg, when reg is not RE_TRICK_NOREG
    uint64_t push_val; // the value a push immediate left on the stack
    uint8_t jcc;       // condition code plus one, 0 when the predecessor was no jcc
    uint8_t zf;        // 0 unknown, 1 clear, 2 set
    uint8_t cf;        // 0 unknown, 1 clear, 2 set
    uint8_t reg;       // the one register holding a known constant
    bool push;         // the predecessor pushed push_val
} re_trick_t;

#define RE_TRICK_SLOTS 256u
#define RE_TRICK_NOREG 0xFFu
#define RE_TRICK_NONE 0  // walk the instruction as decoded
#define RE_TRICK_FALL 1  // a branch that is never taken: continue at the next instruction
#define RE_TRICK_LOCAL 2 // a jump that always lands on *to, inside this function

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
    bool partial;    // a work budget or the memory ceiling stopped a pass early
    // One bit per code byte, set once a start is queued, so a start that a thousand
    // calls name is queued once. NULL when the arena could not supply it.
    uint64_t *queued;
    re_trick_t *tricks; // RE_TRICK_SLOTS records, deep tier only, else NULL
    uint64_t decodes;   // decode attempts in the current function
    size_t n_tricks;    // control flow the trick recognisers rewrote
    size_t qcursor;     // the next queue entry to walk
    size_t rejected;    // unwind entries the deep tier refused as forged
    size_t rounds;      // gap sweep rounds run
    uint32_t entry_rva; // the image entry, flagged RE_FUNC_ENTRY when walked
} walk_t;

// Append one address to a vector, through the arena the walk was given.
void re_walk_push(re_arena_t *a, re_vec_t *v, uint64_t x);

// Keep one walked function. False once an arena push has failed.
bool re_walk_keep(walk_t *w, re_func_t *f);

// Walk every queued start not yet walked, tagging each new record with flags.
// Returns how many records it kept.
size_t re_walk_drain(walk_t *w, uint32_t flags);

// Queue a candidate function start once. An address outside the code, on a hostile
// page, or already queued is dropped, which the dequeue would have done anyway.
void re_walk_queue(walk_t *w, uint64_t va);

// True when the arena has grown past the tier's memory ceiling.
bool re_walk_over_budget(walk_t *w);

// Walk one function from start, filling the record. Every instruction in the record
// was decoded by this call and marked covered, which is what stops a second walk
// from reporting another function's body as its own.
void re_walk_func(walk_t *w, uint64_t start, re_func_t *f);

// The cheap byte test the prologue sweep uses to find functions nothing points at.
// It never calls the decoder, because that sweep probes every byte of a section.
bool re_walk_looks_like_start(const re_code_t *c, uint64_t va);

// Deep tier: read the predecessor state of in, decide whether it is an opaque
// predicate, a split jump, push and ret, call and pop, or a jump through a register
// holding a constant, and record in's own state for its successor. Returns one of
// RE_TRICK_*; *to is the landing address for RE_TRICK_LOCAL.
int re_trick_step(walk_t *w, const re_insn_t *in, uint64_t *to);

// Deep tier passes over the finished walk, in features/deep/re_fdeep.c. Each takes
// functions the entry passes missed or mis-sized and returns how many it added.
size_t re_fdeep_pdata(walk_t *w);
size_t re_fdeep_gaps(walk_t *w);
