// re_limits.h - what one analysis tier may store and how much work it may spend.
// Module: feature (C11).
// Owns: re_limits_t, the entry tier's caps (today's values) and the deep tier's budgets.
// Depends: none. Read through re_code_t::lim, so a pass never takes its own constant.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RE_LIM_NONE UINT64_MAX

// Result caps make the entry tier fast and are lifted in the deep tier. Work budgets
// (decode attempts, sweep rounds, memory) stay finite in both, because a hostile file
// can ask for unbounded work but must never get it. Reaching a budget sets the pass's
// partial flag; it never fails silently.
typedef struct {
    bool deep;              // the deep tier: pdata reconcile, gap sweep, deobfuscation
    uint64_t edges;         // control flow and data edges kept, whole image
    uint64_t insns;         // instructions walked per function
    uint64_t ptr_seeds;     // code pointers taken from data sections
    uint64_t str_hits;      // strings stored by the strings pass
    uint64_t xref_strings;  // strings indexed to name data references
    uint64_t regions;       // classified windows
    uint64_t stack_sample;  // functions given a stack frame in the stack pass
    uint32_t jtable_max;    // entries a jump table may have and still be counted
    uint32_t gap_rounds;    // gap sweep fixpoint rounds, 0 disables the sweep
    uint64_t decode_budget; // decode attempts per function, junk skips included
    uint64_t mem_max;       // arena bytes before a pass stops, RE_LIM_NONE for none
} re_limits_t;

// A cap as a size_t for an API that counts in size_t; RE_LIM_NONE becomes SIZE_MAX.
static inline size_t re_lim_size(uint64_t v) {
    return v > (uint64_t)SIZE_MAX ? SIZE_MAX : (size_t)v;
}

static inline re_limits_t re_limits_entry(void) {
    re_limits_t l;
    l.deep = false;
    l.edges = 2000000u;
    l.insns = 4096u;
    l.ptr_seeds = 4096u;
    l.str_hits = 20000u;
    l.xref_strings = 20000u;
    l.regions = 65536u;
    l.stack_sample = 256u;
    l.jtable_max = 1024u;
    l.gap_rounds = 0u;
    l.decode_budget = RE_LIM_NONE;
    l.mem_max = RE_LIM_NONE;
    return l;
}

// mem_max is the caller's: a fraction of physical memory, or RE_MEM_MAX.
static inline re_limits_t re_limits_deep(uint64_t mem_max) {
    re_limits_t l;
    l.deep = true;
    l.edges = RE_LIM_NONE;
    l.insns = 1u << 20;
    l.ptr_seeds = RE_LIM_NONE;
    l.str_hits = RE_LIM_NONE;
    l.xref_strings = RE_LIM_NONE;
    l.regions = RE_LIM_NONE;
    l.stack_sample = RE_LIM_NONE;
    l.jtable_max = 65536u;
    l.gap_rounds = 8u;
    l.decode_budget = 1u << 22;
    l.mem_max = mem_max ? mem_max : RE_LIM_NONE;
    return l;
}
#ifdef __cplusplus
}
#endif
