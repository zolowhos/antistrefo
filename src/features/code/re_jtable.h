// re_jtable.h - jump table detection behind an indirect branch.
// Module: feature (C11).
// Owns: recognising a table of case targets and reporting where it lives.
// Depends: re_code, re_func, re_pe. Refuses a table it cannot count.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/code/re_code.h"
#include "features/code/re_func.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_vec.h"

// A table is only reported when its extent is known. A run of valid targets that
// never ends is a pointer array, not a switch, and guessing a length for it would
// be inventing a case count nobody can check.
#define RE_JTABLE_MIN 2u
#define RE_JTABLE_MAX 1024u

typedef struct {
    uint64_t table_va; // first entry
    uint64_t at;       // the indirect branch that dispatches through it
    uint64_t func_va;  // the function it belongs to
    uint32_t count;    // entries, known because the run terminated
    uint32_t bound;    // case count from the bounds check, 0 when there was none
    uint8_t width;     // 4 or 8 bytes per entry
    uint8_t encoding;  // 0 absolute VA, 1 RVA, 2 offset from table_va
} re_jtable_t;

// Scan every function that ends in an indirect branch. Candidates come from the
// data references the walk already recorded, so nothing is decoded a second time.
size_t re_jtable_scan(re_code_t *c, const re_fscan_t *scan, re_arena_t *a, re_vec_t *out);

// The target of entry i, in the same encoding the table was read with, or 0 when
// the index is out of range.
uint64_t re_jtable_target(const re_code_t *c, const re_jtable_t *t, uint32_t i);

// The table an indirect branch already accepted, or NULL. This does not scan.
const re_jtable_t *re_jtable_for(const re_vec_t *tables, uint64_t at);
#ifdef __cplusplus
}
#endif
