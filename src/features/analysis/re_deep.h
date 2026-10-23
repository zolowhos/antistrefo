// re_deep.h - the deep tier: the same passes as the entry tier, with the caps lifted.
// Module: feature (C11).
// Owns: re_deep_run and re_deep_attach, and the progress the background worker reads.
// Depends: re_analyze, re_db, re_thread. Runs on its own arena, never the live session's.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stdint.h>

#include "features/analysis/re_analyze.h"
#include "features/db/re_db.h"
#include "utils/sys/re_thread.h"

// Phase and items done, packed for one atomic cell: the phase in the top 8 bits and
// the item count in the rest. A worker publishes it; the UI reads it.
#define RE_DEEP_PHASES 10u

static inline int64_t re_deep_progress(uint8_t phase, uint64_t done) {
    return ((int64_t)phase << 56) | (int64_t)(done & 0x00FFFFFFFFFFFFFFull);
}

static inline uint8_t re_deep_phase(int64_t p) {
    return (uint8_t)((uint64_t)p >> 56);
}

static inline uint64_t re_deep_done(int64_t p) {
    return (uint64_t)p & 0x00FFFFFFFFFFFFFFull;
}

typedef struct {
    re_atomic_t progress;
    re_atomic_t cancel; // nonzero stops the run at the next phase boundary
} re_deep_ctrl_t;

// Run every pass at deep limits into out, which must be opened on its own arena, and
// write "<binary>.asdb" beside the binary. False when the file is not a binary this
// build decodes, or when the database could not be written; a memory ceiling stops the
// run early with the database marked incomplete and still returns true. ctrl may be
// NULL. The renames in an existing .alt are imported into the database.
bool re_deep_run(re_analysis_t *out, re_deep_ctrl_t *ctrl);

// Attach a valid .asdb to an open entry-tier context: load its results, mark every
// pass done, and keep the mapping alive through an->db. False when no valid database
// exists, in which case the context is unchanged and the entry tier stays in use.
bool re_deep_attach(re_analysis_t *an);

// The default memory ceiling: a quarter of installed memory, or RE_MEM_MAX when set.
uint64_t re_deep_mem_ceiling(void);
#ifdef __cplusplus
}
#endif
