// re_deep_priv.h - the deep tier's internal entry points, shared by its files.
// Module: feature (C11).
// Owns: the hostile classifier, the control flow recovery and the data recovery.
// Depends: re_deep.h, re_decompile. Private to src/features/analysis; not a seam.
#pragma once

#include "features/analysis/re_deep.h"
#include "features/dec/re_decompile.h"

// Classify executable pages as packed or encrypted, record them as notes, and mark
// the code map so the walk never starts a function inside one. scratch is the run's
// own arena and is not reset.
void re_deep_hostile(re_analysis_t *an, re_arena_t *scratch);

// Control flow the walk left flattened: detect a dispatcher loop and record the note.
// Returns how many functions it flagged.
size_t re_deep_flatten(re_analysis_t *an);

// Data the compiler hid: API hashes, GetProcAddress calls and encrypted strings.
// Returns how many notes it added.
size_t re_deep_data(re_analysis_t *an, re_arena_t *scratch);

// Virtualised functions: a VM entry, a dispatcher, or a known protector's section.
// Returns how many functions it flagged.
size_t re_deep_vm(re_analysis_t *an);
