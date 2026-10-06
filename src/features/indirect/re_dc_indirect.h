// re_dc_indirect.h - a name for an indirect call when one def reaches it.
// Module: feature (C11).
// Owns: the lea case and the slot spelling. An ambiguous call is not guessed.
// Depends: re_code. One reaching definition, or the slot form.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stddef.h>
#include <stdint.h>

#include "features/code/re_code.h"

// Write the call text. A single lea of a function prints that function. A call
// through [reg+disp] prints (*slot_0xDISP)(reg). False when the instruction is
// not an indirect call, so the caller keeps call_0x.
bool re_dc_indirect_format(const re_code_t *c, uint64_t call_va, char *dst, size_t cap);

// The same memory call when a vtable was recovered for the object. Slot is
// disp/8, object first. A missing table falls back to the slot form.
bool re_dc_indirect_slot(const re_code_t *c, uint64_t call_va, const char *table, char *dst,
                         size_t cap);
#ifdef __cplusplus
}
#endif
