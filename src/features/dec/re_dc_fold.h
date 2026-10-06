// re_dc_fold.h - copy propagation and dead stack traffic over one function.
// Module: feature (C11).
// Owns: the fold flags and the rewrite that runs after lowering.
// Depends: re_ir. Rewrites ops in place, so a caller that counts ops still can.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include "features/dec/re_ir.h"

// Alias: a register copy that exists so a call prints the source name. Statement:
// a call whose result is not read, printed as a call rather than an assignment.
// Skip: a call the matching return will print. Disp: a load or store whose
// const_val is a displacement already folded into the address.
#define RE_FOLD_ALIAS 0x100u
#define RE_FOLD_STMT 0x200u
#define RE_FOLD_SKIP 0x400u
#define RE_FOLD_DISP 0x800u

// Rewrite f. Never removes an op, so the per instruction counts stay valid, and
// never drops a call, a store that is not a save, or a branch. An IR it does not
// understand is left as it arrived.
void re_dc_fold(re_ir_func_t *f);
#ifdef __cplusplus
}
#endif
