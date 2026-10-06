// re_decompile.h - turns one recovered function back into readable source.
// Module: feature (C11).
// Owns: the emitter's interface, and nothing else.
// Depends: re_code, re_func, re_ir, re_stack, re_xref, re_arena, re_str.
// Depends: re_code, re_func, re_ir, re_stack, re_xref. The architecture arrives
//           through the re_disasm_t vtable, so this file has no per-arch knowledge.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/code/re_code.h"
#include "features/code/re_func.h"
#include "features/code/re_jtable.h"
#include "features/code/re_stack.h"
#include "features/code/re_xref.h"
#include "features/dec/re_ir.h"
#include "utils/mem/re_arena.h"
#include "utils/text/re_str.h"

#define RE_DC_MAX_VARS \
    512 // temporaries per function, so a runaway body cannot grow
        // the table. The lowering refuses past this rather than mint a
        // name that would collide.

// Everything the emitter needs that is not per function. The xref set is what
// turns a call target into an imported name, and the stack record is what turns a
// displacement into a named local.
typedef struct {
    re_code_t *code;
    const re_xrefset_t *xrefs;
    const re_vec_t *jtables; // tables re_jtable_scan already accepted, or NULL
    re_arena_t *arena;
    re_vec_t *sites; // re_dc_site_t, filled with the statement-to-address map
} re_decomp_t;

// Write the C-like body of f to out. The output is pseudo C, not compilable: it is
// the register transfer list expressed in the shape a reader expects, with the
// control flow and the calls named. Anything the arch did not lower is printed as a
// comment carrying the address, so nothing is silently dropped.
void re_decompile_func(const re_decomp_t *d, const re_func_t *f, const re_stack_t *st,
                       re_strbuf_t *out);

// True when the function lowered to something worth reading: at least one modelled
// op and no instruction the emitter had to skip over. A false here means the body is
// data or an arch we do not handle, and the caller should say so rather than print
// an empty function as if it were the truth.
bool re_decompile_ok(const re_decomp_t *d, const re_func_t *f);
#ifdef __cplusplus
}
#endif
