// re_decompile.h - turns one recovered function back into readable source.
// Module: feature (C11).
// Owns: the decompiler's interface, and nothing else.
// Depends: re_code, re_func, re_ir, re_stack, re_xref, re_jtable, re_arena, re_str. The
//           architecture arrives through the re_disasm_t vtable, so no per-arch detail.
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

// Everything the emitter needs that is not per function. The xref set is what
// turns a call target into an imported name, and the stack record is what turns a
// displacement into a named local.
typedef struct {
    re_code_t *code;
    const re_xrefset_t *xrefs;
    const re_vec_t *jtables; // tables re_jtable_scan already accepted, or NULL
    re_arena_t *arena;
    re_vec_t *sites;        // re_dc_site_t: output line to instruction address, or NULL
    const re_fscan_t *scan; // the function table, for callee names and noreturn; or NULL
} re_decomp_t;

// Write f as C-like source to out: blocks are lifted to the IR, values are propagated
// into expressions, calls take the arguments the calling convention passes, and the
// control flow is structured into if, while, do, switch, break and continue, with a
// goto only where the graph allows nothing else. An instruction the backend does not
// lift is printed in place as an __asm statement, so nothing is silently dropped.
void re_decompile_func(const re_decomp_t *d, const re_func_t *f, const re_stack_t *st,
                       re_strbuf_t *out);

// True when the function decodes to at least one instruction. A false here means the
// body is data or an arch we do not handle, and the caller should say so rather than
// print an empty function as if it were the truth. Instructions that decode but do not
// lift are reported in the output's header line, not here.
bool re_decompile_ok(const re_decomp_t *d, const re_func_t *f);
#ifdef __cplusplus
}
#endif
