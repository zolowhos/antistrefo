// re_decompile.c - the decompiler's public entry: one function in, C-like source out.
// Module: feature (C11).
// Owns: the two calls the CLI, the GUI and the MCP server make.
// Depends: re_decompile.h, the core in src/features/dec/core (graph, frame, liveness,
//           expressions, structuring), and re_dc_walk for the decodability check.
#include "features/dec/re_decompile.h"

#include "features/dec/core/re_dcx.h"
#include "features/dec/re_dc_walk.h"

bool re_decompile_ok(const re_decomp_t *d, const re_func_t *f) {
    re_dc_walk_t w = {0};
    if (!d || !f || !d->code || !d->arena)
        return false;
    re_dc_walk(d->code, f, &w, d->arena);
    return RE_VEC_LEN(&w.insns) > 0;
}

void re_decompile_func(const re_decomp_t *d, const re_func_t *f, const re_stack_t *st,
                       re_strbuf_t *out) {
    if (!d || !f || !out || !d->code || !d->arena)
        return;
    if (!dx_decompile(d, f, st, out))
        re_strbuf_puts(out, "// this body did not decode to any instruction\n");
}
