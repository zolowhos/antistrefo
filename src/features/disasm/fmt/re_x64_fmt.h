// re_x64_fmt.h - the x86-64 renderer's private context, shared by its two files.
// Module: feature (C11).
// Owns: the per instruction rendering context and the memory operand entry points.
// Depends: re_x64_form.h and re_strbuf. Private to src/features/disasm.
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "features/disasm/fmt/re_x64_form.h"
#include "utils/text/re_strbuf.h"

typedef struct {
    const x64_insn_t *in;
    const x64_form_t *form;
    const char *ops; // the operand spec actually rendered
    uint64_t addr;
    unsigned osz;  // the effective operand size, after the 64-bit defaults
    unsigned vlen; // the vector length in bytes
    bool w;        // the W bit
    bool simd;     // a vector, mmx, mask or x87 instruction: memory always states its size
    bool branch;   // a near transfer, where F2 is the bnd hint
    bool indirect; // an indirect call or jump, where 3E is the notrack hint
} x64_fctx_t;

// A general purpose register name. rex selects spl..dil over ah..bh for the byte forms.
const char *x64_fmt_gp(unsigned reg, unsigned size, bool rex);

// The ModRM memory operand of the given width, with its size keyword when one is needed,
// its segment, and the EVEX broadcast and compressed displacement applied.
void x64_fmt_mem(re_strbuf_t *o, const x64_fctx_t *c, unsigned size);
// A VSIB memory operand: spec is the element size and index width, "dx" "qh" "qx".
void x64_fmt_vsib(re_strbuf_t *o, const x64_fctx_t *c, const char *spec);
// The absolute moffs operand of the A0..A3 moves.
void x64_fmt_moffs(re_strbuf_t *o, const x64_fctx_t *c, unsigned size);
// True when an operand spec names a vector, mmx or mask register.
bool x64_fmt_is_simd(const char *ops);

// Render one decoded instruction at addr.
void x64_fmt_insn(const x64_insn_t *in, uint64_t addr, re_strbuf_t *o);
