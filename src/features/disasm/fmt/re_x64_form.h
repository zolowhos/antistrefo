// re_x64_form.h - x86-64 instruction forms: the name, the operand list, the constraints.
// Module: feature (C11).
// Owns: the form record, the operand spec grammar, the table registry and the lookup.
// Depends: re_x64_priv.h. Tables only: no state, no I/O, one lookup shared by both users.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/disasm/re_x64_priv.h"

// A form is one row of an opcode map: the encoding it matches and what it means. The
// decoder asks whether any form matches an encoding, which is how a reserved encoding is
// refused instead of being given a length it does not have, and the renderer asks which
// form matches, which is where the name and the operand list come from. One table drives
// both, so the two can never disagree about whether an encoding is an instruction.
//
// Matching is first-hit in table order, so a specific row goes before a general one.
//
// The operand list is a comma separated spec in the notation of the Intel opcode maps:
// an addressing letter, then a size code.
//   E  r/m, register or memory        G  general register from ModRM.reg
//   M  memory only (ModRM.mod != 3)   R  general register from ModRM.rm (mod 3)
//   Z  register in the opcode bits    B  general register from VEX.vvvv
//   I  immediate                      J  relative branch target
//   O  absolute moffs memory          A  accumulator of the size code
//   S  segment register (reg)         C  control register (reg)   D  debug register (reg)
//   V  vector register (reg)          W  vector r/m               U  vector register (rm)
//   H  vector register (vvvv)         L  vector register (imm8[7:4])
//   P  mmx register (reg)             Q  mmx r/m                  N  mmx register (rm)
//   K  mask register (reg)            T  mask register (rm) or memory
//   Y  mask register (vvvv)           X  VSIB memory, element size, 'h' for a half index
// Size codes: b w d q v(operand size) z(16 or 32) y(32 or 64 by W) t(80 bit) p(far
// pointer) x(vector length) h(half the vector length) r(quarter) e(eighth) dq(128)
// qq(256) ss sd sh(scalar float) m(no size: lea, the descriptor tables, the states).
// Immediates: Ib Iw Id Iz Iv, and Is: an imm8 sign extended to the operand size.
// Fixed words: 1 AL CL DX ST STi FS GS XMM0.

// Encoding spaces a form exists in.
#define XS_L 1u
#define XS_V 2u
#define XS_E 4u
#define XS_LV 3u
#define XS_VE 6u
#define XS_LVE 7u

// The mandatory prefix, as a mask over the four values the decoder reports in pfx:
// bit 0 none, bit 1 is 0x66, bit 2 is F3, bit 3 is F2. XP_ANY is an integer form whose
// prefixes are size overrides and repeats rather than part of the opcode.
#define XP_NP 1u
#define XP_66 2u
#define XP_F3 4u
#define XP_F2 8u
#define XP_ANY 15u

// The ModRM mod field: anything, memory only, or register only.
#define XM_ANY 0u
#define XM_MEM 1u
#define XM_REG 2u

#define X_ANY 0xFFu

// The W bit: VEX.W or EVEX.W in those spaces, REX.W in the legacy one.
#define XW_0 0u
#define XW_1 1u
#define XW_ANY 2u

// The vector length, as a mask: bit 0 is 128, bit 1 256, bit 2 512. 0 accepts any.
#define XL_128 1u
#define XL_256 2u
#define XL_512 4u
#define XL_ANY 0u

// Flags. The EVEX ones say which decorations the encoding may carry; the legacy ones say
// how the operand size defaults and whether a lock prefix is legal.
#define XF_K 0x01u   // EVEX write mask
#define XF_Z 0x02u   // EVEX zeroing
#define XF_ER 0x04u  // EVEX embedded rounding on a register form
#define XF_SAE 0x08u // EVEX suppress all exceptions on a register form
#define XF_LOCK 0x10u
#define XF_D64 0x20u // default 64-bit operand size, 0x66 narrows to 16
#define XF_F64 0x40u // forced 64-bit operand size, no prefix changes it
#define XF_T1S 0x80u // EVEX disp8 scales by the element, not the whole memory operand
#define XF_KZ (XF_K | XF_Z)

// The broadcast element of an EVEX form: none, or the element the {1toN} repeats.
#define XB_NONE 0u
#define XB_2 1u
#define XB_4 2u
#define XB_8 3u
#define XB_W 4u // four bytes under W0, eight under W1
#define XB_1 5u // a byte element: only a T1S form scales by it, nothing broadcasts one
#define XB_MASK 7u
// The EVEX W bit a form requires, packed above the broadcast element. VEX and legacy
// encodings of the same row ignore it: vaddps is W-ignored under VEX and W0 under EVEX.
#define XE_W0 0x10u
#define XE_W1 0x20u

typedef struct {
    uint8_t op;
    uint8_t sp;
    uint8_t pfx;
    uint8_t mod;
    uint8_t reg;
    uint8_t rm;
    uint8_t w;
    uint8_t osz; // 0 any, else the effective operand size 2, 4 or 8
    uint8_t l;
    uint8_t bc;
    uint8_t fl;
    const char *mn;
    const char *ops;
} x64_form_t;

// One table: every row of one opcode map, sorted by opcode. Each table file defines one.
typedef struct {
    uint8_t map;
    const x64_form_t *rows;
    size_t n;
} x64_ftab_t;

extern const x64_ftab_t x64_tab0;   // the one byte map
extern const x64_ftab_t x64_tab87;  // the x87 escapes D8..DF
extern const x64_ftab_t x64_tab1;   // the 0F map, integer and system
extern const x64_ftab_t x64_tab1s;  // the 0F map, SSE and its VEX and EVEX forms
extern const x64_ftab_t x64_tab1v;  // the 0F map, VEX and EVEX only
extern const x64_ftab_t x64_tab1e;  // the 0F map, EVEX names that refine the shared rows
extern const x64_ftab_t x64_tab38;  // the 0F38 map
extern const x64_ftab_t x64_tab38e; // the 0F38 map, EVEX only
extern const x64_ftab_t x64_tab3a;  // the 0F3A map

// Row builders. XR spells every constraint out; the rest are the common shapes.
// clang-format 18 and 19 lay out a braced list inside a macro differently, and no
// spelling satisfies both, so this one definition is held as written.
// clang-format off
#define XR(op, sp, pfx, mod, reg, rm, w, osz, l, bc, fl, mn, ops) \
    {op, sp, pfx, mod, reg, rm, w, osz, l, bc, fl, mn, ops}
// clang-format on
// An integer row: any prefix, any ModRM.
#define XI(op, fl, mn, ops) XR(op, XS_L, XP_ANY, XM_ANY, X_ANY, X_ANY, XW_ANY, 0, 0, 0, fl, mn, ops)
// An integer group row, selected by ModRM.reg.
#define XG(op, reg, fl, mn, ops) \
    XR(op, XS_L, XP_ANY, XM_ANY, reg, X_ANY, XW_ANY, 0, 0, 0, fl, mn, ops)
// An integer row selected by the effective operand size.
#define XO(op, osz, fl, mn, ops) \
    XR(op, XS_L, XP_ANY, XM_ANY, X_ANY, X_ANY, XW_ANY, osz, 0, 0, fl, mn, ops)
// A group row restricted to memory or register operands.
#define XGM(op, reg, mod, fl, mn, ops) \
    XR(op, XS_L, XP_ANY, mod, reg, X_ANY, XW_ANY, 0, 0, 0, fl, mn, ops)
// One register encoding of a group: the whole ModRM byte selects it.
#define XGR(op, reg, rm, pfx, mn) XR(op, XS_L, pfx, XM_REG, reg, rm, XW_ANY, 0, 0, 0, 0, mn, "")

// The form an encoding is, or NULL when it is no instruction at all.
const x64_form_t *x64_form_find(const x64_insn_t *in);

// The 3DNow operation the trailing selector byte names, or NULL.
const char *x64_3dnow_name(uint8_t sel);

// The vector length in bytes: 16, 32 or 64. An EVEX register form with embedded
// rounding reaches the full 512 bits whatever L'L says, because L'L holds the mode.
unsigned x64_vlen(const x64_insn_t *in);

// The W bit as forms read it.
static inline unsigned x64_wbit(const x64_insn_t *in) {
    return in->vex ? (unsigned)in->vex_w : (unsigned)((in->rex >> 3) & 1u);
}
