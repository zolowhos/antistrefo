// re_x64_priv.h - internal decoder types for x86-64. Private to src/features/disasm.
// Module: feature (C11).
// Owns: the decode result struct, the opcode classes, and the backend entry points.
// Depends: re_disasm.h. No other feature may include this; it is not a seam.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/meta/re_disasm.h"
#include "utils/text/re_strbuf.h"

// What an opcode does to the instruction stream. The decoder only needs to know
// whether a ModRM follows and how wide the immediate is, so a class is the whole
// of the knowledge needed to walk to the next instruction.
typedef enum {
    XC_BAD = 0,     // not a valid 64-bit opcode, so the walk stops here
    XC_NONE,        // nothing follows
    XC_MODRM,       // ModRM only
    XC_MODRM_IB,    // ModRM then imm8
    XC_MODRM_IW,    // ModRM then imm16
    XC_MODRM_IZ,    // ModRM then imm16 or imm32, picked by the 0x66 prefix
    XC_MODRM_IZB,   // ModRM then imm8, sign extended to the operand size
    XC_REL8,        // rel8
    XC_REL32,       // rel32, which is the only branch width 64-bit mode uses
    XC_IB,          // imm8
    XC_IW,          // imm16
    XC_IZ,          // imm16 or imm32, no ModRM
    XC_IBS,         // imm8 sign extended to 64 bits
    XC_IV,          // imm16, imm32, or imm64, the last only with REX.W
    XC_PTR,         // an 8 byte absolute address, no ModRM
    XC_IW_IB,       // imm16 then imm8, which only enter needs
    XC_MODRM_F6,    // ModRM, then imm8 only when reg selects TEST
    XC_MODRM_F7,    // ModRM, then imm16/32 only when reg selects TEST
    XC_3DNOW,       // 0F 0F, ModRM then a trailing imm8 selector
    XC_MODRM_NOMEM, // one ModRM byte and no addressing: 0F 20..23, mov to and
                    // from a control register. Mod is ignored by the encoding, so
                    // reading a displacement there eats the next instruction.
} x64_class_t;

// A decomposed memory operand. Kept on the instruction so text rendering and the
// emitter never have to re-parse the ModRM, and so neither can disagree about it.
#define RE_REG_NONE 0xFFu
#define RE_REG_RIP 0x10u

// A decoded instruction, before it is projected onto the arch neutral re_insn_t.
typedef struct {
    uint16_t id;      // map in the high bits, opcode in the low
    uint8_t map;      // 0 one-byte, 1 for 0F, 2 for 0F38, 3 for 0F3A
    uint8_t opcode;   // the opcode byte itself, before the map is applied
    uint8_t cls;      // x64_class_t
    uint8_t modrm;    // 0 when the instruction has no ModRM
    bool has_modrm;   // separate from modrm, because a ModRM byte can be 0x00
    uint8_t reg;      // the ModRM reg field, extended by REX.R
    uint8_t rm;       // the ModRM rm field, extended by REX.B
    uint8_t mod;      // the ModRM mod field: 3 means register, otherwise memory
    uint8_t base;     // memory base register, or RE_REG_NONE
    uint8_t index;    // memory index register, or RE_REG_NONE
    uint8_t scale;    // index scale: 1, 2, 4 or 8
    bool is_mem;      // the ModRM operand is memory rather than a register
    uint8_t rex;      // REX byte, 0 when absent
    uint8_t pfx;      // the SIMD prefix: 0 none, 1 is 0x66, 2 is 0xF3, 3 is 0xF2
    uint8_t vex_pp;   // the VEX implied prefix, same encoding as pfx
    uint8_t vex_vvvv; // the VEX third register operand, 0 when the encoding is not VEX
    uint8_t size;     // bytes consumed from the span
    uint8_t opsize;   // operand size in bytes: 2, 4 or 8
    uint8_t addrsize; // address size in bytes: 4 or 8
    bool rip_rel;     // the ModRM used RIP relative addressing
    bool vex;         // encoded with a VEX or EVEX prefix
    bool vex_l;       // the VEX length bit: false is 128 bit, true is 256
    bool vex_w;       // the VEX W bit, which widens the same opcode the way REX.W does
    int64_t imm;      // immediate, or the relative offset for a branch
    int64_t disp;     // RIP relative displacement, signed
    uint64_t target;  // resolved branch or call destination
    uint64_t mem;     // effective address of a RIP relative operand
    bool has_target;
} x64_insn_t;

// The opcode id packs the map so one 16 bit value identifies any encoding.
// How many temporaries one function may mint. The emitter names them through a
// fixed table of this size, so the bound is shared: a lowering that went past it
// would mint a name the emitter cannot hold.
#define RE_UNIQ_MAX 512

#define X64_MAP_SHIFT 8
#define X64_ID(map, op) ((uint16_t)(((map) << X64_MAP_SHIFT) | (op)))
#define X64_ID_MAP(id) ((uint8_t)((id) >> X64_MAP_SHIFT))
#define X64_ID_OP(id) ((uint8_t)((id) & 0xFFu))

// Decode one instruction from the front of p. Returns false, and writes nothing
// usable, on a bad opcode or a truncated instruction. Never guesses a length.
bool x64_decode(const uint8_t *p, size_t n, uint64_t addr, x64_insn_t *out);

// Operand and register helpers, so re_x64_decode.c and re_x64_ops.c agree.
const char *x64_mnem(uint16_t id);
unsigned x64_reg_size(const x64_insn_t *in);
const char *x64_reg_name(unsigned reg, uint8_t opsize);
const char *x64_reg_name_ex(unsigned reg, uint8_t opsize, uint8_t rex);

// Mnemonic selection for the encodings the opcode alone does not determine: the four
// names one SIMD opcode takes under the four prefixes, the VEX maps, and the x87
// escapes. All of them live in re_x64_simd.c and return NULL rather than a number
// with a shape around it when the encoding has no name.
const char *x64_simd_mnem(uint8_t map, unsigned op, uint8_t pfx);

// True when the opcode belongs to one of those tables, that is, when the prefix
// is what decides its name. x64_simd_mnem returning NULL for such an opcode means
// the encoding has no form under this prefix, and the opcode map's one name must
// not be used as a fallback: that name is the form of a different prefix.
bool x64_simd_known(uint8_t map, unsigned op);

// The group opcodes of the 0F map and the 3DNow selector. These take their mnemonic
// from the reg field of the ModRM byte, so none of them can be named by the opcode
// table, and a few of them change name with the prefix as well. Returns NULL when
// the field selects nothing that has a name, which is not the same as a name that
// a fallback should replace.
const char *x64_grp0f_mnem(unsigned op, unsigned modrm, int64_t imm, bool mem, uint8_t pfx);

// The x87 register forms need the stack register rendered, so the shape of the
// operand list comes back with the name: X87_NONE, X87_ST, X87_ST0_ST or X87_ST_ST0.
#define X87_NONE 0u
#define X87_ST 1u
#define X87_ST0_ST 2u
#define X87_ST_ST0 3u
const char *x64_x87_mnem(uint8_t esc, uint8_t modrm, bool mem, uint8_t *shape, uint8_t *st);

// The vector register numbering the projection uses, so a renderer can tell a
// vector operand from an integer one without consulting the encoding again. The
// stride is 32 because a ymm register is what a VEX length bit makes of an xmm one,
// and the mmx file sits on top of both because its registers number eight and are
// shared with the stack of an escape that no longer exists.
#define RE_X64_XMM_BASE 128u
#define RE_X64_YMM_BASE 160u
#define RE_X64_MMX_BASE 192u

// True when the three byte F3 0F 1E FA/FB endbr sequence starts at p. Modern
// x86-64 code opens nearly every function with one, so it must be recognized.
bool x64_is_endbr(const uint8_t *p, size_t n);

// The vtable, wired up in re_x64_ops.c.
extern const struct re_disasm re_disasm_x64;
extern const struct re_disasm re_disasm_x86;

// The name of an instruction, in re_x64_name.c, and the questions the renderer asks
// about the shape of its operand list before it prints one. All of them read the
// projected record rather than the bytes, so the renderer cannot disagree with the
// walk about either the name or the operands.
const char *x64_text_mnemonic(const re_insn_t *in);
const char *x64_text_vex_special(const re_insn_t *in);
const char *x64_text_jcc(unsigned op);
const char *x64_text_cmov(unsigned op);
bool x64_text_has_imm(const re_insn_t *in);
bool x64_group0f_single(unsigned op);
bool x64_group0f_silent(const re_insn_t *in);
bool x64_simd_store(unsigned op, uint8_t pfx);
bool x64_is_group_op(const re_insn_t *in);
bool x64_implicit_reg(const re_insn_t *in, unsigned *reg, uint8_t *force_size);

// The x87 half of the text, in re_x64_x87.c beside the escape tables it reads: the
// width of a memory operand the operation decides, and the stack register forms that
// the whole ModRM byte decides.
const char *x64_x87_mem_kw(const re_insn_t *in);
void x64_x87_regs(re_strbuf_t *out, const re_insn_t *in);

// Text rendering, in re_x64_text.c, and the IR lowering, split across three files
// so each stays inside the line caps: re_x64_lower.c keeps the primitives, the
// mov and test forms, the integer arithmetic block and the flow ops;
// re_x64_lower2.c holds the second integer tranche (shifts, rotates, multiply and
// divide, the stack forms, the extensions, the bit tests); re_x64_lower_simd.c
// holds the vector and scalar float forms. All of them read the projected record
// rather than the bytes, so re_insn_t has to be self sufficient for presentation
// and the IR never needs the image again.
void x64_render(const re_insn_t *in, re_arena_t *a, re_strbuf_t *out);
size_t x64_lower(const re_insn_t *in, re_ir_func_t *f, re_arena_t *a);

// Lowering primitives, in re_x64_lower.c, shared with the other two files so a
// second tranche does not re-derive how an operand, an address or an immediate
// becomes a varnode. Every one refuses rather than guesses, exactly as the
// originals did.
uint16_t x64_lower_osize(const re_insn_t *in);
re_varnode_t x64_lower_reg(const re_insn_t *in, unsigned r);
re_varnode_t x64_lower_rm(const re_insn_t *in);
re_varnode_t x64_lower_uniq(re_ir_func_t *f, uint16_t size);
bool x64_lower_uniq_ok(const re_ir_func_t *f);
re_ir_op_t x64_lower_mk(re_op_kind_t kind);
bool x64_lower_push(re_ir_func_t *f, re_arena_t *a, re_ir_op_t op);
bool x64_lower_imm(re_ir_func_t *f, re_arena_t *a, int64_t v, re_varnode_t *out);
bool x64_lower_addr(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, re_varnode_t *out);

// The second integer tranche and the vector forms, in their own files, with the
// read, write, nop, trap and widening helpers the three share.
bool x64_lower2(const re_insn_t *in, re_ir_func_t *f, re_arena_t *a);
bool x64_lower2_map1(const re_insn_t *in, re_ir_func_t *f, re_arena_t *a);
bool x64_lower3_map0(const re_insn_t *in, re_ir_func_t *f, re_arena_t *a);
bool x64_lower_simd(const re_insn_t *in, re_ir_func_t *f, re_arena_t *a);
bool x64_ld_read_rm(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, uint16_t size,
                    re_varnode_t *out);
bool x64_ld_form2(re_ir_func_t *f, re_arena_t *a, re_op_kind_t kind, re_varnode_t dst,
                  re_varnode_t a0, re_varnode_t b0, re_varnode_t *result);
bool x64_ld_store_rm(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, re_varnode_t val);
bool x64_ld_nop(re_ir_func_t *f, re_arena_t *a);
bool x64_ld_int(re_ir_func_t *f, re_arena_t *a, int64_t v);
bool x64_ld_extend(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, bool sgn, uint16_t srcw);

// The flag model, in re_x64_flags.c: a flag varnode, and the two shapes of
// hidden comparison a flag setting operation records for the next branch.
re_varnode_t x64_flag_vn(unsigned flag);
bool x64_flags_pair(re_ir_func_t *f, re_arena_t *a, unsigned kind, re_varnode_t a0,
                    re_varnode_t b0);
bool x64_flags_result(re_ir_func_t *f, re_arena_t *a, unsigned kind, re_varnode_t result);
