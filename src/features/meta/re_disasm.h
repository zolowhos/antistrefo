// re_disasm.h - the disassembler contract. One vtable, many architectures.
// Module: feature (C11).
// Owns: the decoded instruction record and the vtable every backend implements.
// Depends: re_ir and re_buf. No Capstone type may appear in this header.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/dec/re_ir.h"
#include "utils/mem/re_buf.h"
#include "utils/text/re_str.h"
#include "utils/text/re_strbuf.h"

// A register index of this means the addressing mode left that part out, which is
// not the same as register zero.
#define RE_REG_NONE 0xFFu
#define RE_REG_RIP 0x10u

#define RE_MAX_INSN_LEN 16

typedef struct {
    uint64_t addr;
    uint8_t size;
    // The opcode identity, map in the high byte and opcode in the low. Widened
    // from a single byte in task 3, when the two and three byte maps arrived.
    uint16_t insn_id;
    uint8_t op_count;
    bool is_branch;
    bool is_call;
    bool is_return;
    bool is_conditional; // branch that falls through as well as jumping
    bool rip_rel;        // the memory operand is RIP relative
    bool has_target;     // target is meaningful
    bool has_mem;        // mem is the effective address of the memory operand
    bool has_modrm;
    uint8_t modrm;
    uint8_t opsize; // operand size in bytes: 1, 2, 4 or 8
    uint8_t rex;    // extension prefix, 0 when absent
    // The SIMD prefix the encoding carried, because the same opcode is a different
    // instruction under each: 0 none, 1 is 0x66, 2 is 0xF3, 3 is 0xF2. A VEX or EVEX
    // encoding states its prefix rather than carrying one, and it lands here too.
    uint8_t pfx;
    // The width of an address register: eight bytes, or four under the 0x67 override.
    // An address is not an operand, so this is not the operand size, and printing an
    // address register at the operand size turns [rax] into [eax] on every SIMD
    // instruction in the file.
    uint8_t addrsize;
    bool vex;   // the encoding used VEX or EVEX, so the mnemonic carries its own v
    bool vex_l; // the VEX length bit: false names xmm registers, true names ymm
    // The VEX W bit, which widens the operands the way REX.W does but reaches the
    // instructions REX cannot: 0F 6E without it is movd and with it is movq.
    bool vex_w;
    // The memory operand, decomposed. is_mem is false for a register operand, and
    // base and index are RE_REG_NONE when the addressing mode leaves them out.
    bool is_mem;
    uint8_t mod;
    uint8_t reg; // ModRM reg field, already extended by REX.R
    uint8_t rm;  // ModRM rm field, already extended by REX.B
    uint8_t base;
    uint8_t index;
    uint8_t scale;
    int64_t disp;
    int64_t imm;     // immediate value, or the relative offset of a branch
    uint64_t target; // resolved branch or call destination
    uint64_t mem;    // effective address of a RIP relative memory operand
    uint8_t ops[4];  // architecture specific operand encodings
    // The encoding itself, so a renderer can recover every detail the record above has
    // no field for: segment and repeat prefixes, EVEX masks, a second immediate.
    uint8_t raw[15];
    re_str_t text; // owned by the caller's arena, may be NULL
} re_insn_t;

// The opcode identity, readable without an architecture private header. The map
// is 0 for a one byte opcode, 1 for 0F, 2 for 0F38 and 3 for 0F3A. Arch neutral
// code asks what an instruction is through these, never through a private macro.
#define RE_INSN_MAP(i) ((unsigned)(((i)->insn_id >> 8) & 0xFFu))
#define RE_INSN_OPCODE(i) ((unsigned)((i)->insn_id & 0xFFu))

typedef struct re_disasm {
    void *ctx;
    const char *arch_name;
    uint32_t mode; // 16, 32 or 64 bit address width
    // Decode exactly one instruction at addr. Returns false on a decode failure,
    // an invalid byte, or running off the end of code. Never guesses.
    bool (*decode)(void *ctx, uint64_t addr, re_span_t code, re_insn_t *out);
    // Lower one decoded instruction into the IR. Returns ops written, 0 when the
    // instruction is not modelled, which is not an error.
    size_t (*lower)(void *ctx, const re_insn_t *insn, re_ir_func_t *f, re_arena_t *a);
    // Register name for display and for the emitter's variable naming.
    const char *(*reg_name)(void *ctx, unsigned reg);
    // Register width in bytes, for the emitter's type inference.
    unsigned (*reg_size)(void *ctx, unsigned reg);
    // True when this address looks like the start of a function.
    bool (*is_prologue)(void *ctx, uint64_t addr, re_span_t code);
    const re_trfunc_t *(*trfunc)(void *ctx, uint8_t insn_id);
    // Render one instruction as text into the caller's buffer. Text is a
    // presentation concern, so it sits behind the vtable and never in the IR.
    void (*render)(void *ctx, const re_insn_t *insn, re_arena_t *a, re_strbuf_t *out);
} re_disasm_t;

// Backends are registered by name so the CLI never links an architecture it did
// not ask for, and RE_ENABLE_DISASM=OFF drops the whole table.
const re_disasm_t *re_disasm_find(const char *arch_name);
size_t re_disasm_arch_count(void);
const char *re_disasm_arch_name(size_t index);
// PE IMAGE_FILE_MACHINE to a backend name, or NULL when none applies.
const char *re_disasm_for_machine(uint16_t pe_machine);
#ifdef __cplusplus
}
#endif
