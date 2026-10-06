// re_dc_print.h - the printing layer of the decompiler: names, values, statements.
// Module: feature (C11).
// Owns: the emitter's mutable state and the condition rendering helpers.
// Depends: re_ir, re_dc_walk, re_stack, re_xref, re_disasm, re_strbuf.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/code/re_stack.h"
#include "features/code/re_xref.h"
#include "features/dec/re_dc_walk.h"
#include "features/dec/re_ir.h"
#include "features/flow/re_flow.h"
#include "features/meta/re_disasm.h"
#include "utils/text/re_strbuf.h"

#define RE_DC_REGS 32  // x86-64 general purpose registers, indexed by re_varnode_t.offset
#define RE_DC_TEXT 48  // width of a rendered operand, which is a short name or a literal
#define RE_DC_VARS 512 // temporaries per function, matching the IR's own bound

typedef struct {
    re_strbuf_t *o;
    re_arena_t *a;
    const re_xrefset_t *xrefs; // consulted only to name a call target
    uint64_t insn_addr;        // the instruction being lowered, so a ref can be found
    re_str_t reg[RE_DC_REGS];  // the name currently holding each register
    re_str_t uniq[RE_DC_VARS]; // the name of each temporary, by the IR's unique id
    int64_t cval[RE_DC_VARS];  // the value of each constant, by the same id
    bool caddr[RE_DC_VARS];    // and whether that constant is an address, not a number
    bool touched[RE_DC_REGS];  // registers written since the last call, the argument set
    const re_stack_t *st;      // for naming locals and for the call arguments
    bool have_cmp;             // a comparison is waiting for a branch to use
    uint32_t cmp_cc;           // and the condition that comparison computed
    uint8_t flag_writer;       // which instruction wrote the flags the branch reads
    char cmp_l[RE_DC_TEXT];
    char cmp_r[RE_DC_TEXT];
    char lname[RE_DC_TEXT];
    uint32_t next_tmp;
    size_t n_stmts;
    size_t n_unknown;
    const re_disasm_t *dis;
    const re_vec_t *jtables;
    const re_code_t *code;
    int16_t sw_disp[RE_SLOT_MAX]; // the stack displacements the body touched
    uint8_t sw_w[RE_SLOT_MAX];    // and the widest access each one saw
    uint32_t n_sw;
    uint32_t indent;    // brace nesting level, one step of four spaces per level
    uint64_t next_addr; // the address after the instruction being printed, so a
                        // branch to it can be recognised as a fallthrough
} re_dc_emit_t;

// Format into a caller supplied buffer, for the few places that need a fragment
// before it becomes a statement. The statement writer takes its format directly, so
// this exists only for composing one.
void re_dc_fmt(char *dst, size_t cap, const char *fmt, ...);

// The printed condition for a branch or a select whose four bit condition is cc,
// read against the flag writer the lowering recorded. A real comparison decides
// the full condition set; a test decides zero and sign of its bitwise and; every
// result writing form decides zero and sign of the result it printed. Anything
// else is not derivable, and the caller prints an honest flag name instead of a
// plausible comparison that would be a wrong answer. Returns false then.
bool re_dc_flag_expr(const re_dc_emit_t *e, unsigned cc, char *out, size_t cap);

// The stack strings the deobfuscation pass decoded, printed as comments before
// the body. They name a literal the machine builds one store at a time.
void re_dc_stackstrs(re_dc_emit_t *e, const re_flow_stat_t *fl);

// One unlowered instruction: a comment carrying its address and text, never
// dropped. Silence would read as "nothing happens here", which is how a reader
// is misled about a function.
void re_dc_unlowered(re_dc_emit_t *e, const re_insn_t *in);

// The printing layer's interface. Every one of these writes through the emitter, so
// they take it rather than reaching for a global, and each returns something the
// caller uses in the same statement.
re_str_t re_dc_mint(re_dc_emit_t *e, const char *prefix, uint32_t n);
const char *re_dc_val(re_dc_emit_t *e, re_varnode_t vn, char *scratch);
const char *re_dc_local(re_dc_emit_t *e, int16_t disp);

// The widest access each stack displacement saw, learned from the op stream
// before anything is printed, and the query the declarations and the loads and
// stores read. A width of zero means the displacement was never touched.
void re_dc_learn_widths(re_dc_emit_t *e, const re_ir_func_t *ir);
uint8_t re_dc_slot_width(const re_dc_emit_t *e, int16_t disp);
const char *re_dc_type(uint16_t size);
const char *re_dc_ftype(uint16_t size);
const char *re_dc_binop(re_op_kind_t k);
const char *re_dc_fnop(re_op_kind_t k);
const char *re_dc_ccop(unsigned cc);
const char *re_dc_ccname(unsigned cc);
void re_dc_bind(re_dc_emit_t *e, re_varnode_t vn, re_str_t name);
void re_dc_stmt(re_dc_emit_t *e, const char *fmt, ...);

// One structural line: indent, the text, a newline, and no semicolon. Braces and
// the while clause of a do loop are punctuation, not statements, so they take
// their own writer rather than borrowing the statement one.
void re_dc_line(re_dc_emit_t *e, const char *fmt, ...);

#ifdef __cplusplus
}
#endif
