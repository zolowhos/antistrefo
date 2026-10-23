// re_dcx.h - the block based decompiler core: graph, values, statements, structure.
// Module: feature (C11).
// Owns: the per function context every stage of the core reads and writes.
// Depends: re_ir, re_decompile, re_code, re_func, re_stack, re_xref, re_jtable.
//           Private to src/features/dec; re_decompile.c is the only public entry.
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
#include "features/dec/re_dc_proto.h"
#include "features/dec/re_decompile.h"
#include "features/dec/re_ir.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_vec.h"
#include "utils/text/re_strbuf.h"

#define DX_NONE 0xFFFFFFFFu
#define DX_NREG 16u        // the general purpose registers, rax through r15
#define DX_RSP 4u          // the stack pointer's register number
#define DX_RBP 5u          // the frame pointer's, when the prologue makes it one
#define DX_MAX_INSNS 20000 // a body larger than this is not decompiled, it is refused
#define DX_MAX_ARGS 16u
#define DX_SP_UNKNOWN INT32_MIN

// C operator precedence, highest binding first, so composing two expressions knows
// exactly when the inner one needs parentheses.
enum {
    DX_P_ASSIGN = 2,
    DX_P_COND = 3,
    DX_P_LOR = 4,
    DX_P_LAND = 5,
    DX_P_BOR = 6,
    DX_P_BXOR = 7,
    DX_P_BAND = 8,
    DX_P_EQ = 9,
    DX_P_REL = 10,
    DX_P_SHIFT = 11,
    DX_P_ADD = 12,
    DX_P_MUL = 13,
    DX_P_UNARY = 15,
    DX_P_PRIMARY = 16,
};

// A register or temporary that holds an address inside the frame.
typedef struct {
    bool stk;
    int32_t off;
} dx_sv_t;

// One value the emitter is carrying: text with its precedence, or one of the two
// forms that are printed only once their use is known, a constant and a frame address.
typedef struct {
    const char *s; // the text, NULL for a constant or frame address not yet printed
    uint8_t prec;  // precedence of the outermost operator in s
    uint8_t w;     // the width the machine computed, in bytes
    uint8_t nw;    // the width the C text computes, which a narrower w must cast
    uint8_t ent;   // register number + 1 when this is a register's value on entry
    bool cst;      // a known constant, value in c
    bool stk;      // the address entry rsp + off
    bool mem;      // reads memory or calls: a store or a call must flush it first
    bool fx;       // has a side effect (a call): never dropped, never duplicated
    bool sg;       // the C type of the text is signed at width nw
    int64_t c;
    int32_t off;
    uint32_t deps; // register variables the text reads, by register number
    uint32_t seq;  // program order, so pending values flush in the order computed
    // index forms, so an access prints as a[i] instead of *(T *)(a + i * 4)
    const char *ix; // this value is ix * ixk
    uint8_t ixk;
    bool arr;  // this value is base + aidx * ask, the base a global or a frame slot
    bool astk; // the base is the frame address aoff, else the constant abase
    int64_t abase;
    int32_t aoff;
    const char *aidx;
    uint8_t ask;
    const struct dx_ann *ann; // what the value is known to compute, for idioms; may be NULL
} dx_val_t;

// What a value is known to compute beyond its text: a step of a division by a magic
// constant, the division itself, or a constant multiple of another value.
enum {
    DX_AN_EXT = 1, // a 32 bit value widened to 64
    DX_AN_HI,      // a magic product on its way to a quotient
    DX_AN_SIGN,    // the sign bit of such a product
    DX_AN_XSIGN,   // x >> 31 (or 63), all ones when x is negative
    DX_AN_BIAS,    // 2^k - 1 when x is negative, else 0
    DX_AN_PRE,     // x plus that bias, about to be shifted right by k
    DX_AN_QUOT,    // a quotient
    DX_AN_LIN,     // a constant multiple of a base value
    DX_AN_ADDC     // a base value plus a constant
};
typedef struct dx_ann {
    uint8_t kind;
    bool sgn;    // EXT, HI, QUOT: signed
    bool wide;   // HI: the 64 bit product of a 32 bit value, not a high half
    bool addx;   // HI: the dividend was added to the high half
    bool sar;    // HI: the shift after the product is arithmetic
    bool mixed;  // LIN: terms were combined, so the text reads as a product
    uint8_t fix; // HI: progress of the unsigned fix-up ((x - t) >> 1) + t, 3 when done
    uint8_t w;   // the dividend's width in bytes
    uint8_t sh;  // HI: the right shift taken after the product
    uint64_t m;  // HI: the magic multiplier
    int64_t d;   // QUOT: the divisor; LIN: the coefficient
    dx_val_t x;  // the dividend; EXT: the narrow value; LIN: the base
} dx_ann_t;

// One printed line of a block, without indentation. A statement carries its own
// semicolon; a comment carries its own slashes.
typedef struct {
    const char *s;
    uint64_t va;
} dx_stmt_t;

typedef enum {
    DX_T_FALL = 0, // runs into succ[0]
    DX_T_JUMP,     // jumps to succ[0]
    DX_T_COND,     // succ[0] when cond holds, else succ[1]
    DX_T_RET,      // returns; the return statement is the block's last line
    DX_T_SWITCH,   // jump table: sw[] by case, default in succ[1] when known
    DX_T_EXIT,     // leaves without returning here: tail call, indirect jump, trap
} dx_term_t;

// A branch condition kept as its parts, so the structurer can negate it exactly. A
// leaf is a comparison (l op r) or a raw flag condition; an inner node joins two
// conditions with && or ||, which is what a short circuit compiles to.
enum { DX_C_REL = 0, DX_C_RAW, DX_C_AND, DX_C_OR };
typedef struct dx_cond_s {
    uint8_t kind;                  // DX_C_*
    const char *l, *r;             // operands of a comparison, already parenthesised
    const char *raw;               // a condition with no relational form
    uint8_t op;                    // DX_EQ .. DX_GT for a comparison
    const struct dx_cond_s *a, *b; // the two sides of && or ||
} dx_cond_t;

enum { DX_EQ = 0, DX_NE, DX_LT, DX_GE, DX_LE, DX_GT };

// The flags the last writer left, kept as the values it compared so a branch, a setcc
// or a cmov can print the comparison the architecture actually made.
#define DX_FL_CF 0xF0u // the writer set CF to l != 0 (bt and friends)
typedef struct {
    bool ok;
    uint8_t kind;  // re_setf_t, or DX_FL_CF
    uint8_t w;     // the width compared
    bool same;     // test r, r
    bool ab;       // a and b hold an add or sub's own operands
    uint32_t id;   // the writer, as a flat op index
    dx_val_t l, r; // compared operands, or the result and zero
    dx_val_t a, b;
} dx_flag_t;

typedef struct {
    uint64_t va;  // first instruction
    uint64_t end; // one past the last byte
    uint32_t i0;  // first instruction index in the walk
    uint32_t i1;  // one past the last
    uint8_t term; // dx_term_t
    uint32_t succ[2];
    uint32_t *sw; // switch case targets, n_sw of them, DX_NONE for a hole
    uint32_t n_sw;
    uint64_t target; // a direct transfer's destination, for a tail call's name
    uint32_t *pred;
    uint32_t n_pred;
    uint32_t idom, ipdom, rpo;
    uint32_t use, def, live_in, live_out; // register bit sets
    int32_t sp_in;                        // rsp - entry rsp on entry, DX_SP_UNKNOWN when not known
    re_ir_block_t *ir;
    // what the emitter produced
    re_vec_t stmts;   // dx_stmt_t
    dx_cond_t cond;   // for DX_T_COND
    const char *swv;  // for DX_T_SWITCH: the value switched on
    int64_t swbase;   // the case number of table entry zero
    dx_flag_t fl_out; // the flags at the end, for a successor that reads them
    bool emitted;
    bool dead; // folded into its predecessor's condition
} dx_block_t;

// A stack slot the body touches, keyed by its offset from entry rsp.
typedef struct {
    int32_t off;
    uint8_t w;     // widest access
    bool rd, wr;   // read, written
    bool taken;    // its address escapes, so it is memory and not a scalar
    bool outarg;   // an outgoing argument a call consumes, never read here
    bool used;     // printed at least once, so it needs a declaration
    uint8_t save;  // register number + 1 when the prologue saves that register here
    uint8_t home;  // parameter position + 1 when it is that parameter's home slot
    bool wr_other; // written with something other than the saved or homed value
    uint8_t idx_w; // element width of an indexed access based here, 0 when none
    bool elem;     // an element of the array that starts at abase
    int32_t abase;
    uint32_t alen; // elements, on the array's own slot
} dx_slot_t;

// A variable the body declares: a temporary, or a register carried between blocks.
typedef struct {
    const char *name;
    uint8_t w;
    int16_t reg; // the register it stands for, -1 for a temporary
} dx_var_t;

// What a callee's own body says about it, from the decompiler's analysis of that body.
typedef struct {
    uint64_t va;
    uint8_t state; // 1 being summarised, 2 done, 3 could not be built
    bool noret;    // no path returns to the caller
    bool has_ret;  // returns a value in rax
    uint8_t ret_w; // the width that value is written at, when has_ret
    uint8_t nparams;
    uint8_t nstk;
} dx_sum_t;

typedef struct {
    re_vec_t sums; // dx_sum_t
    uint32_t depth;
    uint32_t spent; // instructions summarised so far
} dx_cache_t;

typedef struct dx_fn {
    const re_decomp_t *d;
    const re_func_t *f;
    const re_stack_t *st;
    re_code_t *code;
    re_arena_t *a;
    re_vec_t insns; // re_insn_t, ascending by address
    uint16_t *nops; // ops each instruction lowered to
    re_ir_func_t ir;
    dx_block_t *b;
    uint32_t nb;     // all blocks, the virtual exits after the real ones
    uint32_t nreal;  // blocks with instructions, ascending by address
    uint32_t *order; // reverse post order of the reachable blocks
    uint32_t norder;
    // facts the passes establish before anything prints
    uint8_t cc;              // re_stack's calling convention
    uint8_t nparams;         // register parameters, by ABI position
    uint8_t pw[DX_MAX_ARGS]; // their widths
    uint8_t nstk;            // stack parameters past the register ones
    bool fp;                 // rbp is a frame pointer, at entry rsp + fp_off
    int32_t fp_off;
    bool has_ret; // the function returns a value in rax
    uint8_t ret_w;
    re_vec_t slots;      // dx_slot_t, sorted by off
    re_vec_t vars;       // dx_var_t
    uint32_t next_v;     // the next vN to mint
    uint32_t *opbase;    // per block: index of its first op in the flat stream
    uint32_t nops_all;   // ops in the whole function
    uint8_t *call_nargs; // per flat op: register arguments of a call
    uint8_t *call_nstk;  // per flat op: stack arguments of a call
    int32_t *op_sp;      // per flat op: rsp - entry rsp before it ran
    int64_t *cv;         // per constant id: its value
    uint8_t *cvk;        // per constant id: whether cv holds one
    dx_sv_t *uq;         // per temporary id: a frame address it holds
    uint8_t *uqk;        // per temporary id: the scale it was multiplied by, 0 when none
    uint32_t nuniq;
    uint16_t *uses;               // per flat op: reads of its result before it is overwritten
    uint8_t *esc;                 // per flat op: its register result is live out of the block
    uint8_t *flive;               // per flat op: a flag writer whose flags something reads
    uint8_t rv_w[DX_NREG];        // width of each register's variable
    const char *rv_name[DX_NREG]; // the variable a register lives in across blocks
    uint32_t n_unlowered;
    dx_cache_t *cache; // callee summaries, shared by every nested analysis
} dx_fn_t;

// ---- callees: re_dcx_callee.c ----
const dx_sum_t *dx_summary(const dx_fn_t *x, uint64_t target);
// The prototype of the import or named function a call or jump at site reaches, when
// the prototype tables list it.
bool dx_proto_at(const dx_fn_t *x, uint64_t site, re_dc_proto_t *out);
// Whether the callers read the rax this function leaves: 1 some do, 0 none of them
// does, -1 unknown (no direct caller seen, or the address escapes).
int dx_callers_read_rax(const dx_fn_t *x);
// The register arguments a jump out of the function passes as a tail call, by the
// target's prototype or summary, or -1 when neither is known.
int dx_tail_nargs(const dx_fn_t *x, const re_ir_op_t *op);

// ---- walk: re_dcx_walk.c ----
uint8_t *dx_walk(dx_fn_t *x, uint64_t *lo);
bool dx_ends_block(const dx_fn_t *x, const re_insn_t *in);
const re_jtable_t *dx_table_at(const dx_fn_t *x, uint64_t va);

// ---- graph: re_dcx_graph.c and re_dcx_dom.c ----
bool dx_build(dx_fn_t *x);
void dx_refresh(dx_fn_t *x);
void dx_link(dx_fn_t *x);
void dx_merge_conds(dx_fn_t *x);
void dx_dominators(dx_fn_t *x);
uint32_t dx_block_at(const dx_fn_t *x, uint64_t va);
uint32_t dx_nsucc(const dx_fn_t *x, uint32_t b);
uint32_t dx_succ(const dx_fn_t *x, uint32_t b, uint32_t i);
bool dx_dominates(const dx_fn_t *x, uint32_t a, uint32_t b);

// ---- frame: re_dcx_frame.c ----
typedef struct {
    int32_t sp; // rsp - entry rsp, DX_SP_UNKNOWN when an and or a dynamic adjust lost it
    dx_sv_t reg[DX_NREG];
} dx_frame_t;

void dx_consts(dx_fn_t *x);
bool dx_cval(const dx_fn_t *x, re_varnode_t v, int64_t *out);
void dx_frame_init(const dx_fn_t *x, dx_frame_t *fr, uint32_t b);
dx_sv_t dx_frame_eval(const dx_fn_t *x, const dx_frame_t *fr, re_varnode_t v);
void dx_frame_step(dx_fn_t *x, dx_frame_t *fr, const re_ir_op_t *op);
void dx_frame_pass(dx_fn_t *x);
dx_slot_t *dx_slot(dx_fn_t *x, int32_t off, bool make);

// ---- facts: re_dcx_facts.c ----
void dx_facts(dx_fn_t *x);
uint32_t dx_op_index(const dx_fn_t *x, uint32_t b, size_t k);
unsigned dx_arg_reg(const dx_fn_t *x, unsigned pos);
int dx_arg_pos(const dx_fn_t *x, unsigned reg);
unsigned dx_max_reg_args(const dx_fn_t *x);
bool dx_volatile(const dx_fn_t *x, unsigned reg);

// ---- values: re_dcx_val.c ----
dx_val_t dx_text(re_arena_t *a, uint8_t prec, uint8_t w, const char *fmt, ...);
const char *dx_str(dx_fn_t *x, const dx_val_t *v);
const char *dx_paren(dx_fn_t *x, const dx_val_t *v, uint8_t prec);
const char *dx_at_width(dx_fn_t *x, const dx_val_t *v, uint8_t w, bool sgn);
dx_val_t dx_cst(int64_t c, uint8_t w);
int64_t dx_sext(int64_t c, uint8_t w);
const char *dx_type(uint8_t w, bool sgn);
const char *dx_const_text(dx_fn_t *x, int64_t c, uint8_t w);
const char *dx_slot_name(dx_fn_t *x, int32_t off);
const char *dx_global_name(dx_fn_t *x, uint64_t va, uint8_t w, bool deref);
const char *dx_reg_name(dx_fn_t *x, unsigned reg, uint8_t w);
const char *dx_mint(dx_fn_t *x, uint8_t w, int reg);
bool dx_simple(const dx_val_t *v);

// ---- emission: re_dcx_emit.c, re_dcx_ops.c, re_dcx_cond.c and re_dcx_call.c ----
typedef struct {
    dx_fn_t *x;
    uint32_t b;
    dx_frame_t fr;
    dx_val_t reg[DX_NREG];
    uint8_t has[DX_NREG];   // reg[] holds a value
    uint16_t left[DX_NREG]; // reads of reg[] still to come in this block
    dx_val_t *uqv;          // by temporary id
    dx_flag_t fl;
    uint32_t wrote;    // argument registers written since the last call
    dx_val_t outv[16]; // outgoing stack arguments stored since the last call
    int32_t outoff[16];
    uint32_t nout;
    uint32_t seq;
    uint64_t va;           // the instruction being emitted
    uint32_t gi;           // the flat index of the op being emitted
    const char *sw_idx;    // the scaled index of the last table load, for a switch
    re_varnode_t last_out; // the last add or sub's result, and its operands, for the
    dx_val_t last_l;       // flags it writes: a carry or a signed compare after a sub
    dx_val_t last_r;       // is a statement about these, not about the result
    dx_val_t rsp_dyn;      // rsp after a dynamic adjustment (alloca), when the frame lost it
    bool has_rsp_dyn;
} dx_em_t;

// Idioms (re_dcx_idiom.c): annotate a high multiply, a widening, or a binary op's result,
// rewriting the text when the annotations add up to a division, remainder or product.
void dx_idiom_mulh(dx_em_t *e, dx_val_t *v, const dx_val_t *a, const dx_val_t *b, bool sgn,
                   uint8_t w);
void dx_idiom_ext(dx_em_t *e, dx_val_t *v, const dx_val_t *xv, bool sgn);
void dx_idiom_bin(dx_em_t *e, uint8_t k, const dx_val_t *l, const dx_val_t *r, uint8_t w,
                  dx_val_t *v);
void dx_idiom_select(dx_em_t *e, const dx_cond_t *c, const dx_val_t *no, const dx_val_t *yes,
                     uint8_t w, dx_val_t *v);

void dx_usecount(dx_fn_t *x);
void dx_emit_all(dx_fn_t *x);
void dx_stmt(dx_em_t *e, const char *fmt, ...);
dx_val_t dx_get(dx_em_t *e, re_varnode_t v);
dx_val_t dx_read(dx_em_t *e, re_varnode_t v, uint8_t w, bool sgn);
void dx_def(dx_em_t *e, re_varnode_t out, dx_val_t v);
void dx_flush_mem(dx_em_t *e);
// The same, leaving the pending value in register keep where it is.
void dx_flush_mem_but(dx_em_t *e, unsigned keep);
dx_val_t dx_materialize(dx_em_t *e, dx_val_t v);
dx_val_t dx_width(dx_fn_t *x, dx_val_t v, uint8_t w, bool sgn);
void dx_emit_op(dx_em_t *e, const re_ir_op_t *op);
dx_val_t dx_mix(dx_em_t *e, dx_val_t v, const dx_val_t *p, const dx_val_t *q);
dx_val_t dx_get_any(dx_em_t *e, re_varnode_t v, uint8_t w, bool sgn);
void dx_def_any(dx_em_t *e, re_varnode_t out, dx_val_t v);
void dx_op_load(dx_em_t *e, const re_ir_op_t *op);
void dx_op_store(dx_em_t *e, const re_ir_op_t *op);
void dx_emit_call(dx_em_t *e, const re_ir_op_t *op);
void dx_emit_return(dx_em_t *e, const re_ir_op_t *op);
void dx_emit_tail(dx_em_t *e, const re_ir_op_t *op);
void dx_flag_set(dx_em_t *e, const re_ir_op_t *op);
dx_cond_t dx_flag_cond(dx_em_t *e, unsigned cc);
dx_val_t dx_flag_value(dx_em_t *e, unsigned cc);
dx_val_t dx_carry(dx_em_t *e);
const char *dx_cond_text(dx_fn_t *x, const dx_cond_t *c, bool neg);
dx_cond_t dx_cond_join(dx_fn_t *x, uint8_t kind, const dx_cond_t *a, bool na, const dx_cond_t *b,
                       bool nb);
const char *dx_callee(dx_em_t *e, const re_ir_op_t *op);

// ---- structure and output: re_dcx_struct.c, re_dcx_loop.c and re_dcx_out.c ----
void dx_print(dx_fn_t *x, re_strbuf_t *out);

// ---- the entry point: re_dcx_main.c ----
bool dx_decompile(const re_decomp_t *d, const re_func_t *f, const re_stack_t *st, re_strbuf_t *out);
#ifdef __cplusplus
}
#endif
