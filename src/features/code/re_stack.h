// re_stack.h - stack frame and calling convention inference for one function.
// Module: feature (C11).
// Owns: which registers arrive as arguments, the frame size, and the local slots.
// Depends: re_code, re_func, re_disasm. An argument count is only reported when
//         the registers that carry arguments were actually seen.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/code/re_code.h"
#include "features/code/re_func.h"
#include "features/pe/re_pe.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_vec.h"

// The two conventions that matter for the architectures in scope. Everything else
// is reported as unknown rather than forced into one of them.
#define RE_CC_UNKNOWN 0u
#define RE_CC_MS64 1u // Windows: rcx, rdx, r8, r9
#define RE_CC_SYSV 2u // SysV: rdi, rsi, rdx, rcx, r8, r9

#define RE_CC_MAX_ARGS 6
// How many distinct stack displacements a function may touch. A bound, so a
// pathological function cannot make the record grow without limit.
#define RE_SLOT_MAX 64

typedef struct {
    uint8_t cc;          // RE_CC_*
    uint32_t n_params;   // arguments inferred, 0 when nothing was seen
    uint32_t frame_size; // stack bytes reserved, from the prologue
    uint32_t n_locals;   // distinct stack slots written below rbp or rsp
    uint32_t n_calls;    // calls made, which clobber the volatile set
    // Which slots of the inferred convention arrived live, as positions in that
    // convention's order: 0 is the first argument. Positions rather than register
    // numbers, because the position is what a caller needs to print a1, a2 and so
    // on, and the two SysV orders do not share register numbers. The register for a
    // position is in kMsArgs or kSysv above.
    uint8_t arg_regs[RE_CC_MAX_ARGS];
    int32_t slots[RE_SLOT_MAX]; // the distinct stack offsets touched
    uint32_t n_slots;
    bool uses_frame_ptr; // rbp is set up, so locals are rbp relative
    bool tail_call;      // ends in a jump rather than a return
    bool homed;          // the four argument registers were homed once
    bool ret_xmm;        // the return is in xmm0, not rax
} re_stack_t;

// Analyse one function. The walk is linear from the entry, which is enough for a
// prologue and an argument scan, and it stops at the first address it cannot
// decode rather than guessing past the end.
void re_stack_analyze(re_code_t *c, const re_func_t *f, re_arena_t *a, re_stack_t *out);

// The convention's name, for display.
const char *re_cc_name(uint8_t cc);

// The register that carries argument number pos (0 based) under this convention, or
// "?" when there is no such argument or the convention is unknown. Positions are what
// re_stack_t::arg_regs holds, so this is how a position becomes a register name.
const char *re_cc_arg_reg_name(uint8_t cc, uint32_t pos);

// True when this PE imports ntoskrnl, hal, or FLTMGR. A driver is never SysV.
bool re_stack_image_ms64(const re_pe_t *pe);

// Force ms64 on that image. Callee-saved registers are dropped from the parameter
// list, and the shadow slots rsp+8 through rsp+0x20 are not locals. A PE with no
// such import is left as the scorer reported it, including SysV.
void re_stack_apply_image(re_stack_t *out, const re_pe_t *pe);

// The return type the signature prints. xmm0 is a double; everything else is rax.
const char *re_cc_ret_type(const re_stack_t *st);
#ifdef __cplusplus
}
#endif
