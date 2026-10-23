// re_ireval.h - a bounded interpreter for the register transfer IR of one function.
// Module: feature (C11).
// Owns: re_ireval_run, its register file, and the copy on write memory overlay.
// Depends: re_code, re_ir. Memory writes never touch the image; a step budget ends the run.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/code/re_code.h"
#include "features/code/re_func.h"
#include "features/dec/re_ir.h"
#include "utils/mem/re_arena.h"

#define RE_IR_STEPS 4096u // the most instructions one run executes
#define RE_IR_WRITES 256u // distinct addresses a run may store to

typedef struct {
    uint64_t regs[16];
    bool known[16];
    uint64_t waddr[RE_IR_WRITES];
    uint64_t wval[RE_IR_WRITES];
    uint8_t wsize[RE_IR_WRITES];
    uint32_t n_writes;
    uint32_t steps;
    bool stopped; // a call, an indirect branch, or the step budget ended the run
} re_ireval_t;

// Execute f from its entry with the registers given, reading the image through c and
// keeping every store in the overlay. Returns false when the function cannot be
// lowered at all. The result is what the registers and the overlay hold at the end.
bool re_ireval_run(const re_code_t *c, const re_func_t *fn, re_arena_t *mem, re_ireval_t *ev);

// The bytes a run stored at va, when it stored a run of them. False otherwise.
bool re_ireval_bytes(const re_ireval_t *e, uint64_t va, uint8_t *dst, size_t n);
#ifdef __cplusplus
}
#endif
