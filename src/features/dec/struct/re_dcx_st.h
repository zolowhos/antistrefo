// re_dcx_st.h - the structurer's private state, shared by its two source files.
// Module: feature (C11).
// Owns: the line list, the region context, and the entry points between the files.
// Depends: re_dcx.h. Private to re_dcx_struct.c and re_dcx_loop.c.
#pragma once

#include "features/dec/core/re_dcx.h"

#define DX_STOPS 32
#define DX_DEPTH 96

typedef struct {
    const char *s;
    uint64_t va;
    uint16_t ind;
    uint32_t label; // block + 1 on a label marker line, 0 on a text line
} dx_ln_t;

typedef struct {
    dx_fn_t *x;
    re_vec_t lines; // dx_ln_t
    uint8_t *done;  // block printed
    uint8_t *need;  // block is a goto target and needs its label
    uint8_t *hdr;   // block is a loop header
    uint32_t *lno;  // label number by block, 0 until a goto needs one
    uint32_t next_l;
    int depth;
} dx_st_t;

typedef struct {
    uint32_t head, follow, latch;
    const uint8_t *body; // bit per block, the innermost loop, NULL outside every loop
    uint32_t sw_follow;  // the innermost switch's end, where break goes
    bool sw_inner;       // a switch sits inside the innermost loop, so break means it
    uint32_t stops[DX_STOPS];
    uint32_t nstops;
    const uint32_t *cases; // the current switch's targets: one case reaches another by goto
    uint32_t ncases;
    uint32_t next_case; // the case printed next, which a body may fall through into
} dx_cx_t;

void dx_line(dx_st_t *s, uint16_t ind, const char *t, uint64_t va);
void dx_goto(dx_st_t *s, uint16_t ind, uint32_t t);
bool dx_in_body(const dx_cx_t *c, uint32_t b);
uint32_t dx_edge(dx_st_t *s, const dx_cx_t *c, uint16_t ind, uint32_t t);
void dx_seq(dx_st_t *s, uint32_t b, const dx_cx_t *c, uint16_t ind);
void dx_body_lines(dx_st_t *s, uint32_t b, uint16_t ind);
uint32_t dx_emit_loop(dx_st_t *s, uint32_t h, const dx_cx_t *c, uint16_t ind);
void dx_drop_trailing(dx_st_t *s, const char *text, uint16_t ind);
