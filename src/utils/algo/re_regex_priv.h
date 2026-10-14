// re_regex_priv.h - private instruction and node types shared by the regex compiler.
// Module: util (C11).
// Owns: the flat program layout, node tree, parser state and compiled regex record.
// Depends: re_regex.h. Internal only, never included outside the regex engine.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils/algo/re_regex.h"

#define RX_NONE (~(size_t)1)
#define RX_FAIL (~(size_t)0)

typedef enum {
    RXI_CHAR,
    RXI_ANY,
    RXI_CLASS,
    RXI_SPLIT,
    RXI_JMP,
    RXI_BOL,
    RXI_EOL,
    RXI_MATCH
} rx_op_t;

typedef struct rx_i {
    uint8_t op;
    uint8_t ch;
    unsigned cls;
    const struct rx_i *x;
    const struct rx_i *y;
} rx_i_t;

typedef struct rx_st {
    const rx_i_t *pc;
    size_t sp;
} rx_st_t;

typedef enum { N_CHAR, N_ANY, N_CLASS, N_BOL, N_EOL, N_CAT, N_ALT, N_REP } ntype_t;

typedef struct rx_n {
    ntype_t type;
    struct rx_n *a;
    struct rx_n *b;
    unsigned char ch;
    unsigned cls;
    unsigned min;
    unsigned max;
} rx_n_t;

struct re_rx {
    re_arena_t *a;
    bool icase;
    bool literal;
    size_t n_inst;
    size_t match_index;
    rx_i_t *prog;
    rx_st_t *stack;
    unsigned char classes[RE_RX_MAX_CLASS][32];
    const char *lit;
    size_t lit_n;
};

typedef struct {
    const char *p;
    const char *end;
    re_arena_t *a;
    re_err_t *err;
    bool icase;
    unsigned n_classes;
    unsigned char classes[RE_RX_MAX_CLASS][32];
    size_t exits[RE_RX_MAX_REPEAT];
    unsigned n_exits;
} parse_t;

void re_rx_fail(parse_t *ps, const char *msg);
void re_rx_cls_set(unsigned char *m, unsigned char c);
void re_rx_cls_range(unsigned char *m, unsigned char lo, unsigned char hi);
bool re_rx_cls_get(const unsigned char *m, unsigned char c);
rx_n_t *re_rx_node(parse_t *ps, ntype_t t);
rx_n_t *re_rx_parse(parse_t *ps);
size_t re_rx_emit(re_rx_t *rx, rx_op_t op);
size_t re_rx_gen(re_rx_t *rx, const rx_n_t *n, parse_t *ps);
#ifdef __cplusplus
}
#endif
