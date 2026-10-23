// re_dcx_loop.c - natural loops printed as while, do while, or while (1).
// Module: feature (C11).
// Owns: the loop body, the loop's follow block, and the choice of loop form.
// Depends: re_dcx_st.h. A loop is a back edge to a block that dominates its source;
//           an irreducible cycle has no such header and is left to gotos.
#include "features/dec/struct/re_dcx_st.h"

#include <string.h>

static bool inb(const uint8_t *body, uint32_t b) {
    return b != DX_NONE && ((body[b >> 3] >> (b & 7u)) & 1u);
}

static void setb(uint8_t *body, uint32_t b) {
    body[b >> 3] |= (uint8_t)(1u << (b & 7u));
}

// The natural loop of h: every block that reaches a back edge source without passing
// through h. Also reports how many back edges there are and the last one's source.
static uint8_t *natural_loop(dx_st_t *s, uint32_t h, uint32_t *latch, uint32_t *nlatch) {
    dx_fn_t *x = s->x;
    uint8_t *body = (uint8_t *)re_arena_calloc(x->a, (x->nb + 8) / 8, 1);
    uint32_t *stack = (uint32_t *)re_arena_alloc(x->a, (x->nb + 1) * sizeof(uint32_t));
    uint32_t sp = 0;
    *nlatch = 0;
    if (!body || !stack)
        return NULL;
    setb(body, h);
    for (uint32_t i = 0; i < x->b[h].n_pred; i++) {
        uint32_t p = x->b[h].pred[i];
        if (!dx_dominates(x, h, p))
            continue;
        *latch = p;
        (*nlatch)++;
        if (!inb(body, p))
            setb(body, p), stack[sp++] = p;
    }
    while (sp) {
        uint32_t v = stack[--sp];
        for (uint32_t i = 0; i < x->b[v].n_pred; i++) {
            uint32_t q = x->b[v].pred[i];
            if (x->b[q].rpo != DX_NONE && !inb(body, q))
                setb(body, q), stack[sp++] = q;
        }
    }
    return body;
}

// Where the loop exits to: the header's post dominator when that is outside the loop,
// else the earliest block in reverse post order that the loop jumps out to.
static uint32_t loop_follow(const dx_st_t *s, uint32_t h, const uint8_t *body) {
    const dx_fn_t *x = s->x;
    uint32_t best = DX_NONE, ip = x->b[h].ipdom;
    if (ip != DX_NONE && !inb(body, ip))
        return ip;
    for (uint32_t v = 0; v < x->nb; v++) {
        if (!inb(body, v))
            continue;
        for (uint32_t i = 0; i < dx_nsucc(x, v); i++) {
            uint32_t t = dx_succ(x, v, i);
            if (t == DX_NONE || inb(body, t) || x->b[t].rpo == DX_NONE || t >= x->nreal)
                continue;
            if (best == DX_NONE || x->b[t].rpo < x->b[best].rpo)
                best = t;
        }
    }
    return best;
}

// while (cond): the header does nothing but test, one side stays and one side leaves.
static bool while_form(dx_st_t *s, uint32_t h, const dx_cx_t *in, uint16_t ind) {
    dx_fn_t *x = s->x;
    const dx_block_t *hb = &x->b[h];
    if (hb->term != DX_T_COND || RE_VEC_LEN(&hb->stmts) != 0)
        return false;
    bool in0 = dx_in_body(in, hb->succ[0]), in1 = dx_in_body(in, hb->succ[1]);
    uint32_t stay = in0 ? hb->succ[0] : hb->succ[1];
    if (in0 == in1 || (in0 ? hb->succ[1] : hb->succ[0]) != in->follow)
        return false;
    dx_body_lines(s, h, ind);
    dx_line(s, ind, dx_text(x->a, 0, 8, "while (%s)", dx_cond_text(x, &hb->cond, !in0)).s, hb->end);
    dx_line(s, ind, "{", 0);
    uint32_t nx = dx_edge(s, in, (uint16_t)(ind + 1), stay);
    if (nx != DX_NONE)
        dx_seq(s, nx, in, (uint16_t)(ind + 1));
    dx_drop_trailing(s, "continue;", (uint16_t)(ind + 1));
    dx_line(s, ind, "}", 0);
    return true;
}

// do { } while (cond): one back edge, from a block that tests and either loops or leaves.
static bool do_form(dx_st_t *s, uint32_t h, uint32_t latch, uint32_t nlatch, dx_cx_t *in,
                    uint16_t ind) {
    dx_fn_t *x = s->x;
    const dx_block_t *lb = &x->b[latch];
    if (nlatch != 1 || lb->term != DX_T_COND)
        return false;
    bool t0h = lb->succ[0] == h && lb->succ[1] == in->follow;
    bool t1h = lb->succ[1] == h && lb->succ[0] == in->follow;
    if (!t0h && !t1h)
        return false;
    in->latch = latch;
    dx_line(s, ind, "do", 0);
    dx_line(s, ind, "{", 0);
    dx_seq(s, h, in, (uint16_t)(ind + 1));
    if (!s->done[latch])
        dx_body_lines(s, latch, (uint16_t)(ind + 1)); // reached only by gotos in the body
    dx_line(s, ind, dx_text(x->a, 0, 8, "} while (%s);", dx_cond_text(x, &lb->cond, t1h)).s,
            lb->end);
    return true;
}

uint32_t dx_emit_loop(dx_st_t *s, uint32_t h, const dx_cx_t *c, uint16_t ind) {
    uint32_t latch = DX_NONE, nlatch = 0;
    uint8_t *body = natural_loop(s, h, &latch, &nlatch);
    dx_cx_t in;
    if (!body) {
        dx_goto(s, ind, h);
        return DX_NONE;
    }
    memset(&in, 0, sizeof(in));
    in.head = h;
    in.follow = loop_follow(s, h, body);
    in.latch = DX_NONE;
    in.body = body;
    in.sw_follow = DX_NONE;
    in.next_case = DX_NONE;
    (void)c;
    if (while_form(s, h, &in, ind) || do_form(s, h, latch, nlatch, &in, ind))
        return in.follow;
    dx_line(s, ind, "while (1)", 0);
    dx_line(s, ind, "{", 0);
    dx_seq(s, h, &in, (uint16_t)(ind + 1));
    dx_drop_trailing(s, "continue;", (uint16_t)(ind + 1));
    dx_line(s, ind, "}", 0);
    return in.follow;
}
