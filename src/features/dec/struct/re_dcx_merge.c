// re_dcx_merge.c - short circuit conditions folded back into one && or ||.
// Module: feature (C11).
// Owns: the rewrite of a chain of condition blocks into one compound condition.
// Depends: re_dcx.h. A compiler lowers "if (a || b)" to two branches that share a
//           target; without folding them back, every such if prints with a goto.
#include "features/dec/core/re_dcx.h"

#include <string.h>

// b can be folded into its predecessor: a test and nothing else, reached only from a.
static bool foldable(const dx_fn_t *x, uint32_t a, uint32_t b) {
    const dx_block_t *p = b < x->nreal ? &x->b[b] : NULL;
    if (!p || b == a || b == 0 || p->dead || p->term != DX_T_COND || p->n_pred != 1)
        return false;
    if (RE_VEC_LEN(&p->stmts) || p->succ[0] == b || p->succ[1] == b)
        return false;
    return p->cond.kind != DX_C_RAW || p->cond.raw;
}

// Try to fold block a's successor on one side into a. Returns true when it did.
static bool fold_side(dx_fn_t *x, uint32_t a, int side) {
    dx_block_t *p = &x->b[a];
    uint32_t b = p->succ[side], other = p->succ[side ^ 1];
    if (!foldable(x, a, b) || other == b)
        return false;
    const dx_block_t *q = &x->b[b];
    dx_cond_t c;
    uint32_t t, f;
    if (side == 1 && (q->succ[0] == other || q->succ[1] == other)) {
        bool nb = q->succ[1] == other; // a || b, or a || !b when b's false side is shared
        c = dx_cond_join(x, DX_C_OR, &p->cond, false, &q->cond, nb);
        t = other;
        f = nb ? q->succ[0] : q->succ[1];
    } else if (side == 0 && (q->succ[0] == other || q->succ[1] == other)) {
        bool nb = q->succ[0] == other; // a && b, or a && !b when b's true side is shared
        c = dx_cond_join(x, DX_C_AND, &p->cond, false, &q->cond, nb);
        t = nb ? q->succ[1] : q->succ[0];
        f = other;
    } else {
        return false;
    }
    p->cond = c;
    p->succ[0] = t;
    p->succ[1] = f;
    if (t == f)
        p->term = DX_T_JUMP, p->succ[1] = DX_NONE;
    dx_block_t *dq = &x->b[b];
    dq->dead = true;
    dq->term = DX_T_EXIT;
    dq->succ[0] = dq->succ[1] = DX_NONE;
    return true;
}

void dx_merge_conds(dx_fn_t *x) {
    bool any = false, changed = true;
    while (changed) {
        changed = false;
        for (uint32_t a = 0; a < x->nreal; a++) {
            const dx_block_t *p = &x->b[a];
            if (p->dead || p->term != DX_T_COND || p->rpo == DX_NONE)
                continue;
            if (fold_side(x, a, 1) || fold_side(x, a, 0)) {
                changed = any = true;
                dx_link(x);
            }
        }
    }
    if (any)
        dx_dominators(x);
}
