// re_dcx_dom.c - reverse post order, dominators and post dominators of the block graph.
// Module: feature (C11).
// Owns: the orderings and the two trees the liveness pass and the structurer read.
// Depends: re_dcx.h. The iterative algorithm of Cooper, Harvey and Kennedy, run once
//           forward from the entry and once backward from a virtual exit node.
#include "features/dec/core/re_dcx.h"

// Iterative depth first search producing a post order; out[] is filled back to front
// so it reads as reverse post order. fwd selects successors, else predecessors.
typedef struct {
    uint32_t node;
    uint32_t next; // the next neighbour index to visit
} frame_t;

static uint32_t nbr_n(const dx_fn_t *x, uint32_t v, bool fwd, uint32_t vexit) {
    if (fwd)
        return dx_nsucc(x, v);
    if (v == vexit) {
        uint32_t n = 0;
        for (uint32_t k = 0; k < x->nb; k++)
            n += x->b[k].rpo != DX_NONE && dx_nsucc(x, k) == 0;
        return n;
    }
    return x->b[v].n_pred;
}

static uint32_t nbr_i(const dx_fn_t *x, uint32_t v, uint32_t i, bool fwd, uint32_t vexit) {
    if (fwd)
        return dx_succ(x, v, i);
    if (v == vexit) {
        for (uint32_t k = 0; k < x->nb; k++)
            if (x->b[k].rpo != DX_NONE && dx_nsucc(x, k) == 0 && i-- == 0)
                return k;
        return DX_NONE;
    }
    return x->b[v].pred[i];
}

static uint32_t dfs(const dx_fn_t *x, uint32_t root, bool fwd, uint32_t vexit, uint8_t *seen,
                    uint32_t *out, frame_t *st) {
    uint32_t total = vexit + 1, n = 0, sp = 0;
    st[sp].node = root;
    st[sp++].next = 0;
    seen[root] = 1;
    while (sp) {
        frame_t *t = &st[sp - 1];
        if (t->next < nbr_n(x, t->node, fwd, vexit)) {
            uint32_t w = nbr_i(x, t->node, t->next++, fwd, vexit);
            if (w != DX_NONE && w < total && !seen[w]) {
                seen[w] = 1;
                st[sp].node = w;
                st[sp++].next = 0;
            }
            continue;
        }
        out[n++] = t->node;
        sp--;
    }
    for (uint32_t i = 0; i < n / 2; i++) {
        uint32_t s = out[i];
        out[i] = out[n - 1 - i];
        out[n - 1 - i] = s;
    }
    return n;
}

static uint32_t meet(const uint32_t *dom, const uint32_t *pos, uint32_t a, uint32_t b) {
    while (a != b) {
        while (pos[a] > pos[b])
            a = dom[a];
        while (pos[b] > pos[a])
            b = dom[b];
    }
    return a;
}

// One dominator problem over an order. preds of a node in this problem are the graph's
// predecessors when fwd, else its successors (and the virtual exit for an exit block).
static void solve(const dx_fn_t *x, const uint32_t *ord, uint32_t n, bool fwd, uint32_t vexit,
                  uint32_t *dom, uint32_t *pos) {
    bool changed = true;
    for (uint32_t i = 0; i <= vexit; i++)
        dom[i] = DX_NONE, pos[i] = DX_NONE;
    for (uint32_t i = 0; i < n; i++)
        pos[ord[i]] = i;
    dom[ord[0]] = ord[0];
    while (changed) {
        changed = false;
        for (uint32_t i = 1; i < n; i++) {
            uint32_t v = ord[i], nd = DX_NONE;
            uint32_t m = fwd ? x->b[v].n_pred : dx_nsucc(x, v);
            for (uint32_t j = 0; j < m; j++) {
                uint32_t p = fwd ? x->b[v].pred[j] : dx_succ(x, v, j);
                if (p == DX_NONE || pos[p] == DX_NONE || dom[p] == DX_NONE)
                    continue;
                nd = nd == DX_NONE ? p : meet(dom, pos, p, nd);
            }
            if (!fwd && m == 0)
                nd = vexit;
            if (nd != DX_NONE && dom[v] != nd) {
                dom[v] = nd;
                changed = true;
            }
        }
    }
}

void dx_dominators(dx_fn_t *x) {
    uint32_t nn = x->nb + 1, vexit = x->nb;
    uint8_t *seen = (uint8_t *)re_arena_calloc(x->a, nn, 1);
    uint32_t *ord = (uint32_t *)re_arena_alloc(x->a, nn * sizeof(uint32_t));
    uint32_t *dom = (uint32_t *)re_arena_alloc(x->a, nn * sizeof(uint32_t));
    uint32_t *pos = (uint32_t *)re_arena_alloc(x->a, nn * sizeof(uint32_t));
    frame_t *st = (frame_t *)re_arena_alloc(x->a, nn * sizeof(frame_t));
    if (!seen || !ord || !dom || !pos || !st)
        return;
    for (uint32_t k = 0; k < x->nb; k++)
        x->b[k].rpo = DX_NONE;
    x->norder = dfs(x, 0, true, vexit, seen, ord, st);
    x->order = (uint32_t *)re_arena_alloc(x->a, (x->norder + 1) * sizeof(uint32_t));
    for (uint32_t i = 0; i < x->norder; i++) {
        x->order[i] = ord[i];
        x->b[ord[i]].rpo = i;
    }
    solve(x, ord, x->norder, true, vexit, dom, pos);
    for (uint32_t k = 0; k < x->nb; k++)
        x->b[k].idom = dom[k];
    for (uint32_t k = 0; k < nn; k++)
        seen[k] = 0;
    uint32_t nr = dfs(x, vexit, false, vexit, seen, ord, st);
    solve(x, ord, nr, false, vexit, dom, pos);
    for (uint32_t k = 0; k < x->nb; k++)
        x->b[k].ipdom = dom[k] == vexit ? DX_NONE : dom[k];
}

// True when a dominates b. Both must be reachable; a block dominates itself.
bool dx_dominates(const dx_fn_t *x, uint32_t a, uint32_t b) {
    if (a == DX_NONE || b == DX_NONE || x->b[b].rpo == DX_NONE)
        return false;
    for (uint32_t guard = 0; guard <= x->nb; guard++) {
        if (b == a)
            return true;
        uint32_t up = x->b[b].idom;
        if (up == b || up == DX_NONE)
            return false;
        b = up;
    }
    return false;
}
