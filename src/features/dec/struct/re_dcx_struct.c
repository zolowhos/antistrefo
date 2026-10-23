// re_dcx_struct.c - folds the block graph into if, switch, break, continue and goto.
// Module: feature (C11).
// Owns: the sequence walk, edges, two way branches and switches.
// Depends: re_dcx_st.h. A block is printed exactly once. Merges come from the post
//           dominator tree and loops from re_dcx_loop.c; anything that fits neither,
//           an irreducible region or a shared tail, becomes a goto to a label.
#include "features/dec/struct/re_dcx_st.h"

#include <string.h>

void dx_line(dx_st_t *s, uint16_t ind, const char *t, uint64_t va) {
    dx_ln_t l = {t, va, ind, 0};
    RE_VEC_PUSH(&s->lines, s->x->a, l);
}

void dx_goto(dx_st_t *s, uint16_t ind, uint32_t t) {
    if (t >= s->x->nreal) {
        dx_line(s, ind,
                dx_text(s->x->a, 0, 8, "JUMPOUT(0x%llX);", (unsigned long long)s->x->b[t].target).s,
                0);
        return;
    }
    if (!s->lno[t])
        s->lno[t] = ++s->next_l;
    s->need[t] = 1;
    dx_line(s, ind, dx_text(s->x->a, 0, 8, "goto LABEL_%u;", s->lno[t]).s, 0);
}

bool dx_in_body(const dx_cx_t *c, uint32_t b) {
    return !c->body || ((c->body[b >> 3] >> (b & 7u)) & 1u);
}

// Every predecessor that is not a back edge into t has been printed, so t can be
// printed here without a later block having to jump into the middle of it.
static bool preds_done(const dx_st_t *s, uint32_t t) {
    const dx_block_t *p = &s->x->b[t];
    for (uint32_t i = 0; i < p->n_pred; i++) {
        uint32_t q = p->pred[i];
        if (!s->done[q] && !dx_dominates(s->x, t, q) && s->x->b[q].rpo != DX_NONE)
            return false;
    }
    return true;
}

// 1 when t is the innermost merge point, where control simply carries on once this
// region ends; 2 when it is an enclosing one, which has to be jumped to; 0 otherwise.
static int stop_kind(const dx_cx_t *c, uint32_t t) {
    if (!c->nstops || t == DX_NONE)
        return 0;
    if (c->stops[c->nstops - 1] == t)
        return 1;
    for (uint32_t i = 0; i + 1 < c->nstops; i++)
        if (c->stops[i] == t)
            return 2;
    return 0;
}

static bool is_stop(const dx_cx_t *c, uint32_t t) {
    for (uint32_t i = 0; i < c->nstops; i++)
        if (c->stops[i] == t)
            return true;
    return false;
}

static bool is_case(const dx_cx_t *c, uint32_t t) {
    for (uint32_t i = 0; i < c->ncases; i++)
        if (c->cases[i] == t)
            return true;
    return false;
}

// A block that only returns, in a line or two, is printed again where it is reached
// instead of being jumped to: a goto to "return v;" says less than the return itself.
static bool small_return(dx_st_t *s, uint32_t t, uint16_t ind) {
    uint32_t chain[4], n = 0, total = 0, b = t;
    // Follow plain jumps from t to a return, at most four blocks and four statements:
    // printing that again where it is reached says more than a goto to it.
    while (b < s->x->nreal && n < 4) {
        const dx_block_t *p = &s->x->b[b];
        for (uint32_t k = 0; k < n; k++)
            if (chain[k] == b)
                return false;
        chain[n++] = b;
        total += (uint32_t)RE_VEC_LEN(&p->stmts);
        if (total > 4 || p->n_sw)
            return false;
        if (p->term == DX_T_RET)
            break;
        if (p->term != DX_T_JUMP && p->term != DX_T_FALL)
            return false;
        b = p->succ[0];
    }
    if (!n || s->x->b[chain[n - 1]].term != DX_T_RET || !total)
        return false;
    for (uint32_t k = 0; k < n; k++) {
        const dx_block_t *p = &s->x->b[chain[k]];
        for (size_t i = 0; i < RE_VEC_LEN(&p->stmts); i++) {
            const dx_stmt_t *st = RE_VEC_PTR(&p->stmts, dx_stmt_t, i);
            dx_line(s, ind, st->s, st->va);
        }
    }
    return true;
}

// Control reaching t: the end of this region, break, continue, goto, or carry on into t.
uint32_t dx_edge(dx_st_t *s, const dx_cx_t *c, uint16_t ind, uint32_t t) {
    int sk = stop_kind(c, t);
    if (t == DX_NONE || sk == 1)
        return DX_NONE;
    if (t == c->next_case)
        return DX_NONE; // falls through into the next case, as the C does
    if (t == c->sw_follow) {
        dx_line(s, ind, "break;", 0);
        return DX_NONE;
    }
    if (t == c->head) {
        dx_line(s, ind, "continue;", 0);
        return DX_NONE;
    }
    if (t == c->follow && c->follow != DX_NONE && !c->sw_inner) {
        dx_line(s, ind, "break;", 0);
        return DX_NONE;
    }
    if (sk == 2 || t >= s->x->nreal || s->done[t] || !dx_in_body(c, t) || is_case(c, t) ||
        !preds_done(s, t) || s->depth > DX_DEPTH) {
        if (!small_return(s, t, ind))
            dx_goto(s, ind, t);
        return DX_NONE;
    }
    return t;
}

void dx_body_lines(dx_st_t *s, uint32_t b, uint16_t ind) {
    const dx_block_t *p = &s->x->b[b];
    dx_ln_t mark = {NULL, p->va, ind, b + 1};
    s->done[b] = 1;
    RE_VEC_PUSH(&s->lines, s->x->a, mark);
    for (size_t i = 0; i < RE_VEC_LEN(&p->stmts); i++) {
        const dx_stmt_t *t = RE_VEC_PTR(&p->stmts, dx_stmt_t, i);
        dx_line(s, ind, t->s, t->va);
    }
}

void dx_drop_trailing(dx_st_t *s, const char *text, uint16_t ind) {
    size_t n = RE_VEC_LEN(&s->lines);
    while (n && RE_VEC_PTR(&s->lines, dx_ln_t, n - 1)->label)
        n--;
    if (!n)
        return;
    const dx_ln_t *l = RE_VEC_PTR(&s->lines, dx_ln_t, n - 1);
    if (l->ind == ind && l->s && re_str_eq_cstr(re_str(l->s), text))
        RE_VEC_PTR(&s->lines, dx_ln_t, n - 1)->s = NULL;
}

// Whether any line that prints was added since index at. A label marker nothing jumps
// to yet does not count: an arm holding only that is empty.
static bool added_text(const dx_st_t *s, size_t at) {
    for (size_t i = at; i < RE_VEC_LEN(&s->lines); i++)
        if (RE_VEC_PTR(&s->lines, dx_ln_t, i)->s)
            return true;
    return false;
}

static dx_cx_t push_stop(const dx_cx_t *c, uint32_t m) {
    dx_cx_t n = *c;
    n.next_case = DX_NONE; // falling into the next case is only silent at a case's top level
    if (m != DX_NONE && n.nstops < DX_STOPS)
        n.stops[n.nstops++] = m;
    return n;
}

static void arm(dx_st_t *s, uint32_t t, const dx_cx_t *c, uint16_t ind) {
    uint32_t nx = dx_edge(s, c, ind, t);
    if (nx != DX_NONE)
        dx_seq(s, nx, c, ind);
}

static uint32_t first_index(const dx_block_t *p, uint32_t t) {
    for (uint32_t j = 0; j < p->n_sw; j++)
        if (p->sw[j] == t)
            return j;
    return DX_NONE;
}

// The target the case after case i prints, so a body that runs into it falls through.
static uint32_t next_target(const dx_block_t *p, uint32_t i, uint32_t dflt) {
    for (uint32_t j = i + 1; j < p->n_sw; j++) {
        uint32_t t = p->sw[j];
        if (t != DX_NONE && t != dflt && first_index(p, t) == j)
            return t;
    }
    return DX_NONE;
}

// The cases of a switch whose block is already printed. dflt is where an out of range
// value goes, when a bounds check before the table said so.
static uint32_t switch_cases(dx_st_t *s, uint32_t b, uint32_t dflt, const char *val,
                             const dx_cx_t *c, uint16_t ind) {
    dx_fn_t *x = s->x;
    const dx_block_t *p = &x->b[b];
    uint32_t m = p->ipdom;
    dx_line(s, ind,
            dx_text(x->a, 0, 8, "switch (%s)",
                    val      ? val
                    : p->swv ? p->swv
                             : "?")
                .s,
            p->end);
    dx_line(s, ind, "{", 0);
    dx_cx_t in = push_stop(c, DX_NONE);
    in.sw_follow = m;
    in.sw_inner = c->head != DX_NONE;
    in.cases = p->sw;
    in.ncases = p->n_sw;
    for (uint32_t i = 0; i < p->n_sw; i++) {
        uint32_t t = p->sw[i];
        if (t == DX_NONE || t == dflt || first_index(p, t) != i)
            continue;
        for (uint32_t j = i; j < p->n_sw; j++)
            if (p->sw[j] == t)
                dx_line(s, ind, dx_text(x->a, 0, 8, "case %u:", j).s, 0);
        dx_cx_t one = in;
        one.next_case = next_target(p, i, dflt);
        if (s->done[t] || t == m)
            dx_edge(s, &one, (uint16_t)(ind + 1), t);
        else
            dx_seq(s, t, &one, (uint16_t)(ind + 1));
    }
    if (dflt != DX_NONE && dflt != m) {
        dx_line(s, ind, "default:", 0);
        arm(s, dflt, &in, (uint16_t)(ind + 1));
    }
    dx_line(s, ind, "}", 0);
    return m;
}

// A conditional whose one side leaves the region: a break, a continue or a goto. It
// prints as a one line if, and the walk carries on with the other side.
static bool exit_if(dx_st_t *s, uint32_t b, const dx_cx_t *c, uint16_t ind, uint32_t *next) {
    dx_fn_t *x = s->x;
    const dx_block_t *p = &x->b[b];
    for (int side = 0; side < 2; side++) {
        uint32_t t = p->succ[side], o = p->succ[side ^ 1];
        bool leaves = t >= x->nreal || t == c->follow || t == c->head || t == c->sw_follow ||
                      s->done[t] || !dx_in_body(c, t) || stop_kind(c, t) == 2;
        if (!leaves || o == t || stop_kind(c, t) == 1)
            continue;
        dx_line(s, ind, dx_text(x->a, 0, 8, "if (%s)", dx_cond_text(x, &p->cond, side == 1)).s,
                p->end);
        dx_line(s, ind, "{", 0);
        dx_edge(s, c, (uint16_t)(ind + 1), t);
        dx_line(s, ind, "}", 0);
        *next = o;
        return true;
    }
    return false;
}

// Whether to is reachable from from without passing through avoid or leaving the region.
static bool reaches(dx_st_t *s, const dx_cx_t *c, uint32_t from, uint32_t to, uint32_t avoid) {
    dx_fn_t *x = s->x;
    if (x->nb > 4000 || from >= x->nreal)
        return false;
    uint8_t *seen = (uint8_t *)re_arena_calloc(x->a, x->nb + 1, 1);
    uint32_t *st = (uint32_t *)re_arena_alloc(x->a, (x->nb + 1) * sizeof(uint32_t));
    uint32_t sp = 0;
    if (!seen || !st)
        return false;
    st[sp++] = from;
    seen[from] = 1;
    while (sp) {
        uint32_t v = st[--sp];
        if (v == to)
            return true;
        for (uint32_t i = 0; i < dx_nsucc(x, v); i++) {
            uint32_t w = dx_succ(x, v, i);
            if (w == DX_NONE || w >= x->nreal || seen[w] || w == avoid || !dx_in_body(c, w) ||
                w == c->head)
                continue;
            seen[w] = 1;
            st[sp++] = w;
        }
    }
    return false;
}

// Where the two arms of the branch at b meet. The post dominator, unless one arm runs
// into the other's first block: then that block is the merge even though the other arm
// can also leave by a return, and the branch prints as a one armed if before it.
static uint32_t merge_of(dx_st_t *s, const dx_cx_t *c, uint32_t b) {
    const dx_block_t *p = &s->x->b[b];
    uint32_t T = p->succ[0], F = p->succ[1];
    // An arm that goes straight to where the enclosing region carries on needs no body:
    // that block is the merge, and the other arm is a one armed if before it.
    if (stop_kind(c, T) == 1 || stop_kind(c, F) == 1)
        return stop_kind(c, T) == 1 ? T : F;
    if (F < s->x->nreal && !s->done[F] && reaches(s, c, T, F, b))
        return F;
    if (T < s->x->nreal && !s->done[T] && reaches(s, c, F, T, b))
        return T;
    return p->ipdom;
}

// A two way branch. The fallthrough side prints first, as the then branch, which is
// the order the compiler laid the source out in.
static uint32_t emit_if(dx_st_t *s, uint32_t b, const dx_cx_t *c, uint16_t ind) {
    dx_fn_t *x = s->x;
    const dx_block_t *p = &x->b[b];
    uint32_t T = p->succ[0], F = p->succ[1], m = p->ipdom, next;
    const dx_block_t *fb = F < x->nreal ? &x->b[F] : NULL;
    if (fb && fb->term == DX_T_SWITCH && fb->n_pred == 1 && !s->done[F] && p->cond.l &&
        (p->cond.op == DX_GT || p->cond.op == DX_GE)) {
        dx_body_lines(s, F, ind);
        return switch_cases(s, F, T, p->cond.l, c, ind);
    }
    if (exit_if(s, b, c, ind, &next))
        return next;
    m = merge_of(s, c, b);
    if (m != DX_NONE && !dx_in_body(c, m))
        m = DX_NONE;
    dx_cx_t in = push_stop(c, m);
    if (T == m || F == m) {
        uint32_t one = T == m ? F : T;
        dx_line(s, ind, dx_text(x->a, 0, 8, "if (%s)", dx_cond_text(x, &p->cond, T == m)).s,
                p->end);
        dx_line(s, ind, "{", 0);
        arm(s, one, &in, (uint16_t)(ind + 1));
        dx_line(s, ind, "}", 0);
        return m;
    }
    size_t at = RE_VEC_LEN(&s->lines);
    dx_line(s, ind, dx_text(x->a, 0, 8, "if (%s)", dx_cond_text(x, &p->cond, true)).s, p->end);
    dx_line(s, ind, "{", 0);
    arm(s, F, &in, (uint16_t)(ind + 1));
    if (!added_text(s, at + 2)) {
        // nothing runs on the fallthrough side: the taken side is the only arm
        s->lines.len = at;
        dx_line(s, ind, dx_text(x->a, 0, 8, "if (%s)", dx_cond_text(x, &p->cond, false)).s, p->end);
        dx_line(s, ind, "{", 0);
        arm(s, T, &in, (uint16_t)(ind + 1));
        dx_line(s, ind, "}", 0);
        return m;
    }
    dx_line(s, ind, "}", 0);
    size_t before = RE_VEC_LEN(&s->lines);
    dx_line(s, ind, "else", 0);
    dx_line(s, ind, "{", 0);
    arm(s, T, &in, (uint16_t)(ind + 1));
    if (!added_text(s, before + 2))
        s->lines.len = before; // an empty else says nothing
    else
        dx_line(s, ind, "}", 0);
    return m;
}

void dx_seq(dx_st_t *s, uint32_t b, const dx_cx_t *c, uint16_t ind) {
    s->depth++;
    if (is_stop(c, b))
        b = dx_edge(s, c, ind, b);
    while (b != DX_NONE) {
        dx_fn_t *x = s->x;
        if (s->done[b] || b >= x->nreal) {
            dx_goto(s, ind, b);
            break;
        }
        if (s->hdr[b] && b != c->head) {
            b = dx_emit_loop(s, b, c, ind);
            if (b != DX_NONE)
                b = dx_edge(s, c, ind, b);
            continue;
        }
        dx_body_lines(s, b, ind);
        if (b == c->latch)
            break;
        const dx_block_t *p = &x->b[b];
        if (p->term == DX_T_COND)
            b = emit_if(s, b, c, ind);
        else if (p->term == DX_T_SWITCH)
            b = switch_cases(s, b, DX_NONE, NULL, c, ind);
        else if (p->term == DX_T_FALL || p->term == DX_T_JUMP)
            b = p->succ[0];
        else
            break;
        b = dx_edge(s, c, ind, b);
    }
    s->depth--;
}
