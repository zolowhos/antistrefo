// re_dcx_out.c - the printed function: signature, declarations, body, address map.
// Module: feature (C11).
// Owns: running the structurer, the header and declarations, and the final text.
// Depends: re_dcx_st.h, re_dc_print (the site record), re_map. Declarations come after
//           the body is built, because the body is what mints the variables.
#include "features/dec/struct/re_dcx_st.h"

#include "features/dec/re_dc_print.h"
#include "utils/mem/re_map.h"

#include <string.h>

static void puts_ind(re_strbuf_t *o, uint16_t ind) {
    for (uint16_t i = 0; i < ind; i++)
        re_strbuf_puts(o, "    ");
}

static uint32_t count_nl(const re_strbuf_t *o, size_t from) {
    uint32_t n = 0;
    for (size_t i = from; o->p && i < o->len; i++)
        n += o->p[i] == '\n';
    return n;
}

static void params(dx_fn_t *x, re_strbuf_t *o) {
    unsigned n = 0;
    re_strbuf_puts(o, "(");
    for (unsigned p = 0; p < x->nparams; p++, n++)
        re_strbuf_appendf(o, "%s%s a%u", n ? ", " : "", dx_type(x->pw[p], false), p + 1);
    for (unsigned k = 0; k < x->nstk; k++, n++)
        re_strbuf_appendf(o, "%suint64_t a%u", n ? ", " : "", dx_max_reg_args(x) + k + 1);
    re_strbuf_puts(o, n ? ")\n" : "void)\n");
}

static bool ident(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

// The names a declaration may print, each marked when a printed line uses it as a whole
// identifier. Declarations follow the text, so a variable whose only statement was
// dropped as dead is not declared. One pass over the text marks every name, where a
// search per name read every line once for each variable.
typedef struct {
    re_map_t ids;  // name -> its index in seen, from 1
    uint8_t *seen; // seen[id]: some line uses the name; seen[0] stays 0
    uint32_t n, cap;
} dx_used_t;

static uint32_t used_add(dx_used_t *u, const char *name) {
    re_str_t k = re_str(name);
    uintptr_t id = (uintptr_t)re_map_gets(&u->ids, k);
    if (id || u->n >= u->cap)
        return (uint32_t)id;
    id = ++u->n;
    return re_map_puts(&u->ids, k, (const void *)id) ? (uint32_t)id : 0;
}

// Every maximal identifier run is looked up once: a run equal to a name is that name
// with no identifier character on either side, the whole identifier test exactly.
static void used_scan(dx_used_t *u, const dx_st_t *s) {
    for (size_t i = 0; u->n && i < RE_VEC_LEN(&s->lines); i++) {
        const char *p = RE_VEC_PTR(&s->lines, dx_ln_t, i)->s;
        for (size_t at = 0; p && p[at];) {
            size_t b = at;
            while (ident(p[at]))
                at++;
            if (at == b) {
                at++;
                continue;
            }
            if (p[b] >= '0' && p[b] <= '9')
                continue; // a number names nothing
            uintptr_t id = (uintptr_t)re_map_get(&u->ids, p + b, at - b);
            if (id)
                u->seen[id] = 1;
        }
    }
}

static bool slot_declares(const dx_fn_t *x, const dx_slot_t *sl) {
    return sl->off < (x->cc == RE_CC_SYSV ? 8 : 0x28) && !sl->elem;
}

// ids[i] is variable i's name and ids[nv + i] slot i's, 0 for a slot that never
// declares. NULL when the arena is out.
static const uint32_t *used_build(dx_fn_t *x, const dx_st_t *s, dx_used_t *u) {
    size_t nv = RE_VEC_LEN(&x->vars), ns = RE_VEC_LEN(&x->slots);
    uint32_t *ids = (uint32_t *)re_arena_calloc(x->a, nv + ns + 1, sizeof(uint32_t));
    u->seen = (uint8_t *)re_arena_calloc(x->a, nv + ns + 1, 1);
    u->n = 0;
    u->cap = (uint32_t)(nv + ns);
    re_map_init(&u->ids, x->a, nv + ns);
    if (!ids || !u->seen)
        return NULL;
    for (size_t i = 0; i < nv; i++)
        ids[i] = used_add(u, RE_VEC_PTR(&x->vars, dx_var_t, i)->name);
    for (size_t i = 0; i < ns; i++) {
        const dx_slot_t *sl = RE_VEC_PTR(&x->slots, dx_slot_t, i);
        if (slot_declares(x, sl))
            ids[nv + i] = used_add(u, dx_slot_name(x, sl->off));
    }
    used_scan(u, s);
    return ids;
}

static void declarations(dx_fn_t *x, const dx_st_t *s, re_strbuf_t *o) {
    dx_used_t u;
    const uint32_t *ids = used_build(x, s, &u);
    size_t nv = RE_VEC_LEN(&x->vars);
    bool any = false;
    if (!ids)
        return;
    for (size_t i = 0; i < nv; i++) {
        const dx_var_t *v = RE_VEC_PTR(&x->vars, dx_var_t, i);
        if (!u.seen[ids[i]])
            continue;
        re_strbuf_appendf(o, "    %s %s;", dx_type(v->w, false), v->name);
        if (v->reg >= 0)
            re_strbuf_appendf(o, " // %s", dx_reg_name(x, (unsigned)v->reg, 8));
        re_strbuf_puts(o, "\n");
        any = true;
    }
    for (size_t i = 0; i < RE_VEC_LEN(&x->slots); i++) {
        const dx_slot_t *sl = RE_VEC_PTR(&x->slots, dx_slot_t, i);
        if (!u.seen[ids[nv + i]])
            continue;
        uint8_t w = sl->w ? sl->w : 8;
        if (sl->idx_w)
            re_strbuf_appendf(o, "    %s %s[%u];\n", dx_type(sl->idx_w, false),
                              dx_slot_name(x, sl->off), (unsigned)sl->alen);
        else if (w == 1 || w == 2 || w == 4 || w == 8 || w == 16)
            re_strbuf_appendf(o, "    %s %s;\n", dx_type(w, false), dx_slot_name(x, sl->off));
        else
            re_strbuf_appendf(o, "    uint8_t %s[%u];\n", dx_slot_name(x, sl->off), (unsigned)w);
        any = true;
    }
    if (any)
        re_strbuf_puts(o, "\n");
}

void dx_header(dx_fn_t *x, const dx_st_t *s, re_strbuf_t *o) {
    static const char *const kCc[] = {"unknown", "ms64", "sysv"};
    const char *name = x->f->name.n
                           ? dx_text(x->a, 0, 8, "%.*s", (int)x->f->name.n, x->f->name.p).s
                           : dx_text(x->a, 0, 8, "sub_%llX", (unsigned long long)x->f->va).s;
    re_strbuf_appendf(o, "// %s @ 0x%llX, size 0x%X, %s", name, (unsigned long long)x->f->va,
                      (unsigned)x->f->size, kCc[x->cc < 3 ? x->cc : 0]);
    if (x->n_unlowered)
        re_strbuf_appendf(o, ", %u instruction(s) not lifted", x->n_unlowered);
    re_strbuf_puts(o, "\n");
    re_strbuf_appendf(o, "%s %s", x->has_ret ? dx_type(x->ret_w ? x->ret_w : 8, false) : "void",
                      name);
    params(x, o);
    re_strbuf_puts(o, "{\n");
    declarations(x, s, o);
}

static void structure(dx_fn_t *x, dx_st_t *s) {
    dx_cx_t root;
    memset(s, 0, sizeof(*s));
    s->x = x;
    re_vec_init(&s->lines, sizeof(dx_ln_t));
    s->done = (uint8_t *)re_arena_calloc(x->a, x->nb + 1, 1);
    s->need = (uint8_t *)re_arena_calloc(x->a, x->nb + 1, 1);
    s->hdr = (uint8_t *)re_arena_calloc(x->a, x->nb + 1, 1);
    s->lno = (uint32_t *)re_arena_calloc(x->a, x->nb + 1, sizeof(uint32_t));
    if (!s->done || !s->need || !s->hdr || !s->lno)
        return;
    for (uint32_t b = 0; b < x->nreal; b++)
        for (uint32_t i = 0; i < x->b[b].n_pred; i++)
            if (dx_dominates(x, b, x->b[b].pred[i]))
                s->hdr[b] = 1;
    memset(&root, 0, sizeof(root));
    root.head = root.follow = root.latch = root.sw_follow = root.next_case = DX_NONE;
    dx_seq(s, 0, &root, 1);
    // Blocks no structured path reached print after the body, but only those a goto
    // names: a block every path reached as a duplicated tail is already printed in full.
    for (bool more = true; more;) {
        more = false;
        for (uint32_t i = 0; i < x->norder; i++) {
            uint32_t b = x->order[i];
            if (b >= x->nreal || s->done[b] || !s->need[b])
                continue;
            dx_seq(s, b, &root, 1);
            more = true;
        }
    }
    if (!x->has_ret)
        dx_drop_trailing(s, "return;", 1);
}

static bool ends_block(const dx_st_t *s, size_t i) {
    for (size_t k = i + 1; k < RE_VEC_LEN(&s->lines); k++) {
        const dx_ln_t *l = RE_VEC_PTR(&s->lines, dx_ln_t, k);
        if (l->label && !s->need[l->label - 1])
            continue;
        if (!l->label && !l->s)
            continue;
        return !l->label && l->s[0] == '}';
    }
    return true;
}

// The next line that prints, skipping dropped lines and labels nothing jumps to.
static size_t next_shown(const dx_st_t *s, size_t i) {
    for (size_t k = i + 1; k < RE_VEC_LEN(&s->lines); k++) {
        const dx_ln_t *l = RE_VEC_PTR(&s->lines, dx_ln_t, k);
        if ((l->label && s->need[l->label - 1]) || (!l->label && l->s))
            return k;
    }
    return RE_VEC_LEN(&s->lines);
}

// { one statement } prints without the braces, the way a person writes it. A label
// inside, a nested block or a do loop's closing line keeps them.
static void unbrace(dx_st_t *s) {
    size_t n = RE_VEC_LEN(&s->lines);
    for (size_t i = 0; i < n; i++) {
        dx_ln_t *open = RE_VEC_PTR(&s->lines, dx_ln_t, i);
        if (open->label || !open->s || open->s[0] != '{' || open->s[1])
            continue;
        size_t a = next_shown(s, i), b = a < n ? next_shown(s, a) : n;
        if (b >= n)
            continue;
        dx_ln_t *mid = RE_VEC_PTR(&s->lines, dx_ln_t, a),
                *close = RE_VEC_PTR(&s->lines, dx_ln_t, b);
        if (mid->label || close->label || !close->s || close->s[0] != '}' || close->s[1])
            continue;
        if (mid->s[0] == '{' || mid->s[0] == '}' || mid->ind != open->ind + 1 || mid->s[0] == 'c')
            continue; // a nested block, or a case label, keeps its braces
        open->s = NULL;
        close->s = NULL;
    }
}

static void site(dx_fn_t *x, uint32_t line, uint64_t va) {
    re_dc_site_t st;
    if (!x->d->sites || !va)
        return;
    st.line = line;
    st.va = va;
    RE_VEC_PUSH(x->d->sites, x->a, st);
}

void dx_print(dx_fn_t *x, re_strbuf_t *out) {
    dx_st_t s;
    size_t start = out->len;
    dx_merge_conds(x);
    structure(x, &s);
    unbrace(&s);
    dx_header(x, &s, out);
    uint32_t line = count_nl(out, start) + 1;
    for (size_t i = 0; i < RE_VEC_LEN(&s.lines); i++) {
        const dx_ln_t *l = RE_VEC_PTR(&s.lines, dx_ln_t, i);
        if (l->label) {
            if (!s.need[l->label - 1])
                continue;
            // A label must label a statement: one at the end of a block gets an empty one.
            re_strbuf_appendf(out, "LABEL_%u:%s\n", s.lno[l->label - 1],
                              ends_block(&s, i) ? ";" : "");
            line++;
            continue;
        }
        if (!l->s)
            continue;
        puts_ind(out, l->ind);
        re_strbuf_puts(out, l->s);
        re_strbuf_puts(out, "\n");
        site(x, line, l->va);
        line++;
    }
    re_strbuf_puts(out, "}\n");
}
