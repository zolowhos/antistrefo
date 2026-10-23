// re_dcx_main.c - the core's one entry point: build, analyse, emit, structure, print.
// Module: feature (C11).
// Owns: the order the stages run in.
// Depends: re_dcx.h, re_flow (the deobfuscation and constant passes run on the IR first).
#include "features/dec/core/re_dcx.h"

#include "features/flow/re_flow.h"

#include <string.h>

// Stack probes: __chkstk and its relatives take the frame size in rax, touch each page
// and return with every register as it was. As a call they would clobber rax and print
// alloca(__chkstk()); as what they are, they print nothing.
static bool is_probe(const dx_fn_t *x, uint64_t target) {
    static const char *const kProbe[] = {"__chkstk",      "_chkstk",          "__alloca_probe",
                                         "_alloca_probe", "_alloca_probe_16", "__chkstk_ms",
                                         "___chkstk_ms"};
    const re_fscan_t *s = x->d->scan;
    long i = s ? re_func_index_of(s, target) : -1;
    const re_func_t *g = i >= 0 ? re_func_at(s, (size_t)i) : NULL;
    if (!g || g->va != target || !g->name.n)
        return false;
    for (size_t k = 0; k < sizeof(kProbe) / sizeof(kProbe[0]); k++)
        if (re_str_eq_cstr(g->name, kProbe[k]))
            return true;
    return false;
}

static void drop_probes(dx_fn_t *x) {
    for (uint32_t b = 0; b < x->nreal; b++) {
        re_ir_block_t *blk = x->b[b].ir;
        for (size_t k = 0; blk && k < blk->n_ops; k++)
            if (blk->ops[k].op == RE_OP_CALL && is_probe(x, (uint64_t)blk->ops[k].const_val))
                blk->ops[k].op = RE_OP_NOP;
    }
}

static void stack_strings(const re_flow_stat_t *fl, re_strbuf_t *out) {
    for (size_t i = 0; i < RE_VEC_LEN(&fl->strs); i++) {
        const re_flow_str_t *s = RE_VEC_PTR(&fl->strs, re_flow_str_t, i);
        re_strbuf_appendf(out, "// stack string at 0x%llX: \"%s\"\n", (unsigned long long)s->at,
                          s->text);
    }
}

bool dx_decompile(const re_decomp_t *d, const re_func_t *f, const re_stack_t *st,
                  re_strbuf_t *out) {
    dx_fn_t x;
    re_flow_stat_t fl;
    dx_cache_t cache;
    memset(&x, 0, sizeof(x));
    memset(&cache, 0, sizeof(cache));
    re_vec_init(&cache.sums, sizeof(dx_sum_t));
    x.cache = &cache;
    x.d = d;
    x.f = f;
    x.st = st;
    x.code = d->code;
    x.a = d->arena;
    x.cc = st && st->cc ? st->cc : RE_CC_MS64;
    re_vec_init(&x.vars, sizeof(dx_var_t));
    if (!dx_build(&x))
        return false;
    re_flow_stat_init(&fl, x.a);
    re_flow_apply(&x.ir, x.code, x.a, &fl);
    dx_refresh(&x);
    drop_probes(&x);
    dx_consts(&x);
    dx_frame_pass(&x);
    dx_facts(&x);
    dx_usecount(&x);
    dx_emit_all(&x);
    stack_strings(&fl, out);
    dx_print(&x, out);
    return true;
}
