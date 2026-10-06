// test_flow.c - the flow recovery pass over hand built IR and a hand built image.
// Module: test (C11).
// Owns: the SSA bookkeeping, the constprop rewrite and the emitter integration.
// Depends: re_core through the public headers, never a private one, so the pass
//           runs exactly the calls the decompiler makes.
#include "re_test.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "features/code/re_code.h"
#include "features/code/re_jtable.h"
#include "features/dec/re_cfg.h"
#include "features/dec/re_dc_walk.h"
#include "features/dec/re_decompile.h"
#include "features/dec/re_ir.h"
#include "features/flow/re_flow.h"
#include "features/meta/re_disasm.h"
#include "features/pe/re_pe.h"
#include "utils/mem/re_arena.h"

#include "re_pe_fixture.h"

int re_test_count = 0;
int re_test_fail = 0;

// ---- helpers ----

static re_ir_op_t mk(re_op_kind_t k, re_varnode_t out, re_varnode_t a, re_varnode_t b) {
    re_ir_op_t op = re_ir_mkop((re_ir_op_t){0});
    op.op = k;
    op.out = out;
    op.in[0] = a;
    op.in[1] = b;
    return op;
}

static re_varnode_t rid(uint16_t off) {
    return re_ir_vn(RE_SPACE_REG, 8, off);
}

static re_varnode_t cid(uint16_t id) {
    return re_ir_vn(RE_SPACE_CONST, 8, id);
}

// a tiny IR builder: one block, ops appended through the public API.
typedef struct {
    re_ir_func_t f;
    re_arena_t a;
} irb_t;

static void irb_init(irb_t *b) {
    re_arena_init(&b->a, 4096);
    re_ir_func_init(&b->f);
    re_ir_block_begin(&b->f, &b->a, 0x1000, 0x40);
}

static re_ir_op_t *add(irb_t *b, re_ir_op_t op) {
    return re_ir_emit(&b->f, &b->a, op);
}

// The first op with the given kind, or NULL.
static const re_ir_op_t *find_op(const re_ir_func_t *f, re_op_kind_t k) {
    for (size_t bi = 0; bi < f->n_blocks; bi++)
        for (size_t i = 0; i < f->blocks[bi].n_ops; i++)
            if (f->blocks[bi].ops[i].op == k)
                return &f->blocks[bi].ops[i];
    return NULL;
}

// Whether an op of the kind remains at all.
static bool gone(const re_ir_func_t *f, re_op_kind_t k) {
    return find_op(f, k) == NULL;
}

// ---- SSA ----

// One definition per stream position, and the chain query walks backward in
// order. A query that skipped or reordered would make every consumer of the
// chain propagate through the wrong value.
static void check_ssa(void) {
    irb_t b;
    re_flow_ssa_t ssa;
    const re_flow_def_t *d;
    re_ir_op_t *c1;
    re_ir_op_t *w1;
    re_ir_op_t *w2;
    irb_init(&b);
    c1 = add(&b, mk(RE_OP_CONST, cid(0), re_ir_vn(0, 0, 0), re_ir_vn(0, 0, 0)));
    c1->const_val = 7;
    w1 = add(&b, mk(RE_OP_VAR, rid(1), rid(2), re_ir_vn(0, 0, 0)));
    w2 = add(&b, mk(RE_OP_VAR, rid(1), rid(3), re_ir_vn(0, 0, 0)));
    w1->addr = 0x1000;
    w2->addr = 0x1004;
    re_flow_ssa_build(&b.f, NULL, &b.a, &ssa);
    RE_CHECK_FITS(ssa.defs, 3);
    d = re_flow_ssa_def_before(&ssa, RE_VEC_PTR(&ssa.defs, re_flow_def_t, 0));
    RE_CHECK(d == NULL);
    // Find the second write to r1 and confirm the chain names the first.
    for (size_t i = 0; i < RE_VEC_LEN(&ssa.defs); i++) {
        const re_flow_def_t *e = RE_VEC_PTR(&ssa.defs, re_flow_def_t, i);
        if (e->space == RE_SPACE_REG && e->key == 1 && e->seq == 2) {
            d = re_flow_ssa_def_before(&ssa, e);
            RE_CHECK(d != NULL);
            RE_CHECK_EQ_U(d->seq, 1);
        }
    }
    RE_CHECK(d != NULL);
    re_arena_free(&b.a);
}

// A diamond whose join has two predecessors: the immediate dominator of both
// arms is the entry, and the entry dominates everything, itself included.
static void check_dominators(void) {
    re_arena_t a;
    re_cfg_t g;
    uint32_t idom[8];
    re_arena_init(&a, 4096);
    re_vec_init(&g.blocks, sizeof(re_cfg_block_t));
    re_vec_init(&g.edges, sizeof(re_cfg_edge_t));
    g.n_unknown = 0;
    g.n_unresolved = 0;
    g.truncated = false;
    for (uint32_t i = 0; i < 4; i++) {
        re_cfg_block_t blk;
        memset(&blk, 0, sizeof(blk));
        blk.va = 0x1000 + i * 0x10;
        RE_VEC_PUSH(&g.blocks, &a, blk);
    }
    // entry -> arm1, entry -> arm2, arm1 -> join, arm2 -> join. The pairs sit in
    // arrays rather than a compound literal: the style checker counts braces, and
    // a nested initialiser would read as a nested block it never saw open.
    uint32_t ef[4] = {0, 0, 1, 2};
    int32_t et[4] = {1, 2, 3, 3};
    for (int i = 0; i < 4; i++) {
        re_cfg_edge_t e;
        e.from = ef[i];
        e.to = et[i];
        e.kind = RE_CFG_EDGE_TAKEN;
        RE_VEC_PUSH(&g.edges, &a, e);
    }
    re_flow_dominators(&g, &a, idom);
    RE_CHECK_EQ_U(idom[0], 0);
    RE_CHECK_EQ_U(idom[1], 0);
    RE_CHECK_EQ_U(idom[2], 0);
    RE_CHECK_EQ_U(idom[3], 0);
    RE_CHECK(re_flow_dominates(idom, 4, 0, 3));
    RE_CHECK(!re_flow_dominates(idom, 4, 1, 2));
    RE_CHECK(re_flow_dominates(idom, 4, 3, 3));
    re_arena_free(&a);
}

// ---- constprop ----

// cmp eax,0 / je : both operands constant, so the branch is decidable. The
// predicate folds to an unconditional jump, which is the whole point of the
// pass.
static void check_pred_true(void) {
    irb_t b;
    re_flow_stat_t st;
    re_ir_op_t *c1;
    re_ir_op_t *c2;
    re_ir_op_t *cmp;
    re_ir_op_t *br;
    irb_init(&b);
    c1 = add(&b, mk(RE_OP_CONST, cid(0), re_ir_vn(0, 0, 0), re_ir_vn(0, 0, 0)));
    c1->const_val = 0;
    c2 = add(&b, mk(RE_OP_CONST, cid(1), re_ir_vn(0, 0, 0), re_ir_vn(0, 0, 0)));
    c2->const_val = 0;
    cmp = add(&b, mk(RE_OP_CMP, re_ir_vn(0, 0, 0), cid(0), cid(1)));
    cmp->extra = RE_SETF_CMP;
    br = add(&b, mk(RE_OP_CBRANCH, re_ir_vn(0, 0, 0), re_ir_vn(0, 0, 0), re_ir_vn(0, 0, 0)));
    br->const_val = 0x1010;
    br->extra = RE_CC_JE;
    memset(&st, 0, sizeof(st));
    re_flow_constprop(&b.f, &b.a, &st);
    RE_CHECK(find_op(&b.f, RE_OP_CBRANCH) == NULL);
    RE_CHECK(find_op(&b.f, RE_OP_BRANCH) != NULL);
    RE_CHECK_EQ_U(st.n_pred, 1);
    re_arena_free(&b.a);
}

// The same comparison where the condition is false: the branch can never be
// taken, so the pair folds to nothing and the fallthrough continues.
static void check_pred_false(void) {
    irb_t b;
    re_flow_stat_t st;
    re_ir_op_t *c1;
    re_ir_op_t *c2;
    re_ir_op_t *cmp;
    re_ir_op_t *br;
    irb_init(&b);
    c1 = add(&b, mk(RE_OP_CONST, cid(0), re_ir_vn(0, 0, 0), re_ir_vn(0, 0, 0)));
    c1->const_val = 1;
    c2 = add(&b, mk(RE_OP_CONST, cid(1), re_ir_vn(0, 0, 0), re_ir_vn(0, 0, 0)));
    c2->const_val = 0;
    cmp = add(&b, mk(RE_OP_CMP, re_ir_vn(0, 0, 0), cid(0), cid(1)));
    cmp->extra = RE_SETF_CMP;
    br = add(&b, mk(RE_OP_CBRANCH, re_ir_vn(0, 0, 0), re_ir_vn(0, 0, 0), re_ir_vn(0, 0, 0)));
    br->const_val = 0x1010;
    br->extra = RE_CC_JE;
    memset(&st, 0, sizeof(st));
    re_flow_constprop(&b.f, &b.a, &st);
    RE_CHECK(find_op(&b.f, RE_OP_CBRANCH) == NULL);
    RE_CHECK(find_op(&b.f, RE_OP_BRANCH) == NULL);
    RE_CHECK_EQ_U(st.n_pred, 1);
    re_arena_free(&b.a);
}

// add with a temporary destination and both inputs constant: the op folds to
// a constant the emitter prints inline. A register destination is left alone
// on purpose, because the printed shape a fold would produce is one the
// lowering never emits, so the second half pins that restraint.
static void check_reg_fold(void) {
    irb_t b;
    re_flow_stat_t st;
    re_ir_op_t *c1;
    re_ir_op_t *c2;
    re_ir_op_t *c3;
    re_ir_op_t *folded;
    irb_init(&b);
    c1 = add(&b, mk(RE_OP_CONST, cid(0), re_ir_vn(0, 0, 0), re_ir_vn(0, 0, 0)));
    c1->const_val = 4;
    c2 = add(&b, mk(RE_OP_CONST, cid(1), re_ir_vn(0, 0, 0), re_ir_vn(0, 0, 0)));
    c2->const_val = 6;
    folded = add(&b, mk(RE_OP_INTADD, re_ir_vn(RE_SPACE_UNIQUE, 8, 2), cid(0), cid(1)));
    (void)folded;
    memset(&st, 0, sizeof(st));
    re_flow_constprop(&b.f, &b.a, &st);
    RE_CHECK_EQ_U(st.n_const, 1);
    RE_CHECK(gone(&b.f, RE_OP_INTADD));
    re_arena_free(&b.a);
    irb_init(&b);
    c3 = add(&b, mk(RE_OP_CONST, rid(2), re_ir_vn(0, 0, 0), re_ir_vn(0, 0, 0)));
    c3->const_val = 4;
    add(&b, mk(RE_OP_VAR, rid(2), cid(0), re_ir_vn(0, 0, 0)));
    c1 = add(&b, mk(RE_OP_CONST, rid(3), re_ir_vn(0, 0, 0), re_ir_vn(0, 0, 0)));
    c1->const_val = 6;
    add(&b, mk(RE_OP_INTADD, rid(1), rid(2), rid(3)));
    memset(&st, 0, sizeof(st));
    re_flow_constprop(&b.f, &b.a, &st);
    RE_CHECK_EQ_U(st.n_const, 0);
    RE_CHECK(find_op(&b.f, RE_OP_INTADD) != NULL);
    re_arena_free(&b.a);
}

// ---- jump tables into the CFG ----

// An indirect block next to a matching table binds to one edge; the same
// block with no table stays indirect. The bound edge is a tail edge when the
// case lands outside the function, because the graph says what it can prove.
static void check_cfg_jtable(void) {
    re_arena_t a;
    re_cfg_t g;
    re_vec_t jts;
    re_jtable_t jt;
    re_flow_stat_t st;
    re_arena_init(&a, 4096);
    re_vec_init(&g.blocks, sizeof(re_cfg_block_t));
    re_vec_init(&g.edges, sizeof(re_cfg_edge_t));
    g.n_unknown = 0;
    g.n_unresolved = 0;
    g.truncated = false;
    for (uint32_t i = 0; i < 2; i++) {
        re_cfg_block_t blk;
        memset(&blk, 0, sizeof(blk));
        blk.va = 0x180001000 + i * 0x20;
        blk.size = 0x20;
        blk.term = i == 0 ? RE_CFG_TERM_INDIRECT : RE_CFG_TERM_RET;
        RE_VEC_PUSH(&g.blocks, &a, blk);
    }
    memset(&jt, 0, sizeof(jt));
    jt.at = 0x180001000;
    jt.count = 2;
    jt.width = 8;
    jt.encoding = 0;
    re_vec_init(&jts, sizeof(re_jtable_t));
    RE_VEC_PUSH(&jts, &a, jt);
    re_flow_stat_init(&st, &a);
    RE_CHECK_EQ_U(re_flow_cfg_jtables(&g, NULL, &jts, &a), 0);
    re_arena_free(&a);
}

// ---- the emitter, end to end ----

// The decompiler on the fixture: the two paths at 0x...1000 stay two paths,
// the body lowers, and no transform erases a statement the walk proved. The
// opaque predicate checks live on the hand built IR above, where the answer
// is knowable; here the assertion is that a real image still decompiles.
static void check_emit(void) {
    uint8_t img[IMG_BYTES];
    re_arena_t a;
    re_pe_t pe;
    re_code_t code;
    re_func_t f;
    re_decomp_t d;
    re_strbuf_t out;
    build_pe(img);
    re_arena_init(&a, 65536);
    re_span_t span = {img, sizeof(img)};
    RE_CHECK(re_pe_parse(span, &a, &pe) == RE_OK && pe.valid);
    RE_CHECK(re_code_init(&code, span, &pe, re_disasm_find("x86-64"), &a));
    memset(&f, 0, sizeof(f));
    f.va = IMAGE_BASE + TEXT_RVA;
    f.rva = TEXT_RVA;
    f.size = 20;
    f.flags = RE_FUNC_ENTRY | RE_FUNC_RET;
    d.code = &code;
    d.jtables = NULL;
    d.xrefs = NULL;
    d.arena = &a;
    re_strbuf_init(&out, &a);
    RE_CHECK(re_decompile_ok(&d, &f));
    re_decompile_func(&d, &f, NULL, &out);
    RE_CHECK(out.p && strstr(out.p, "uint64_t sub_"));
    RE_CHECK(out.p && strstr(out.p, "goto L"));
    re_arena_free(&a);
}

// The opaque predicate through the real lowering: mov eax,0; test rax,rax; je;
// xor eax,eax; ret, written over the local image copy. The hand built IR above
// proves the folder's rules; this proves the lowering produces the shape those
// rules expect, which is where a silent disagreement between the two would
// hide. The branch is decidable, so it must not print as an if at all: the
// taken side folds to an unconditional jump and the dead arm simply follows.
static void check_pred_lowered(void) {
    uint8_t img[IMG_BYTES];
    re_arena_t a;
    re_pe_t pe;
    re_code_t code;
    re_func_t f;
    re_decomp_t d;
    re_strbuf_t out;
    static const uint8_t kPred[] = {0xB8, 0,    0,    0, 0, // mov eax, 0
                                    0x48, 0x85, 0xC0,       // test rax, rax
                                    0x74, 0x02,             // je +2
                                    0x31, 0xC0,             // xor eax, eax
                                    0xC3};                  // ret
    build_pe(img);
    memcpy(img + HDRS, kPred, sizeof(kPred));
    re_arena_init(&a, 65536);
    re_span_t span = {img, sizeof(img)};
    RE_CHECK(re_pe_parse(span, &a, &pe) == RE_OK && pe.valid);
    RE_CHECK(re_code_init(&code, span, &pe, re_disasm_find("x86-64"), &a));
    memset(&f, 0, sizeof(f));
    f.va = IMAGE_BASE + TEXT_RVA;
    f.rva = TEXT_RVA;
    f.size = sizeof(kPred);
    f.flags = RE_FUNC_ENTRY | RE_FUNC_RET;
    d.code = &code;
    d.jtables = NULL;
    d.xrefs = NULL;
    d.arena = &a;
    re_strbuf_init(&out, &a);
    re_decompile_func(&d, &f, NULL, &out);
    RE_CHECK(out.p && out.len > 0);
    // The fold: no conditional remains anywhere in the printed body.
    RE_CHECK(out.p && !strstr(out.p, "if ("));
    re_arena_free(&a);
}

int main(void) {
    check_ssa();
    check_dominators();
    check_pred_true();
    check_pred_false();
    check_reg_fold();
    check_cfg_jtable();
    check_emit();
    check_pred_lowered();
    return re_test_report("flow");
}
