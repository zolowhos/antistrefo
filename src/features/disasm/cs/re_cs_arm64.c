// re_cs_arm64.c - Capstone ARM-64 backend behind the re_disasm vtable.
// Module: feature (C11).
// Owns: decode, render, prologue sniff, and register names for AArch64.
// Depends: Capstone only in this file. Feature callers never see a Capstone type.
#ifndef RE_ENABLE_CAPSTONE
typedef int re_cs_arm64_omitted_t;
#else
#    include "features/disasm/cs/re_cs_priv.h"

#    include <stddef.h>
#    include <stdint.h>
#    include <string.h>

#    include <capstone/capstone.h>

#    include "utils/text/re_str.h"
#    include "utils/text/re_strbuf.h"

typedef struct {
    csh handle;
    int state; // 0 unopened, 1 open, -1 failed
} re_cs_arm64_ctx_t;

static re_cs_arm64_ctx_t g_ctx;

static bool cs_ready(re_cs_arm64_ctx_t *c) {
    if (c->state == 1)
        return true;
    if (c->state < 0)
        return false;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &c->handle) != CS_ERR_OK) {
        c->state = -1;
        return false;
    }
    cs_option(c->handle, CS_OPT_DETAIL, CS_OPT_ON);
    c->state = 1;
    return true;
}

static bool has_group(const cs_insn *in, uint8_t group) {
    size_t i;
    if (!in->detail)
        return false;
    for (i = 0; i < in->detail->groups_count; i++) {
        if (in->detail->groups[i] == group)
            return true;
    }
    return false;
}

static bool is_conditional(const cs_insn *in) {
    arm64_cc cc;
    if (!in->detail)
        return false;
    cc = in->detail->arm64.cc;
    if (cc != ARM64_CC_INVALID && cc != ARM64_CC_AL && cc != ARM64_CC_NV)
        return true;
    return in->id == ARM64_INS_CBZ || in->id == ARM64_INS_CBNZ || in->id == ARM64_INS_TBZ ||
           in->id == ARM64_INS_TBNZ;
}

static bool take_imm_target(const cs_insn *in, uint64_t *out) {
    size_t i;
    if (!in->detail || !has_group(in, CS_GRP_BRANCH_RELATIVE))
        return false;
    for (i = 0; i < in->detail->arm64.op_count; i++) {
        const cs_arm64_op *op = &in->detail->arm64.operands[i];
        if (op->type == ARM64_OP_IMM) {
            *out = (uint64_t)op->imm;
            return true;
        }
    }
    return false;
}

static void classify(const cs_insn *in, re_insn_t *o) {
    o->is_return = has_group(in, CS_GRP_RET);
    o->is_call = has_group(in, CS_GRP_CALL);
    o->is_branch = has_group(in, CS_GRP_JUMP) && !o->is_call && !o->is_return;
    o->is_conditional = (o->is_branch || o->is_call) && is_conditional(in);
    if ((o->is_call || o->is_branch) && take_imm_target(in, &o->target))
        o->has_target = true;
}

static void clear_insn(re_insn_t *out, uint64_t addr) {
    memset(out, 0, sizeof(*out));
    out->addr = addr;
    out->base = RE_REG_NONE;
    out->index = RE_REG_NONE;
    out->reg = RE_REG_NONE;
    out->rm = RE_REG_NONE;
    out->text = re_str("");
}

static void take_regs(const cs_insn *in, re_insn_t *out) {
    size_t i;
    unsigned got = 0;
    if (!in->detail)
        return;
    out->op_count = (uint8_t)in->detail->arm64.op_count;
    // re_insn_t register fields are uint8_t. Capstone's X0..X28 sit above 255, so
    // only the compact names (fp, lr, sp, ...) can be stored here. High ids stay
    // RE_REG_NONE rather than wrapping into the wrong register.
    for (i = 0; i < in->detail->arm64.op_count && got < 2; i++) {
        const cs_arm64_op *op = &in->detail->arm64.operands[i];
        unsigned r;
        if (op->type != ARM64_OP_REG)
            continue;
        r = (unsigned)op->reg;
        if (r > 0xFFu)
            continue;
        if (got == 0)
            out->reg = (uint8_t)r;
        else
            out->rm = (uint8_t)r;
        got++;
    }
}

static bool fill_from_cs(const cs_insn *in, re_insn_t *out) {
    if (in->size == 0 || in->size > RE_MAX_INSN_LEN)
        return false;
    clear_insn(out, in->address);
    out->size = (uint8_t)in->size;
    out->insn_id = (uint16_t)in->id;
    out->opsize = 8;
    out->addrsize = 8;
    take_regs(in, out);
    classify(in, out);
    return true;
}

static bool arm64_decode(void *ctx, uint64_t addr, re_span_t code, re_insn_t *out) {
    re_cs_arm64_ctx_t *c = (re_cs_arm64_ctx_t *)ctx;
    cs_insn *insn = NULL;
    size_t n;
    bool ok;
    if (!c || !out || !code.p || code.n == 0 || !cs_ready(c))
        return false;
    n = cs_disasm(c->handle, code.p, code.n, addr, 1, &insn);
    if (n == 0)
        return false;
    ok = fill_from_cs(&insn[0], out);
    cs_free(insn, n);
    return ok;
}

static size_t arm64_lower(void *ctx, const re_insn_t *insn, re_ir_func_t *f, re_arena_t *a) {
    (void)ctx;
    (void)insn;
    (void)f;
    (void)a;
    return 0;
}

static const char *arm64_reg_name(void *ctx, unsigned reg) {
    re_cs_arm64_ctx_t *c = (re_cs_arm64_ctx_t *)ctx;
    const char *n;
    if (!c || !cs_ready(c) || reg == RE_REG_NONE || reg > 0xFFu)
        return "?";
    // Capstone ARM64 register ids for X0..X30 sit above 255, so the decode path
    // cannot stash them in a uint8_t field. Named GPRs that fit (fp, lr, sp) do.
    n = cs_reg_name(c->handle, (unsigned)reg);
    return n ? n : "?";
}

static unsigned arm64_reg_size(void *ctx, unsigned reg) {
    (void)ctx;
    (void)reg;
    return 8;
}

static bool is_stp_fp_lr(const cs_insn *in) {
    const cs_arm64_op *a;
    const cs_arm64_op *b;
    if (in->id != ARM64_INS_STP || !in->detail || in->detail->arm64.op_count < 2)
        return false;
    a = &in->detail->arm64.operands[0];
    b = &in->detail->arm64.operands[1];
    return a->type == ARM64_OP_REG && b->type == ARM64_OP_REG && a->reg == ARM64_REG_FP &&
           b->reg == ARM64_REG_LR;
}

static bool is_sub_sp(const cs_insn *in) {
    const cs_arm64_op *d;
    const cs_arm64_op *s;
    if (in->id != ARM64_INS_SUB || !in->detail || in->detail->arm64.op_count < 2)
        return false;
    d = &in->detail->arm64.operands[0];
    s = &in->detail->arm64.operands[1];
    return d->type == ARM64_OP_REG && s->type == ARM64_OP_REG && d->reg == ARM64_REG_SP &&
           s->reg == ARM64_REG_SP;
}

static bool is_mov_fp_sp(const cs_insn *in) {
    const cs_arm64_op *d;
    const cs_arm64_op *s;
    if (in->id != ARM64_INS_MOV || !in->detail || in->detail->arm64.op_count < 2)
        return false;
    d = &in->detail->arm64.operands[0];
    s = &in->detail->arm64.operands[1];
    return d->type == ARM64_OP_REG && s->type == ARM64_OP_REG && d->reg == ARM64_REG_FP &&
           s->reg == ARM64_REG_SP;
}

static bool is_prologue_insn(const cs_insn *in) {
    return is_stp_fp_lr(in) || is_sub_sp(in) || is_mov_fp_sp(in);
}

static bool arm64_prologue(void *ctx, uint64_t addr, re_span_t code) {
    re_cs_arm64_ctx_t *c = (re_cs_arm64_ctx_t *)ctx;
    const uint8_t *p;
    size_t left;
    uint64_t at;
    unsigned steps = 0;
    if (!c || !cs_ready(c) || !code.p || code.n == 0)
        return false;
    p = code.p;
    left = code.n;
    at = addr;
    while (left >= 4 && steps < 8) {
        cs_insn *insn = NULL;
        size_t n = cs_disasm(c->handle, p, left, at, 1, &insn);
        bool hit;
        size_t sz;
        if (n == 0)
            return false;
        hit = is_prologue_insn(&insn[0]);
        sz = insn[0].size;
        cs_free(insn, n);
        if (hit)
            return true;
        if (sz == 0 || sz > left)
            return false;
        p += sz;
        left -= sz;
        at += sz;
        steps++;
    }
    return false;
}

static const re_trfunc_t *arm64_trfunc(void *ctx, uint8_t insn_id) {
    (void)ctx;
    (void)insn_id;
    return NULL;
}

static void arm64_render(void *ctx, const re_insn_t *insn, re_arena_t *a, re_strbuf_t *out) {
    re_cs_arm64_ctx_t *c = (re_cs_arm64_ctx_t *)ctx;
    const char *mnem;
    (void)a;
    if (!c || !insn || !out || !cs_ready(c))
        return;
    mnem = cs_insn_name(c->handle, insn->insn_id);
    if (!mnem)
        mnem = "unk";
    re_strbuf_puts(out, mnem);
    if (insn->has_target)
        re_strbuf_appendf(out, " #0x%llx", (unsigned long long)insn->target);
    else if (insn->is_call || insn->is_branch)
        re_strbuf_puts(out, " <indirect>");
}

const re_disasm_t re_disasm_arm64 = {
    &g_ctx,         "arm64",        64,           arm64_decode, arm64_lower, arm64_reg_name,
    arm64_reg_size, arm64_prologue, arm64_trfunc, arm64_render,
};
#endif
