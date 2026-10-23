// re_trick.c - control flow tricks the deep walk sees through: opaque predicates and kin.
// Module: feature (C11).
// Owns: re_trick_step, the predecessor state table, and the x86 patterns it recognises.
// Depends: re_func_priv.h, re_code. Rewrites a transfer only when its outcome is certain.
#include "features/code/re_func_priv.h"

#include <string.h>

#define FLAG_UNKNOWN 0u
#define FLAG_CLEAR 1u
#define FLAG_SET 2u

static re_trick_t *slot(walk_t *w, uint64_t next) {
    return &w->tricks[(next ^ (next >> 9)) & (RE_TRICK_SLOTS - 1u)];
}

static const re_trick_t *pred_of(walk_t *w, uint64_t va) {
    const re_trick_t *t = slot(w, va);
    return t->next == va ? t : NULL;
}

// The condition code of a Jcc, or -1. Short forms are 70-7F, near forms 0F 80-8F.
static int jcc_code(const re_insn_t *in) {
    if (!in->is_branch || !in->is_conditional)
        return -1;
    if (in->insn_id >= 0x0070u && in->insn_id <= 0x007Fu)
        return (int)(in->insn_id - 0x0070u);
    if (in->insn_id >= 0x0180u && in->insn_id <= 0x018Fu)
        return (int)(in->insn_id - 0x0180u);
    return -1;
}

// 1 when the branch is always taken, 0 when never, -1 when the flags do not decide it.
static int decide(const re_trick_t *p, int cc) {
    int zf = p->zf == FLAG_UNKNOWN ? -1 : (p->zf == FLAG_SET);
    int cf = p->cf == FLAG_UNKNOWN ? -1 : (p->cf == FLAG_SET);
    switch (cc) {
        case 2: // jb: CF
            return cf;
        case 3: // jae: !CF
            return cf < 0 ? -1 : !cf;
        case 4: // je: ZF
            return zf;
        case 5: // jne: !ZF
            return zf < 0 ? -1 : !zf;
        case 6: // jbe: CF or ZF
            if (cf == 1 || zf == 1)
                return 1;
            return (cf == 0 && zf == 0) ? 0 : -1;
        case 7: // ja: !CF and !ZF
            if (cf == 1 || zf == 1)
                return 0;
            return (cf == 0 && zf == 0) ? 1 : -1;
        default:
            return -1;
    }
}

// xor, sub or cmp of a register with itself: ZF set and CF clear whatever it held.
static bool self_op(const re_insn_t *in) {
    switch (in->insn_id) {
        case 0x0028u:
        case 0x0029u:
        case 0x002Au:
        case 0x002Bu:
        case 0x0030u:
        case 0x0031u:
        case 0x0032u:
        case 0x0033u:
        case 0x0038u:
        case 0x0039u:
        case 0x003Au:
        case 0x003Bu:
            return in->has_modrm && !in->is_mem && in->reg == in->rm;
        default:
            return false;
    }
}

// Instructions that leave every flag alone, so the predecessor's flag facts carry over.
static bool keeps_flags(const re_insn_t *in) {
    uint16_t id = in->insn_id;
    if (id == 0x0090u || id == 0x011Fu || id == 0x008Du || jcc_code(in) >= 0)
        return true;
    if ((id >= 0x0088u && id <= 0x008Bu) || (id >= 0x00B0u && id <= 0x00BFu))
        return true;
    if (id == 0x00C6u || id == 0x00C7u || id == 0x0068u || id == 0x006Au)
        return true;
    return id >= 0x0050u && id <= 0x005Fu;
}

static void flags_after(const re_trick_t *p, const re_insn_t *in, re_trick_t *n) {
    if (self_op(in)) {
        n->zf = FLAG_SET;
        n->cf = FLAG_CLEAR;
    } else if (in->insn_id == 0x00F9u || in->insn_id == 0x00F8u) {
        n->zf = p ? p->zf : FLAG_UNKNOWN;
        n->cf = in->insn_id == 0x00F9u ? FLAG_SET : FLAG_CLEAR;
    } else if (in->insn_id == 0x00F5u && p && p->cf != FLAG_UNKNOWN) {
        n->zf = p->zf;
        n->cf = p->cf == FLAG_SET ? FLAG_CLEAR : FLAG_SET;
    } else if (p && keeps_flags(in)) {
        n->zf = p->zf;
        n->cf = p->cf;
    }
}

// The register an instruction loads a known constant into, with the value, or
// RE_TRICK_NOREG. Arithmetic with an immediate on the register already tracked folds
// into the constant, which is how a split constant (mov, then xor with a key) is seen.
static void reg_after(const re_trick_t *p, const re_insn_t *in, re_trick_t *n) {
    uint16_t id = in->insn_id;
    uint8_t digit = (uint8_t)((in->modrm >> 3) & 7u);
    if (id >= 0x00B8u && id <= 0x00BFu && in->opsize >= 4) {
        n->reg = (uint8_t)((id & 7u) | ((in->rex & 1u) ? 8u : 0u));
        n->reg_val = (uint64_t)in->imm;
    } else if (id == 0x00C7u && in->has_modrm && !in->is_mem && digit == 0u) {
        n->reg = in->rm;
        n->reg_val = (uint64_t)in->imm;
    } else if (id == 0x008Du && in->rip_rel && in->has_mem) {
        n->reg = in->reg;
        n->reg_val = in->mem;
    } else if ((id == 0x0081u || id == 0x0083u) && p && p->reg != RE_TRICK_NOREG && in->has_modrm &&
               !in->is_mem && in->rm == p->reg) {
        uint64_t k = (uint64_t)in->imm;
        n->reg = p->reg;
        if (digit == 0u)
            n->reg_val = p->reg_val + k;
        else if (digit == 5u)
            n->reg_val = p->reg_val - k;
        else if (digit == 6u)
            n->reg_val = p->reg_val ^ k;
        else
            n->reg = RE_TRICK_NOREG;
    }
}

// Record what in leaves behind for the instruction that falls through after it.
static void record(walk_t *w, const re_trick_t *p, const re_insn_t *in) {
    re_trick_t n;
    int cc = jcc_code(in);
    memset(&n, 0, sizeof(n));
    n.next = in->addr + in->size;
    n.reg = RE_TRICK_NOREG;
    flags_after(p, in, &n);
    reg_after(p, in, &n);
    if (cc >= 0 && in->has_target) {
        n.jcc = (uint8_t)(cc + 1);
        n.jcc_to = in->target;
    }
    if (in->insn_id == 0x0068u || in->insn_id == 0x006Au) {
        n.push = true;
        n.push_val = (uint64_t)in->imm;
    }
    *slot(w, n.next) = n;
}

// call $+N followed by pop: the call only reads its own address. Not a function.
static bool call_pop(walk_t *w, const re_insn_t *in) {
    re_insn_t t;
    uint64_t next = in->addr + in->size;
    if (!in->is_call || !in->has_target || in->target < next || in->target - next > 16u)
        return false;
    if (!re_code_insn(w->code, in->target, &t))
        return false;
    return t.insn_id >= 0x0058u && t.insn_id <= 0x005Fu;
}

static int classify(walk_t *w, const re_trick_t *p, const re_insn_t *in, uint64_t *to) {
    int cc = jcc_code(in);
    if (cc >= 0 && in->has_target && p) {
        int d = decide(p, cc);
        if (d == 0)
            return RE_TRICK_FALL;
        if (d == 1 || (p->jcc && (p->jcc - 1) == (cc ^ 1) && p->jcc_to == in->target)) {
            *to = in->target;
            return RE_TRICK_LOCAL;
        }
    }
    if (in->is_return && p && p->push && re_code_in_code(w->code, p->push_val)) {
        *to = p->push_val;
        return RE_TRICK_LOCAL;
    }
    if (call_pop(w, in)) {
        *to = in->target;
        return RE_TRICK_LOCAL;
    }
    if (in->insn_id == 0x00FFu && in->has_modrm && !in->is_mem && in->is_branch && !in->is_call &&
        p && p->reg == in->rm && re_code_in_code(w->code, p->reg_val)) {
        *to = p->reg_val;
        return RE_TRICK_LOCAL;
    }
    return RE_TRICK_NONE;
}

int re_trick_step(walk_t *w, const re_insn_t *in, uint64_t *to) {
    const re_trick_t *p;
    re_trick_t copy;
    int act;
    if (!w->tricks)
        return RE_TRICK_NONE;
    p = pred_of(w, in->addr);
    if (p) {
        copy = *p; // the slot for in's successor may be the same slot
        p = &copy;
    }
    act = classify(w, p, in, to);
    record(w, p, in);
    return act;
}
