// re_deobf.c - the deobfuscation idioms that need the image bytes.
// Module: feature (C11).
// Owns: indirect call recovery, the call $+5 trampoline, and stack strings.
// Depends: re_flow.h, re_code, re_ir. The op stream is rewritten in place
//           only: re_ir_emit reallocates the op array, so a pass that
//           inserted ops would leave earlier pointers dangling.
#include "features/flow/re_flow.h"

#include <string.h>

// The longest stack string the pass will decode. A longer run is memcpy
// shaped or a buffer filled at runtime, and naming either a string would be
// inventing one.
#define RE_STACKSTR_MAX RE_FLOW_STR_MAX

// A byte at a virtual address, through the code map's own translation. Every
// image read in this pass goes through here, so an address outside the mapped
// raw data reads as absent rather than as memory that is not there.
static bool byte_at(const re_code_t *c, uint64_t va, uint8_t *out) {
    uint64_t off;
    if (!c || !re_code_offset(c, va, &off) || off >= c->img.n)
        return false;
    *out = c->img.p[off];
    return true;
}

// A little endian quad, read byte at a time so an entry that runs off the end
// of the mapped data reads as absent instead of as a truncated value.
static bool read_u64(const re_code_t *c, uint64_t va, uint64_t *out) {
    uint64_t v = 0;
    uint8_t b;
    for (int i = 0; i < 8; i++) {
        if (!byte_at(c, va + (uint64_t)i, &b))
            return false;
        v |= (uint64_t)b << (8 * i);
    }
    *out = v;
    return true;
}

static void count(re_flow_stat_t *st, size_t *which, size_t n) {
    if (!st)
        return;
    *which += n;
}

// The call $+5 trampoline: a call whose target is the next instruction is a
// push of a return address and nothing else. It becomes a NOP when nothing
// between the pair can observe the pushed address: no store could capture it
// and no call could return from inside the trampoline. The jump that follows
// is left alone, because the printed body follows its target either way.
static void thunk_site(re_ir_func_t *f, re_ir_op_t *call, re_flow_stat_t *st) {
    if (call->op != RE_OP_CALL || call->const_val != (int64_t)(call->addr + 5))
        return;
    for (size_t bi = 0; bi < f->n_blocks; bi++) {
        for (size_t k = 0; k < f->blocks[bi].n_ops; k++) {
            re_ir_op_t *op = &f->blocks[bi].ops[k];
            if (op->addr <= call->addr)
                continue;
            if (op->op == RE_OP_BRANCH) {
                if ((uint64_t)op->const_val == call->addr + 5) {
                    call->op = RE_OP_NOP;
                    count(st, &st->n_thunk, 1);
                }
                return;
            }
            if (op->op == RE_OP_STORE || op->op == RE_OP_CALL || op->op == RE_OP_CALLIND ||
                op->op == RE_OP_RETURN || op->op == RE_OP_CBRANCH)
                return;
        }
    }
}

// One indirect call. A rip relative call through a data slot is the form both
// the loader and the vtables produce, and the slot's contents name the target:
// an internal one resolves, an import slot reads as zero before the loader has
// run and stays an honest indirect. Requiring the target to be recovered code
// keeps a junk slot from being reported as a call into nowhere.
static void callind_site(re_code_t *c, re_ir_op_t *op, re_flow_stat_t *st) {
    re_insn_t insn;
    uint64_t target;
    if (op->op != RE_OP_CALLIND || !c)
        return;
    if (!re_code_insn(c, op->addr, &insn))
        return;
    if (!insn.is_call || insn.has_target || !insn.is_mem || !insn.rip_rel)
        return;
    if (!read_u64(c, insn.mem, &target) || !target)
        return;
    if (!re_code_in_code(c, target))
        return;
    op->op = RE_OP_CALL;
    op->const_val = (int64_t)target;
    count(st, &st->n_callind, 1);
}

// A byte this pass is willing to name as text: printable, or the terminator.
static bool text_byte(uint8_t b) {
    return b == 0 || (b >= 0x20 && b <= 0x7E);
}

// Decode one run of immediate stores to ascending frame slots. The bytes are
// the stored constants in little endian order, which is the order the machine
// writes them in, and the run ends at the first store that does not continue
// the pattern. Returns the ops consumed.
// The immediate a store wrote. The value varnode names the constant op that
// defined it, and the value itself lives in that op, so the lookup walks the
// ids the block recorded while the pass walked it. An id the block never
// defined names no value here.
static int64_t imm_of(const int64_t *vals, const re_varnode_t *vn) {
    if (vn->space != RE_SPACE_CONST || vn->offset >= RE_FLOW_MAX_KEYS)
        return 0;
    return vals[vn->offset];
}

static size_t stackstr_run(const re_ir_op_t *ops, size_t n, size_t at, const int64_t *vals,
                           uint8_t *buf, size_t *len) {
    size_t k = at;
    size_t nb = 0;
    int64_t expect = (int16_t)ops[at].in[2].offset;
    *len = 0;
    while (k < n && nb + 8 <= RE_STACKSTR_MAX) {
        const re_ir_op_t *op = &ops[k];
        uint16_t sz = op->in[1].size;
        uint64_t v;
        if (op->op != RE_OP_STORE || op->in[1].space != RE_SPACE_CONST ||
            op->in[2].space != RE_SPACE_STACK || (int16_t)op->in[2].offset != expect || sz == 0 ||
            sz > 8)
            break;
        v = (uint64_t)imm_of(vals, &op->in[1]);
        for (uint16_t j = 0; j < sz; j++) {
            uint8_t b = (uint8_t)((v >> (8 * j)) & 0xFFu);
            if (!text_byte(b))
                return k;
            buf[nb++] = b;
        }
        expect = (int16_t)(expect + sz);
        *len = nb;
        k++;
    }
    return k;
}

// A run becomes a string when it spells at least four characters and holds at
// least one real letter inside, which keeps a run of terminators from being
// recorded as an empty string that prints nowhere.
static bool stackstr_worth(const uint8_t *buf, size_t len) {
    size_t letters = 0;
    if (len < 4)
        return false;
    for (size_t i = 0; i < len && buf[i]; i++)
        if (buf[i] >= 0x20 && buf[i] <= 0x7E)
            letters++;
    return letters >= 4;
}

static void stackstr_record(re_flow_stat_t *st, uint64_t at, const uint8_t *buf, size_t len) {
    re_flow_str_t s;
    size_t cut = len;
    if (!st)
        return;
    for (size_t i = 0; i < cut; i++) {
        if (buf[i] == 0) {
            cut = i;
            break;
        }
    }
    if (cut >= sizeof(s.text))
        cut = sizeof(s.text) - 1;
    s.at = at;
    memcpy(s.text, buf, cut);
    s.text[cut] = 0;
    RE_VEC_PUSH(&st->strs, st->strs_a, s);
}

// The driver over one block: indirect calls first, then thunks, then stack
// string runs, with the run skipping the ops it consumed so a run that is
// itself a thunk's body is not visited twice.
// The constant ids this block defined, recorded as the walk passes them so a
// store can name the value it wrote. The array is per block: ids are minted
// in order, so a store's immediate always sits behind it in the same block.
// A run that minted past the bound names nothing, matching the emitter's own
// refusal to print a temporary it cannot index.
// The table starts all zero and is put back to all zero after each block, by clearing
// the ids the block wrote, rather than cleared whole for every block.
static void const_table(const re_ir_block_t *blk, int64_t *vals, bool set) {
    for (size_t k = 0; k < blk->n_ops; k++) {
        const re_ir_op_t *op = &blk->ops[k];
        if (op->op == RE_OP_CONST && op->out.space == RE_SPACE_CONST &&
            op->out.offset < RE_FLOW_MAX_KEYS)
            vals[op->out.offset] = set ? op->const_val : 0;
    }
}

static void block_sites(re_ir_func_t *f, re_code_t *c, size_t bi, re_flow_stat_t *st,
                        int64_t *vals) {
    const re_ir_block_t *blk = &f->blocks[bi];
    size_t k = 0;
    const_table(blk, vals, true);
    while (k < blk->n_ops) {
        re_ir_op_t *op = &blk->ops[k];
        uint8_t buf[RE_STACKSTR_MAX];
        size_t len = 0;
        size_t end;
        callind_site(c, op, st);
        thunk_site(f, op, st);
        if (op->op == RE_OP_STORE && op->in[1].space == RE_SPACE_CONST &&
            op->in[2].space == RE_SPACE_STACK) {
            end = stackstr_run(blk->ops, blk->n_ops, k, vals, buf, &len);
            if (stackstr_worth(buf, len))
                stackstr_record(st, op->addr, buf, len);
            k = end > k ? end : k + 1;
            continue;
        }
        k++;
    }
    const_table(blk, vals, false); // nothing above turns an op into or out of a constant
}

void re_flow_deobf(re_ir_func_t *f, re_code_t *c, re_arena_t *a, re_flow_stat_t *st) {
    int64_t vals[RE_FLOW_MAX_KEYS];
    if (!f || !st)
        return;
    (void)a;
    if (st->strs_a)
        re_vec_clear(&st->strs);
    memset(vals, 0, sizeof(vals));
    for (size_t bi = 0; bi < f->n_blocks; bi++)
        block_sites(f, c, bi, st, vals);
}
