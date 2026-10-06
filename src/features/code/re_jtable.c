// re_jtable.c - recognises a table of case targets behind an indirect branch.
// Module: feature (C11).
// Owns: the entry counting, the absolute against relative decision, and the scan.
// Depends: re_jtable.h. A table is reported only when its length is known, since
//           a case count nobody can check is worse than no case count.
#include "features/code/re_jtable.h"

#include "features/pe/re_pe.h"
#include "utils/mem/re_buf.h"

// How an entry value becomes an address. A PE jump table stores an RVA, GCC
// stores an offset from the table, and a hand written one can store a full virtual
// address, so all three are tried and the one that explains the most entries wins.
typedef enum { ENC_VA = 0, ENC_RVA, ENC_REL } enc_t;

typedef struct {
    uint32_t count;
    enc_t enc;
    uint8_t width;
} shape_t;

// An entry is only a case target if it lands in code. That single test is what
// separates a jump table from a string table or an array of pointers, because
// both live in .rdata and both are full of plausible looking numbers.
static bool is_code(const re_code_t *c, uint64_t va) {
    return re_code_in_code(c, va);
}

static uint64_t decode_entry(enc_t enc, uint64_t table, uint64_t raw, uint64_t base) {
    if (enc == ENC_REL)
        return table + (uint64_t)(int64_t)(int32_t)(uint32_t)raw;
    if (enc == ENC_RVA)
        return base + raw;
    return raw;
}

// Read one entry of the given width, little endian, which is the only order a PE
// stores them in. The address is translated to a file offset first, because the
// table lives at a virtual address and the image is indexed by offset.
static bool read_entry(const re_code_t *c, uint64_t table, uint8_t width, uint32_t i,
                       uint64_t *out) {
    uint64_t off = 0;
    if (!re_code_offset(c, table + (uint64_t)i * width, &off))
        return false;
    if (width == 8)
        return re_rd64(c->img, off, out);
    uint32_t v = 0;
    if (!re_rd32(c->img, off, &v))
        return false;
    *out = v;
    return true;
}

// Read entries of the given width and encoding, stopping at the first one that is
// not code. The count is only believed when the run actually ended, so an endless
// run of valid pointers is reported as zero rather than as a huge switch.
static shape_t count_shape(const re_code_t *c, uint64_t table, uint8_t width, enc_t enc) {
    shape_t s;
    s.count = 0;
    s.enc = enc;
    s.width = width;
    for (uint32_t i = 0; i < RE_JTABLE_MAX; i++) {
        uint64_t raw = 0;
        if (!read_entry(c, table, width, i, &raw))
            break;
        if (!is_code(c, decode_entry(enc, table, raw, c->base))) {
            // A run that ends on the first miss is a table. A run that reaches
            // the cap without ending is not, and the count stays zero.
            s.count = (i >= RE_JTABLE_MIN) ? i : 0u;
            return s;
        }
        s.count = i + 1;
    }
    // The cap was reached, so the end was never seen. Not a table we can count.
    s.count = 0;
    return s;
}

// Pick the encoding that explains the most entries.
static shape_t best_shape(const re_code_t *c, uint64_t table) {
    shape_t best;
    shape_t cands[4];
    best.count = 0;
    best.enc = ENC_RVA;
    best.width = 4;
    cands[0] = count_shape(c, table, 4, ENC_RVA);
    cands[1] = count_shape(c, table, 4, ENC_REL);
    cands[2] = count_shape(c, table, 8, ENC_RVA);
    cands[3] = count_shape(c, table, 4, ENC_VA);
    for (size_t i = 0; i < 4; i++) {
        if (cands[i].count > best.count)
            best = cands[i];
    }
    return best;
}

// The table address is usually not referenced directly. GCC emits a lea of a base
// register followed by a load through it with a displacement, so the table lives
// at base + disp and the only way to see it is to carry the base across. This is
// deliberately not a data flow analysis: it tracks just the two forms that set a
// register to a known value, and nothing else.
typedef struct {
    bool ok[16];
    uint64_t val[16];
} consts_t;

static void track_lea(consts_t *c, const re_insn_t *in) {
    unsigned op = RE_INSN_OPCODE(in);
    if (RE_INSN_MAP(in) != 0 || op != 0x8D || !in->has_mem)
        return;
    if (in->index != RE_REG_NONE || in->reg >= 16)
        return;
    c->ok[in->reg] = true;
    c->val[in->reg] = in->mem;
}

// mov reg, imm64, which is the other way a base gets a known value.
static void track_mov_imm(consts_t *c, const re_insn_t *in) {
    unsigned op = RE_INSN_OPCODE(in);
    if (RE_INSN_MAP(in) != 0 || op < 0xB8 || op > 0xBF)
        return;
    unsigned r = (op - 0xB8u) + ((in->rex & 1u) ? 8u : 0u);
    if (r >= 16)
        return;
    c->ok[r] = true;
    c->val[r] = (uint64_t)in->imm;
}

// Any write to a tracked register invalidates it, because a stale constant is how
// a table address becomes a confident wrong answer.
static void kill(consts_t *c, const re_insn_t *in) {
    if (!in->has_modrm || in->is_call)
        return;
    if (in->reg < 16)
        c->ok[in->reg] = false;
    if (in->is_mem && in->rm < 16)
        c->ok[in->rm] = false;
}

// The address of a table referenced through a known base, or false when the base
// is something we did not track. The index is deliberately ignored: it is the case
// number being scaled, and it is the base plus displacement that names the table.
// Requiring a constant index would miss the two level form GCC emits, where the
// table sits at base + disp and the index selects a second table.
static bool known_addr(const consts_t *c, const re_insn_t *in, uint64_t *out) {
    if (!in->is_mem || in->base >= 16)
        return false;
    if (!c->ok[in->base])
        return false;
    *out = c->val[in->base] + (uint64_t)in->disp;
    return true;
}

// The case count from the bounds check in front of the dispatch, when there is
// one. It is a cross check on the table, not the source of the count.
static uint32_t bound_of(const re_insn_t *in) {
    unsigned op = RE_INSN_OPCODE(in);
    if (RE_INSN_MAP(in) != 0)
        return 0;
    if (op == 0x83 || op == 0x3D || (op >= 0x80 && op <= 0x81))
        return in->imm > 0 && in->imm < 100000 ? (uint32_t)in->imm + 1u : 0u;
    return 0;
}

uint64_t re_jtable_target(const re_code_t *c, const re_jtable_t *t, uint32_t i) {
    uint64_t raw = 0;
    if (i >= t->count || !read_entry(c, t->table_va, t->width, i, &raw))
        return 0;
    return decode_entry((enc_t)t->encoding, t->table_va, raw, c->base);
}

// Walk the straight run in front of the dispatch, carrying known register values,
// and test every memory address that turns out to be constant. The walk is linear
// and stops at the dispatch, so a table set up on another path is not found. That
// limitation is deliberate: chasing control flow here would find tables the
// dispatch cannot actually reach.
static bool find_table(const re_code_t *c, const re_func_t *f, re_jtable_t *out) {
    consts_t cst;
    uint64_t va = f->va;
    uint32_t bound = 0;
    bool found = false;
    unsigned i;
    for (i = 0; i < 16; i++) {
        cst.ok[i] = false;
        cst.val[i] = 0;
    }
    while (va < f->dispatch) {
        re_insn_t in;
        uint64_t addr = 0;
        uint32_t b;
        if (!re_code_insn(c, va, &in))
            return false;
        // Invalidate first, then define. Killing after tracking would clear the
        // register the instruction had just set, and the base would never survive
        // the lea that introduces it.
        kill(&cst, &in);
        track_lea(&cst, &in);
        track_mov_imm(&cst, &in);
        b = bound_of(&in);
        if (b)
            bound = b;
        if (!found && known_addr(&cst, &in, &addr)) {
            shape_t s = best_shape(c, addr);
            if (s.count) {
                out->table_va = addr;
                out->at = f->dispatch;
                out->func_va = f->va;
                out->count = s.count;
                out->width = s.width;
                out->encoding = (uint8_t)s.enc;
                out->bound = bound;
                found = true;
            }
        }
        va += in.size;
    }
    return found;
}

size_t re_jtable_scan(re_code_t *c, const re_fscan_t *scan, re_arena_t *a, re_vec_t *out) {
    re_vec_clear(out);
    for (size_t fi = 0; fi < RE_VEC_LEN(&scan->funcs); fi++) {
        const re_func_t *f = RE_VEC_PTR(&scan->funcs, re_func_t, fi);
        re_jtable_t t;
        if (!f->dispatch)
            continue;
        t.table_va = 0;
        if (!find_table(c, f, &t))
            continue;
        if (!RE_VEC_PUSH(out, a, t))
            break;
    }
    return RE_VEC_LEN(out);
}

const re_jtable_t *re_jtable_for(const re_vec_t *tables, uint64_t at) {
    size_t i;
    if (!tables || !at)
        return NULL;
    for (i = 0; i < RE_VEC_LEN(tables); i++) {
        const re_jtable_t *t = RE_VEC_PTR(tables, re_jtable_t, i);
        if (t->at != at)
            continue;
        if (t->count < RE_JTABLE_MIN || t->count > RE_JTABLE_MAX)
            return NULL;
        if (t->width != 4 && t->width != 8)
            return NULL;
        return t;
    }
    return NULL;
}
