// re_func_walk.c - the recursive descent over one function's decoded control flow.
// Module: feature (C11).
// Owns: the block walk, the junk resync, edge recording, and the frame size.
// Depends: re_func_priv.h and re_code. Split from re_func.c, which now holds only
// the seeding passes; the seam between them is re_func_priv.h and nothing else.
#include "features/code/re_func_priv.h"

#include "features/pe/re_pe.h"

// How far the walk scans for the next decodable byte after one it cannot decode.
// Bounded because an unbounded scan is a decode of the whole section, and a
// function that needs more than this is not one the recovery can honestly claim.
#define RE_JUNK_MAX 16u

// Everything about the body being walked that is not part of its record. The cursor
// is a position in blocks rather than a pop, because the vector has no remove and a
// cursor needs none.
typedef struct {
    re_vec_t blocks; // uint64_t, addresses still to walk
    size_t cursor;
    uint64_t hi;   // highest address walked, plus the length of what was there
    uint64_t end;  // the compiler's declared end, 0 when it declared none
    uint64_t halt; // end of the highest halting instruction seen, 0 when none
    bool cut;      // the walk met bytes it could not explain and stopped there
} fnwalk_t;

void re_walk_push(re_arena_t *a, re_vec_t *v, uint64_t x) {
    RE_VEC_PUSH(v, a, x);
}

static void add_edge(re_arena_t *a, re_vec_t *v, uint64_t from, uint64_t to, uint8_t kind,
                     bool has_to) {
    re_edge_t e;
    e.from = from;
    e.to = to;
    e.kind = kind;
    e.has_to = has_to;
    RE_VEC_PUSH(v, a, e);
}

bool re_walk_looks_like_start(const re_code_t *c, uint64_t va) {
    re_span_t b;
    const uint8_t *p;
    if (!re_code_at(c, va, &b) || b.n < 4)
        return false;
    p = (const uint8_t *)b.p;
    if (p[0] == 0xF3 && p[1] == 0x0F && p[2] == 0x1E && (p[3] == 0xFA || p[3] == 0xFB))
        return true; // endbr64 or endbr32
    if (p[0] == 0x55)
        return true; // push rbp
    if (p[0] == 0x48 && p[1] == 0x89 && p[2] == 0xE5)
        return true; // mov rbp, rsp
    if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC)
        return true; // sub rsp, imm8
    if (p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xEC)
        return true; // sub rsp, imm32
    return false;
}

// The stack a function reserves. Only a sub rsp inside the prologue window
// counts, and the window is counted in instructions this function actually walked
// rather than in bytes, so a frame size can never be read out of the next
// function when this one is short.
static bool sub_rsp(const re_insn_t *in, uint32_t *out) {
    if (in->insn_id != 0x0081 && in->insn_id != 0x0083)
        return false;
    if (in->modrm != 0xEC)
        return false;
    if (in->imm <= 0 || in->imm >= 65536)
        return false;
    *out = (uint32_t)in->imm;
    return true;
}

// A data reference is a RIP relative operand, or a wide immediate that looks like
// an address in this image. Both are how code reaches strings, jump tables and
// import addresses, and neither is a control flow edge, so they are recorded
// separately or a caller asking "what does this function touch" sees nothing.
static bool data_ref(const re_code_t *c, const re_insn_t *in) {
    if (in->is_call || in->is_branch)
        return false; // the operand is the transfer's own target, not a data use
    if (in->has_mem)
        return true;
    if (in->opsize == 8 && in->imm > 0xFFFF && (uint64_t)in->imm >= c->base)
        return true;
    return false;
}

// An instruction that stops the processor's flow without transferring anywhere.
// 1 is a trap that a compiler also uses as padding, so the walk continues past it;
// 2 is a halt, which by definition has no fall-through, and the block ends there.
// Treating a halt as fall-through walked into whatever followed - the next
// function's bytes, or a jump table - and then reported those as this function's.
static uint8_t halt_kind(const re_insn_t *in) {
    switch (in->insn_id) {
        case 0x00CCu: // int3
            return 1;
        case 0x010Bu: // ud2
        case 0x01FFu: // ud0
        case 0x01B9u: // ud1
        case 0x00F4u: // hlt
            return 2;
        default:
            return 0;
    }
}

// The address the compiler declared as this function's end, or 0 when nothing
// declares one. A walk that runs past the declared end is how the next function's
// body ends up inside this function's record, and the unwind table is the only
// statement of where a function stops that is not an inference.
static uint64_t declared_end(walk_t *w, uint64_t start) {
    re_pe_unwind_t u;
    if (!w->code->pe)
        return 0;
    if (!re_pe_unwind_covering(w->code->pe, (uint32_t)(start - w->code->base), &u))
        return 0;
    if (w->code->base + u.begin != start || u.end <= u.begin)
        return 0;
    return w->code->base + u.end;
}

// Skip over bytes that do not decode. They are data the compiler left inside a
// function - a jump table, a string, an alignment fill - and the honest move is
// to count them and resume at the first address that decodes again. Returns 0
// when nothing decodes inside the bound, which ends the function there.
static uint64_t skip_junk(walk_t *w, uint64_t va, uint64_t bound, uint32_t *junk) {
    re_insn_t in;
    for (uint64_t k = 1; k <= (uint64_t)RE_JUNK_MAX; k++) {
        if (bound && va + k >= bound)
            break;
        if (!re_code_in_code(w->code, va + k))
            break;
        if (re_code_insn(w->code, va + k, &in)) {
            *junk += (uint32_t)k;
            return va + k;
        }
    }
    return 0;
}

// A branch into the middle of an instruction somebody else already walked. The
// decode at the target succeeds, which is why this cannot be told from an
// ordinary boundary by the covered bit alone; its bytes being covered is the
// difference, and it is what a target in the middle of a long instruction looks
// like. A target that does not decode at all is the same fact.
static bool mid_insn(const re_code_t *c, uint64_t va) {
    re_insn_t in;
    if (!re_code_insn(c, va, &in))
        return true;
    return re_code_covered(c, va, in.size);
}

// One direct transfer, and what to do about it. The distinction that matters is
// conditional against unconditional: a conditional branch target is another block
// of this same function, while an unconditional jmp is a tail call into a
// different function and its target must go to the function queue instead.
// Treating the second as a block is how one function ends up reporting another
// function's instructions as its own.
//
// A transfer through a RIP relative operand names its target too. That form is how
// a driver calls a Windows API, through the import slot, and calling it indirect
// would throw away the single most useful fact about the reference.
static bool other_unwind(const walk_t *w, const re_func_t *f, uint64_t target) {
    re_pe_unwind_t u;
    uint32_t rva = (uint32_t)(target - w->code->base);
    return re_pe_unwind_covering(w->code->pe, rva, &u) && w->code->base + u.begin != f->va;
}

static void take_edge(walk_t *w, fnwalk_t *s, const re_insn_t *in, re_func_t *f) {
    uint8_t kind = RE_EDGE_NONE;
    uint64_t target = in->has_target ? in->target : (in->has_mem ? in->mem : 0);
    bool have = in->has_target || in->has_mem;
    if (data_ref(w->code, in))
        add_edge(w->a, w->edges, in->addr, in->has_mem ? in->mem : (uint64_t)in->imm, RE_EDGE_DATA,
                 true);
    if (in->is_call)
        kind = RE_EDGE_CALL;
    else if (in->is_branch)
        kind = in->is_conditional ? RE_EDGE_COND : RE_EDGE_JUMP;
    if (kind == RE_EDGE_NONE)
        return;
    if (!have) {
        // An unresolved transfer is still a fact about the function: a call
        // through a register cannot be resolved, and an indirect jump is a
        // dispatch. Both are recorded so the report can say so out loud.
        add_edge(w->a, w->edges, in->addr, 0, kind, false);
        f->open_edges++;
        if (in->is_call)
            f->n_calls++;
        else {
            f->n_jumps++;
            f->flags |= RE_FUNC_JTABLE;
            if (!f->dispatch)
                f->dispatch = in->addr;
        }
        return;
    }
    add_edge(w->a, w->edges, in->addr, target, kind, true);
    if (in->is_call)
        f->n_calls++;
    else
        f->n_jumps++;
    if (!re_code_in_code(w->code, target)) {
        // A call through an import slot lands in data, not code, and that is
        // expected rather than a call that left the image.
        if (!in->has_mem)
            f->flags |= RE_FUNC_EXTERNAL;
        return;
    }
    if (in->is_call || !in->is_conditional) {
        re_walk_push(w->a, w->queue, target);
        return;
    }
    if (!re_code_covered(w->code, target, 1))
        re_walk_push(w->a, other_unwind(w, f, target) ? w->queue : &s->blocks, target);
    // The bytes are claimed and the target is not on a boundary. Inside this
    // function's own body that is a branch into a mis-decoded stretch, which is a
    // decode problem; outside it two records share bytes, which is the overlap
    // worth reporting. The edge is already recorded and the walk does not descend,
    // because descending would let this function claim instructions that another
    // one already reported.
    else if (!(target >= f->va && target < f->va + f->size) && mid_insn(w->code, target))
        f->flags |= RE_FUNC_OVERLAP;
}

// Everything the record starts out as. A record that is only partly initialised
// reports whatever was in the memory behind it, and the field that was left out is
// always the one that matters, so all of them are set here.
static void start_func(fnwalk_t *s, walk_t *w, uint64_t start, re_func_t *f) {
    s->cursor = 0;
    s->hi = start;
    s->halt = 0;
    s->cut = false;
    re_vec_init(&s->blocks, sizeof(uint64_t));
    re_walk_push(w->a, &s->blocks, start);
    s->end = declared_end(w, start);
    f->va = start;
    f->dispatch = 0;
    f->rva = (uint32_t)(start - w->code->base);
    f->n_insns = 0;
    f->n_calls = 0;
    f->n_jumps = 0;
    f->junk = 0;
    f->open_edges = 0;
    f->flags = 0;
    f->name = re_str("");
    f->module = re_str("");
    f->frame_size = 0;
    f->size = 0;
    f->out_edges = 0;
}

// One block: decode at va and either record the instruction, skip the bytes that
// do not decode, or note that the walk could go no further.
static void walk_block(walk_t *w, fnwalk_t *s, re_func_t *f, uint64_t va) {
    re_insn_t in;
    uint32_t frame = 0;
    uint8_t halt;
    if (s->end && va >= s->end)
        return; // the declared end of this function, not the next one's body
    if (!re_code_insn(w->code, va, &in)) {
        uint64_t next = skip_junk(w, va, s->end, &f->junk);
        if (!next) {
            s->cut = true;
            return;
        }
        if (next > s->hi)
            s->hi = next;
        f->flags |= RE_FUNC_JUNK;
        re_walk_push(w->a, &s->blocks, next);
        return;
    }
    if (re_code_covered(w->code, va, in.size))
        return;
    re_code_mark(w->code, va, in.size);
    f->n_insns++;
    if (va + in.size > s->hi)
        s->hi = va + in.size;
    // The extent so far, so a transfer can tell a branch into this function's own
    // body from one into bytes another function claimed.
    f->size = (uint32_t)(s->hi - f->va);
    if (s->end > f->va)
        f->size = (uint32_t)(s->end - f->va);
    if (f->n_insns <= 12 && f->frame_size == 0 && sub_rsp(&in, &frame))
        f->frame_size = frame;
    if (in.is_return)
        f->flags |= RE_FUNC_RET;
    halt = halt_kind(&in);
    if (halt)
        s->halt = va + in.size;
    take_edge(w, s, &in, f);
    // A declared end beats the first ret. The bytes after it belong to this
    // function until the compiler's end, and stopping here is how a filter
    // that has its own unwind entry gets merged into the parent.
    if (s->end && va + in.size < s->end && halt != 2u)
        re_walk_push(w->a, &s->blocks, va + in.size);
    else if (!in.is_return && halt != 2u && !(in.is_branch && !in.is_conditional))
        re_walk_push(w->a, &s->blocks, va + in.size);
}

// What the record says once the walk is over: its extent, whether it was cut short,
// whether it is a thunk, and whether it can return at all.
static void finish_func(fnwalk_t *s, re_func_t *f) {
    f->size = (uint32_t)(s->hi - f->va);
    // Truncation is the instruction ceiling and nothing else. Stopping with blocks
    // pending because they lie past the declared end is the walk having finished
    // the function, and calling that truncation marked three quarters of a system
    // image as cut short.
    if (f->n_insns >= RE_FUNC_MAX_INSNS && s->cursor < RE_VEC_LEN(&s->blocks))
        f->flags |= RE_FUNC_TRUNC;
    // A body that is little more than a jump is a thunk: a jump through the
    // import table, or a tail call the compiler left in place.
    if (f->n_insns <= 2 && f->n_jumps >= 1)
        f->flags |= RE_FUNC_THUNK;
    // The body ends on a halting instruction, no path returned, and the walk ended
    // on its own rather than by running into bytes it could not explain. A tail
    // call is deliberately not enough: it returns whatever it called.
    if (s->halt && s->halt == s->hi && !s->cut &&
        !(f->flags & (RE_FUNC_RET | RE_FUNC_TRUNC | RE_FUNC_JTABLE)))
        f->flags |= RE_FUNC_NORETURN;
    re_vec_truncate(&s->blocks, 0);
}

void re_walk_func(walk_t *w, uint64_t start, re_func_t *f) {
    fnwalk_t s;
    start_func(&s, w, start, f);
    while (s.cursor < RE_VEC_LEN(&s.blocks) && f->n_insns < RE_FUNC_MAX_INSNS) {
        uint64_t va = *(const uint64_t *)RE_VEC_PTR(&s.blocks, uint64_t, s.cursor);
        s.cursor++;
        walk_block(w, &s, f, va);
    }
    finish_func(&s, f);
}
