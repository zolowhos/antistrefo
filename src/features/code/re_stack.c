// re_stack.c - which registers arrive as arguments, and how big the frame is.
// Module: feature (C11).
// Owns: the read and write sets, the argument scan, and the local slot count.
// Depends: re_stack.h. A register is an argument only when it is read before
//           anything writes it, which is the one claim that can be made without a
//           full data flow analysis, and a miss costs a parameter, not a wrong one.
#include "features/code/re_stack.h"

#include "utils/text/re_str.h"

// Windows passes the first four integer arguments in rcx, rdx, r8, r9; SysV uses
// six and starts at rdi. The two overlap in the middle, which is why a function
// that reads rcx and rdi is ambiguous and is reported as such.
static const uint8_t kMsArgs[4] = {1, 2, 8, 9};         // rcx, rdx, r8, r9
static const uint8_t kSysvArgs[6] = {7, 6, 2, 1, 8, 9}; // rdi, rsi, rdx, rcx, r8, r9

typedef struct {
    bool written[16];
    bool arg_seen[16]; // read before anything wrote it, so it arrived as input
    int32_t slots[RE_SLOT_MAX];
    uint32_t n_slots;
} flow_t;

// A read of a register nothing has written yet is an argument. This has to be
// recorded as the walk goes rather than scored at the end, because a call
// clobbers every volatile register and a final comparison would then find the
// registers written and conclude the function takes no arguments at all.
static void note_read(flow_t *fl, unsigned r) {
    if (r >= 16)
        return;
    if (!fl->written[r])
        fl->arg_seen[r] = true;
}

// Record a stack displacement, counting each one once. A range would be cheaper
// and wrong: two functions can touch one slot each at the extremes of a wide range
// and the difference between them is not a thousand locals.
static void note_slot(flow_t *fl, int64_t d) {
    uint32_t i;
    if (d > 0 || d < -0x4000)
        return; // an argument slot or something implausible, not a local
    for (i = 0; i < fl->n_slots; i++) {
        if (fl->slots[i] == (int32_t)d)
            return;
    }
    if (fl->n_slots < RE_SLOT_MAX)
        fl->slots[fl->n_slots++] = (int32_t)d;
}

// The registers an instruction reads and the registers it writes. Written as an
// explicit list per class rather than a table of bitmasks, because the classes
// with a write to the r/m operand are the exception and the exception is the
// whole point of writing this by hand.
static void mark(flow_t *fl, const re_insn_t *in, unsigned map, unsigned op) {
    unsigned r;
    if (in->is_mem) {
        note_read(fl, in->base);
        note_read(fl, in->index);
        note_slot(fl, in->disp);
    }
    if (in->is_call) {
        // A call reads its register arguments and destroys the volatile set, so
        // the only thing left is which of them were live on entry.
        for (r = 0; r < 16; r++) {
            if (r == 15)
                continue; // r15 is callee saved
            fl->written[r] = true;
        }
        return;
    }
    if (in->has_modrm) {
        unsigned reg = in->reg;
        unsigned rm = in->rm;
        // These read the r/m operand and write the reg operand; the mov forms
        // are the other way round and are the common case in a prologue.
        if (map == 0 && (op == 0x89 || op == 0x88)) {
            if (in->is_mem) {
                note_slot(fl, in->disp);
            } else {
                note_read(fl, rm);
            }
            if (reg < 16)
                fl->written[reg] = true;
            return;
        }
        if (map == 0 && (op == 0x8B || op == 0x8D || op == 0x63)) {
            // mov and movsxd read the source and write the destination, and lea
            // reads only the address. Marking the source as read is what makes an
            // argument register visible at all.
            if (!in->is_mem)
                note_read(fl, rm);
            if (reg < 16)
                fl->written[reg] = true;
            return;
        }
        if (map == 0 && (op == 0xC6 || op == 0xC7)) {
            if (reg < 16)
                fl->written[reg] = true;
            return;
        }
        if (map == 1 && (op == 0xB6 || op == 0xB7 || op == 0xBE || op == 0xBF)) {
            if (reg < 16)
                fl->written[reg] = true;
            return;
        }
        // The eight ALU operations in their r/m, reg form, opcodes 0x00 to 0x3D.
        // This family reads the reg field and writes the r/m field, which is the
        // opposite way round from mov, so it must be handled before the catch all
        // below rather than falling into it. Falling in marks the source register
        // written when the instruction read it, so an argument that is only ever
        // used in arithmetic looks like it was never passed at all. CMP, 0x38 to
        // 0x3D, writes no register. 0x0F is the escape to a two byte opcode and is
        // not one of these, though the map test below already keeps it out.
        if (map == 0 && in->has_modrm && op != 0x0Fu && op <= 0x3Du) {
            if (in->is_mem)
                note_slot(fl, in->disp);
            if (reg < 16)
                note_read(fl, reg);
            if (op < 0x38u && rm < 16)
                fl->written[rm] = true;
            return;
        }
        // Anything else with a ModRM: read the r/m, write the reg. Overstating
        // the write set can only lose an argument, never invent one.
        if (in->is_mem) {
            note_slot(fl, in->disp);
        } else {
            note_read(fl, rm);
        }
        if (reg < 16)
            fl->written[reg] = true;
        return;
    }
    if (map == 0 && op >= 0x50 && op <= 0x57) {
        r = (op - 0x50u) + ((in->rex & 1u) ? 8u : 0u);
        if (r < 16)
            fl->written[r] = true;
        return;
    }
    if (map == 0 && op >= 0x58 && op <= 0x5F) {
        r = (op - 0x58u) + ((in->rex & 1u) ? 8u : 0u);
        if (r < 16)
            fl->written[r] = true;
        return;
    }
    if (map == 0 && op >= 0xB0 && op <= 0xBF) {
        r = (op - 0xB0u) + ((in->rex & 1u) ? 8u : 0u);
        if (r < 16)
            fl->written[r] = true;
    }
}

// How many of a convention's argument registers arrived live, and which.
static uint32_t score(const flow_t *fl, const uint8_t *set, size_t n, uint8_t *out) {
    uint32_t count = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned r = set[i];
        if (r < 16 && fl->arg_seen[r]) {
            out[count] = (uint8_t)i;
            count++;
        }
    }
    return count;
}

static void count_locals(const flow_t *fl, re_stack_t *out) {
    out->n_locals = fl->n_slots;
    // n_slots has to be set as well as n_locals. They are equal by construction here,
    // and a caller reads whichever it was written against - the decompiler loops on
    // n_slots - so leaving it unset hands out uninitialised memory as a count, and
    // the locals a function reports then depend on whatever was on the stack.
    out->n_slots = fl->n_slots;
    for (uint32_t i = 0; i < fl->n_slots && i < RE_SLOT_MAX; i++)
        out->slots[i] = fl->slots[i];
}

void re_stack_analyze(re_code_t *c, const re_func_t *f, re_arena_t *a, re_stack_t *out) {
    flow_t fl;
    uint64_t va = f->va;
    uint8_t ms[RE_CC_MAX_ARGS];
    uint8_t sv[RE_CC_MAX_ARGS];
    uint32_t n_ms;
    uint32_t n_sv;
    unsigned i;
    (void)a;
    for (i = 0; i < 16; i++) {
        fl.written[i] = false;
        fl.arg_seen[i] = false;
    }
    fl.n_slots = 0;
    out->cc = RE_CC_UNKNOWN;
    out->n_params = 0;
    out->n_locals = 0;
    out->n_calls = f->n_calls;
    out->frame_size = f->frame_size;
    out->uses_frame_ptr = false;
    out->tail_call = (f->flags & RE_FUNC_THUNK) != 0;
    out->homed = false;
    out->ret_xmm = false;
    while (va < f->va + f->size) {
        re_insn_t in;
        unsigned map;
        unsigned op;
        if (!re_code_insn(c, va, &in))
            break;
        map = RE_INSN_MAP(&in);
        op = RE_INSN_OPCODE(&in);
        if (map == 0 && (op == 0x8D || op == 0x89) && in.reg == 5 && !in.is_mem)
            out->uses_frame_ptr = true;
        mark(&fl, &in, map, op);
        va += in.size;
    }
    n_ms = score(&fl, kMsArgs, 4, ms);
    n_sv = score(&fl, kSysvArgs, 6, sv);
    if (n_sv > n_ms) {
        out->cc = RE_CC_SYSV;
        out->n_params = n_sv;
        for (i = 0; i < n_sv && i < RE_CC_MAX_ARGS; i++)
            out->arg_regs[i] = sv[i];
    } else if (n_ms > 0) {
        out->cc = RE_CC_MS64;
        out->n_params = n_ms;
        for (i = 0; i < n_ms && i < RE_CC_MAX_ARGS; i++)
            out->arg_regs[i] = ms[i];
    }
    count_locals(&fl, out);
}

const char *re_cc_name(uint8_t cc) {
    if (cc == RE_CC_MS64)
        return "ms64";
    if (cc == RE_CC_SYSV)
        return "sysv";
    return "unknown";
}

// The names are in the internal register numbering the flow walk uses, which is why
// they are listed rather than derived: kMsArgs above holds positions in that
// numbering and this is the one place that turns a position into a register name.
static const char *const kMsNames[4] = {"rcx", "rdx", "r8", "r9"};
static const char *const kSysvNames[6] = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};

const char *re_cc_arg_reg_name(uint8_t cc, uint32_t pos) {
    if (cc == RE_CC_MS64)
        return pos < 4u ? kMsNames[pos] : "?";
    if (cc == RE_CC_SYSV)
        return pos < 6u ? kSysvNames[pos] : "?";
    return "?";
}

static bool dll_stem(re_str_t dll, const char *want) {
    size_t i;
    size_t n = dll.n;
    if (n >= 4 && (dll.p[n - 4] == '.'))
        n -= 4;
    for (i = 0; want[i]; i++) {
        char c = i < n ? dll.p[i] : 0;
        char w = want[i];
        if (c >= 'A' && c <= 'Z')
            c = (char)(c - 'A' + 'a');
        if (c != w)
            return false;
    }
    return i == n;
}

bool re_stack_image_ms64(const re_pe_t *pe) {
    size_t i;
    if (!pe || !pe->valid || !pe->pe32plus)
        return false;
    // A Windows image is Microsoft x64 whether it is a driver or a crackme.
    // Subsystem 1 is native, 2 is GUI, 3 is console. Anything else keeps the
    // scorer's answer, so a header with no Windows subsystem is not forced.
    if (pe->subsystem == 1 || pe->subsystem == 2 || pe->subsystem == 3)
        return true;
    for (i = 0; i < RE_VEC_LEN(&pe->imports); i++) {
        const re_pe_imp_t *im = RE_VEC_PTR(&pe->imports, re_pe_imp_t, i);
        if (dll_stem(im->dll, "ntoskrnl") || dll_stem(im->dll, "hal") ||
            dll_stem(im->dll, "fltmgr"))
            return true;
    }
    return false;
}

// SysV positions 2..5 are rdx, rcx, r8, r9. rdi and rsi are callee-saved on
// Windows and must not survive the force.
static bool sysv_to_ms(uint8_t pos, uint8_t *ms) {
    static const uint8_t kMap[6] = {0xFF, 0xFF, 1, 0, 2, 3};
    if (pos >= 6 || kMap[pos] == 0xFF)
        return false;
    *ms = kMap[pos];
    return true;
}

static void drop_shadow(re_stack_t *out) {
    uint32_t i, n = 0;
    for (i = 0; i < out->n_slots && i < RE_SLOT_MAX; i++) {
        int32_t d = out->slots[i];
        if (d == 8 || d == 0x10 || d == 0x18 || d == 0x20)
            continue;
        out->slots[n++] = d;
    }
    out->n_slots = n;
    out->n_locals = n;
    out->homed = true;
}

void re_stack_apply_image(re_stack_t *out, const re_pe_t *pe) {
    uint8_t kept[4];
    uint32_t n = 0, i;
    if (!out || !re_stack_image_ms64(pe))
        return;
    for (i = 0; i < out->n_params && i < RE_CC_MAX_ARGS; i++) {
        uint8_t pos = out->arg_regs[i];
        if (out->cc == RE_CC_SYSV) {
            if (!sysv_to_ms(pos, &pos))
                continue;
        } else if (pos >= 4) {
            continue;
        }
        kept[n++] = pos;
    }
    out->cc = RE_CC_MS64;
    out->n_params = n;
    for (i = 0; i < n; i++)
        out->arg_regs[i] = kept[i];
    drop_shadow(out);
}

const char *re_cc_ret_type(const re_stack_t *st) {
    if (st && st->ret_xmm)
        return "double ";
    return "uint64_t ";
}
