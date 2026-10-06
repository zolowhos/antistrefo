// re_x64_ops.c - registers, control flow classification, and the x86-64 vtable.
// Module: feature (C11).
// Owns: the register tables, the branch, call and return rules, and the projection.
// Depends: re_x64_priv.h and re_x64_decode. Text and IR live in their own files.
#include "features/disasm/re_x64_priv.h"

#include "features/disasm/re_x64_tab.h"
#include "features/disasm/re_x64_tab0f.h"

// Register names by size. The byte set has two spellings because a REX byte makes
// 4 through 7 mean spl, bpl, sil and dil instead of ah, ch, dh and bh.
static const char *const kRegB[16] = {"al",  "cl",  "dl",   "bl",   "ah",   "ch",   "dh",   "bh",
                                      "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"};
static const char *const kRegBL[16] = {"al",   "cl",   "dl",   "bl",  "spl",  "bpl",
                                       "sil",  "dil",  "r8b",  "r9b", "r10b", "r11b",
                                       "r12b", "r13b", "r14b", "r15b"};
static const char *const kRegW[16] = {"ax",  "cx",  "dx",   "bx",   "sp",   "bp",   "si",   "di",
                                      "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"};
static const char *const kRegD[16] = {"eax", "ecx", "edx",  "ebx",  "esp",  "ebp",  "esi",  "edi",
                                      "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
static const char *const kRegQ[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                      "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};
static const char *const kRegX[16] = {"xmm0",  "xmm1",  "xmm2",  "xmm3", "xmm4",  "xmm5",
                                      "xmm6",  "xmm7",  "xmm8",  "xmm9", "xmm10", "xmm11",
                                      "xmm12", "xmm13", "xmm14", "xmm15"};
static const char *const kRegY[16] = {"ymm0",  "ymm1",  "ymm2",  "ymm3", "ymm4",  "ymm5",
                                      "ymm6",  "ymm7",  "ymm8",  "ymm9", "ymm10", "ymm11",
                                      "ymm12", "ymm13", "ymm14", "ymm15"};
static const char *const kRegM[8] = {"mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7"};

// The maps 2 and 3 have no names in the opcode map: every instruction in them takes
// its name from the prefix and the opcode together, which is the table in
// re_x64_simd.c. Returning NULL here is what keeps a placeholder out of the text.
const char *x64_mnem(uint16_t id) {
    uint8_t map = X64_ID_MAP(id);
    uint8_t op = X64_ID_OP(id);
    if (map > 1)
        return NULL;
    return map ? kOp0F[op].m : kOp1[op].m;
}

const char *x64_reg_name(unsigned reg, uint8_t opsize) {
    if (reg >= RE_X64_MMX_BASE)
        return reg < RE_X64_MMX_BASE + 8u ? kRegM[reg - RE_X64_MMX_BASE] : NULL;
    if (reg >= RE_X64_YMM_BASE)
        return reg < RE_X64_MMX_BASE ? kRegY[reg - RE_X64_YMM_BASE] : NULL;
    if (reg >= RE_X64_XMM_BASE)
        return reg < RE_X64_YMM_BASE ? kRegX[reg - RE_X64_XMM_BASE] : NULL;
    if (reg >= 64)
        return NULL;
    if (opsize == 1)
        return kRegB[reg & 15u];
    if (opsize == 2)
        return kRegW[reg & 15u];
    if (opsize == 8)
        return kRegQ[reg & 15u];
    return kRegD[reg & 15u];
}

// The byte spelling changes once a REX prefix is present, so the low four names
// are chosen by the instruction rather than by the register number alone.
const char *x64_reg_name_ex(unsigned reg, uint8_t opsize, uint8_t rex) {
    if (opsize == 1 && (rex & 0x0Fu) != 0 && reg < 8)
        return kRegBL[reg];
    return x64_reg_name(reg, opsize);
}

unsigned x64_reg_size(const x64_insn_t *in) {
    if (in->cls == XC_MODRM_F6)
        return 1;
    if (in->cls == XC_MODRM_F7)
        return in->opsize == 2 ? 2u : 4u;
    if (in->cls == XC_IB || in->cls == XC_IBS || in->cls == XC_REL8 || in->cls == XC_MODRM_IB ||
        in->cls == XC_MODRM_IZB)
        return 1;
    if (in->opsize == 2)
        return 2;
    return in->opsize == 8 ? 8u : 4u;
}

// F3 0F 1E FA is endbr64 and FB is endbr32. Modern x86-64 opens nearly every
// function with one, so recognising it is what makes prologue sniffing work.
bool x64_is_endbr(const uint8_t *p, size_t n) {
    return n >= 4 && p[0] == 0xF3 && p[1] == 0x0F && p[2] == 0x1E && (p[3] == 0xFA || p[3] == 0xFB);
}

// True for the register pushes a frame pointer prologue is built from.
static bool is_push(const x64_insn_t *in, unsigned reg) {
    if (in->map != 0 || in->cls != XC_NONE)
        return false;
    if (in->opcode < 0x50 || in->opcode > 0x57)
        return false;
    return (unsigned)(in->opcode - 0x50u) + ((in->rex & 1u) ? 8u : 0u) == reg;
}

// The shape of a standard prologue: a callee saved push, or a stack adjustment,
// or a frame pointer being set up. One of those appearing near the top is what
// distinguishes a function from the middle of a switch or a jump table target.
static bool is_prologue_insn(const x64_insn_t *in) {
    if (in->map != 0)
        return false;
    if (in->opcode == 0x81 || in->opcode == 0x83) {
        if (in->modrm == 0xEC)
            return true; // sub rsp, imm
    }
    if (in->opcode == 0x8B && (in->modrm == 0xE5 || in->modrm == 0xEC))
        return true; // mov rbp, rsp, or mov ebp, esp
    if (in->opcode == 0x89 && in->modrm == 0xE5)
        return true; // mov rsp, rbp, the epilogue half
    if (in->opcode == 0xC9)
        return true; // leave
    return is_push(in, 5) || is_push(in, 3) || is_push(in, 6) || is_push(in, 7) ||
           is_push(in, 12) || is_push(in, 13) || is_push(in, 14) || is_push(in, 15);
}

// Map an x86 opcode onto the arch neutral branch, call and return flags. An
// indirect transfer through memory has no resolvable target, and saying so is
// what keeps a caller from inventing one.
static void classify(const x64_insn_t *in, re_insn_t *o) {
    unsigned reg = ((unsigned)in->modrm >> 3) & 7u;
    bool direct = in->cls == XC_REL8 || in->cls == XC_REL32;
    if (in->map == 1 && in->opcode >= 0x80 && in->opcode <= 0x8F) {
        o->is_branch = true;
        o->is_conditional = true;
    } else if (in->map != 0) {
        return;
    } else if (in->opcode == 0xC3 || in->opcode == 0xC2) {
        o->is_return = true;
        return;
    } else if (in->opcode == 0xE8) {
        o->is_call = true;
    } else if (in->opcode == 0xE9 || in->opcode == 0xEB) {
        o->is_branch = true;
    } else if (in->opcode >= 0x70 && in->opcode <= 0x7F) {
        o->is_branch = true;
        o->is_conditional = true;
    } else if (in->opcode >= 0xE0 && in->opcode <= 0xE3) {
        o->is_branch = true;
        o->is_conditional = true;
    } else if (in->opcode == 0xFF && (reg == 2u || reg == 3u)) {
        o->is_call = true;
    } else if (in->opcode == 0xFF && (reg == 4u || reg == 5u)) {
        o->is_branch = true;
    }
    if ((o->is_call || o->is_branch) && !direct)
        o->has_target = false;
}

// Whether the operands of an instruction are vector registers rather than general
// purpose ones. The SIMD blocks of the 0F map are contiguous runs, which is why this
// can be a range test rather than a table: everything from 0F 10 to 0F 17, 28 to 2F,
// 50 to FE operates on vector registers, and the rest of the map - cpuid, rdtsc,
// cmov, the bit tests, the fences, movnti - does not. A VEX or EVEX encoding reaches
// the same map, so the test is the same one: the mask register moves an AVX-512
// encoding adds sit above 0F 90 and are not vector operations at all.
// The 0F38 and 0F3A maps hold a handful of instructions whose operands are general
// purpose registers even though everything around them is a vector one: the byte
// swapping moves, the carry chains, stores and shifts that share those opcode bytes
// with them, and the rotate the 0F3A map reaches under its F2 prefix.
static bool is_gp_map_op(const x64_insn_t *in) {
    if (in->map == 2u)
        return in->opcode == 0xF0u || in->opcode == 0xF1u || in->opcode == 0xF5u ||
               in->opcode == 0xF6u || in->opcode == 0xF7u;
    return in->map == 3u && in->opcode == 0xF0u && in->pfx == 3u;
}

static bool is_simd(const x64_insn_t *in) {
    if (in->map >= 2)
        return !is_gp_map_op(in);
    if (in->map != 1)
        return false;
    // movnti sits in the middle of the packed integer block and moves a general
    // purpose register, so the vector names are wrong for both of its operands.
    if (in->opcode == 0xC3u)
        return false;
    return in->opcode == 0x0Fu || // 3DNow, which is mmx all the way through
           (in->opcode >= 0x10u && in->opcode <= 0x17u) ||
           (in->opcode >= 0x28u && in->opcode <= 0x2Fu) ||
           (in->opcode >= 0x50u && in->opcode <= 0x7Fu) ||
           (in->opcode >= 0xC2u && in->opcode <= 0xC6u) ||
           (in->opcode >= 0xD0u && in->opcode <= 0xFEu);
}

// The mmx forms. Most of the packed integer block is a 64-bit mmx operation when no
// prefix is present and a 128-bit xmm one under 0x66, so the prefix decides the
// register file as well as the name. A VEX encoding has no mmx form at all, and the
// conversions between the two register files are left as xmm because naming one
// half of them right and the other half wrong reads worse than naming both alike.
static bool is_mmx(const x64_insn_t *in) {
    unsigned op = in->opcode;
    if (in->vex || in->map != 1 || in->pfx != 0)
        return false;
    return op == 0x0Fu || (op >= 0x60u && op <= 0x6Fu) || (op >= 0x70u && op <= 0x77u) ||
           (op >= 0x7Eu && op <= 0x7Fu) || (op >= 0xD0u && op <= 0xFEu);
}

static bool x64_vt_decode(void *ctx, uint64_t addr, re_span_t code, re_insn_t *out) {
    x64_insn_t in;
    (void)ctx;
    if (!x64_decode(code.p, code.n, addr, &in))
        return false;
    out->addr = addr;
    out->size = in.size;
    out->insn_id = in.id;
    out->op_count = in.has_modrm ? 2u : 1u;
    out->is_branch = false;
    out->is_call = false;
    out->is_return = false;
    out->is_conditional = false;
    out->rip_rel = in.rip_rel;
    out->has_target = in.has_target;
    out->has_modrm = in.has_modrm;
    out->modrm = in.modrm;
    out->opsize = in.opsize;
    out->rex = in.rex;
    out->addrsize = in.addrsize;
    out->pfx = in.pfx;
    out->vex = in.vex;
    out->vex_l = in.vex_l;
    out->vex_w = in.vex_w;
    out->imm = in.imm;
    out->target = in.target;
    out->mem = in.mem;
    out->has_mem = in.rip_rel;
    out->is_mem = in.is_mem;
    out->mod = in.mod;
    // A vector operand is numbered above the general purpose ones, so a renderer and
    // the emitter can tell them apart from the number alone. The length bit of the
    // encoding decides whether the name is xmm or ymm, and the mmx forms are always
    // 64 bit, which is why the register file is chosen here and not by the renderer.
    // An operand that is memory is left alone: its fields are the address, not a
    // register.
    if (is_simd(&in)) {
        bool mm = is_mmx(&in);
        unsigned vb = mm ? RE_X64_MMX_BASE : (in.vex_l ? RE_X64_YMM_BASE : RE_X64_XMM_BASE);
        out->reg = (uint8_t)(vb + (mm ? (in.reg & 7u) : in.reg));
        if (!in.is_mem)
            out->rm = (uint8_t)(vb + (mm ? (in.rm & 7u) : in.rm));
        // For a SIMD instruction the operand size is the width of the register, which
        // is what the text renderer needs to say how wide a memory operand is. It is
        // not read as a general purpose size anywhere: these instructions do not move
        // a general purpose register.
        out->opsize = mm ? 8u : (in.vex_l ? 32u : 16u);
    } else {
        out->reg = in.reg;
        out->rm = in.rm;
    }
    out->base = in.base;
    out->index = in.index;
    out->scale = in.scale;
    out->disp = in.disp;
    out->ops[0] = X64_ID_OP(in.id);
    out->ops[1] = in.map;
    out->ops[2] = (uint8_t)(((unsigned)in.modrm >> 3) & 7u);
    out->ops[3] = (uint8_t)(in.modrm & 7u);
    out->text = re_str("");
    classify(&in, out);
    return true;
}

// Sniff a bounded window rather than the whole section, because a prologue lives
// in the first handful of instructions and walking a whole section to find one
// would be wasted work.
static bool x64_vt_prologue(void *ctx, uint64_t addr, re_span_t code) {
    size_t i = 0;
    unsigned steps = 0;
    (void)ctx;
    if (x64_is_endbr(code.p, code.n))
        return true;
    while (i < code.n && steps < 8) {
        x64_insn_t in;
        if (!x64_decode(code.p + i, code.n - i, addr + i, &in))
            return false;
        if (is_prologue_insn(&in))
            return true;
        i += in.size;
        steps++;
    }
    return false;
}

static const char *x64_vt_reg_name(void *ctx, unsigned reg) {
    (void)ctx;
    return x64_reg_name(reg, 8);
}

static unsigned x64_vt_reg_size(void *ctx, unsigned reg) {
    (void)ctx;
    if (reg >= RE_X64_MMX_BASE)
        return 8;
    if (reg >= RE_X64_YMM_BASE)
        return 32;
    if (reg >= RE_X64_XMM_BASE)
        return 16;
    return (reg / 16u) == 4u ? 2u : (reg / 16u) == 3u ? 4u : 8u;
}

// No transfer function is published yet. Returning NULL is the honest answer and
// the seam treats it as "not modelled", not as an error.
static const re_trfunc_t *x64_vt_trfunc(void *ctx, uint8_t insn_id) {
    (void)ctx;
    (void)insn_id;
    return NULL;
}

static void x64_vt_render(void *ctx, const re_insn_t *insn, re_arena_t *a, re_strbuf_t *out) {
    (void)ctx;
    x64_render(insn, a, out);
}

static size_t x64_vt_lower(void *ctx, const re_insn_t *insn, re_ir_func_t *f, re_arena_t *a) {
    (void)ctx;
    return x64_lower(insn, f, a);
}

const re_disasm_t re_disasm_x86 = {
    NULL,
    "x86",
    32,
    x64_vt_decode,
    x64_vt_lower,
    x64_vt_reg_name,
    x64_vt_reg_size,
    x64_vt_prologue,
    x64_vt_trfunc,
    x64_vt_render,
};

const re_disasm_t re_disasm_x64 = {
    NULL,
    "x86-64",
    64,
    x64_vt_decode,
    x64_vt_lower,
    x64_vt_reg_name,
    x64_vt_reg_size,
    x64_vt_prologue,
    x64_vt_trfunc,
    x64_vt_render,
};
