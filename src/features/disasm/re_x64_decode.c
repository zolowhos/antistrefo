// re_x64_decode.c - the x86-64 decoder. It walks one instruction and stops.
// Module: feature (C11).
// Owns: prefix, VEX/EVEX, opcode, ModRM, SIB, displacement and immediate decoding.
// Depends: re_x64_priv.h, the opcode class tables and the form tables.
#include "features/disasm/re_x64_priv.h"

#include <string.h>

#include "features/disasm/fmt/re_x64_form.h"
#include "features/disasm/re_x64_tab.h"
#include "features/disasm/re_x64_tab0f.h"

// The longest instruction the processor accepts. A sixteenth byte raises #GP, so a
// decode that needs one is not an instruction.
#define X64_MAX_LEN 15u

// What a byte is in prefix position: 1 a legacy prefix, 2 a REX byte, 0 neither.
static const uint8_t kPfx[256] = {
    [0x26] = 1, [0x2E] = 1, [0x36] = 1, [0x3E] = 1, [0x64] = 1, [0x65] = 1, [0x66] = 1,
    [0x67] = 1, [0xF0] = 1, [0xF2] = 1, [0xF3] = 1, [0x40] = 2, [0x41] = 2, [0x42] = 2,
    [0x43] = 2, [0x44] = 2, [0x45] = 2, [0x46] = 2, [0x47] = 2, [0x48] = 2, [0x49] = 2,
    [0x4A] = 2, [0x4B] = 2, [0x4C] = 2, [0x4D] = 2, [0x4E] = 2, [0x4F] = 2,
};

// The segment a prefix byte overrides, in the numbering of x64_insn_t.seg.
static uint8_t seg_of(uint8_t c) {
    switch (c) {
        case 0x26:
            return 1;
        case 0x2E:
            return 2;
        case 0x36:
            return 3;
        case 0x3E:
            return 4;
        case 0x64:
            return 5;
        default:
            return 6; // 0x65
    }
}

// The 0F map opcodes whose meaning no prefix changes and which are valid with any
// operand. A legacy encoding of one of these needs no form lookup to be accepted, which
// keeps the walk fast through the conditional jumps, moves and bit operations that
// make up nearly all of the two byte map in real code. Bit n of word n/32.
static const uint32_t kMap1Plain[8] = {
    0x80000820u, // 00..1F: 05 syscall, 0B ud2, 1F nop
    0x00020000u, // 20..3F: 31 rdtsc
    0x0000FFFFu, // 40..5F: 40..4F cmov
    0x00000000u, // 60..7F
    0xFFFFFFFFu, // 80..9F: jcc, setcc
    0x0000B83Cu, // A0..BF: A2 cpuid, A3 bt, A4 A5 shld, AB bts, AC AD shrd, AF imul
    0x0000FF00u, // C0..DF: C8..CF bswap
    0x00000000u, // E0..FF
};

static bool map1_plain(uint8_t op) {
    return (kMap1Plain[op >> 5] >> (op & 31u)) & 1u;
}

// Legacy prefixes and REX. A REX byte is void when a legacy prefix follows it, so the
// register is cleared rather than kept, and that is why the order matters.
static bool x64_prefixes(const uint8_t *b, size_t *i, x64_insn_t *in, bool *asize, bool *rex_seen) {
    for (;;) {
        uint8_t c = b[*i];
        uint8_t k = kPfx[c];
        if (k == 0)
            return true;
        if (++*i >= X64_MAX_LEN)
            return false;
        if (k == 2) {
            in->rex = c;
            *rex_seen = true;
            continue;
        }
        in->rex = 0;
        if (c == 0x66)
            in->p66 = true;
        else if (c == 0x67)
            *asize = true;
        else if (c == 0xF0)
            in->lock = true;
        else if (c == 0xF2 || c == 0xF3)
            in->rep = (c == 0xF3) ? 2u : 3u;
        else if (seg_of(c) >= 5u || in->seg < 5u)
            in->seg = seg_of(c); // es, cs, ss and ds are null in long mode
    }
}

// VEX2, VEX3 and EVEX, which stand in for the escape bytes and the REX byte. The
// register extension bits are stored inverted in all three, and are complemented back
// into a REX byte here so the ModRM decoding below is the same for every encoding.
static bool x64_vex(const uint8_t *b, size_t *i, uint8_t esc, x64_insn_t *in) {
    uint8_t p0 = b[(*i)++];
    uint8_t p1 = 0;
    uint8_t p2 = 0;
    unsigned r, x, bb, w = 0;
    if (esc == 0xC5) {
        r = !(p0 & 0x80u);
        x = 0;
        bb = 0;
        in->vex_vvvv = (uint8_t)((~p0 >> 3) & 15u);
        in->vex_l = (p0 & 4u) != 0;
        in->vex_pp = (uint8_t)(p0 & 3u);
        in->map = 1;
    } else {
        p1 = b[(*i)++];
        r = !(p0 & 0x80u);
        x = !(p0 & 0x40u);
        bb = !(p0 & 0x20u);
        w = (p1 >> 7) & 1u;
        in->vex_vvvv = (uint8_t)((~p1 >> 3) & 15u);
        in->vex_pp = (uint8_t)(p1 & 3u);
        if (esc == 0xC4) {
            in->map = (uint8_t)(p0 & 0x1Fu);
            in->vex_l = (p1 & 4u) != 0;
            if (in->map < 1 || in->map > 3)
                return false;
        } else {
            // EVEX: P0 bit 3 is reserved zero, P1 bit 2 is fixed one. Map 4 is the APX
            // promotion map and 7 is unassigned; neither is an instruction before APX.
            p2 = b[(*i)++];
            in->map = (uint8_t)(p0 & 7u);
            if ((p0 & 0x08u) || !(p1 & 0x04u) || in->map == 0 || in->map == 4 || in->map == 7)
                return false;
            in->evex = true;
            in->ev_z = (p2 & 0x80u) != 0;
            in->ev_ll = (uint8_t)((p2 >> 5) & 3u);
            in->ev_b = (p2 & 0x10u) != 0;
            in->ev_aaa = (uint8_t)(p2 & 7u);
            in->vex_l = in->ev_ll == 1u;
            in->vr = (uint8_t)(!(p0 & 0x10u) << 4); // R', bit 4 of the reg operand
            in->vv = (uint8_t)(!(p2 & 0x08u) << 4); // V', bit 4 of vvvv
        }
    }
    in->vex = true;
    in->vex_w = w != 0;
    in->vv = (uint8_t)(in->vv | in->vex_vvvv);
    in->pfx = in->vex_pp;
    in->rex = (uint8_t)(0x40u | (w << 3) | (r << 2) | (x << 1) | bb);
    in->opcode = b[(*i)++];
    return true;
}

// The class for a resolved map and opcode, or false when the map has none. The 0F38
// and FP16 maps are all ModRM by construction, and 0F3A is ModRM plus an imm8.
static bool x64_class(uint8_t map, uint8_t op, uint8_t *cls) {
    uint8_t c;
    if (map == 2 || map == 5 || map == 6) {
        *cls = XC_MODRM;
        return true;
    }
    if (map == 3) {
        *cls = XC_MODRM_IB;
        return true;
    }
    if (map > 1)
        return false;
    c = map ? kOp0F[op].cls : kOp1[op].cls;
    if (c == XC_BAD)
        return false;
    *cls = c;
    return true;
}

static int64_t le_s(const uint8_t *p, unsigned k) {
    uint64_t v = 0;
    for (unsigned j = 0; j < k; j++)
        v |= (uint64_t)p[j] << (8u * j);
    if (k < 8u) {
        unsigned sh = 64u - 8u * k;
        return (int64_t)(v << sh) >> sh;
    }
    return (int64_t)v;
}

// ModRM, and the SIB and displacement it drags in. Every register number is extended
// by REX.R, REX.X or REX.B here, so a consumer never applies a prefix itself.
static void x64_modrm(const uint8_t *b, size_t *i, x64_insn_t *in) {
    uint8_t m = b[(*i)++];
    unsigned mod = m >> 6;
    unsigned rm = m & 7u;
    unsigned rr = (in->rex & 4u) ? 8u : 0u;
    unsigned rx = (in->rex & 2u) ? 8u : 0u;
    unsigned rb = (in->rex & 1u) ? 8u : 0u;
    in->has_modrm = true;
    in->modrm = m;
    in->mod = (uint8_t)mod;
    in->reg = (uint8_t)(((m >> 3) & 7u) + rr);
    in->rm = (uint8_t)(rm + rb);
    in->vr = (uint8_t)(in->vr | in->reg);
    in->is_mem = mod != 3u;
    // The control and debug register moves ignore mod: the byte is the whole operand.
    if (mod == 3u || in->cls == XC_MODRM_NOMEM) {
        in->is_mem = mod != 3u && in->cls != XC_MODRM_NOMEM;
        // EVEX.X is bit 4 of a register r/m operand, the vector registers 16 to 31.
        in->vm = (uint8_t)(in->rm | ((in->evex && rx) ? 16u : 0u));
        return;
    }
    if (rm == 4u) {
        uint8_t sib = b[(*i)++];
        unsigned idx = ((sib >> 3) & 7u) + rx;
        in->scale = (uint8_t)(1u << (sib >> 6));
        in->sib_idx = (uint8_t)(idx | (in->vv & 16u));
        // Index 4 without REX.X is no index at all; a VSIB form reads it as xmm4,
        // which is why the raw field is kept beside this one.
        in->index = (idx == 4u) ? RE_REG_NONE : (uint8_t)idx;
        if ((sib & 7u) == 5u && mod == 0u) {
            in->base = RE_REG_NONE;
            in->disp = le_s(b + *i, 4);
            in->disp_size = 4;
            *i += 4;
            return;
        }
        in->base = (uint8_t)((sib & 7u) + rb);
    } else if (mod == 0u && rm == 5u) {
        // RIP relative in 64-bit addressing; with a 0x67 prefix it is RIP relative too,
        // through eip, and the address still counts from the end of the instruction.
        in->base = RE_REG_RIP;
        in->rip_rel = true;
        in->disp = le_s(b + *i, 4);
        in->disp_size = 4;
        *i += 4;
        return;
    } else {
        in->base = in->rm;
    }
    if (mod == 1u) {
        in->disp = le_s(b + *i, 1);
        in->disp_size = 1;
        *i += 1;
    } else if (mod == 2u) {
        in->disp = le_s(b + *i, 4);
        in->disp_size = 4;
        *i += 4;
    }
}

// Immediate width in bytes. 0x66 narrows 16 and 32 and REX.W widens only the encodings
// that have a 64-bit form, which is why XC_IV is a class of its own.
static unsigned x64_imm_bytes(const x64_insn_t *in) {
    bool w = (in->rex & 0x08u) != 0;
    bool d = in->opsize == 2;
    unsigned reg = (in->modrm >> 3) & 7u;
    switch (in->cls) {
        case XC_IB:
        case XC_IBS:
        case XC_MODRM_IB:
        case XC_MODRM_IZB:
        case XC_3DNOW:
        case XC_REL8:
            return 1;
        case XC_IW:
        case XC_MODRM_IW:
            return 2;
        case XC_PTR:
            return in->addrsize == 4u ? 4u : 8u;
        case XC_IZ:
        case XC_MODRM_IZ:
            return d ? 2u : 4u;
        case XC_REL32:
            return 4u; // a near branch is 32 bits wide in 64-bit mode whatever 0x66 says
        case XC_IV:
            return w ? 8u : (d ? 2u : 4u);
        case XC_IW_IB:
            return 2; // the imm8 behind it is read separately into imm2
        case XC_MODRM_F6:
            return reg <= 1u ? 1u : 0u;
        case XC_MODRM_F7:
            return reg <= 1u ? (d ? 2u : 4u) : 0u;
        default:
            return 0;
    }
}

static bool has_modrm(uint8_t cls) {
    return cls == XC_MODRM || cls == XC_MODRM_IB || cls == XC_MODRM_IW || cls == XC_MODRM_IZ ||
           cls == XC_MODRM_IZB || cls == XC_MODRM_F6 || cls == XC_MODRM_F7 || cls == XC_3DNOW ||
           cls == XC_MODRM_NOMEM;
}

// Reserved one-byte encodings that depend on ModRM; the processor raises #UD.
static bool x64_undef0(const x64_insn_t *in) {
    unsigned reg = (in->modrm >> 3) & 7u;
    switch (in->opcode) {
        case 0x8D: // lea of a register is no address
            return in->mod == 3u;
        case 0x8C: // mov from a segment register: six segment registers
        case 0x8E:
            return reg > 5u || (in->opcode == 0x8E && reg == 1u); // mov cs is #UD
        case 0x8F:
            return reg != 0u;
        case 0xC6:
        case 0xC7:
            // Reg 7 is xabort or xbegin, and both have exactly one encoding, ModRM F8.
            return reg != 0u && (reg != 7u || in->modrm != 0xF8u);
        case 0xFE:
            return reg > 1u;
        case 0xFF:
            return reg == 7u || ((reg == 3u || reg == 5u) && in->mod == 3u);
        default:
            return false;
    }
}

// EVEX decoration validity: mask, zeroing, broadcast and rounding must match the form.
static bool x64_evex_ok(const x64_insn_t *in, const x64_form_t *f) {
    bool rounding = in->ev_b && !in->is_mem;
    if (in->ev_aaa && !(f->fl & XF_K))
        return false;
    // Zeroing is a kind of masking: without a mask register it is #UD.
    if (in->ev_z && (!(f->fl & XF_Z) || !in->ev_aaa))
        return false;
    // L'L of 3 is reserved, except where it is the rounding mode of a register form.
    if (in->ev_ll == 3u && !(rounding && (f->fl & XF_ER)))
        return false;
    if (!in->ev_b)
        return true;
    if (in->is_mem)
        return (f->bc & XB_MASK) != XB_NONE && !(f->fl & XF_T1S);
    return (f->fl & (XF_ER | XF_SAE)) != 0;
}

// True when an operand list reads VEX.vvvv: a vector, a general or a mask register.
static bool uses_vvvv(const char *ops) {
    for (const char *p = ops; *p; p++)
        if ((p == ops || p[-1] == ',') && (*p == 'H' || *p == 'B' || *p == 'Y'))
            return true;
    return false;
}

// True when an operand list has a VSIB memory operand, whose index EVEX.V' extends.
static bool uses_vsib(const char *ops) {
    for (const char *p = ops; *p; p++)
        if ((p == ops || p[-1] == ',') && *p == 'X' && p[1] != 'M')
            return true;
    return false;
}

// Register file range checks: mask 0..7, bounds 0..3, VSIB overlap rules.
static bool regs_ok(const x64_insn_t *in, const char *ops) {
    for (const char *p = ops; *p; p++) {
        if (p != ops && p[-1] != ',')
            continue;
        if (p[0] == 'K' && (in->vr & 0x18u))
            return false;
        if (p[0] == 'Y' && (in->vv & 0x18u))
            return false;
        if (p[0] == 'T' && in->mod == 3u && (in->vm & 0x18u))
            return false;
        if (p[0] == 'B' && p[1] == 'R' && in->reg > 3u)
            return false;
        if (p[0] == 'B' && p[1] == 'E' && in->mod == 3u && in->rm > 3u)
            return false;
        if (p[0] == 'X' && p[1] != 'M') {
            unsigned idx = in->sib_idx & 31u;
            if ((in->modrm & 7u) != 4u || in->vr == idx || (!in->evex && in->vv == idx) ||
                (!in->evex && in->vv == in->vr))
                return false;
        }
    }
    return true;
}

// The control registers that exist are cr0, cr2, cr3, cr4 and cr8; the debug registers
// stop at dr7. Naming any other is #UD.
static bool crdr_ok(const x64_insn_t *in) {
    unsigned r = in->reg;
    if (in->map != 1u || in->opcode < 0x20u || in->opcode > 0x23u)
        return true;
    if (in->opcode == 0x20u || in->opcode == 0x22u)
        return r == 0u || r == 2u || r == 3u || r == 4u || r == 8u;
    return r < 8u;
}

// Form-table validity: reserved encodings, lock, vvvv unused check, EVEX decorations.
static bool x64_formal(const x64_insn_t *in) {
    const x64_form_t *f;
    bool x87 = in->map == 0 && in->opcode >= 0xD8u && in->opcode <= 0xDFu;
    bool plain = !in->vex && !in->lock &&
                 ((in->map == 0 && !x87) || (in->map == 1 && map1_plain(in->opcode)));
    if (plain)
        return true;
    f = x64_form_find(in);
    if (!f)
        return false;
    // 3DNow: the trailing selector must name a real operation.
    if (in->map == 1 && in->opcode == 0x0Fu && !in->vex && !x64_3dnow_name((uint8_t)in->imm))
        return false;
    if (in->lock && (!(f->fl & XF_LOCK) || !in->is_mem))
        return false;
    if (!crdr_ok(in) || !regs_ok(in, f->ops))
        return false;
    // VEX/EVEX: vvvv must be unused (all ones) when the form has no H/B/Y operand.
    if (in->vex && !uses_vvvv(f->ops)) {
        unsigned used = uses_vsib(f->ops) ? 15u : 31u;
        if (in->vv & used)
            return false;
    }
    return !in->evex || x64_evex_ok(in, f);
}

static void blank(x64_insn_t *in) {
    memset(in, 0, sizeof(*in));
    in->base = RE_REG_NONE;
    in->index = RE_REG_NONE;
    in->scale = 1;
    in->opsize = 4;
    in->addrsize = 8;
}

// The opcode, through the escapes or a vector prefix, which names its own map.
static bool x64_opcode(const uint8_t *b, size_t *i, x64_insn_t *in, bool rex_seen) {
    uint8_t c = b[(*i)++];
    in->raw_op0 = c;
    if (c == 0xC5 || c == 0xC4 || c == 0x62) {
        // A vector prefix after 66/F2/F3/F0/REX is #UD; a voided REX does not count.
        (void)rex_seen;
        if (in->p66 || in->rep || in->lock || in->rex)
            return false;
        return x64_vex(b, i, c, in);
    }
    in->opcode = c;
    if (c != 0x0F)
        return true;
    c = b[(*i)++];
    if (c == 0x38 || c == 0x3A) {
        in->map = (c == 0x38) ? 2u : 3u;
        in->opcode = b[(*i)++];
        return true;
    }
    in->map = 1;
    in->opcode = c;
    return true;
}

// Read the immediates and resolve a branch target from the end of the instruction.
static void x64_finish(const uint8_t *b, size_t *i, uint64_t addr, x64_insn_t *in) {
    unsigned nb = x64_imm_bytes(in);
    if (nb) {
        in->imm = le_s(b + *i, nb);
        in->imm_size = (uint8_t)nb;
        *i += nb;
    }
    if (in->cls == XC_IW_IB)
        in->imm2 = b[(*i)++];
    if (in->cls == XC_REL8 || in->cls == XC_REL32) {
        in->target = addr + (uint64_t)*i + (uint64_t)in->imm;
        in->has_target = true;
    }
    if (in->rip_rel)
        in->mem = addr + (uint64_t)*i + (uint64_t)in->disp;
}

bool x64_decode(const uint8_t *p, size_t n, uint64_t addr, x64_insn_t *out) {
    uint8_t b[24];
    size_t i = 0;
    size_t avail = n < X64_MAX_LEN ? n : X64_MAX_LEN;
    bool asize = false;
    bool rex_seen = false;
    x64_insn_t in;
    if (!p || avail == 0)
        return false;
    memcpy(b, p, avail);
    memset(b + avail, 0, sizeof(b) - avail);
    blank(&in);
    if (!x64_prefixes(b, &i, &in, &asize, &rex_seen))
        return false;
    in.pfx = in.rep ? in.rep : (in.p66 ? 1u : 0u);
    if (!x64_opcode(b, &i, &in, rex_seen) || !x64_class(in.map, in.opcode, &in.cls))
        return false;
    in.opsize = (uint8_t)((in.rex & 0x08u) ? 8u : (in.p66 ? 2u : 4u));
    in.addrsize = (uint8_t)(asize ? 4u : 8u);
    // F2 0F F0 is lddqu, which carries no immediate where the class table says one.
    if (in.map == 1 && in.opcode == 0xF0u && in.pfx == 3u)
        in.cls = XC_MODRM;
    // 66 and F2 0F 78 are the SSE4a extrq and insertq, which carry a field length and
    // an index as two imm8s where the VMX form beside them carries none.
    if (in.map == 1 && in.opcode == 0x78u && !in.vex && (in.pfx == 1u || in.pfx == 3u))
        in.cls = XC_MODRM_IW;
    if (has_modrm(in.cls))
        x64_modrm(b, &i, &in);
    if (in.map == 0 && in.has_modrm && x64_undef0(&in))
        return false;
    // Push and pop default to a 64-bit operand in long mode.
    if (in.map == 0 && in.opcode >= 0x50u && in.opcode <= 0x5Fu)
        in.opsize = in.p66 ? 2u : 8u;
    x64_finish(b, &i, addr, &in);
    if (i > avail || i > X64_MAX_LEN)
        return false;
    in.size = (uint8_t)i;
    in.id = X64_ID(in.map, in.opcode);
    if (!x64_formal(&in))
        return false;
    *out = in;
    return true;
}
