// re_x64_t0.c - the one byte opcode map: every form, groups included.
// Module: feature (C11).
// Owns: the names and operand lists of the 0x00..0xFF opcodes outside the x87 escapes.
// Depends: re_x64_form.h. A table, sorted by opcode; within one opcode, first hit wins.
#include "features/disasm/fmt/re_x64_form.h"

#define L XF_LOCK
#define D XF_D64
#define F XF_F64

// The eight arithmetic blocks share one shape: two lockable stores, two loads, and the
// two accumulator forms against an immediate.
#define ALU(o, mn, lk)                                                                 \
    XI(o + 0, lk, mn, "Eb,Gb"), XI(o + 1, lk, mn, "Ev,Gv"), XI(o + 2, 0, mn, "Gb,Eb"), \
        XI(o + 3, 0, mn, "Gv,Ev"), XI(o + 4, 0, mn, "AL,Ib"), XI(o + 5, 0, mn, "Av,Iz")

// Group 1: the same eight operations against an immediate. Compare is the one that
// stores nothing and so cannot be locked.
#define G1(o, ops)                                                                 \
    XG(o, 0, L, "add", ops), XG(o, 1, L, "or", ops), XG(o, 2, L, "adc", ops),      \
        XG(o, 3, L, "sbb", ops), XG(o, 4, L, "and", ops), XG(o, 5, L, "sub", ops), \
        XG(o, 6, L, "xor", ops), XG(o, 7, 0, "cmp", ops)

// Group 2: the rotates and shifts. /6 is an undocumented alias of shl, and named so.
#define G2(o, ops)                                                                 \
    XG(o, 0, 0, "rol", ops), XG(o, 1, 0, "ror", ops), XG(o, 2, 0, "rcl", ops),     \
        XG(o, 3, 0, "rcr", ops), XG(o, 4, 0, "shl", ops), XG(o, 5, 0, "shr", ops), \
        XG(o, 6, 0, "shl", ops), XG(o, 7, 0, "sar", ops)

// Group 3: test against an immediate, then the one operand arithmetic.
#define G3(o, s, imm)                                                                    \
    XG(o, 0, 0, "test", "E" s "," imm), XG(o, 1, 0, "test", "E" s "," imm),              \
        XG(o, 2, L, "not", "E" s), XG(o, 3, L, "neg", "E" s), XG(o, 4, 0, "mul", "E" s), \
        XG(o, 5, 0, "imul", "E" s), XG(o, 6, 0, "div", "E" s), XG(o, 7, 0, "idiv", "E" s)

// A string primitive: the byte form, then the word, doubleword and quadword forms of the
// next opcode, which the operand size picks between.
#define STR(o, b, w, d, q) \
    XI(o, 0, b, ""), XO(o + 1, 2, 0, w, ""), XO(o + 1, 8, 0, q, ""), XI(o + 1, 0, d, "")

static const x64_form_t kRows[] = {
    ALU(0x00, "add", L),
    ALU(0x08, "or", L),
    ALU(0x10, "adc", L),
    ALU(0x18, "sbb", L),
    ALU(0x20, "and", L),
    ALU(0x28, "sub", L),
    ALU(0x30, "xor", L),
    ALU(0x38, "cmp", 0),
    XI(0x50, D, "push", "Zv"),
    XI(0x51, D, "push", "Zv"),
    XI(0x52, D, "push", "Zv"),
    XI(0x53, D, "push", "Zv"),
    XI(0x54, D, "push", "Zv"),
    XI(0x55, D, "push", "Zv"),
    XI(0x56, D, "push", "Zv"),
    XI(0x57, D, "push", "Zv"),
    XI(0x58, D, "pop", "Zv"),
    XI(0x59, D, "pop", "Zv"),
    XI(0x5A, D, "pop", "Zv"),
    XI(0x5B, D, "pop", "Zv"),
    XI(0x5C, D, "pop", "Zv"),
    XI(0x5D, D, "pop", "Zv"),
    XI(0x5E, D, "pop", "Zv"),
    XI(0x5F, D, "pop", "Zv"),
    XI(0x63, 0, "movsxd", "Gv,Ez"),
    XI(0x68, D, "push", "Iz"),
    XI(0x69, 0, "imul", "Gv,Ev,Iz"),
    XI(0x6A, D, "push", "Is"),
    XI(0x6B, 0, "imul", "Gv,Ev,Is"),
    XI(0x6C, 0, "insb", ""),
    XO(0x6D, 2, 0, "insw", ""),
    XI(0x6D, 0, "insd", ""),
    XI(0x6E, 0, "outsb", ""),
    XO(0x6F, 2, 0, "outsw", ""),
    XI(0x6F, 0, "outsd", ""),
    XI(0x70, F, "jo", "Jb"),
    XI(0x71, F, "jno", "Jb"),
    XI(0x72, F, "jb", "Jb"),
    XI(0x73, F, "jae", "Jb"),
    XI(0x74, F, "je", "Jb"),
    XI(0x75, F, "jne", "Jb"),
    XI(0x76, F, "jbe", "Jb"),
    XI(0x77, F, "ja", "Jb"),
    XI(0x78, F, "js", "Jb"),
    XI(0x79, F, "jns", "Jb"),
    XI(0x7A, F, "jp", "Jb"),
    XI(0x7B, F, "jnp", "Jb"),
    XI(0x7C, F, "jl", "Jb"),
    XI(0x7D, F, "jge", "Jb"),
    XI(0x7E, F, "jle", "Jb"),
    XI(0x7F, F, "jg", "Jb"),
    G1(0x80, "Eb,Ib"),
    G1(0x81, "Ev,Iz"),
    G1(0x83, "Ev,Is"),
    XI(0x84, 0, "test", "Eb,Gb"),
    XI(0x85, 0, "test", "Ev,Gv"),
    XI(0x86, L, "xchg", "Eb,Gb"),
    XI(0x87, L, "xchg", "Ev,Gv"),
    XI(0x88, 0, "mov", "Eb,Gb"),
    XI(0x89, 0, "mov", "Ev,Gv"),
    XI(0x8A, 0, "mov", "Gb,Eb"),
    XI(0x8B, 0, "mov", "Gv,Ev"),
    XGM(0x8C, X_ANY, XM_MEM, 0, "mov", "Mw,Sw"),
    XI(0x8C, 0, "mov", "Ev,Sw"),
    XI(0x8D, 0, "lea", "Gv,Mm"),
    XGM(0x8E, X_ANY, XM_MEM, 0, "mov", "Sw,Mw"),
    XI(0x8E, 0, "mov", "Sw,Ew"),
    XG(0x8F, 0, D, "pop", "Ev"),
    XR(0x90, XS_L, XP_F3, XM_ANY, X_ANY, X_ANY, XW_ANY, 0, 0, 0, 0, "pause", ""),
    XI(0x90, 0, "nop", ""),
    XI(0x91, 0, "xchg", "Zv,Av"),
    XI(0x92, 0, "xchg", "Zv,Av"),
    XI(0x93, 0, "xchg", "Zv,Av"),
    XI(0x94, 0, "xchg", "Zv,Av"),
    XI(0x95, 0, "xchg", "Zv,Av"),
    XI(0x96, 0, "xchg", "Zv,Av"),
    XI(0x97, 0, "xchg", "Zv,Av"),
    XO(0x98, 2, 0, "cbw", ""),
    XO(0x98, 8, 0, "cdqe", ""),
    XI(0x98, 0, "cwde", ""),
    XO(0x99, 2, 0, "cwd", ""),
    XO(0x99, 8, 0, "cqo", ""),
    XI(0x99, 0, "cdq", ""),
    XI(0x9B, 0, "wait", ""),
    XO(0x9C, 2, D, "pushf", ""),
    XI(0x9C, D, "pushfq", ""),
    XO(0x9D, 2, D, "popf", ""),
    XI(0x9D, D, "popfq", ""),
    XI(0x9E, 0, "sahf", ""),
    XI(0x9F, 0, "lahf", ""),
    XI(0xA0, 0, "mov", "AL,Ob"),
    XI(0xA1, 0, "mov", "Av,Ov"),
    XI(0xA2, 0, "mov", "Ob,AL"),
    XI(0xA3, 0, "mov", "Ov,Av"),
    STR(0xA4, "movsb", "movsw", "movsd", "movsq"),
    STR(0xA6, "cmpsb", "cmpsw", "cmpsd", "cmpsq"),
    XI(0xA8, 0, "test", "AL,Ib"),
    XI(0xA9, 0, "test", "Av,Iz"),
    STR(0xAA, "stosb", "stosw", "stosd", "stosq"),
    STR(0xAC, "lodsb", "lodsw", "lodsd", "lodsq"),
    STR(0xAE, "scasb", "scasw", "scasd", "scasq"),
    XI(0xB0, 0, "mov", "Zb,Ib"),
    XI(0xB1, 0, "mov", "Zb,Ib"),
    XI(0xB2, 0, "mov", "Zb,Ib"),
    XI(0xB3, 0, "mov", "Zb,Ib"),
    XI(0xB4, 0, "mov", "Zb,Ib"),
    XI(0xB5, 0, "mov", "Zb,Ib"),
    XI(0xB6, 0, "mov", "Zb,Ib"),
    XI(0xB7, 0, "mov", "Zb,Ib"),
    XI(0xB8, 0, "mov", "Zv,Iv"),
    XI(0xB9, 0, "mov", "Zv,Iv"),
    XI(0xBA, 0, "mov", "Zv,Iv"),
    XI(0xBB, 0, "mov", "Zv,Iv"),
    XI(0xBC, 0, "mov", "Zv,Iv"),
    XI(0xBD, 0, "mov", "Zv,Iv"),
    XI(0xBE, 0, "mov", "Zv,Iv"),
    XI(0xBF, 0, "mov", "Zv,Iv"),
    G2(0xC0, "Eb,Ib"),
    G2(0xC1, "Ev,Ib"),
    XI(0xC2, F, "ret", "Iw"),
    XI(0xC3, F, "ret", ""),
    XR(0xC6, XS_L, XP_ANY, XM_REG, 7, 0, XW_ANY, 0, 0, 0, 0, "xabort", "Ib"),
    XG(0xC6, 0, 0, "mov", "Eb,Ib"),
    XR(0xC7, XS_L, XP_ANY, XM_REG, 7, 0, XW_ANY, 0, 0, 0, 0, "xbegin", "Jz"),
    XG(0xC7, 0, 0, "mov", "Ev,Iz"),
    XI(0xC8, D, "enter", "Iw,I2"),
    XI(0xC9, D, "leave", ""),
    XI(0xCA, 0, "retf", "Iw"),
    XI(0xCB, 0, "retf", ""),
    XI(0xCC, 0, "int3", ""),
    XI(0xCD, 0, "int", "Ib"),
    XO(0xCF, 2, 0, "iret", ""),
    XO(0xCF, 8, 0, "iretq", ""),
    XI(0xCF, 0, "iretd", ""),
    G2(0xD0, "Eb,1"),
    G2(0xD1, "Ev,1"),
    G2(0xD2, "Eb,CL"),
    G2(0xD3, "Ev,CL"),
    XI(0xD7, 0, "xlat", ""),
    XI(0xE0, F, "loopne", "Jb"),
    XI(0xE1, F, "loope", "Jb"),
    XI(0xE2, F, "loop", "Jb"),
    XI(0xE3, F, "jrcxz", "Jb"),
    XI(0xE4, 0, "in", "AL,Ib"),
    XI(0xE5, 0, "in", "Az,Ib"),
    XI(0xE6, 0, "out", "Ib,AL"),
    XI(0xE7, 0, "out", "Ib,Az"),
    XI(0xE8, F, "call", "Jz"),
    XI(0xE9, F, "jmp", "Jz"),
    XI(0xEB, F, "jmp", "Jb"),
    XI(0xEC, 0, "in", "AL,DX"),
    XI(0xED, 0, "in", "Az,DX"),
    XI(0xEE, 0, "out", "DX,AL"),
    XI(0xEF, 0, "out", "DX,Az"),
    XI(0xF1, 0, "int1", ""),
    XI(0xF4, 0, "hlt", ""),
    XI(0xF5, 0, "cmc", ""),
    G3(0xF6, "b", "Ib"),
    G3(0xF7, "v", "Iz"),
    XI(0xF8, 0, "clc", ""),
    XI(0xF9, 0, "stc", ""),
    XI(0xFA, 0, "cli", ""),
    XI(0xFB, 0, "sti", ""),
    XI(0xFC, 0, "cld", ""),
    XI(0xFD, 0, "std", ""),
    XG(0xFE, 0, L, "inc", "Eb"),
    XG(0xFE, 1, L, "dec", "Eb"),
    XG(0xFF, 0, L, "inc", "Ev"),
    XG(0xFF, 1, L, "dec", "Ev"),
    XG(0xFF, 2, F, "call", "Ev"),
    XG(0xFF, 3, 0, "call far", "Mp"),
    XG(0xFF, 4, F, "jmp", "Ev"),
    XG(0xFF, 5, 0, "jmp far", "Mp"),
    XG(0xFF, 6, D, "push", "Ev"),
};

const x64_ftab_t x64_tab0 = {0, kRows, sizeof(kRows) / sizeof(kRows[0])};
