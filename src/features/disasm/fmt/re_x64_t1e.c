// re_x64_t1e.c - the 0F map EVEX forms whose name or operands differ from the VEX form.
// Module: feature (C11).
// Owns: element-sized moves, logic, compares into mask, quadword EVEX.W forms.
// Depends: re_x64_form.h. Consulted before the shared rows; sorted by opcode.
#include "features/disasm/fmt/re_x64_form.h"

#define KZ XF_KZ
#define ER XF_ER
#define SAE XF_SAE
#define NP XP_NP
#define P66 XP_66
#define PF3 XP_F3
#define PF2 XP_F2

#define E(op, pfx, mod, reg, w, bc, fl, mn, ops) \
    XR(op, XS_E, pfx, mod, reg, X_ANY, w, 0, 0, bc, fl, mn, ops)
#define E2(op, pfx, w, bc, fl, mn, ops) E(op, pfx, XM_ANY, X_ANY, w, bc, fl, mn, ops)
// The doubleword and quadword forms of one 0x66 integer opcode.
#define DQ(op, mn, ops) \
    E2(op, P66, XW_0, XB_4, KZ, mn "d", ops), E2(op, P66, XW_1, XB_8, KZ, mn "q", ops)

static const x64_form_t kRows[] = {
    E2(0x5B, NP, XW_1, XB_8, KZ | ER, "vcvtqq2ps", "Vh,Wx"),
    E2(0x64, P66, XW_ANY, 0, XF_K, "vpcmpgtb", "K,Hx,Wx"),
    E2(0x65, P66, XW_ANY, 0, XF_K, "vpcmpgtw", "K,Hx,Wx"),
    E2(0x66, P66, XW_0, XB_4, XF_K, "vpcmpgtd", "K,Hx,Wx"),
    E2(0x6F, P66, XW_0, 0, KZ, "vmovdqa32", "Vx,Wx"),
    E2(0x6F, P66, XW_1, 0, KZ, "vmovdqa64", "Vx,Wx"),
    E2(0x6F, PF3, XW_0, 0, KZ, "vmovdqu32", "Vx,Wx"),
    E2(0x6F, PF3, XW_1, 0, KZ, "vmovdqu64", "Vx,Wx"),
    E2(0x6F, PF2, XW_0, 0, KZ, "vmovdqu8", "Vx,Wx"),
    E2(0x6F, PF2, XW_1, 0, KZ, "vmovdqu16", "Vx,Wx"),
    E(0x72, P66, XM_ANY, 0, XW_0, XB_4, KZ, "vprord", "Hx,Wx,Ib"),
    E(0x72, P66, XM_ANY, 0, XW_1, XB_8, KZ, "vprorq", "Hx,Wx,Ib"),
    E(0x72, P66, XM_ANY, 1, XW_0, XB_4, KZ, "vprold", "Hx,Wx,Ib"),
    E(0x72, P66, XM_ANY, 1, XW_1, XB_8, KZ, "vprolq", "Hx,Wx,Ib"),
    E(0x72, P66, XM_ANY, 4, XW_1, XB_8, KZ, "vpsraq", "Hx,Wx,Ib"),
    E2(0x74, P66, XW_ANY, 0, XF_K, "vpcmpeqb", "K,Hx,Wx"),
    E2(0x75, P66, XW_ANY, 0, XF_K, "vpcmpeqw", "K,Hx,Wx"),
    E2(0x76, P66, XW_0, XB_4, XF_K, "vpcmpeqd", "K,Hx,Wx"),
    E2(0x7F, P66, XW_0, 0, KZ, "vmovdqa32", "Wx,Vx"),
    E2(0x7F, P66, XW_1, 0, KZ, "vmovdqa64", "Wx,Vx"),
    E2(0x7F, PF3, XW_0, 0, KZ, "vmovdqu32", "Wx,Vx"),
    E2(0x7F, PF3, XW_1, 0, KZ, "vmovdqu64", "Wx,Vx"),
    E2(0x7F, PF2, XW_0, 0, KZ, "vmovdqu8", "Wx,Vx"),
    E2(0x7F, PF2, XW_1, 0, KZ, "vmovdqu16", "Wx,Vx"),
    E2(0xC2, NP, XW_0, XB_4, XF_K | SAE, "vcmpps", "K,Hx,Wx,Ib"),
    E2(0xC2, P66, XW_1, XB_8, XF_K | SAE, "vcmppd", "K,Hx,Wx,Ib"),
    E2(0xC2, PF3, XW_0, 0, XF_K | SAE, "vcmpss", "K,Hdq,Wss,Ib"),
    E2(0xC2, PF2, XW_1, 0, XF_K | SAE, "vcmpsd", "K,Hdq,Wsd,Ib"),
    DQ(0xDB, "vpand", "Vx,Hx,Wx"),
    DQ(0xDF, "vpandn", "Vx,Hx,Wx"),
    E2(0xE2, P66, XW_1, 0, KZ, "vpsraq", "Vx,Hx,Wdq"),
    E2(0xE6, PF3, XW_1, XB_8, KZ | ER, "vcvtqq2pd", "Vx,Wx"),
    DQ(0xEB, "vpor", "Vx,Hx,Wx"),
    DQ(0xEF, "vpxor", "Vx,Hx,Wx"),
};

const x64_ftab_t x64_tab1e = {1, kRows, sizeof(kRows) / sizeof(kRows[0])};
