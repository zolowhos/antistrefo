// re_x64_t1v.c - the 0F map forms that exist only under VEX or EVEX.
// Module: feature (C11).
// Owns: vzeroupper, vzeroall, AVX-512 mask ops, EVEX unsigned/quadword conversions.
// Depends: re_x64_form.h. A table sorted by opcode; first hit wins.
#include "features/disasm/fmt/re_x64_form.h"

#define KZ XF_KZ
#define ER XF_ER
#define SAE XF_SAE
#define NP XP_NP
#define P66 XP_66
#define PF3 XP_F3
#define PF2 XP_F2

// A mask register row: VEX, a prefix, the W bit and the vector length all select.
#define KR(op, pfx, mod, w, l, mn, ops) XR(op, XS_V, pfx, mod, X_ANY, X_ANY, w, 0, l, 0, 0, mn, ops)
// The four widths of one mask operation: word, byte, quadword, doubleword.
#define K4(op, l, mn, ops)                                                               \
    KR(op, NP, XM_REG, XW_0, l, mn "w", ops), KR(op, P66, XM_REG, XW_0, l, mn "b", ops), \
        KR(op, NP, XM_REG, XW_1, l, mn "q", ops), KR(op, P66, XM_REG, XW_1, l, mn "d", ops)
// An EVEX only row with its W bit.
#define EV(op, pfx, w, bc, fl, mn, ops) \
    XR(op, XS_E, pfx, XM_ANY, X_ANY, X_ANY, w, 0, 0, bc, fl, mn, ops)

static const x64_form_t kRows[] = {
    K4(0x41, XL_256, "kand", "K,Y,T"),
    K4(0x42, XL_256, "kandn", "K,Y,T"),
    K4(0x44, XL_128, "knot", "K,T"),
    K4(0x45, XL_256, "kor", "K,Y,T"),
    K4(0x46, XL_256, "kxnor", "K,Y,T"),
    K4(0x47, XL_256, "kxor", "K,Y,T"),
    K4(0x4A, XL_256, "kadd", "K,Y,T"),
    KR(0x4B, P66, XM_REG, XW_0, XL_256, "kunpckbw", "K,Y,T"),
    KR(0x4B, NP, XM_REG, XW_0, XL_256, "kunpckwd", "K,Y,T"),
    KR(0x4B, NP, XM_REG, XW_1, XL_256, "kunpckdq", "K,Y,T"),
    XR(0x77, XS_V, NP, XM_ANY, X_ANY, X_ANY, XW_ANY, 0, XL_128, 0, 0, "vzeroupper", ""),
    XR(0x77, XS_V, NP, XM_ANY, X_ANY, X_ANY, XW_ANY, 0, XL_256, 0, 0, "vzeroall", ""),
    EV(0x78, NP, XW_0, XB_4, KZ | SAE, "vcvttps2udq", "Vx,Wx"),
    EV(0x78, NP, XW_1, XB_8, KZ | SAE, "vcvttpd2udq", "Vh,Wx"),
    EV(0x78, P66, XW_0, XB_4, KZ | SAE, "vcvttps2uqq", "Vx,Wh"),
    EV(0x78, P66, XW_1, XB_8, KZ | SAE, "vcvttpd2uqq", "Vx,Wx"),
    EV(0x78, PF3, XW_ANY, 0, SAE, "vcvttss2usi", "Gy,Wss"),
    EV(0x78, PF2, XW_ANY, 0, SAE, "vcvttsd2usi", "Gy,Wsd"),
    EV(0x79, NP, XW_0, XB_4, KZ | ER, "vcvtps2udq", "Vx,Wx"),
    EV(0x79, NP, XW_1, XB_8, KZ | ER, "vcvtpd2udq", "Vh,Wx"),
    EV(0x79, P66, XW_0, XB_4, KZ | ER, "vcvtps2uqq", "Vx,Wh"),
    EV(0x79, P66, XW_1, XB_8, KZ | ER, "vcvtpd2uqq", "Vx,Wx"),
    EV(0x79, PF3, XW_ANY, 0, ER, "vcvtss2usi", "Gy,Wss"),
    EV(0x79, PF2, XW_ANY, 0, ER, "vcvtsd2usi", "Gy,Wsd"),
    EV(0x7A, P66, XW_0, XB_4, KZ | SAE, "vcvttps2qq", "Vx,Wh"),
    EV(0x7A, P66, XW_1, XB_8, KZ | SAE, "vcvttpd2qq", "Vx,Wx"),
    EV(0x7A, PF3, XW_0, XB_4, KZ, "vcvtudq2pd", "Vx,Wh"),
    EV(0x7A, PF3, XW_1, XB_8, KZ | ER, "vcvtuqq2pd", "Vx,Wx"),
    EV(0x7A, PF2, XW_0, XB_4, KZ | ER, "vcvtudq2ps", "Vx,Wx"),
    EV(0x7A, PF2, XW_1, XB_8, KZ | ER, "vcvtuqq2ps", "Vh,Wx"),
    EV(0x7B, P66, XW_0, XB_4, KZ | ER, "vcvtps2qq", "Vx,Wh"),
    EV(0x7B, P66, XW_1, XB_8, KZ | ER, "vcvtpd2qq", "Vx,Wx"),
    EV(0x7B, PF3, XW_ANY, 0, ER, "vcvtusi2ss", "Vdq,Hdq,Ey"),
    EV(0x7B, PF2, XW_ANY, 0, ER, "vcvtusi2sd", "Vdq,Hdq,Ey"),
    KR(0x90, NP, XM_ANY, XW_0, XL_128, "kmovw", "K,Tw"),
    KR(0x90, P66, XM_ANY, XW_0, XL_128, "kmovb", "K,Tb"),
    KR(0x90, NP, XM_ANY, XW_1, XL_128, "kmovq", "K,Tq"),
    KR(0x90, P66, XM_ANY, XW_1, XL_128, "kmovd", "K,Td"),
    KR(0x91, NP, XM_MEM, XW_0, XL_128, "kmovw", "Mw,K"),
    KR(0x91, P66, XM_MEM, XW_0, XL_128, "kmovb", "Mb,K"),
    KR(0x91, NP, XM_MEM, XW_1, XL_128, "kmovq", "Mq,K"),
    KR(0x91, P66, XM_MEM, XW_1, XL_128, "kmovd", "Md,K"),
    KR(0x92, NP, XM_REG, XW_0, XL_128, "kmovw", "K,Rd"),
    KR(0x92, P66, XM_REG, XW_0, XL_128, "kmovb", "K,Rd"),
    KR(0x92, PF2, XM_REG, XW_0, XL_128, "kmovd", "K,Rd"),
    KR(0x92, PF2, XM_REG, XW_1, XL_128, "kmovq", "K,Rq"),
    KR(0x93, NP, XM_REG, XW_0, XL_128, "kmovw", "Gd,T"),
    KR(0x93, P66, XM_REG, XW_0, XL_128, "kmovb", "Gd,T"),
    KR(0x93, PF2, XM_REG, XW_0, XL_128, "kmovd", "Gd,T"),
    KR(0x93, PF2, XM_REG, XW_1, XL_128, "kmovq", "Gq,T"),
    K4(0x98, XL_128, "kortest", "K,T"),
    K4(0x99, XL_128, "ktest", "K,T"),
};

const x64_ftab_t x64_tab1v = {1, kRows, sizeof(kRows) / sizeof(kRows[0])};
