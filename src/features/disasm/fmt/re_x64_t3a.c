// re_x64_t3a.c - the 0F3A map: every form carries an imm8 behind its operands.
// Module: feature (C11).
// Owns: SSE4 rounds, blends, inserts, extracts, string compares, AVX-512 ternlog.
// Depends: re_x64_form.h. Sorted by opcode; EVEX rows precede shared; first hit wins.
#include "features/disasm/fmt/re_x64_form.h"

#define KZ XF_KZ
#define K XF_K
#define ER XF_ER
#define SAE XF_SAE
#define NP XP_NP
#define P66 XP_66
#define PF2 XP_F2
#define ANY XM_ANY
#define NOT128 (XL_256 | XL_512)

#define V(op, sp, pfx, w, l, bc, fl, mn, ops) \
    XR(op, sp, pfx, ANY, X_ANY, X_ANY, w, 0, l, bc, fl, mn, ops)
#define E0(op, l, bc, fl, mn, ops) V(op, XS_E, P66, XW_0, l, bc, fl, mn, ops)
#define E1(op, l, bc, fl, mn, ops) V(op, XS_E, P66, XW_1, l, bc, fl, mn, ops)
#define WP(op, l, bc0, bc1, fl, a, b, ops) E0(op, l, bc0, fl, a, ops), E1(op, l, bc1, fl, b, ops)
#define VO(op, w, l, mn, ops) V(op, XS_V, P66, w, l, 0, 0, mn, ops)
#define LV(op, l, mn, ops) V(op, XS_LV, P66, XW_ANY, l, 0, 0, mn, ops)
#define KS(op, a, b)                                                             \
    XR(op, XS_V, P66, XM_REG, X_ANY, X_ANY, XW_0, 0, XL_128, 0, 0, a, "K,T,Ib"), \
        XR(op, XS_V, P66, XM_REG, X_ANY, X_ANY, XW_1, 0, XL_128, 0, 0, b, "K,T,Ib")

static const x64_form_t kRows[] = {
    E1(0x00, NOT128, XB_8, KZ, "vpermq", "Vx,Wx,Ib"),
    VO(0x00, XW_1, XL_256, "vpermq", "Vqq,Wqq,Ib"),
    E1(0x01, NOT128, XB_8, KZ, "vpermpd", "Vx,Wx,Ib"),
    VO(0x01, XW_1, XL_256, "vpermpd", "Vqq,Wqq,Ib"),
    VO(0x02, XW_0, 0, "vpblendd", "Vx,Hx,Wx,Ib"),
    WP(0x03, 0, XB_4, XB_8, KZ, "valignd", "valignq", "Vx,Hx,Wx,Ib"),
    E0(0x04, 0, XB_4, KZ, "vpermilps", "Vx,Wx,Ib"),
    VO(0x04, XW_0, 0, "vpermilps", "Vx,Wx,Ib"),
    E1(0x05, 0, XB_8, KZ, "vpermilpd", "Vx,Wx,Ib"),
    VO(0x05, XW_0, 0, "vpermilpd", "Vx,Wx,Ib"),
    VO(0x06, XW_0, XL_256, "vperm2f128", "Vqq,Hqq,Wqq,Ib"),
    E0(0x08, 0, XB_4, KZ | SAE, "vrndscaleps", "Vx,Wx,Ib"),
    LV(0x08, 0, "roundps", "Vx,Wx,Ib"),
    E1(0x09, 0, XB_8, KZ | SAE, "vrndscalepd", "Vx,Wx,Ib"),
    LV(0x09, 0, "roundpd", "Vx,Wx,Ib"),
    E0(0x0A, 0, 0, KZ | SAE, "vrndscaless", "Vdq,Hdq,Wss,Ib"),
    LV(0x0A, 0, "roundss", "Vdq,Hdq,Wss,Ib"),
    E1(0x0B, 0, 0, KZ | SAE, "vrndscalesd", "Vdq,Hdq,Wsd,Ib"),
    LV(0x0B, 0, "roundsd", "Vdq,Hdq,Wsd,Ib"),
    LV(0x0C, 0, "blendps", "Vx,Hx,Wx,Ib"),
    LV(0x0D, 0, "blendpd", "Vx,Hx,Wx,Ib"),
    LV(0x0E, 0, "pblendw", "Vx,Hx,Wx,Ib"),
    V(0x0F, XS_L, NP, XW_ANY, 0, 0, 0, "palignr", "Pq,Qq,Ib"),
    V(0x0F, XS_LVE, P66, XW_ANY, 0, 0, KZ, "palignr", "Vx,Hx,Wx,Ib"),
    V(0x14, XS_LVE, P66, XW_ANY, XL_128, 0, 0, "pextrb", "Ebd,Vdq,Ib"),
    V(0x15, XS_LVE, P66, XW_ANY, XL_128, 0, 0, "pextrw", "Ewd,Vdq,Ib"),
    V(0x16, XS_LVE, P66, XW_1, XL_128, 0, 0, "pextrq", "Eq,Vdq,Ib"),
    V(0x16, XS_LVE, P66, XW_ANY, XL_128, 0, 0, "pextrd", "Ed,Vdq,Ib"),
    V(0x17, XS_LVE, P66, XW_ANY, XL_128, 0, 0, "extractps", "Ed,Vdq,Ib"),
    E0(0x18, NOT128, 0, KZ, "vinsertf32x4", "Vx,Hx,Wdq,Ib"),
    E1(0x18, NOT128, 0, KZ, "vinsertf64x2", "Vx,Hx,Wdq,Ib"),
    VO(0x18, XW_0, XL_256, "vinsertf128", "Vqq,Hqq,Wdq,Ib"),
    E0(0x19, NOT128, 0, KZ, "vextractf32x4", "Wdq,Vx,Ib"),
    E1(0x19, NOT128, 0, KZ, "vextractf64x2", "Wdq,Vx,Ib"),
    VO(0x19, XW_0, XL_256, "vextractf128", "Wdq,Vqq,Ib"),
    WP(0x1A, XL_512, 0, 0, KZ, "vinsertf32x8", "vinsertf64x4", "Vx,Hx,Wqq,Ib"),
    WP(0x1B, XL_512, 0, 0, KZ, "vextractf32x8", "vextractf64x4", "Wqq,Vx,Ib"),
    V(0x1D, XS_VE, P66, XW_0, 0, 0, KZ | SAE, "vcvtps2ph", "Wh,Vx,Ib"),
    WP(0x1E, 0, XB_4, XB_8, K, "vpcmpud", "vpcmpuq", "K,Hx,Wx,Ib"),
    WP(0x1F, 0, XB_4, XB_8, K, "vpcmpd", "vpcmpq", "K,Hx,Wx,Ib"),
    V(0x20, XS_LVE, P66, XW_ANY, XL_128, 0, 0, "pinsrb", "Vdq,Hdq,Ebd,Ib"),
    V(0x21, XS_LVE, P66, XW_ANY, XL_128, XE_W0, 0, "insertps", "Vdq,Hdq,Wss,Ib"),
    V(0x22, XS_LVE, P66, XW_1, XL_128, 0, 0, "pinsrq", "Vdq,Hdq,Eq,Ib"),
    V(0x22, XS_LVE, P66, XW_ANY, XL_128, 0, 0, "pinsrd", "Vdq,Hdq,Ed,Ib"),
    WP(0x23, NOT128, XB_4, XB_8, KZ, "vshuff32x4", "vshuff64x2", "Vx,Hx,Wx,Ib"),
    WP(0x25, 0, XB_4, XB_8, KZ, "vpternlogd", "vpternlogq", "Vx,Hx,Wx,Ib"),
    WP(0x26, 0, XB_4, XB_8, KZ | SAE, "vgetmantps", "vgetmantpd", "Vx,Wx,Ib"),
    E0(0x27, 0, 0, KZ | SAE, "vgetmantss", "Vdq,Hdq,Wss,Ib"),
    E1(0x27, 0, 0, KZ | SAE, "vgetmantsd", "Vdq,Hdq,Wsd,Ib"),
    KS(0x30, "kshiftrb", "kshiftrw"),
    KS(0x31, "kshiftrd", "kshiftrq"),
    KS(0x32, "kshiftlb", "kshiftlw"),
    KS(0x33, "kshiftld", "kshiftlq"),
    E0(0x38, NOT128, 0, KZ, "vinserti32x4", "Vx,Hx,Wdq,Ib"),
    E1(0x38, NOT128, 0, KZ, "vinserti64x2", "Vx,Hx,Wdq,Ib"),
    VO(0x38, XW_0, XL_256, "vinserti128", "Vqq,Hqq,Wdq,Ib"),
    E0(0x39, NOT128, 0, KZ, "vextracti32x4", "Wdq,Vx,Ib"),
    E1(0x39, NOT128, 0, KZ, "vextracti64x2", "Wdq,Vx,Ib"),
    VO(0x39, XW_0, XL_256, "vextracti128", "Wdq,Vqq,Ib"),
    WP(0x3A, XL_512, 0, 0, KZ, "vinserti32x8", "vinserti64x4", "Vx,Hx,Wqq,Ib"),
    WP(0x3B, XL_512, 0, 0, KZ, "vextracti32x8", "vextracti64x4", "Wqq,Vx,Ib"),
    WP(0x3E, 0, 0, 0, K, "vpcmpub", "vpcmpuw", "K,Hx,Wx,Ib"),
    WP(0x3F, 0, 0, 0, K, "vpcmpb", "vpcmpw", "K,Hx,Wx,Ib"),
    LV(0x40, 0, "dpps", "Vx,Hx,Wx,Ib"),
    LV(0x41, XL_128, "dppd", "Vdq,Hdq,Wdq,Ib"),
    E0(0x42, 0, 0, KZ, "vdbpsadbw", "Vx,Hx,Wx,Ib"),
    LV(0x42, 0, "mpsadbw", "Vx,Hx,Wx,Ib"),
    WP(0x43, NOT128, XB_4, XB_8, KZ, "vshufi32x4", "vshufi64x2", "Vx,Hx,Wx,Ib"),
    V(0x44, XS_LVE, P66, XW_ANY, 0, 0, 0, "pclmulqdq", "Vx,Hx,Wx,Ib"),
    VO(0x46, XW_0, XL_256, "vperm2i128", "Vqq,Hqq,Wqq,Ib"),
    VO(0x4A, XW_0, 0, "vblendvps", "Vx,Hx,Wx,Lx"),
    VO(0x4B, XW_0, 0, "vblendvpd", "Vx,Hx,Wx,Lx"),
    VO(0x4C, XW_0, 0, "vpblendvb", "Vx,Hx,Wx,Lx"),
    WP(0x50, 0, XB_4, XB_8, KZ | SAE, "vrangeps", "vrangepd", "Vx,Hx,Wx,Ib"),
    E0(0x51, 0, 0, KZ | SAE, "vrangess", "Vdq,Hdq,Wss,Ib"),
    E1(0x51, 0, 0, KZ | SAE, "vrangesd", "Vdq,Hdq,Wsd,Ib"),
    WP(0x54, 0, XB_4, XB_8, KZ | SAE, "vfixupimmps", "vfixupimmpd", "Vx,Hx,Wx,Ib"),
    E0(0x55, 0, 0, KZ | SAE, "vfixupimmss", "Vdq,Hdq,Wss,Ib"),
    E1(0x55, 0, 0, KZ | SAE, "vfixupimmsd", "Vdq,Hdq,Wsd,Ib"),
    WP(0x56, 0, XB_4, XB_8, KZ | SAE, "vreduceps", "vreducepd", "Vx,Wx,Ib"),
    E0(0x57, 0, 0, KZ | SAE, "vreducess", "Vdq,Hdq,Wss,Ib"),
    E1(0x57, 0, 0, KZ | SAE, "vreducesd", "Vdq,Hdq,Wsd,Ib"),
    LV(0x60, XL_128, "pcmpestrm", "Vdq,Wdq,Ib"),
    LV(0x61, XL_128, "pcmpestri", "Vdq,Wdq,Ib"),
    LV(0x62, XL_128, "pcmpistrm", "Vdq,Wdq,Ib"),
    LV(0x63, XL_128, "pcmpistri", "Vdq,Wdq,Ib"),
    WP(0x66, 0, XB_4, XB_8, K, "vfpclassps", "vfpclasspd", "K,Wx,Ib"),
    E0(0x67, 0, 0, K, "vfpclassss", "K,Wss,Ib"),
    E1(0x67, 0, 0, K, "vfpclasssd", "K,Wsd,Ib"),
    E1(0x70, 0, 0, KZ, "vpshldw", "Vx,Hx,Wx,Ib"),
    WP(0x71, 0, XB_4, XB_8, KZ, "vpshldd", "vpshldq", "Vx,Hx,Wx,Ib"),
    E1(0x72, 0, 0, KZ, "vpshrdw", "Vx,Hx,Wx,Ib"),
    WP(0x73, 0, XB_4, XB_8, KZ, "vpshrdd", "vpshrdq", "Vx,Hx,Wx,Ib"),
    V(0xCC, XS_L, NP, XW_ANY, 0, 0, 0, "sha1rnds4", "Vdq,Wdq,Ib"),
    V(0xCE, XS_L, P66, XW_ANY, 0, 0, 0, "gf2p8affineqb", "Vx,Hx,Wx,Ib"),
    V(0xCE, XS_VE, P66, XW_1, 0, XB_8 | XE_W1, KZ, "vgf2p8affineqb", "Vx,Hx,Wx,Ib"),
    V(0xCF, XS_L, P66, XW_ANY, 0, 0, 0, "gf2p8affineinvqb", "Vx,Hx,Wx,Ib"),
    V(0xCF, XS_VE, P66, XW_1, 0, XB_8 | XE_W1, KZ, "vgf2p8affineinvqb", "Vx,Hx,Wx,Ib"),
    LV(0xDF, XL_128, "aeskeygenassist", "Vdq,Wdq,Ib"),
    XR(0xF0, XS_V, PF2, ANY, X_ANY, X_ANY, XW_ANY, 0, XL_128, 0, 0, "rorx", "Gy,Ey,Ib"),
};

const x64_ftab_t x64_tab3a = {3, kRows, sizeof(kRows) / sizeof(kRows[0])};
