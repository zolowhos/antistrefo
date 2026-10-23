// re_x64_t38.c - the 0F38 map: SSSE3, SSE4, AES, SHA, AVX2, FMA, BMI and their EVEX forms.
// Module: feature (C11).
// Owns: every 0F38 form whose EVEX encoding, where it has one, keeps the VEX name.
// Depends: re_x64_form.h. A table sorted by opcode; first hit wins. EVEX forms with a
// name or operand list of their own are in re_x64_t38e.c, consulted first.
#include "features/disasm/fmt/re_x64_form.h"

#define KZ XF_KZ
#define ER XF_ER
#define SAE XF_SAE
#define NP XP_NP
#define P66 XP_66
#define PF3 XP_F3
#define PF2 XP_F2
#define ANY XM_ANY
#define MEM XM_MEM
#define REG XM_REG

#define V(op, sp, pfx, mod, w, l, bc, fl, mn, ops) \
    XR(op, sp, pfx, mod, X_ANY, X_ANY, w, 0, l, bc, fl, mn, ops)
// The MMX form and the 0x66 vector form of one SSSE3 opcode.
#define S3(op, sp, bc, fl, mn, ops)                     \
    V(op, XS_L, NP, ANY, XW_ANY, 0, 0, 0, mn, "Pq,Qq"), \
        V(op, sp, P66, ANY, XW_ANY, 0, bc, fl, mn, ops)
// A 0x66 row in all three spaces, and in the legacy and VEX spaces only.
#define P(op, bc, fl, mn, ops) V(op, XS_LVE, P66, ANY, XW_ANY, 0, bc, fl, mn, ops)
#define PLV(op, mn, ops) V(op, XS_LV, P66, ANY, XW_ANY, 0, 0, 0, mn, ops)
// A VEX and EVEX row under 0x66 with its W bit.
#define VE(op, w, bc, fl, mn, ops) V(op, XS_VE, P66, ANY, w, 0, bc, fl, mn, ops)
#define VO(op, w, l, mn, ops) V(op, XS_V, P66, ANY, w, l, 0, 0, mn, ops)
// The packed single and packed double forms of one FMA opcode, and the scalar ones.
#define FMP(op, mn)                                   \
    VE(op, XW_0, XB_4, KZ | ER, mn "ps", "Vx,Hx,Wx"), \
        VE(op, XW_1, XB_8, KZ | ER, mn "pd", "Vx,Hx,Wx")
#define FMS(op, mn)                                   \
    VE(op, XW_0, 0, KZ | ER, mn "ss", "Vdq,Hdq,Wss"), \
        VE(op, XW_1, 0, KZ | ER, mn "sd", "Vdq,Hdq,Wsd")
// A BMI row: VEX, one prefix, a general register operand list.
#define BMI(op, pfx, mn, ops) V(op, XS_V, pfx, ANY, XW_ANY, XL_128, 0, 0, mn, ops)

static const x64_form_t kRows[] = {
    S3(0x00, XS_LVE, 0, KZ, "pshufb", "Vx,Hx,Wx"),
    S3(0x01, XS_LV, 0, 0, "phaddw", "Vx,Hx,Wx"),
    S3(0x02, XS_LV, 0, 0, "phaddd", "Vx,Hx,Wx"),
    S3(0x03, XS_LV, 0, 0, "phaddsw", "Vx,Hx,Wx"),
    S3(0x04, XS_LVE, 0, KZ, "pmaddubsw", "Vx,Hx,Wx"),
    S3(0x05, XS_LV, 0, 0, "phsubw", "Vx,Hx,Wx"),
    S3(0x06, XS_LV, 0, 0, "phsubd", "Vx,Hx,Wx"),
    S3(0x07, XS_LV, 0, 0, "phsubsw", "Vx,Hx,Wx"),
    S3(0x08, XS_LV, 0, 0, "psignb", "Vx,Hx,Wx"),
    S3(0x09, XS_LV, 0, 0, "psignw", "Vx,Hx,Wx"),
    S3(0x0A, XS_LV, 0, 0, "psignd", "Vx,Hx,Wx"),
    S3(0x0B, XS_LVE, 0, KZ, "pmulhrsw", "Vx,Hx,Wx"),
    VE(0x0C, XW_0, XB_4, KZ, "vpermilps", "Vx,Hx,Wx"),
    VO(0x0D, XW_0, 0, "vpermilpd", "Vx,Hx,Wx"),
    VO(0x0E, XW_0, 0, "vtestps", "Vx,Wx"),
    VO(0x0F, XW_0, 0, "vtestpd", "Vx,Wx"),
    V(0x10, XS_L, P66, ANY, XW_ANY, 0, 0, 0, "pblendvb", "Vdq,Wdq,XMM0"),
    VE(0x13, XW_0, 0, KZ | SAE, "vcvtph2ps", "Vx,Wh"),
    V(0x14, XS_L, P66, ANY, XW_ANY, 0, 0, 0, "blendvps", "Vdq,Wdq,XMM0"),
    V(0x15, XS_L, P66, ANY, XW_ANY, 0, 0, 0, "blendvpd", "Vdq,Wdq,XMM0"),
    VO(0x16, XW_0, XL_256, "vpermps", "Vqq,Hqq,Wqq"),
    PLV(0x17, "ptest", "Vx,Wx"),
    V(0x18, XS_VE, P66, ANY, XW_0, 0, 0, KZ, "vbroadcastss", "Vx,Wss"),
    VO(0x19, XW_0, XL_256, "vbroadcastsd", "Vqq,Wsd"),
    V(0x1A, XS_V, P66, MEM, XW_0, XL_256, 0, 0, "vbroadcastf128", "Vqq,Mdq"),
    S3(0x1C, XS_LVE, 0, KZ, "pabsb", "Vx,Wx"),
    S3(0x1D, XS_LVE, 0, KZ, "pabsw", "Vx,Wx"),
    S3(0x1E, XS_LVE, XB_4 | XE_W0, KZ, "pabsd", "Vx,Wx"),
    P(0x20, 0, KZ, "pmovsxbw", "Vx,Wh"),
    P(0x21, 0, KZ, "pmovsxbd", "Vx,Wr"),
    P(0x22, 0, KZ, "pmovsxbq", "Vx,We"),
    P(0x23, 0, KZ, "pmovsxwd", "Vx,Wh"),
    P(0x24, 0, KZ, "pmovsxwq", "Vx,Wr"),
    P(0x25, XE_W0, KZ, "pmovsxdq", "Vx,Wh"),
    P(0x28, XB_8 | XE_W1, KZ, "pmuldq", "Vx,Hx,Wx"),
    PLV(0x29, "pcmpeqq", "Vx,Hx,Wx"),
    V(0x2A, XS_LVE, P66, MEM, XW_ANY, 0, XE_W0, 0, "movntdqa", "Vx,Mx"),
    P(0x2B, XB_4 | XE_W0, KZ, "packusdw", "Vx,Hx,Wx"),
    V(0x2C, XS_V, P66, MEM, XW_0, 0, 0, 0, "vmaskmovps", "Vx,Hx,Mx"),
    V(0x2D, XS_V, P66, MEM, XW_0, 0, 0, 0, "vmaskmovpd", "Vx,Hx,Mx"),
    V(0x2E, XS_V, P66, MEM, XW_0, 0, 0, 0, "vmaskmovps", "Mx,Hx,Vx"),
    V(0x2F, XS_V, P66, MEM, XW_0, 0, 0, 0, "vmaskmovpd", "Mx,Hx,Vx"),
    P(0x30, 0, KZ, "pmovzxbw", "Vx,Wh"),
    P(0x31, 0, KZ, "pmovzxbd", "Vx,Wr"),
    P(0x32, 0, KZ, "pmovzxbq", "Vx,We"),
    P(0x33, 0, KZ, "pmovzxwd", "Vx,Wh"),
    P(0x34, 0, KZ, "pmovzxwq", "Vx,Wr"),
    P(0x35, XE_W0, KZ, "pmovzxdq", "Vx,Wh"),
    VO(0x36, XW_0, XL_256, "vpermd", "Vqq,Hqq,Wqq"),
    PLV(0x37, "pcmpgtq", "Vx,Hx,Wx"),
    P(0x38, 0, KZ, "pminsb", "Vx,Hx,Wx"),
    P(0x39, XB_4 | XE_W0, KZ, "pminsd", "Vx,Hx,Wx"),
    P(0x3A, 0, KZ, "pminuw", "Vx,Hx,Wx"),
    P(0x3B, XB_4 | XE_W0, KZ, "pminud", "Vx,Hx,Wx"),
    P(0x3C, 0, KZ, "pmaxsb", "Vx,Hx,Wx"),
    P(0x3D, XB_4 | XE_W0, KZ, "pmaxsd", "Vx,Hx,Wx"),
    P(0x3E, 0, KZ, "pmaxuw", "Vx,Hx,Wx"),
    P(0x3F, XB_4 | XE_W0, KZ, "pmaxud", "Vx,Hx,Wx"),
    P(0x40, XB_4 | XE_W0, KZ, "pmulld", "Vx,Hx,Wx"),
    V(0x41, XS_LV, P66, ANY, XW_ANY, XL_128, 0, 0, "phminposuw", "Vdq,Wdq"),
    VE(0x45, XW_0, XB_4, KZ, "vpsrlvd", "Vx,Hx,Wx"),
    VE(0x45, XW_1, XB_8, KZ, "vpsrlvq", "Vx,Hx,Wx"),
    VE(0x46, XW_0, XB_4, KZ, "vpsravd", "Vx,Hx,Wx"),
    VE(0x47, XW_0, XB_4, KZ, "vpsllvd", "Vx,Hx,Wx"),
    VE(0x47, XW_1, XB_8, KZ, "vpsllvq", "Vx,Hx,Wx"),
    VE(0x50, XW_0, XB_4, KZ, "vpdpbusd", "Vx,Hx,Wx"),
    V(0x50, XS_V, NP, ANY, XW_0, 0, 0, 0, "vpdpbuud", "Vx,Hx,Wx"),
    V(0x50, XS_V, PF3, ANY, XW_0, 0, 0, 0, "vpdpbsud", "Vx,Hx,Wx"),
    V(0x50, XS_V, PF2, ANY, XW_0, 0, 0, 0, "vpdpbssd", "Vx,Hx,Wx"),
    VE(0x51, XW_0, XB_4, KZ, "vpdpbusds", "Vx,Hx,Wx"),
    V(0x51, XS_V, NP, ANY, XW_0, 0, 0, 0, "vpdpbuuds", "Vx,Hx,Wx"),
    V(0x51, XS_V, PF3, ANY, XW_0, 0, 0, 0, "vpdpbsuds", "Vx,Hx,Wx"),
    V(0x51, XS_V, PF2, ANY, XW_0, 0, 0, 0, "vpdpbssds", "Vx,Hx,Wx"),
    VE(0x52, XW_0, XB_4, KZ, "vpdpwssd", "Vx,Hx,Wx"),
    VE(0x53, XW_0, XB_4, KZ, "vpdpwssds", "Vx,Hx,Wx"),
    VE(0x58, XW_0, 0, KZ, "vpbroadcastd", "Vx,Wd"),
    VO(0x59, XW_0, 0, "vpbroadcastq", "Vx,Wq"),
    V(0x5A, XS_V, P66, MEM, XW_0, XL_256, 0, 0, "vbroadcasti128", "Vqq,Mdq"),
    VE(0x78, XW_0, 0, KZ, "vpbroadcastb", "Vx,Wb"),
    VE(0x79, XW_0, 0, KZ, "vpbroadcastw", "Vx,Ww"),
    V(0x80, XS_L, P66, MEM, XW_ANY, 0, 0, 0, "invept", "Gq,Mdq"),
    V(0x81, XS_L, P66, MEM, XW_ANY, 0, 0, 0, "invvpid", "Gq,Mdq"),
    V(0x82, XS_L, P66, MEM, XW_ANY, 0, 0, 0, "invpcid", "Gq,Mdq"),
    V(0x8C, XS_V, P66, MEM, XW_0, 0, 0, 0, "vpmaskmovd", "Vx,Hx,Mx"),
    V(0x8C, XS_V, P66, MEM, XW_1, 0, 0, 0, "vpmaskmovq", "Vx,Hx,Mx"),
    V(0x8E, XS_V, P66, MEM, XW_0, 0, 0, 0, "vpmaskmovd", "Mx,Hx,Vx"),
    V(0x8E, XS_V, P66, MEM, XW_1, 0, 0, 0, "vpmaskmovq", "Mx,Hx,Vx"),
    V(0x90, XS_V, P66, MEM, XW_0, 0, 0, 0, "vpgatherdd", "Vx,Xdx,Hx"),
    V(0x90, XS_V, P66, MEM, XW_1, 0, 0, 0, "vpgatherdq", "Vx,Xqh,Hx"),
    V(0x91, XS_V, P66, MEM, XW_0, 0, 0, 0, "vpgatherqd", "Vh,Xdx,Hh"),
    V(0x91, XS_V, P66, MEM, XW_1, 0, 0, 0, "vpgatherqq", "Vx,Xqx,Hx"),
    V(0x92, XS_V, P66, MEM, XW_0, 0, 0, 0, "vgatherdps", "Vx,Xdx,Hx"),
    V(0x92, XS_V, P66, MEM, XW_1, 0, 0, 0, "vgatherdpd", "Vx,Xqh,Hx"),
    V(0x93, XS_V, P66, MEM, XW_0, 0, 0, 0, "vgatherqps", "Vh,Xdx,Hh"),
    V(0x93, XS_V, P66, MEM, XW_1, 0, 0, 0, "vgatherqpd", "Vx,Xqx,Hx"),
    FMP(0x96, "vfmaddsub132"),
    FMP(0x97, "vfmsubadd132"),
    FMP(0x98, "vfmadd132"),
    FMS(0x99, "vfmadd132"),
    FMP(0x9A, "vfmsub132"),
    FMS(0x9B, "vfmsub132"),
    FMP(0x9C, "vfnmadd132"),
    FMS(0x9D, "vfnmadd132"),
    FMP(0x9E, "vfnmsub132"),
    FMS(0x9F, "vfnmsub132"),
    FMP(0xA6, "vfmaddsub213"),
    FMP(0xA7, "vfmsubadd213"),
    FMP(0xA8, "vfmadd213"),
    FMS(0xA9, "vfmadd213"),
    FMP(0xAA, "vfmsub213"),
    FMS(0xAB, "vfmsub213"),
    FMP(0xAC, "vfnmadd213"),
    FMS(0xAD, "vfnmadd213"),
    FMP(0xAE, "vfnmsub213"),
    FMS(0xAF, "vfnmsub213"),
    VE(0xB4, XW_1, XB_8, KZ, "vpmadd52luq", "Vx,Hx,Wx"),
    VE(0xB5, XW_1, XB_8, KZ, "vpmadd52huq", "Vx,Hx,Wx"),
    FMP(0xB6, "vfmaddsub231"),
    FMP(0xB7, "vfmsubadd231"),
    FMP(0xB8, "vfmadd231"),
    FMS(0xB9, "vfmadd231"),
    FMP(0xBA, "vfmsub231"),
    FMS(0xBB, "vfmsub231"),
    FMP(0xBC, "vfnmadd231"),
    FMS(0xBD, "vfnmadd231"),
    FMP(0xBE, "vfnmsub231"),
    FMS(0xBF, "vfnmsub231"),
    V(0xC8, XS_L, NP, ANY, XW_ANY, 0, 0, 0, "sha1nexte", "Vdq,Wdq"),
    V(0xC9, XS_L, NP, ANY, XW_ANY, 0, 0, 0, "sha1msg1", "Vdq,Wdq"),
    V(0xCA, XS_L, NP, ANY, XW_ANY, 0, 0, 0, "sha1msg2", "Vdq,Wdq"),
    V(0xCB, XS_L, NP, ANY, XW_ANY, 0, 0, 0, "sha256rnds2", "Vdq,Wdq,XMM0"),
    V(0xCC, XS_L, NP, ANY, XW_ANY, 0, 0, 0, "sha256msg1", "Vdq,Wdq"),
    V(0xCD, XS_L, NP, ANY, XW_ANY, 0, 0, 0, "sha256msg2", "Vdq,Wdq"),
    V(0xCF, XS_L, P66, ANY, XW_ANY, 0, 0, 0, "gf2p8mulb", "Vx,Hx,Wx"),
    V(0xCF, XS_VE, P66, ANY, XW_0, 0, XE_W0, KZ, "vgf2p8mulb", "Vx,Hx,Wx"),
    XR(0xD8, XS_L, PF3, MEM, 0, X_ANY, XW_ANY, 0, 0, 0, 0, "aesencwide128kl", "Mm"),
    XR(0xD8, XS_L, PF3, MEM, 1, X_ANY, XW_ANY, 0, 0, 0, 0, "aesdecwide128kl", "Mm"),
    XR(0xD8, XS_L, PF3, MEM, 2, X_ANY, XW_ANY, 0, 0, 0, 0, "aesencwide256kl", "Mm"),
    XR(0xD8, XS_L, PF3, MEM, 3, X_ANY, XW_ANY, 0, 0, 0, 0, "aesdecwide256kl", "Mm"),
    V(0xDB, XS_LV, P66, ANY, XW_ANY, XL_128, 0, 0, "aesimc", "Vdq,Wdq"),
    P(0xDC, 0, 0, "aesenc", "Vx,Hx,Wx"),
    V(0xDC, XS_L, PF3, REG, XW_ANY, 0, 0, 0, "loadiwkey", "Vdq,Udq"),
    V(0xDC, XS_L, PF3, MEM, XW_ANY, 0, 0, 0, "aesenc128kl", "Vdq,Mm"),
    P(0xDD, 0, 0, "aesenclast", "Vx,Hx,Wx"),
    V(0xDD, XS_L, PF3, MEM, XW_ANY, 0, 0, 0, "aesdec128kl", "Vdq,Mm"),
    P(0xDE, 0, 0, "aesdec", "Vx,Hx,Wx"),
    V(0xDE, XS_L, PF3, MEM, XW_ANY, 0, 0, 0, "aesenc256kl", "Vdq,Mzm"),
    P(0xDF, 0, 0, "aesdeclast", "Vx,Hx,Wx"),
    V(0xDF, XS_L, PF3, MEM, XW_ANY, 0, 0, 0, "aesdec256kl", "Vdq,Mzm"),
    V(0xF0, XS_L, NP | P66, MEM, XW_ANY, 0, 0, 0, "movbe", "Gv,Mv"),
    V(0xF0, XS_L, PF2, ANY, XW_ANY, 0, 0, 0, "crc32", "Gy,Eb"),
    V(0xF1, XS_L, NP | P66, MEM, XW_ANY, 0, 0, 0, "movbe", "Mv,Gv"),
    V(0xF1, XS_L, PF2, ANY, XW_ANY, 0, 0, 0, "crc32", "Gy,Ev"),
    BMI(0xF2, NP, "andn", "Gy,By,Ey"),
    XR(0xF3, XS_V, NP, XM_ANY, 1, X_ANY, XW_ANY, 0, XL_128, 0, 0, "blsr", "By,Ey"),
    XR(0xF3, XS_V, NP, XM_ANY, 2, X_ANY, XW_ANY, 0, XL_128, 0, 0, "blsmsk", "By,Ey"),
    XR(0xF3, XS_V, NP, XM_ANY, 3, X_ANY, XW_ANY, 0, XL_128, 0, 0, "blsi", "By,Ey"),
    BMI(0xF5, NP, "bzhi", "Gy,Ey,By"),
    BMI(0xF5, PF3, "pext", "Gy,By,Ey"),
    BMI(0xF5, PF2, "pdep", "Gy,By,Ey"),
    V(0xF5, XS_L, P66, MEM, XW_0, 0, 0, 0, "wrussd", "Md,Gd"),
    V(0xF5, XS_L, P66, MEM, XW_1, 0, 0, 0, "wrussq", "Mq,Gq"),
    V(0xF6, XS_L, P66, ANY, XW_ANY, 0, 0, 0, "adcx", "Gy,Ey"),
    V(0xF6, XS_L, PF3, ANY, XW_ANY, 0, 0, 0, "adox", "Gy,Ey"),
    V(0xF6, XS_L, NP, MEM, XW_0, 0, 0, 0, "wrssd", "Md,Gd"),
    V(0xF6, XS_L, NP, MEM, XW_1, 0, 0, 0, "wrssq", "Mq,Gq"),
    BMI(0xF6, PF2, "mulx", "Gy,By,Ey"),
    BMI(0xF7, NP, "bextr", "Gy,Ey,By"),
    BMI(0xF7, P66, "shlx", "Gy,Ey,By"),
    BMI(0xF7, PF3, "sarx", "Gy,Ey,By"),
    BMI(0xF7, PF2, "shrx", "Gy,Ey,By"),
    V(0xF8, XS_L, P66, MEM, XW_ANY, 0, 0, 0, "movdir64b", "Ga,Mzm"),
    V(0xF8, XS_L, PF3, MEM, XW_ANY, 0, 0, 0, "enqcmds", "Ga,Mzm"),
    V(0xF8, XS_L, PF2, MEM, XW_ANY, 0, 0, 0, "enqcmd", "Ga,Mzm"),
    V(0xF9, XS_L, NP, MEM, XW_ANY, 0, 0, 0, "movdiri", "My,Gy"),
    V(0xFA, XS_L, PF3, REG, XW_ANY, 0, 0, 0, "encodekey128", "Gd,Rd"),
    V(0xFB, XS_L, PF3, REG, XW_ANY, 0, 0, 0, "encodekey256", "Gd,Rd"),
};

const x64_ftab_t x64_tab38 = {2, kRows, sizeof(kRows) / sizeof(kRows[0])};
