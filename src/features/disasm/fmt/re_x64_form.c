// re_x64_form.c - the form lookup the decoder and the renderer share.
// Module: feature (C11).
// Owns: the table registry, the constraint match, the 3DNow selector names.
// Depends: re_x64_form.h and the tables. Pure functions over const data.
#include "features/disasm/fmt/re_x64_form.h"

// The registry, in priority order: within one map the first table holding a matching
// row wins, so the EVEX-only rows are consulted before the shared vector rows they
// refine, and x87 sits beside the one byte map whose escapes it names.
static const x64_ftab_t *const kTabs[] = {
    &x64_tab0,  &x64_tab87,  &x64_tab1e, &x64_tab1,  &x64_tab1s,
    &x64_tab1v, &x64_tab38e, &x64_tab38, &x64_tab3a,
};

unsigned x64_vlen(const x64_insn_t *in) {
    if (!in->vex)
        return 16u;
    if (!in->evex)
        return in->vex_l ? 32u : 16u;
    if (in->ev_b && in->mod == 3u)
        return 64u;
    return in->ev_ll >= 2u ? 64u : (in->ev_ll ? 32u : 16u);
}

static bool form_match(const x64_form_t *f, const x64_insn_t *in, unsigned enc, unsigned lbit) {
    unsigned reg = (in->modrm >> 3) & 7u;
    if (!(f->sp & enc) || !(f->pfx & (1u << in->pfx)))
        return false;
    if (f->mod == XM_MEM && (!in->has_modrm || in->mod == 3u))
        return false;
    if (f->mod == XM_REG && (!in->has_modrm || in->mod != 3u))
        return false;
    if (f->reg != X_ANY && reg != f->reg)
        return false;
    if (f->rm != X_ANY && (in->modrm & 7u) != f->rm)
        return false;
    if (f->w != XW_ANY && x64_wbit(in) != f->w)
        return false;
    if (f->osz && in->opsize != f->osz)
        return false;
    if (in->evex && (f->bc & (XE_W0 | XE_W1)) && in->vex_w != ((f->bc & XE_W1) != 0))
        return false;
    return !(f->l && in->vex && !(f->l & lbit));
}

// The first row of a table at or after op, by binary search: the tables are sorted.
static size_t lower_bound(const x64_form_t *t, size_t n, uint8_t op) {
    size_t lo = 0;
    size_t hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        if (t[mid].op < op)
            lo = mid + 1u;
        else
            hi = mid;
    }
    return lo;
}

const x64_form_t *x64_form_find(const x64_insn_t *in) {
    unsigned enc = in->evex ? XS_E : (in->vex ? XS_V : XS_L);
    unsigned lbit = x64_vlen(in) == 64u ? XL_512 : (x64_vlen(in) == 32u ? XL_256 : XL_128);
    for (size_t k = 0; k < sizeof(kTabs) / sizeof(kTabs[0]); k++) {
        const x64_form_t *t = kTabs[k]->rows;
        size_t n = kTabs[k]->n;
        size_t j;
        if (kTabs[k]->map != in->map)
            continue;
        for (j = lower_bound(t, n, in->opcode); j < n && t[j].op == in->opcode; j++)
            if (form_match(&t[j], in, enc, lbit))
                return &t[j];
    }
    return NULL;
}

// The 3DNow operations, named by the byte after the operand rather than the opcode.
static const struct {
    uint8_t sel;
    const char *name;
} k3dnow[] = {
    {0x0C, "pi2fw"},    {0x0D, "pi2fd"},   {0x1C, "pf2iw"},   {0x1D, "pf2id"},   {0x8A, "pfnacc"},
    {0x8E, "pfpnacc"},  {0x90, "pfcmpge"}, {0x94, "pfmin"},   {0x96, "pfrcp"},   {0x97, "pfrsqrt"},
    {0x9A, "pfsub"},    {0x9E, "pfadd"},   {0xA0, "pfcmpgt"}, {0xA4, "pfmax"},   {0xA6, "pfrcpit1"},
    {0xA7, "pfrsqit1"}, {0xAA, "pfsubr"},  {0xAE, "pfacc"},   {0xB0, "pfcmpeq"}, {0xB4, "pfmul"},
    {0xB6, "pfrcpit2"}, {0xB7, "pmulhrw"}, {0xBB, "pswapd"},  {0xBF, "pavgusb"},
};

const char *x64_3dnow_name(uint8_t sel) {
    for (size_t k = 0; k < sizeof(k3dnow) / sizeof(k3dnow[0]); k++)
        if (k3dnow[k].sel == sel)
            return k3dnow[k].name;
    return NULL;
}
