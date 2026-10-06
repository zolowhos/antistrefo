// re_dc_indirect.c - names an indirect call from the one def that reaches it.
// Module: feature (C11).
// Owns: the lea match and the unresolved slot spelling.
// Depends: re_dc_indirect.h. A second def is not a target.
#include "features/indirect/re_dc_indirect.h"

static const char *reg_name(unsigned r) {
    static const char *const k[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                      "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};
    return r < 16 ? k[r] : "reg";
}

static size_t put(char *dst, size_t cap, size_t n, const char *s) {
    size_t i = 0;
    while (s[i] && n + 1 < cap) {
        dst[n++] = s[i++];
    }
    if (n < cap)
        dst[n] = 0;
    return n;
}

static size_t put_hex(char *dst, size_t cap, size_t n, uint64_t v) {
    char rev[16];
    int k = 0;
    const char *d = "0123456789abcdef";
    if (!v)
        return put(dst, cap, n, "0");
    while (v && k < 16) {
        rev[k++] = d[v & 15u];
        v >>= 4;
    }
    while (k && n + 1 < cap)
        dst[n++] = rev[--k];
    if (n < cap)
        dst[n] = 0;
    return n;
}

static bool one_lea(const re_code_t *c, uint64_t call_va, unsigned reg, uint64_t *target) {
    uint64_t va = call_va > 0x40 ? call_va - 0x40 : 0;
    unsigned defs = 0;
    uint64_t found = 0;
    while (va < call_va) {
        re_insn_t in;
        if (!re_code_insn(c, va, &in) || in.size == 0) {
            va++;
            continue;
        }
        if (RE_INSN_OPCODE(&in) == 0x8D && in.reg == reg) {
            defs++;
            if (in.has_target)
                found = in.target;
            else if (in.is_mem && in.base >= 16)
                found = va + in.size + (uint64_t)in.disp;
        }
        va += in.size;
    }
    if (defs != 1 || !found)
        return false;
    *target = found;
    return true;
}

bool re_dc_indirect_format(const re_code_t *c, uint64_t call_va, char *dst, size_t cap) {
    re_insn_t in;
    uint64_t target = 0;
    size_t n = 0;
    if (!c || !dst || cap == 0 || !re_code_insn(c, call_va, &in) || !in.is_call || in.has_target)
        return false;
    if (!in.is_mem && one_lea(c, call_va, in.rm, &target)) {
        n = put(dst, cap, 0, "sub_");
        n = put_hex(dst, cap, n, target);
        put(dst, cap, n, "()");
        return true;
    }
    if (in.is_mem) {
        n = put(dst, cap, 0, "(*slot_0x");
        n = put_hex(dst, cap, n, (uint64_t)in.disp);
        n = put(dst, cap, n, ")(");
        n = put(dst, cap, n, reg_name(in.base));
        put(dst, cap, n, ")");
        return true;
    }
    return false;
}

bool re_dc_indirect_slot(const re_code_t *c, uint64_t call_va, const char *table, char *dst,
                         size_t cap) {
    re_insn_t in;
    size_t n = 0;
    if (!table || !table[0])
        return re_dc_indirect_format(c, call_va, dst, cap);
    if (!c || !dst || !re_code_insn(c, call_va, &in) || !in.is_call || !in.is_mem)
        return false;
    n = put(dst, cap, 0, table);
    n = put(dst, cap, n, "::slot");
    n = put_hex(dst, cap, n, (uint64_t)in.disp / 8u);
    n = put(dst, cap, n, "(");
    n = put(dst, cap, n, reg_name(in.base));
    put(dst, cap, n, ")");
    return true;
}
