// re_dataobf.c - names what the compiler hid: hashed APIs, dynamic imports, strings.
// Module: feature (C11).
// Owns: re_deep_data and the hash functions and the constant scan it uses.
// Depends: re_deep_priv.h, re_ireval, re_crc. A name is recorded only on one match.
#include "features/analysis/re_deep_priv.h"

#include "features/flow/re_ireval.h"
#include "utils/algo/re_crc.h"

#define RE_HASH_NAMES 48u

// The exports a packed program resolves by hash often enough that matching against
// them recovers the call. The image's own imports are added to the same list.
static const char *const kApi[] = {
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "GetModuleHandleA",
    "GetModuleHandleW",
    "VirtualAlloc",
    "VirtualProtect",
    "VirtualFree",
    "CreateThread",
    "CreateFileA",
    "CreateFileW",
    "ReadFile",
    "WriteFile",
    "CloseHandle",
    "GetTickCount",
    "Sleep",
    "WinExec",
    "ShellExecuteA",
    "URLDownloadToFileA",
    "InternetOpenA",
    "HttpSendRequestA",
    "RegOpenKeyExA",
    "RegSetValueExA",
    "CreateProcessA",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "LdrLoadDll",
    "LdrGetProcedureAddress",
};

static uint32_t ror13(const char *s) {
    uint32_t h = 0;
    for (size_t i = 0; s[i]; i++) {
        h = (h >> 13) | (h << 19);
        h += (uint8_t)s[i];
    }
    return h;
}

static uint32_t djb2(const char *s) {
    uint32_t h = 5381u;
    for (size_t i = 0; s[i]; i++)
        h = h * 33u + (uint8_t)s[i];
    return h;
}

static uint32_t fnv1a(const char *s) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; s[i]; i++) {
        h ^= (uint8_t)s[i];
        h *= 16777619u;
    }
    return h;
}

typedef struct {
    const char *name;
    uint32_t h[4]; // ror13, djb2, fnv1a, crc32
} hashed_t;

static void build_table(const re_analysis_t *an, hashed_t *t, size_t *n, re_arena_t *a) {
    *n = 0;
    for (size_t i = 0; i < sizeof(kApi) / sizeof(kApi[0]) && *n < RE_HASH_NAMES; i++) {
        t[*n].name = kApi[i];
        (*n)++;
    }
    for (size_t i = 0; i < RE_VEC_LEN(&an->pe.syms) && *n < RE_HASH_NAMES; i++) {
        re_str_t s = RE_VEC_AT(&an->pe.syms, re_str_t, i);
        char *copy = re_arena_strndup(a, s.p, s.n);
        if (copy) {
            t[*n].name = copy;
            (*n)++;
        }
    }
    re_crc_init();
    for (size_t i = 0; i < *n; i++) {
        t[i].h[0] = ror13(t[i].name);
        t[i].h[1] = djb2(t[i].name);
        t[i].h[2] = fnv1a(t[i].name);
        t[i].h[3] = re_crc32_ieee_final(t[i].name, re_str(t[i].name).n);
    }
}

// The one name every scheme hashes k to, or NULL when the schemes disagree, which is
// reported as no match rather than as a guess.
static const char *match_hash(const hashed_t *t, size_t n, uint32_t k) {
    const char *found = NULL;
    if (k < 0x10000u)
        return NULL; // a small constant collides with everything
    for (size_t i = 0; i < n; i++) {
        for (int s = 0; s < 4; s++) {
            if (t[i].h[s] != k)
                continue;
            if (found && found != t[i].name)
                return NULL;
            found = t[i].name;
        }
    }
    return found;
}

static void add_note(re_analysis_t *an, uint64_t va, uint32_t kind, const char *text) {
    re_note_t n;
    n.va = va;
    n.aux = 0;
    n.kind = kind;
    n.text = re_str(re_arena_strdup(an->arena, text));
    RE_VEC_PUSH(&an->notes, an->arena, n);
}

// Immediate operands compared or moved inside a function, which is where a hashed API
// lives. Only values that match exactly one name are recorded.
static size_t scan_hashes(re_analysis_t *an, const hashed_t *t, size_t n) {
    size_t found = 0;
    for (size_t i = 0; i < RE_VEC_LEN(&an->scan.funcs); i++) {
        const re_func_t *f = RE_VEC_PTR(&an->scan.funcs, re_func_t, i);
        uint64_t va = f->va;
        uint32_t seen = 0;
        while (va < f->va + f->size && seen < RE_FUNC_MAX_INSNS) {
            re_insn_t in;
            const char *name;
            if (!re_code_insn(&an->code, va, &in) || !in.size)
                break;
            seen++;
            name = in.imm > 0 ? match_hash(t, n, (uint32_t)in.imm) : NULL;
            if (name) {
                add_note(an, in.addr, RE_NOTE_API_HASH, name);
                found++;
            }
            va += in.size;
        }
    }
    return found;
}

size_t re_deep_data(re_analysis_t *an, re_arena_t *scratch) {
    hashed_t table[RE_HASH_NAMES];
    size_t n = 0;
    build_table(an, table, &n, scratch);
    return scan_hashes(an, table, n);
}
