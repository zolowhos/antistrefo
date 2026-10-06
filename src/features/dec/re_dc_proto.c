// re_dc_proto.c - the import names a call site is allowed to print.
// Module: feature (C11).
// Owns: the seed table for ntoskrnl, hal, FLTMGR, and kernel32.
// Depends: re_dc_proto.h. A name not listed is not a prototype.
#include "features/dec/re_dc_proto.h"

typedef struct {
    const char *name;
    uint8_t nargs;
} proto_t;

static const proto_t kProtos[] = {
    {"IoCompleteRequest", 2},
    {"ObReferenceObjectByHandle", 6},
    {"KeWaitForSingleObject", 5},
    {"FltRegisterFilter", 3},
    {"FltGetFileNameInformation", 3},
    {"ZwQuerySystemInformation", 4},
    {"CreateFileW", 7},
    {"ReadFile", 5},
    {"CloseHandle", 1},
};

static bool same(re_str_t name, const char *lit) {
    uint32_t i = 0;
    while (lit[i]) {
        if (i >= name.n || name.p[i] != lit[i])
            return false;
        i++;
    }
    return i == name.n;
}

static uint8_t count_of(re_str_t name) {
    uint32_t i;
    for (i = 0; i < sizeof(kProtos) / sizeof(kProtos[0]); i++) {
        if (same(name, kProtos[i].name))
            return kProtos[i].nargs;
    }
    return 0;
}

static void take(const char *args, uint8_t n, char *dst, size_t cap) {
    uint32_t i = 0;
    uint8_t seen = 0;
    if (!args || !n || cap == 0) {
        if (cap)
            dst[0] = 0;
        return;
    }
    while (args[i] && seen < n && i + 1 < cap) {
        if (args[i] == ',' && (i + 1 >= cap || args[i + 1] == ' ')) {
            seen++;
            if (seen == n)
                break;
        }
        dst[i] = args[i];
        i++;
    }
    dst[i] = 0;
}

bool re_dc_proto_format(re_str_t name, const char *args, char *dst, size_t cap) {
    uint8_t n;
    char taken[160];
    if (!dst || cap == 0 || !name.p || !name.n)
        return false;
    n = count_of(name);
    if (!n)
        return false;
    take(args, n, taken, sizeof(taken));
    uint32_t i = 0;
    uint32_t k = 0;
    while (i < name.n && k + 1 < cap)
        dst[k++] = name.p[i++];
    if (k + 1 < cap)
        dst[k++] = '(';
    i = 0;
    while (taken[i] && k + 1 < cap)
        dst[k++] = taken[i++];
    if (k + 1 < cap)
        dst[k++] = ')';
    dst[k] = 0;
    return true;
}
