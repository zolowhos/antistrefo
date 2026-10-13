// re_disasm.c - the architecture registry. Callers name an arch, they never link one.
// Module: feature (C11).
// Owns: the table of backends, the lookup by name, and the RE_ENABLE_DISASM gate.
// Depends: re_disasm.h. A parse-only build resolves every lookup to NULL.
#include "features/meta/re_disasm.h"

#include <stddef.h>

#include "features/disasm/re_x64_priv.h"
#ifdef RE_ENABLE_CAPSTONE
#include "features/disasm/cs/re_cs_priv.h"
#endif

// Native x86-64 / x86 first. Capstone fills ARM-64 (rules 8.1 order) when linked.
// An empty slot is worse than a missing one, so Capstone-off builds omit arm64.
static const re_disasm_t *const kBackends[] = {
#ifdef RE_ENABLE_DISASM
    &re_disasm_x64,
    &re_disasm_x86,
#ifdef RE_ENABLE_CAPSTONE
    &re_disasm_arm64,
#endif
#endif
};

size_t re_disasm_arch_count(void) {
    return sizeof(kBackends) / sizeof(kBackends[0]);
}

const char *re_disasm_arch_name(size_t index) {
    if (index >= re_disasm_arch_count())
        return NULL;
    return kBackends[index]->arch_name;
}

// NULL when the name is unknown or the build has no disassembler at all, so a
// caller reports unsupported architecture instead of dereferencing nothing.
const re_disasm_t *re_disasm_find(const char *arch_name) {
    size_t i;
    for (i = 0; i < re_disasm_arch_count(); i++) {
        if (re_str_eq_cstr(re_str(arch_name), kBackends[i]->arch_name))
            return kBackends[i];
    }
    return NULL;
}

// PE IMAGE_FILE_MACHINE to the backend name re_disasm_find expects. NULL means
// this build has no decoder for that machine, which is not the same as a decode
// failure on a supported one.
const char *re_disasm_for_machine(uint16_t pe_machine) {
    switch (pe_machine) {
        case 0x8664:
            return "x86-64";
        case 0x014c:
            return "x86";
        case 0xAA64:
            return "arm64";
        default:
            return NULL;
    }
}
