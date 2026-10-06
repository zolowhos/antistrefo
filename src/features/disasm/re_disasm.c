// re_disasm.c - the architecture registry. Callers name an arch, they never link one.
// Module: feature (C11).
// Owns: the table of backends, the lookup by name, and the RE_ENABLE_DISASM gate.
// Depends: re_disasm.h. A parse-only build resolves every lookup to NULL.
#include "features/meta/re_disasm.h"

#include <stddef.h>

#include "features/disasm/re_x64_priv.h"

// The one backend that exists in task 3. x86-32 and ARM-64 slots are absent on
// purpose: rules 8.1 fixes the order at x86-64 then ARM-64, and an entry that
// decodes nothing is worse than an entry that is not there.
static const re_disasm_t *const kBackends[] = {
#ifdef RE_ENABLE_DISASM
    &re_disasm_x64,
    &re_disasm_x86,
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
