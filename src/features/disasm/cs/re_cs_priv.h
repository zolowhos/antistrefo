// re_cs_priv.h - Capstone-backed backends. Private to src/features/disasm/cs.
// Module: feature (C11).
// Owns: the ARM-64 vtable entry point reached only through re_disasm_find.
// Depends: re_disasm.h. Capstone types stay in the .c files, never here.
#pragma once

#include "features/meta/re_disasm.h"

#ifdef RE_ENABLE_CAPSTONE
extern const re_disasm_t re_disasm_arm64;
#endif
