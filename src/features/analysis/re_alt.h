// re_alt.h - user function renames persisted in a sidecar .alt mapping file.
// Module: feature (C11).
// Owns: RVA-keyed rename map, load/save of "<binary>.alt", apply onto a scan.
// Depends: re_func, re_arena, re_vec, re_str. Key is function RVA (stable id).
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/code/re_func.h"
#include "features/pe/re_pe.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_vec.h"
#include "utils/text/re_str.h"

#define RE_ALT_NAME_MAX 128u
#define RE_ALT_MAX_ENTS (1u << 20)

// One rename: the function's RVA is the stable key; the name is arena-owned text.
typedef struct {
    uint32_t rva;
    re_str_t name;
} re_alt_ent_t;

// In-memory map for one binary. Sorted by rva for binary search. Empty when no
// sidecar exists yet. Names live in arena.
typedef struct {
    re_vec_t ents; // re_alt_ent_t
    re_arena_t *arena;
} re_alt_t;

void re_alt_init(re_alt_t *m, re_arena_t *a);

// Sidecar path: append ".alt" to the binary path (foo.exe -> foo.exe.alt).
char *re_alt_sidecar(re_arena_t *a, const char *bin_path);

// Load "<bin>.alt" if present. Missing file is success with an empty map.
bool re_alt_load(re_alt_t *m, const char *bin_path);

// Write the map as line-oriented "0xRVA=name" text. Creates or replaces the file.
bool re_alt_save(const re_alt_t *m, const char *bin_path);

// Insert or replace by RVA. Empty name removes the entry. Returns false on OOM
// or when the name is rejected (empty after trim, control chars, too long).
bool re_alt_set(re_alt_t *m, uint32_t rva, re_str_t name);

// Lookup by RVA, or NULL when unset.
const re_alt_ent_t *re_alt_find(const re_alt_t *m, uint32_t rva);

// Overwrite each matching function's display name. User renames win over exports
// and signatures. Returns how many functions were renamed.
size_t re_alt_apply(re_fscan_t *scan, const re_alt_t *m);

// Resolve a target token to an RVA: hex/decimal address, or a current function
// name (including the synthetic sub_<va> form). Returns false when nothing matches.
bool re_alt_resolve(const re_fscan_t *scan, const re_pe_t *pe, re_str_t target, uint32_t *rva_out);
#ifdef __cplusplus
}
#endif
