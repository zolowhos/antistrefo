// re_dc_ptab.h - the shape of the import prototype tables.
// Module: feature (C11).
// Owns: one row per import: its name, argument count and result kind.
// Depends: stddef, stdint. The rows are data; re_dc_proto searches them.
#pragma once

#include <stddef.h>
#include <stdint.h>

// ret: 'v' returns nothing, 'i' a signed 32 bit value (BOOL, int, LONG, NTSTATUS),
// 'u' an unsigned 32 bit value (DWORD, UINT), 'p' a 64 bit value (a pointer, a
// HANDLE, a SIZE_T).
typedef struct {
    const char *name;
    uint8_t nargs;
    char ret;
} re_dc_pent_t;

typedef struct {
    const re_dc_pent_t *rows; // sorted by byte order
    size_t n;
} re_dc_ptab_t;

extern const re_dc_ptab_t re_dc_ptab_k32;
extern const re_dc_ptab_t re_dc_ptab_crt;
extern const re_dc_ptab_t re_dc_ptab_nt;
extern const re_dc_ptab_t re_dc_ptab_win;
