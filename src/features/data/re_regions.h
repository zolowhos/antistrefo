// re_regions.h - what kind of thing each region of the image is, and why.
// Module: feature (C11).
// Owns: the region record, the classification rules, and the evidence counters.
// Depends: re_code, re_func, re_pe, re_xref, re_vec. Every classification carries the
//           evidence that produced it, and a region the evidence does not settle is
//           reported as unknown rather than guessed at.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/code/re_code.h"
#include "features/code/re_func.h"
#include "features/code/re_xref.h"
#include "features/pe/re_pe.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_vec.h"

// What a region is taken to be. UNKNOWN is a real answer and is expected: a
// protected binary defeats most of this evidence, and a region it cannot settle
// must say so.
typedef enum {
    RE_REG_CODE = 0, // executable and claimed by decoded functions
    RE_REG_DATA,     // writable, or written through by code
    RE_REG_RDATA,    // read only, holding strings or constants
    RE_REG_PAD,      // almost entirely filler
    RE_REG_UNKNOWN,  // the evidence did not settle it
} re_reg_kind_t;

// How much the evidence agreed. Reported as a number so a caller can filter on it
// instead of trusting every region equally.
#define RE_REG_CONF_NONE 0u
#define RE_REG_CONF_LOW 1u
#define RE_REG_CONF_MED 2u
#define RE_REG_CONF_HIGH 3u

// Hard cap on classified windows. A 200MB SizeOfImage at 4KiB is ~50k windows;
// without a cap a corrupt or sparse SizeOfImage can request millions of records.
#define RE_REGIONS_MAX 65536u

typedef struct {
    uint64_t va;
    uint32_t rva;
    uint32_t size;
    uint8_t kind;       // re_reg_kind_t
    uint8_t confidence; // RE_REG_CONF_*
    double entropy;     // Shannon entropy of the bytes present on disk
    uint32_t n_funcs;   // functions whose extent intersects the region
    uint32_t func_bytes;
    uint32_t n_strings;   // strings starting in the region
    uint32_t n_data_refs; // references from code into the region
    uint32_t n_jtables;   // jump tables whose entries start in the region
    uint32_t fill_pct;    // percentage of filler bytes, 0-100
    bool exec;            // the containing section is executable
    bool writable;
    bool readable;
    char sec[9]; // containing section name, empty when there is none
} re_region_t;

// Evidence that costs a whole-image pass to gather, done once by re_region_scan and
// then only searched. Both lists are virtual addresses in ascending order; either may
// be NULL when the caller had no scan to give.
typedef struct {
    const re_vec_t *jtables; // uint64_t, ascending
    const re_vec_t *strings; // uint64_t, ascending
} re_region_ev_t;

// Classify [va, va+size) once per call. Returns false when size is zero.
bool re_region_classify(re_code_t *c, const re_fscan_t *scan, const re_xrefset_t *xs,
                        const re_pe_t *pe, const re_region_ev_t *ev, uint64_t va, uint64_t size,
                        re_region_t *out, re_arena_t *a);

// Walk the image in windows of `win` bytes and classify each. Regions that fall
// entirely outside every section are still reported, because a packed file often
// hides code there and leaving the gap unexplained would be the wrong default.
// Stops when out is full and sets *truncated.
size_t re_region_scan(re_code_t *c, const re_fscan_t *scan, const re_xrefset_t *xs,
                      const re_pe_t *pe, size_t win, re_vec_t *out, bool *truncated, re_arena_t *a);

// The name of a kind, for the report. Never NULL.
const char *re_reg_kind_name(uint8_t kind);

// The name of a confidence level, for the report. Never NULL.
const char *re_reg_conf_name(uint8_t conf);

#ifdef __cplusplus
}
#endif
