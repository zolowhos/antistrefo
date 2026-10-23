// re_db_priv.h - the pieces the .asdb writer, reader and decompile store share.
// Module: feature (C11).
// Owns: the summary vector's field order and the decompile section entry points.
// Depends: re_db.h, re_fsave. Private to src/features/db; not a seam.
#pragma once

#include "features/db/re_db.h"
#include "utils/sys/re_fsave.h"

// The SUMMARY section is a vector of u64, one per field below, in this order. A new
// field is appended and RE_DB_VERSION is not bumped; a reader of an older file finds
// the vector shorter and refuses it, which rebuilds the database.
typedef enum {
    RE_DBV_DEEP = 0,
    RE_DBV_SCAN_TRUNC,
    RE_DBV_SCAN_PARTIAL,
    RE_DBV_PDATA_WALKED,
    RE_DBV_PDATA_REJECTED,
    RE_DBV_GAP_FOUND,
    RE_DBV_GAP_ROUNDS,
    RE_DBV_TRICKS,
    RE_DBV_XS_INDIRECT,
    RE_DBV_PDB_REF,
    RE_DBV_PDB_LEN,
    RE_DBV_PDB_OFF,
    RE_DBV_ASCII,
    RE_DBV_WIDE,
    RE_DBV_GO_VERSION,
    RE_DBV_GO_PTR,
    RE_DBV_GO_NFUNCS,
    RE_DBV_GO_NNAMED,
    RE_DBV_GO_TEXT,
    RE_DBV_GO_TRUNC,
    RE_DBV_GO_NAMED,
    RE_DBV_SIG_BEFORE,
    RE_DBV_SIG_LOADED,
    RE_DBV_SIG_REJECTED,
    RE_DBV_SIG_SKIPPED,
    RE_DBV_NAMED,
    RE_DBV_NM_SLOTS,
    RE_DBV_NM_FUNCS,
    RE_DBV_NM_SCOPES,
    RE_DBV_NM_VCALLS,
    RE_DBV_SC_FUNCS,
    RE_DBV_SC_PDATA,
    RE_DBV_SC_PDATA_HIT,
    RE_DBV_SC_EDGES,
    RE_DBV_SC_EDGES_OK,
    RE_DBV_SC_CALLS,
    RE_DBV_SC_CALLS_NAMED,
    RE_DBV_SC_INSNS,
    RE_DBV_SC_LOWERED,
    RE_DBV_SC_INDIRECT,
    RE_DBV_SC_INDIRECT_OK,
    RE_DBV_SC_SCORE, // the double's bits
    RE_DBV_COUNT
} re_dbv_t;

// Fill v from an, except the PDB string reference, which the writer adds.
void re_db_summary_fill(const re_analysis_t *an, uint64_t v[RE_DBV_COUNT]);

// Restore what v holds into an. The PDB text is resolved by the caller.
void re_db_summary_apply(const uint64_t v[RE_DBV_COUNT], re_analysis_t *an);

// Stream the DECOMP_TEXT, DECOMP_INDEX and STACK sections, appending their directory
// entries. False when the source aborted or a write failed.
bool re_db_write_decomp(re_fsave_t *fs, re_db_sec_t *dir, uint32_t *n_dir, const re_analysis_t *an,
                        const re_db_decsrc_t *dec, re_arena_t *a);

// Loaders for the sections re_db_read.c does not decode itself, in re_db_load.c.
bool re_db_load_notes(const re_db_t *db, re_analysis_t *an);
bool re_db_load_strings(const re_db_t *db, re_analysis_t *an);
bool re_db_load_regions(const re_db_t *db, re_analysis_t *an);
bool re_db_load_names(const re_db_t *db, re_analysis_t *an);

// The string a record names at field offset off (u32 offset, u32 length) through the
// string table. Empty when absent or out of bounds. The view points into the mapping.
re_str_t re_db_strref(const re_db_t *db, re_span_t rec, uint64_t off);

// Record i of a section as a bounds checked span. False when the section is absent,
// has another element size, or i is past its count.
bool re_db_rec(const re_db_t *db, re_dbs_t id, uint32_t elem, uint64_t i, re_span_t *out);

// Field loads from a record span. A record is always read whole through re_db_rec, so
// a short read cannot happen; the zero on failure is a guard, not a meaning.
static inline uint8_t re_db_f8(re_span_t r, uint64_t off) {
    uint8_t v = 0;
    re_rd8(r, off, &v);
    return v;
}

static inline uint32_t re_db_f32(re_span_t r, uint64_t off) {
    uint32_t v = 0;
    re_rd32(r, off, &v);
    return v;
}

static inline uint64_t re_db_f64(re_span_t r, uint64_t off) {
    uint64_t v = 0;
    re_rd64(r, off, &v);
    return v;
}
