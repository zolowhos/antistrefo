// re_db.h - the .asdb sidecar: one binary's deep analysis, mapped and bounds checked.
// Module: feature (C11).
// Owns: the on-disk layout, the writer, the mapped reader, and the user edits section.
// Depends: re_analyze, re_buf, re_fsave, re_hash. Little-endian, no pointers, no clock.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/analysis/re_alt.h"
#include "features/analysis/re_analyze.h"
#include "utils/algo/re_hash.h"
#include "utils/mem/re_buf.h"

// Layout. A header, sections each aligned to RE_DB_ALIGN, the directory, then the
// USER section last so a rename rewrites only the tail of the file.
//
//   header (RE_DB_HDR bytes)
//     0 magic "ASDB"   4 version   8 schema "antistrefo/1", NUL padded to 16
//    24 source size   32 source SHA-256   64 flags   68 sections   72 directory offset
//    80 user offset   88..127 zero
//   directory entry (RE_DB_DIRENT bytes)
//     0 id   4 element size   8 offset   16 size   24 count   32 zero
//
// Every multi-byte field is little-endian and written field by field, and nothing in
// the file depends on time, addresses in memory or thread scheduling, so the same
// binary always gives the same bytes.
#define RE_DB_MAGIC 0x42445341u
#define RE_DB_VERSION 1u
#define RE_DB_SCHEMA "antistrefo/1"
#define RE_DB_SUFFIX ".asdb"
#define RE_DB_HDR 128u
#define RE_DB_DIRENT 40u
#define RE_DB_ALIGN 64u
#define RE_DB_COMPLETE 0x1u // every pass finished; false when a ceiling stopped one
#define RE_DB_PARTIAL 0x2u  // a work budget cut some pass short, results are a subset
#define RE_DB_USER_MAGIC 0x52455355u

// Record sizes, in bytes. A reader refuses a section whose element size differs.
#define RE_DB_FUNC_REC 72u
#define RE_DB_EDGE_REC 24u
#define RE_DB_XREF_REC 32u
#define RE_DB_JT_REC 40u
#define RE_DB_STR_REC 24u
#define RE_DB_DEV_REC 24u
#define RE_DB_REGION_REC 72u
#define RE_DB_NOTE_REC 32u
#define RE_DB_VCALL_REC 16u
#define RE_DB_SCOPE_REC 16u
#define RE_DB_STACK_REC 24u
#define RE_DB_DECIDX_REC 16u
#define RE_DB_PASS_REC 24u

typedef enum {
    RE_DBS_NONE = 0,
    RE_DBS_SUMMARY,      // one record: counts and the score, see re_db_write.c
    RE_DBS_PASSES,       // re_pass_stat_t, in run order
    RE_DBS_STRTAB,       // NUL terminated strings, referenced by offset
    RE_DBS_FUNCS,        // re_func_t, ascending by va
    RE_DBS_EDGES,        // re_edge_t, walk order
    RE_DBS_XREF_FWD,     // re_xref_t, sorted by from
    RE_DBS_XREF_BACK,    // uint32_t indices into XREF_FWD, sorted by to
    RE_DBS_JTABLES,      // re_jtable_t
    RE_DBS_STRINGS,      // re_str_hit_t
    RE_DBS_DEVICES,      // re_devname_t
    RE_DBS_REGIONS,      // re_region_t
    RE_DBS_NOTES,        // re_note_t
    RE_DBS_VCALLS,       // re_vcall_t
    RE_DBS_SCOPES,       // re_eh_scope_t
    RE_DBS_STACK,        // one per function, in FUNCS order
    RE_DBS_DECOMP_INDEX, // one per function: offset and length into DECOMP_TEXT
    RE_DBS_DECOMP_TEXT,  // the decompiled text of every function, concatenated
    RE_DBS_COUNT
} re_dbs_t;

typedef struct {
    uint32_t id;
    uint32_t elem;
    uint64_t off;
    uint64_t size;
    uint64_t count;
} re_db_sec_t;

typedef struct re_db_s {
    re_file_t file; // the mapping; every read goes through re_rd* on file.whole
    uint64_t src_size;
    uint8_t src_sha[RE_SHA256_LEN];
    uint32_t flags;
    uint64_t user_off;
    re_db_sec_t sec[RE_DBS_COUNT]; // by id; size 0 when the file has no such section
    re_str_t path;
    bool ok;
} re_db_t;

// One function's precomputed decompile, produced by the deep tier while writing.
typedef struct {
    const char *text;
    uint32_t len;
    bool ok;
    re_stack_t st;
} re_db_dec_t;

// The deep tier hands the writer a source of decompiled text, filled a chunk at a time
// so the text of 600,000 functions never sits in memory at once. Strings in out stay
// valid until the next call. Returns false to abort the write.
typedef struct {
    bool (*chunk)(void *ctx, size_t first, size_t n, re_db_dec_t *out);
    void *ctx;
    size_t chunk_n; // functions per call
} re_db_decsrc_t;

// "<binary>.asdb", arena owned.
char *re_db_path(re_arena_t *a, const char *bin_path);

// Hash the source the way the header records it.
void re_db_hash_source(re_span_t src, uint8_t out[RE_SHA256_LEN]);

// Write the analysis to "<binary>.asdb" through a temp file and an atomic replace.
// dec may be NULL, which leaves the decompile sections out. user carries the renames
// to keep. complete is false when a memory ceiling stopped the deep tier.
bool re_db_write(const re_analysis_t *an, const re_db_decsrc_t *dec, const re_alt_t *user,
                 bool complete, re_arena_t *scratch);

// Map path and validate it against the source. False when the file is absent, from
// another version, for another source, incomplete, or malformed; err then says which.
bool re_db_open(re_db_t *db, const char *path, re_span_t src, re_arena_t *a, re_err_t *err);
void re_db_close(re_db_t *db);

// A section's bytes, or an empty span when absent. Never past the end of the file.
re_span_t re_db_section(const re_db_t *db, re_dbs_t id);

// Load one pass's results into an. Strings point into the mapping, so the database
// must stay open for as long as an is used. False on a malformed section.
bool re_db_load_pass(const re_db_t *db, re_analysis_t *an, re_pass_t pass);

// The precomputed decompile of function index i, or false when there is none. ok is
// what re_decompile_ok said when it was written; text is then the emitter's output.
bool re_db_decomp(const re_db_t *db, size_t i, re_str_t *text, bool *ok);

// Read the USER section's renames into m. An absent or corrupt section loads nothing;
// corrupt is reported through *bad so the caller can warn once.
bool re_db_user_load(const re_db_t *db, re_alt_t *m, bool *bad);

// Rewrite the USER section of the .asdb at path in place. The file stays mapped by
// anyone who has it open; they keep their view and see the edits on their next open.
bool re_db_user_save(const char *path, const re_alt_t *m, re_arena_t *scratch);

// Serialise m as a USER payload into sb, for the writer and the in-place save.
void re_db_user_encode(const re_alt_t *m, re_strbuf_t *sb);
#ifdef __cplusplus
}
#endif
