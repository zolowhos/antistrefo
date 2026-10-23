// re_analyze.h - one file, analysed once, with the passes that ran over it recorded.
// Module: feature (C11).
// Owns: the shared analysis context, the pass list, and the per pass outcome.
// Depends: re_pe, re_code, re_func, re_xref, re_jtable, re_strings, re_regions,
//           re_stack, re_flirt, re_arena, re_vec. The decoder is reached only through
//           the re_disasm_t vtable, so no x86 detail appears here.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/code/re_code.h"
#include "features/code/re_func.h"
#include "features/code/re_jtable.h"
#include "features/code/re_stack.h"
#include "features/code/re_xref.h"
#include "features/data/re_gopath.h"
#include "features/data/re_regions.h"
#include "features/data/re_strings.h"
#include "features/flow/re_names.h"
#include "features/lib/re_flirt.h"
#include "features/pe/re_pe.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_vec.h"
#include "re_score.h"

// The passes, in the order they run. Order matters and is not arbitrary: functions
// must exist before their edges can be indexed, and a cross reference needs a
// function to attribute an instruction to. A pass that needs an earlier one cannot
// run without it, which is why the order is a list and not a set.
typedef enum {
    RE_PASS_FORMAT = 0, // the PE itself: sections, directories, entropy
    RE_PASS_FUNCS,      // recursive descent from the entry point and exports
    RE_PASS_SYMBOLS,    // the image's own function table, when it has one
    RE_PASS_XREFS,      // both directions of the reference graph
    RE_PASS_JTABLES,    // indirect branch dispatch
    RE_PASS_STRINGS,    // string and device extraction
    RE_PASS_REGIONS,    // code versus data, per window
    RE_PASS_STACK,      // argument registers and frame sizes, per function
    RE_PASS_FLIRT,      // byte pattern library identification
    RE_PASS_NAMES,      // vtable slot naming, virtual call recovery, EH scopes
    RE_PASS_SCORE,      // the quality scoreboard over everything the passes found
    RE_PASS_COUNT
} re_pass_t;

// Why a pass did not produce a result. A pass that did not run is reported with one
// of these rather than being omitted, because a report that silently leaves out the
// pass it could not do reads exactly like one where the pass found nothing.
typedef enum {
    RE_PASS_RAISED_NONE = 0,
    RE_PASS_SKIP_UNSUPPORTED, // the file is not a PE this build parses
    RE_PASS_SKIP_EMPTY,       // nothing to work on: no functions, no sections
    RE_PASS_SKIP_NO_DECODER,  // no instruction decoder in this build
    RE_PASS_SKIP_LIMIT        // the cap was hit, so the result is partial
} re_pass_skip_t;

typedef struct {
    re_pass_t pass;
    uint64_t ms;    // processor milliseconds, 0 when the platform has no clock
    uint64_t count; // what the pass found, in whatever unit means something for it
    bool ran;
    uint8_t skip; // re_pass_skip_t
    bool partial;
} re_pass_stat_t;

// What the deep tier learned that has no home in the per-pass results: a hostile
// range, a resolved API hash, a decrypted string, a virtualised or flattened function.
typedef enum {
    RE_NOTE_NONE = 0,
    RE_NOTE_ENCRYPTED,  // va..va+aux is packed or encrypted on disk
    RE_NOTE_ENTRY,      // the entry point lies in such a range
    RE_NOTE_API_HASH,   // the constant at va is the hash aux of the export text
    RE_NOTE_DYN_IMPORT, // the pointer stored at va was resolved at run time as text
    RE_NOTE_DECRYPTED,  // the routine at aux decrypts the bytes at va to text
    RE_NOTE_VM,         // the function at va enters a virtual machine, aux handlers
    RE_NOTE_FLATTENED,  // the function at va is driven by a dispatcher at aux
    RE_NOTE_PACKER,     // the section named text is a known protector's
} re_note_kind_t;

typedef struct {
    uint64_t va;
    uint64_t aux;
    uint32_t kind; // re_note_kind_t
    re_str_t text;
} re_note_t;

struct re_db_s;

// The shared context. One of these per open file: the file stays mapped, the PE
// stays parsed, and each pass runs at most once via re_analysis_ensure, so a
// second command over the same file reads this instead of rediscovering it. Open
// alone is map+parse; heavy passes stay demand-driven for large images.
// The tag is named so a context header can forward declare the pointer type without
// including this one.
typedef struct re_analysis_s {
    re_arena_t *arena; // owns every allocation below, and the file mapping
    re_str_t path;     // what was opened, so a cache can be checked before it is reused
    re_file_t file;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_xrefset_t xs;
    re_strings_t strs;
    re_vec_t jtables; // re_jtable_t
    re_vec_t regions; // re_region_t
    re_vec_t gosyms;  // re_gosym_t, what the Go function table named
    re_goinfo_t go;   // the table's own shape, zeroed when there is none
    size_t go_named;  // functions a Go symbol table named
    re_vec_t sigs;    // re_sig_t, what the signature pass loaded
    re_sigdb_t sigdb; // the same set, indexed by first byte
    re_flirt_load_stat_t sigstat;
    re_names_stat_t names; // what the naming pass recovered
    re_score_t score;      // the scoreboard's six ratios and their composite
    size_t named;          // functions a signature named
    re_vec_t passes;       // re_pass_stat_t, one per pass, in run order
    re_vec_t notes;        // re_note_t, deep tier only, ascending by va then kind
    struct re_db_s *db;    // the attached .asdb; passes load from it instead of running
    bool deep;             // results are the deep tier's, from a run or a database
    bool has_pe;
    bool has_code;
    bool ok;
} re_analysis_t;

// Zero the context. Nothing is allocated and nothing is mapped yet.
void re_analysis_init(re_analysis_t *an, re_arena_t *a);

// Map path and parse the PE (format pass only). Does not walk code, scan strings,
// or build xrefs: those run on demand through re_analysis_ensure so a large image
// can sit mapped without retaining multi-GB analysis structures. Returns false
// only when the file could not be opened.
bool re_analysis_open(re_analysis_t *an, re_arena_t *a, const char *path);

// Run every not-yet-run pass through `last` inclusive, in order. Safe to call
// repeatedly. Returns false when the context is not open; a pass that skips or
// hits an internal cap still leaves the context usable and is recorded as such.
bool re_analysis_ensure(re_analysis_t *an, re_pass_t last);

// Convenience: ensure every pass through the scoreboard has run.
static inline bool re_analysis_run_all(re_analysis_t *an) {
    return re_analysis_ensure(an, RE_PASS_SCORE);
}

// Release the mapping and everything allocated from the arena. The arena itself is
// the caller's and is not freed here.
void re_analysis_close(re_analysis_t *an);

// The record for one pass, or NULL past the end.
const re_pass_stat_t *re_analysis_pass(const re_analysis_t *an, re_pass_t pass);

// The name of a pass, for the report. Never NULL.
const char *re_analysis_pass_name(re_pass_t pass);

// The reason a pass was skipped, in words a reader can act on. Never NULL.
const char *re_analysis_skip_name(uint8_t skip);

// The stack record for one function, filled in on demand rather than held for every
// function at once, because a 150,000 function image would otherwise carry 150,000
// records nobody asked for. The context is not const because the walk marks the code
// map as it goes.
bool re_analysis_stack_of(re_analysis_t *an, size_t index, re_stack_t *out);

// Apply a table the image states about itself to a function table. A function takes a
// name only when an entry starts at exactly its own address, so a table read with the
// wrong origin names nothing rather than naming the wrong functions, and a function the
// image already names keeps that name. Returns how many functions it named. This is a
// function and not a step inside a pass because the command line names functions too, and
// a report that names them differently from the analysis would be two answers to one
// question.
size_t re_symbols_apply(re_fscan_t *scan, const re_vec_t *syms);

#ifdef __cplusplus
}
#endif
