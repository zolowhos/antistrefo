// re_strings.h - printable string extraction, device names and PDB paths.
// Module: feature (C11).
// Owns: ASCII and UTF-16 runs, neighbor windows, device names, debug paths.
// Depends: re_buf, re_vec, re_str, re_arena. No I/O, no globals, all keys bounded.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils/algo/re_regex.h"
#include "utils/json/re_json.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_buf.h"
#include "utils/mem/re_vec.h"
#include "utils/text/re_str.h"

#define RE_STR_HITS_MAX 65536
// Neighbor windows stay small. A caller that asks for more is clamped here.
#define RE_STR_CONTEXT_MAX 16
#define RE_STR_NEIGHBOR_CAP 1024

typedef struct {
    uint64_t off;
    re_str_t text; // owned by the caller's arena
    bool wide;
} re_str_hit_t;

typedef struct {
    re_str_t name;
    uint64_t off;
    bool wide;
    bool dynamic; // contains a %s style placeholder, so the real name is built
                  // at runtime and never appears in the file
} re_devname_t;

typedef struct {
    re_vec_t hits;    // re_str_hit_t
    re_vec_t devices; // re_devname_t
    re_str_t pdb;
    uint64_t pdb_off;
    uint64_t ascii_count;
    uint64_t wide_count;
} re_strings_t;

void re_strings_init(re_strings_t *s);

// Scan for printable runs of at least min_len. max caps how many hits are stored.
// The walk still covers the whole image, so ascii_count and wide_count are totals.
void re_strings_scan(re_span_t img, size_t min_len, size_t max, re_arena_t *a, re_strings_t *out);

// One page of runs. total counts every match, including those skipped by offset
// or dropped past the store cap. truncated is total larger than the stored page.
typedef struct {
    re_vec_t hits; // re_str_hit_t
    size_t total;
    bool truncated;
} re_str_page_t;

void re_str_page_init(re_str_page_t *p);

// Walk the whole image. rx null keeps every run. A regex keeps a run only when
// it matches, so non-matches are never copied. limit 0 stores up to RE_STR_HITS_MAX.
void re_strings_collect(re_span_t img, size_t min_len, re_rx_t *rx, size_t offset, size_t limit,
                        re_arena_t *a, re_str_page_t *out);

// The printable run containing off, plus up to neighbors runs of the same
// encoding on each side. Neighbors are capped at RE_STR_CONTEXT_MAX and each
// copied neighbor at RE_STR_NEIGHBOR_CAP. The run itself is the full string.
typedef struct {
    re_str_hit_t run;
    bool found;
    re_vec_t before; // re_str_hit_t, file order
    re_vec_t after;  // re_str_hit_t, file order
} re_str_around_t;

void re_str_around(re_span_t img, uint64_t off, bool wide, size_t min_len, size_t neighbors,
                   re_arena_t *a, re_str_around_t *out);

// Write hits as a JSON array of {off, wide, text} under key.
void re_str_hits_json(re_jw_t *w, const char *key, const re_vec_t *hits);

// Find \Device\ and \DosDevices\ names in both encodings, flagging the ones that
// are format strings. A driver whose device name is built at runtime still
// reaches the kernel, so reporting it as unresolved matters for triage.
void re_strings_devices(re_span_t img, size_t max, re_arena_t *a, re_strings_t *out);

// Recover the PDB path from an RSDS CodeView record, the cheapest provenance
// signal a binary gives away for free.
void re_strings_pdb(re_span_t img, re_arena_t *a, re_strings_t *out);

// True when a string looks like it contains a printf placeholder.
bool re_str_is_dynamic(re_str_t s);

// Apply a regex filter with offset and limit, returning the total match count so
// the caller can report truncation honestly.
size_t re_strings_filter(re_arena_t *a, const re_strings_t *s, re_rx_t *rx, size_t offset,
                         size_t limit, re_vec_t *out_hits);
#ifdef __cplusplus
}
#endif
