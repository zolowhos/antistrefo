// re_search.h - three search modes: text, immediate value, and byte pattern.
// Module: feature (C11).
// Owns: pattern parsing, the three matchers, and hit reporting.
// Depends: re_buf, re_str, re_regex, re_arena, re_vec. No I/O, no globals.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils/mem/re_arena.h"
#include "utils/mem/re_buf.h"
#include "utils/mem/re_vec.h"
#include "utils/sys/re_err.h"
#include "utils/text/re_str.h"

typedef enum {
    RE_SEARCH_TEXT = 0,  // pattern is text, or a regex when use_regex
    RE_SEARCH_IMMEDIATE, // pattern is a hex or decimal value to find literally
    RE_SEARCH_BYTES,     // pattern is hex with ? and ?? wildcards
    RE_SEARCH_SIGNATURE, // whole word match only, for symbol style lookups
} re_search_kind_t;

typedef struct {
    uint64_t off; // file offset
    uint32_t rva; // 0 when the offset is not inside a section
    bool has_rva;
    bool wide;     // the match came from a UTF-16 run, not an ASCII one
    re_str_t text; // the match rendered as text, for immediates and patterns
} re_search_hit_t;

// Backstop on how many hits are kept when the caller asked for no limit, so a
// search for a single byte in a large image cannot exhaust memory. Hitting it
// sets more, because a dropped hit that is not reported is a wrong answer.
#define RE_SEARCH_MAX_HITS 2000u

typedef struct {
    re_vec_t hits; // re_search_hit_t
    size_t total;  // matches found before the limit stopped the scan
    bool more;     // the scan stopped at the limit, so total is a floor
} re_search_t;

void re_search_init(re_search_t *s);

// Parse a pattern into a byte pattern. '?' is a one byte wildcard and "??" is a
// two byte wildcard, which is the convention every signature format uses. Returns
// false and fills err on an odd digit count or a stray character.
bool re_search_parse_pattern(re_arena_t *a, const char *pat, uint8_t **bytes, uint8_t **mask,
                             size_t *n, re_err_t *err);

// Find a literal byte pattern, honouring the mask.
void re_search_bytes(re_span_t img, const uint8_t *pat, const uint8_t *mask, size_t n,
                     size_t offset, size_t limit, re_arena_t *a, re_search_t *out);

// Find every little endian and big endian encoding of a 1, 2, 4 or 8 byte value.
void re_search_immediate(re_span_t img, uint64_t value, unsigned width, bool both_endians,
                         size_t offset, size_t limit, re_arena_t *a, re_search_t *out);

// Search every width in {1,2,4,8} that can hold value, both endians, deduped by off.
// Agents are not forced to know encoding width or zero-pad the query digits.
void re_search_immediate_all(re_span_t img, uint64_t value, size_t offset, size_t limit,
                             re_arena_t *a, re_search_t *out);

// Find text, optionally as a regex, in both encodings. Wide matches are narrowed
// so the reported text is always one byte per character.
void re_search_text(re_span_t img, re_str_t pat, bool use_regex, bool case_insensitive,
                    bool wide_only, size_t offset, size_t limit, re_arena_t *a, re_search_t *out);

// Find a whole word match, so a search for main does not report domain.
void re_search_signature(re_span_t img, re_str_t pat, size_t offset, size_t limit, re_arena_t *a,
                         re_search_t *out);

// Render a 16 byte window as hex with wildcards collapsed, for context.
void re_search_render(re_arena_t *a, re_span_t win, re_str_t *out);
