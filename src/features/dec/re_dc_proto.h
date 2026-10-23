// re_dc_proto.h - argument counts and result kinds for imports by name.
// Module: feature (C11).
// Owns: the lookup over the prototype tables and the call text it produces.
// Depends: re_str, dec/proto/re_dc_ptab. The tables are data. Nothing here parses a header.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils/text/re_str.h"

// What a known import takes and gives back. ret is 'v' (nothing), 'i' (signed 32
// bit), 'u' (unsigned 32 bit) or 'p' (64 bit: a pointer, handle or size).
typedef struct {
    uint8_t nargs;
    char ret;
} re_dc_proto_t;

// The prototype of name, trying the name as given and then without a trailing A or W,
// so CreateFileW and CreateFileA both find CreateFile. False when it is not listed.
bool re_dc_proto_find(re_str_t name, re_dc_proto_t *out);

// Write "Name(a, b)" using at most the table's argument count. False when the
// name is not in the table, so the caller keeps its own spelling. A shorter
// lowered call is not padded.
bool re_dc_proto_format(re_str_t name, const char *args, char *dst, size_t cap);

// The argument count of a known import, or -1 when the name is not in the table.
int re_dc_proto_nargs(re_str_t name);
#ifdef __cplusplus
}
#endif
