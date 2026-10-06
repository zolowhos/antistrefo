// re_dc_proto.h - argument counts for the imports a driver actually calls.
// Module: feature (C11).
// Owns: the name-to-count table and the call text it produces.
// Depends: re_str. The table is data. Nothing here parses a header.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils/text/re_str.h"

// Write "Name(a, b)" using at most the table's argument count. False when the
// name is not in the table, so the caller keeps its own spelling. A shorter
// lowered call is not padded.
bool re_dc_proto_format(re_str_t name, const char *args, char *dst, size_t cap);
#ifdef __cplusplus
}
#endif
