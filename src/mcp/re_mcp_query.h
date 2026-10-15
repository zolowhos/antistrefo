// re_mcp_query.h - native execute_query runner over existing re_* commands.
// Module: mcp (C11).
// Owns: op name validation and in-process command capture for MCP agents.
// Depends: re_table, re_strbuf. No Python, no subprocess, no network.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils/mem/re_arena.h"
#include "utils/sys/re_err.h"
#include "utils/text/re_strbuf.h"

// Run one analysis op against db_path. On success out holds the command JSON.
// On failure out may hold an error object and err is set.
bool re_mcp_query_run(re_arena_t *a, const char *db_path, const char *op, const char *arg,
                      uint64_t len, uint64_t off, uint64_t rva, bool has_len, bool has_off,
                      bool has_rva, const char *regex, size_t limit, size_t offset, size_t context,
                      const char *exports, const char *names, const char *order, re_strbuf_t *out,
                      re_err_t *err);

// Reference blurb for execute_query ops (ida-mcp reference replacement).
const char *re_mcp_query_reference(const char *query);

#ifdef __cplusplus
}
#endif
