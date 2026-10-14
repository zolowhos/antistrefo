// re_mcp_exec.h - run the ida-mcp execute_python shim against one database.
// Module: mcp (C++17).
// Owns: locating the shim, spawning python3, capturing result JSON.
// Depends: re_strbuf, re_mcp_db. No protocol framing here.
#pragma once

#include "utils/text/re_strbuf.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Set the scripts/ directory that holds ida_mcp_shim.py (from CMake or main).
void re_mcp_exec_set_scripts(const char *dir);

// Run code against db_path. On success out holds {result,stdout,stderr}.
// On failure out holds an error object and returns false.
bool re_mcp_exec_python(const char *db_path, const char *code, re_strbuf_t *out);

// Static reference text for the antistrefo ida-domain subset.
const char *re_mcp_reference_text(const char *query);

#ifdef __cplusplus
}
#endif
