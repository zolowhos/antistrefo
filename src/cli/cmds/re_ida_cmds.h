// re_ida_cmds.h - ida-mcp style database and execute_query entry points.
// Module: cli (C11).
// Owns: nothing. Declares open/list/close/save/execute_query/reference.
// Depends: cli/re_table.h. Same names drive argv and MCP tools/list.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include "cli/app/re_table.h"

int re_cmd_open_database(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_list_databases(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_close_database(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_save_database(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_execute_query(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_reference(re_ctx_t *ctx, const char *path, int argc, char **argv);

#ifdef __cplusplus
}
#endif
