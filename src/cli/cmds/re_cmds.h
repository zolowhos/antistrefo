// re_cmds.h - entry points for every command in the table.
// Module: cli (C11).
// Owns: nothing. Declares the dispatch surface re_table.c binds to.
// Depends: cli/re_table.h for re_ctx_t. Every command returns a process exit code.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include "cli/app/re_table.h"

int re_cmd_info(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_triage(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_sections(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_imports(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_exports(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_strings(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_vtables(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_hexdump(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_search(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_demangle(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_rules(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_entropy(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_funcs(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_xrefs(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_jtables(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_disasm(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_context(re_ctx_t *ctx, const char *path, int argc, char **argv);
#ifdef __cplusplus
}
#endif
