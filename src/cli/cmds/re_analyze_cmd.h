// re_analyze_cmd.h - the analyze command's entry point.
// Module: cli (C11).
// Owns: nothing. Declares the one entry point the command table binds to.
// Depends: re_table.h for re_ctx_t.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include "cli/app/re_table.h"

int re_cmd_analyze(re_ctx_t *ctx, const char *path, int argc, char **argv);

// The deep tier, in the foreground, writing "<file>.asdb" beside the binary.
int re_cmd_deep(re_ctx_t *ctx, const char *path, int argc, char **argv);
#ifdef __cplusplus
}
#endif
