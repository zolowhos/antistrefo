// re_table.h - the one command table that feeds both the CLI and the MCP tool list.
// Module: cli (C11).
// Owns: command metadata, shared argument parsing and the dispatch contract.
// Depends: re_str, re_strbuf, re_err. No globals except the table itself.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils/mem/re_arena.h"
#include "utils/sys/re_err.h"
#include "utils/text/re_str.h"
#include "utils/text/re_strbuf.h"

#define RE_CMD_NAME_MAX 24
#define RE_CMD_SUMMARY_MAX 96
#define RE_CMD_MAX_ARGS 16

typedef enum {
    // The default is JSON because the parse layer cannot know whether stdout is a
    // terminal, and guessing wrong breaks a pipe. The renderers ask
    // re_report_wanted, which resolves the default against the real stdout.
    RE_FMT_OUT_JSON = 0,
    RE_FMT_OUT_TEXT,
} re_out_fmt_t;

typedef struct re_ctx {
    re_arena_t *arena;
    re_out_fmt_t out;
    size_t limit; // default 200, the agent context guard
    size_t offset;
    uint64_t off;   // hexdump offset
    uint64_t len;   // hexdump length
    re_str_t regex; // empty when no filter was given
    bool has_regex;
    bool no_color; // --no-color, which also honours the NO_COLOR convention
    // Where a command writes its response. NULL means stdout, which is every case
    // except the MCP server: it points at a temporary file so the bytes can be
    // handed back as structured content instead of going to the client as text.
    void *stream;
    // The session's already analysed file, borrowed from whoever opened it. NULL in
    // every argv invocation, so a command must treat it as an optimisation and not a
    // requirement: without it the command builds its own. A command may only use it
    // when an->path matches the file it was asked about.
    struct re_analysis_s *session;
    re_err_t *err;
} re_ctx_t;

// Every command receives the already parsed context, so no command re-parses argv
// and the MCP layer can synthesise the same context from a tool call.
typedef int (*re_cmd_fn)(re_ctx_t *ctx, const char *path, int argc, char **argv);

typedef struct {
    char name[RE_CMD_NAME_MAX];
    char summary[RE_CMD_SUMMARY_MAX];
    char usage[64];
    re_cmd_fn fn;
    bool needs_path;
    // An interactive command wants the terminal stdio lives on: the full screen view
    // and the shell prompt. The MCP server refuses these before running anything,
    // because a protocol frame stream and a TUI cannot share the same pipe.
    bool interactive;
} re_cmd_t;

const re_cmd_t *re_cmd_table(size_t *count);
const re_cmd_t *re_cmd_find(const char *name);

// Where a command's response goes: ctx->stream when set, stdout otherwise.
void *re_ctx_out(const re_ctx_t *ctx);

// Parse the flags every command shares. Returns false and fills err on a bad flag,
// so a command only ever sees the positional path.
bool re_cmd_parse(re_ctx_t *ctx, int argc, char **argv, int *first_positional, re_err_t *err);

// The first positional argument at or after from, or NULL. A command receives the
// file as argv[0] and then the remaining tokens *including any flags*, so a
// command that wants an address has to skip the flags itself. A flag is assumed
// to take the token after it, which is true of every flag this CLI defines, and is
// far better than reading a flag's value as the address.
const char *re_cmd_positional(int argc, char **argv, int from);

// Write the envelope every response carries, so no command can forget it.
void re_cmd_begin(re_ctx_t *ctx, re_strbuf_t *head);
#ifdef __cplusplus
}
#endif
