// re_context_cmd.c - report the live GUI / MCP session snapshot.
// Module: cli (C11).
// Owns: the context command body for argv and MCP tools/call.
// Depends: re_table, re_mcp_live, re_jw. No file I/O of its own.
#include "cli/cmds/re_cmds.h"

#include "utils/json/re_json.h"
#include "utils/text/re_util.h"
#include "mcp/re_mcp_live.h"

#include <stdio.h>

int re_cmd_context(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_mcp_live_t live;
    re_jw_t w;
    int first = 0;
    re_err_t err;
    (void)path;
    err.code = RE_OK;
    if (!ctx->err)
        ctx->err = &err;
    if (!re_cmd_parse(ctx, argc, argv, &first, ctx->err))
        return 2;
    re_mcp_live_snapshot(&live);
    re_jw_init(&w, ctx->arena);
    re_jw_obj(&w);
    re_jw_kcstr(&w, "schema", "antistrefo/1");
    re_jw_kcstr(&w, "tool", "context");
    re_jw_kbool(&w, "loaded", live.loaded);
    re_jw_kcstr(&w, "path", live.loaded ? live.path : "");
    re_jw_kcstr(&w, "name", live.loaded ? live.name : "");
    re_jw_kcstr(&w, "format", live.format[0] ? live.format : "");
    re_jw_kcstr(&w, "arch", live.arch[0] ? live.arch : "");
    re_jw_ku64(&w, "sel", (uint64_t)live.sel);
    re_jw_khex(&w, "func_rva", live.func_rva, 8);
    re_jw_kcstr(&w, "func_name", live.func_name);
    re_jw_kbool(&w, "mcp_up", live.mcp_up);
    re_jw_kcstr(&w, "mcp_endpoint", live.mcp_endpoint);
    re_jw_ku64(&w, "gen", (uint64_t)live.gen);
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
    return 0;
}
