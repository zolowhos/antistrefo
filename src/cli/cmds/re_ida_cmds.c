// re_ida_cmds.c - ida-mcp shaped database and execute_python commands.
// Module: cli (C11).
// Owns: open/list/close/save/execute_python/reference JSON bodies.
// Depends: re_mcp_db, re_mcp_exec, re_jw. MCP omits antistrefo/1 via ida_shape.
#include "cli/cmds/re_ida_cmds.h"

#include "utils/json/re_jr.h"
#include "utils/json/re_json.h"
#include "utils/sys/re_err.h"
#include "utils/text/re_str.h"
#include "utils/text/re_strbuf.h"
#include "mcp/re_mcp_db.h"
#include "mcp/re_mcp_exec.h"

#include <stdio.h>
#include <string.h>

static void begin_obj(re_ctx_t *ctx, re_jw_t *w, const char *tool) {
    re_jw_init(w, ctx->arena);
    re_jw_obj(w);
    if (!ctx->ida_shape) {
        re_jw_kcstr(w, "schema", "antistrefo/1");
        re_jw_kcstr(w, "tool", tool);
        re_jw_key(w, "ida");
        re_jw_obj(w);
    }
}

static void end_obj(re_ctx_t *ctx, re_jw_t *w) {
    if (!ctx->ida_shape)
        re_jw_obj_end(w);
    re_jw_obj_end(w);
    re_jw_flush(w, re_ctx_out(ctx));
}

static void write_raw(re_ctx_t *ctx, const char *p, size_t n) {
    FILE *fp = (FILE *)re_ctx_out(ctx);
    if (fp && p && n)
        fwrite(p, 1, n, fp);
}

static void emit_open(re_ctx_t *ctx, const re_mcp_db_t *db) {
    re_jw_t w;
    begin_obj(ctx, &w, "open_database");
    re_jw_kcstr(&w, "instance_id", db->id);
    re_jw_kcstr(&w, "backend", db->backend);
    re_jw_kcstr(&w, "status", db->current ? "current" : "attached");
    re_jw_kcstr(&w, "recovery", "none");
    re_jw_kcstr(&w, "log_path", "");
    re_jw_knull(&w, "mcp_id");
    re_jw_kcstr(&w, "hint",
                "Call reference(query) before execute_python. db and ida_domain are available.");
    end_obj(ctx, &w);
}

int re_cmd_open_database(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_mcp_db_t db;
    const char *file = path;
    const char *set_tok;
    bool set_cur = true;
    int first = 0;
    if (!re_cmd_parse(ctx, argc, argv, &first, ctx->err))
        return 2;
    if (!file || !file[0])
        file = re_cmd_positional(argc, argv, first);
    if (!file || !file[0]) {
        RE_ERR_SET(ctx->err, RE_E_USAGE, "open_database needs path");
        return 2;
    }
    // Skip a positional that repeats the path; the next token is set_current.
    set_tok = re_cmd_positional(argc, argv, first);
    if (set_tok && re_str_eq_cstr(re_str(set_tok), file)) {
        int i = first;
        while (i < argc && !re_str_eq_cstr(re_str(argv[i]), file))
            i++;
        set_tok = re_cmd_positional(argc, argv, i + 1);
    }
    if (set_tok &&
        (re_str_eq_cstr(re_str(set_tok), "0") || re_str_eq_cstr(re_str(set_tok), "false")))
        set_cur = false;
    if (!re_mcp_db_open(file, set_cur, "idalib", &db)) {
        RE_ERR_SET(ctx->err, RE_E_IO, "too many databases open");
        return 6;
    }
    emit_open(ctx, &db);
    return 0;
}

static void instance_row(re_jw_t *w, const re_mcp_db_t *db) {
    re_jw_obj(w);
    re_jw_kcstr(w, "path", db->path);
    re_jw_kcstr(w, "backend", db->backend);
    re_jw_kcstr(w, "status", db->current ? "current" : "attached");
    re_jw_kcstr(w, "instance_id", db->id);
    re_jw_knull(w, "error");
    re_jw_obj_end(w);
}

int re_cmd_list_databases(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_mcp_db_t list[RE_MCP_DB_MAX];
    re_jw_t w;
    size_t n;
    int first = 0;
    (void)path;
    if (!re_cmd_parse(ctx, argc, argv, &first, ctx->err))
        return 2;
    n = re_mcp_db_list(list, RE_MCP_DB_MAX);
    begin_obj(ctx, &w, "list_databases");
    re_jw_key(&w, "instances");
    re_jw_arr(&w);
    for (size_t i = 0; i < n; i++)
        instance_row(&w, &list[i]);
    re_jw_arr_end(&w);
    end_obj(ctx, &w);
    return 0;
}

int re_cmd_close_database(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    const char *id;
    bool closed = false;
    re_jw_t w;
    int first = 0;
    (void)path;
    if (!re_cmd_parse(ctx, argc, argv, &first, ctx->err))
        return 2;
    id = re_cmd_positional(argc, argv, first);
    if (!re_mcp_db_close(id, &closed) || !closed) {
        RE_ERR_SET(ctx->err, RE_E_USAGE, "no database to close");
        return 2;
    }
    begin_obj(ctx, &w, "close_database");
    re_jw_kbool(&w, "closed", true);
    end_obj(ctx, &w);
    return 0;
}

int re_cmd_save_database(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_jw_t w;
    int first = 0;
    (void)path;
    if (!re_cmd_parse(ctx, argc, argv, &first, ctx->err))
        return 2;
    re_jw_init(&w, ctx->arena);
    re_jw_obj(&w);
    re_jw_key(&w, "error");
    re_jw_obj(&w);
    re_jw_kcstr(&w, "code", "unsupported");
    re_jw_kcstr(&w, "message",
                "save_database is unsupported: antistrefo does not persist an IDA database");
    re_jw_obj_end(&w);
    re_jw_obj_end(&w);
    re_jw_flush(&w, re_ctx_out(ctx));
    if (ctx->err)
        RE_ERR_SET(ctx->err, RE_E_UNSUPPORTED, "save_database unsupported");
    return 5;
}

int re_cmd_execute_python(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    const char *id = NULL;
    const char *code = NULL;
    const char *db_path;
    re_strbuf_t out;
    int first = 0;
    bool ok;
    (void)path;
    if (!re_cmd_parse(ctx, argc, argv, &first, ctx->err))
        return 2;
    // argv: [code] or [instance_id, code] when two positionals.
    if (first < argc && first + 1 < argc) {
        id = argv[first];
        code = argv[first + 1];
    } else if (first < argc) {
        code = argv[first];
    }
    if (!code) {
        RE_ERR_SET(ctx->err, RE_E_USAGE, "execute_python needs code");
        return 2;
    }
    db_path = re_mcp_db_path(id);
    re_strbuf_init(&out, ctx->arena);
    ok = re_mcp_exec_python(db_path, code, &out);
    if (ctx->ida_shape) {
        write_raw(ctx, out.p, out.len);
        return ok ? 0 : 5;
    }
    {
        re_jw_t w;
        begin_obj(ctx, &w, "execute_python");
        re_jw_kcstr(&w, "raw", out.p ? out.p : "{}");
        end_obj(ctx, &w);
    }
    return ok ? 0 : 5;
}

int re_cmd_reference(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    const char *query;
    const char *text;
    re_strbuf_t b;
    int first = 0;
    (void)path;
    if (!re_cmd_parse(ctx, argc, argv, &first, ctx->err))
        return 2;
    query = re_cmd_positional(argc, argv, first);
    text = re_mcp_reference_text(query);
    if (ctx->ida_shape) {
        re_strbuf_init(&b, ctx->arena);
        re_jr_escape(&b, re_str(text));
        write_raw(ctx, b.p, b.len);
        return 0;
    }
    {
        re_jw_t w;
        begin_obj(ctx, &w, "reference");
        re_jw_kcstr(&w, "text", text);
        end_obj(ctx, &w);
    }
    return 0;
}
