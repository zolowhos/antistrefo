// re_mcp_tools.cpp - argument translation and execution for the MCP tool surface.
// Module: mcp (C++17).
// Owns: the per command argument table and the run of one captured command.
// Depends: re_mcp_tools.h, re_cmds. Commands get the same argv shape the CLI passes.
#include "mcp/re_mcp_tools.h"

#include "utils/json/re_jr.h"
#include "cli/cmds/re_cmds.h"

#include <cstdio>
#include <cstring>

namespace {

struct ArgSpec {
    const char *json;
    const char *flag;
    const char *desc;
    bool is_num;
};

struct ToolSpec {
    const char *cmd;
    ArgSpec args[4];
};

constexpr ArgSpec kEnd = {NULL, NULL, NULL, false};
const ToolSpec kToolArgs[] = {
    {"open_database",
     {{"set_current", NULL, "become the default target for execute_python", false},
      kEnd,
      kEnd,
      kEnd}},
    {"execute_python",
     {{"code", NULL, "python against the open database", false},
      {"instance_id", NULL, "optional database instance id", false},
      {"timeout", NULL, "ignored; accepted for ida-mcp parity", true},
      kEnd}},
    {"reference", {{"query", NULL, "API or task to look up", false}, kEnd, kEnd, kEnd}},
    {"close_database",
     {{"instance_id", NULL, "optional database instance id", false}, kEnd, kEnd, kEnd}},
    {"save_database",
     {{"instance_id", NULL, "optional database instance id", false}, kEnd, kEnd, kEnd}},
};

const ToolSpec *spec_for(const char *cmd) {
    for (const ToolSpec &t : kToolArgs) {
        if (re_str_eq_cstr(re_str(t.cmd), cmd))
            return &t;
    }
    return NULL;
}

void prop(re_strbuf_t *b, bool *first, const char *name, const char *kind, const char *desc) {
    if (!*first)
        re_strbuf_putc(b, ',');
    *first = false;
    re_strbuf_puts(b, "\"");
    re_strbuf_puts(b, name);
    re_strbuf_puts(b, "\":{\"type\":\"");
    re_strbuf_puts(b, kind);
    re_strbuf_puts(b, "\",\"description\":");
    re_jr_escape(b, re_str(desc));
    re_strbuf_putc(b, '}');
}

void tool_error(re_strbuf_t *out, const char *code, const char *msg, bool *is_error) {
    re_strbuf_puts(out, "{\"error\":{\"code\":");
    re_jr_escape(out, re_str(code));
    re_strbuf_puts(out, ",\"message\":");
    re_jr_escape(out, re_str(msg));
    re_strbuf_puts(out, "}}");
    *is_error = true;
}

bool is_ida_tool(const char *name) {
    return re_str_eq_cstr(re_str(name), "open_database") ||
           re_str_eq_cstr(re_str(name), "list_databases") ||
           re_str_eq_cstr(re_str(name), "close_database") ||
           re_str_eq_cstr(re_str(name), "save_database") ||
           re_str_eq_cstr(re_str(name), "execute_python") ||
           re_str_eq_cstr(re_str(name), "reference");
}

// Fixed ida-mcp input schemas for the six tools (plus generic path for open).
bool schema_ida(const char *name, re_strbuf_t *b) {
    if (re_str_eq_cstr(re_str(name), "open_database")) {
        re_strbuf_puts(b, "{\"type\":\"object\",\"properties\":{"
                          "\"path\":{\"type\":\"string\",\"description\":"
                          "\"Path to a local executable or IDB. A GUI instance is used when "
                          "available.\"},"
                          "\"set_current\":{\"type\":\"boolean\",\"description\":"
                          "\"Whether this database should become the default target for "
                          "execute_python().\",\"default\":true},"
                          "\"load_options\":{\"description\":"
                          "\"Accepted for parity; ignored by antistrefo.\"}"
                          "},\"required\":[\"path\"]}");
        return true;
    }
    if (re_str_eq_cstr(re_str(name), "execute_python")) {
        re_strbuf_puts(b, "{\"type\":\"object\",\"properties\":{"
                          "\"code\":{\"type\":\"string\",\"description\":"
                          "\"Python code that runs against an already-open database.\"},"
                          "\"instance_id\":{\"description\":\"Optional database instance id.\"},"
                          "\"timeout\":{\"type\":\"number\",\"description\":"
                          "\"Accepted for parity; not enforced.\"}"
                          "},\"required\":[\"code\"]}");
        return true;
    }
    if (re_str_eq_cstr(re_str(name), "reference")) {
        re_strbuf_puts(b, "{\"type\":\"object\",\"properties\":{"
                          "\"query\":{\"type\":\"string\",\"description\":"
                          "\"Class, method, or reverse-engineering concept to look up.\"}"
                          "},\"required\":[\"query\"]}");
        return true;
    }
    if (re_str_eq_cstr(re_str(name), "list_databases")) {
        re_strbuf_puts(b, "{\"type\":\"object\",\"properties\":{},\"required\":[]}");
        return true;
    }
    if (re_str_eq_cstr(re_str(name), "save_database") ||
        re_str_eq_cstr(re_str(name), "close_database")) {
        re_strbuf_puts(b, "{\"type\":\"object\",\"properties\":{"
                          "\"instance_id\":{\"description\":\"Optional database instance id.\"}"
                          "},\"required\":[]}");
        return true;
    }
    return false;
}

char *num_tok(char (*tok)[24], int *n, long long v) {
    char *t = tok[(*n)++];
    std::snprintf(t, 24, "%lld", v);
    return t;
}

bool run_captured(re_ctx_t *ctx, const re_cmd_t *cmd, const char *path, char **argv, int argc,
                  re_strbuf_t *out, int *rc) {
    FILE *sink = std::tmpfile();
    if (!sink)
        return false;
    ctx->stream = sink;
    *rc = cmd->fn(ctx, path, argc, argv);
    std::rewind(sink);
    char chunk[4096];
    size_t got;
    while ((got = std::fread(chunk, 1, sizeof(chunk), sink)) > 0)
        re_strbuf_append(out, chunk, got);
    std::fclose(sink);
    while (out->len && (out->p[out->len - 1] == '\n' || out->p[out->len - 1] == '\r'))
        out->p[--out->len] = '\0';
    return out->len > 0;
}

} // namespace

void mcp_tool_error(re_strbuf_t *out, const char *msg, bool *is_error) {
    tool_error(out, "tool_error", msg, is_error);
}

void mcp_tool_schema(const re_cmd_t *cmd, re_strbuf_t *b) {
    if (schema_ida(cmd->name, b))
        return;
    bool first = true;
    re_strbuf_puts(b, "{\"type\":\"object\",\"properties\":{");
    if (cmd->needs_path) {
        prop(b, &first, "path", "string", "the file to read, an absolute or relative path");
        prop(b, &first, "session", "string", "unused; prefer open_database");
    }
    const ToolSpec *spec = spec_for(cmd->name);
    if (spec) {
        for (const ArgSpec &s : spec->args) {
            if (!s.json)
                break;
            prop(b, &first, s.json, s.is_num ? "integer" : "string", s.desc);
        }
    }
    prop(b, &first, "offset", "integer", "skip this many results");
    prop(b, &first, "limit", "integer", "return at most this many results");
    re_strbuf_puts(b, "},\"required\":[]}");
}

int build_argv_ida(const re_cmd_t *cmd, const re_jr_t *args, re_arena_t *a, char **argv) {
    int argc = 0;
    if (re_str_eq_cstr(re_str(cmd->name), "open_database")) {
        if (args && re_jr_has(args, "set_current") &&
            !re_jr_bool(re_jr_get(args, "set_current"), true))
            argv[argc++] = const_cast<char *>("0");
        return argc;
    }
    if (re_str_eq_cstr(re_str(cmd->name), "execute_python")) {
        re_str_t id = re_jr_str(re_jr_get(args, "instance_id"), "");
        re_str_t code = re_jr_str(re_jr_get(args, "code"), "");
        if (id.n)
            argv[argc++] = re_arena_strndup(a, id.p, id.n);
        if (code.n)
            argv[argc++] = re_arena_strndup(a, code.p, code.n);
        return argc;
    }
    if (re_str_eq_cstr(re_str(cmd->name), "reference")) {
        re_str_t q = re_jr_str(re_jr_get(args, "query"), "");
        if (q.n)
            argv[argc++] = re_arena_strndup(a, q.p, q.n);
        return argc;
    }
    if (re_str_eq_cstr(re_str(cmd->name), "close_database") ||
        re_str_eq_cstr(re_str(cmd->name), "save_database")) {
        re_str_t id = re_jr_str(re_jr_get(args, "instance_id"), "");
        if (id.n)
            argv[argc++] = re_arena_strndup(a, id.p, id.n);
        return argc;
    }
    return -1;
}

int build_argv(const re_cmd_t *cmd, const char *path, const re_jr_t *args, re_arena_t *a,
               char **argv, char (*tok)[24]) {
    int argc = build_argv_ida(cmd, args, a, argv);
    int ntok = 0;
    if (argc >= 0)
        return argc;
    argc = 0;
    if (cmd->needs_path)
        argv[argc++] = const_cast<char *>(path);
    const ToolSpec *spec = spec_for(cmd->name);
    if (spec && spec->args[0].json && !spec->args[0].flag) {
        re_str_t v = re_jr_str(re_jr_get(args, spec->args[0].json), "");
        if (v.n)
            argv[argc++] = re_arena_strndup(a, v.p, v.n);
    }
    int64_t limit = re_jr_i64(re_jr_get(args, "limit"), -1);
    if (limit > 0) {
        argv[argc++] = const_cast<char *>("--limit");
        argv[argc++] = num_tok(tok, &ntok, limit);
    }
    int64_t offset = re_jr_i64(re_jr_get(args, "offset"), -1);
    if (offset >= 0) {
        argv[argc++] = const_cast<char *>("--offset");
        argv[argc++] = num_tok(tok, &ntok, offset);
    }
    if (spec) {
        for (const ArgSpec &s : spec->args) {
            if (!s.json)
                break;
            if (!s.flag || !re_jr_has(args, s.json))
                continue;
            argv[argc++] = const_cast<char *>(s.flag);
            if (s.is_num) {
                argv[argc++] = num_tok(tok, &ntok, re_jr_i64(re_jr_get(args, s.json), 0));
            } else {
                re_str_t v = re_jr_str(re_jr_get(args, s.json), "");
                argv[argc++] = v.n ? re_arena_strndup(a, v.p, v.n) : const_cast<char *>("");
            }
        }
    }
    return argc;
}

void mcp_run_tool(const re_cmd_t *cmd, const char *path, const re_jr_t *args, re_arena_t *a,
                  re_strbuf_t *out, bool *is_error) {
    char tok[8][24];
    char *argv[16];
    int argc = build_argv(cmd, path, args, a, argv, tok);
    re_ctx_t ctx;
    re_err_t err;
    re_arena_t work;
    int rc = 0;
    std::memset(&ctx, 0, sizeof(ctx));
    re_arena_init(&work, 0);
    ctx.arena = &work;
    ctx.err = &err;
    ctx.out = RE_FMT_OUT_JSON;
    ctx.ida_shape = is_ida_tool(cmd->name);
    err.code = RE_OK;
    if (ctx.ida_shape) {
        if (cmd->needs_path && (!path || !path[0])) {
            tool_error(out, "usage", "no file: give path, or open one in the gui", is_error);
            re_arena_free(&work);
            return;
        }
        if (!run_captured(&ctx, cmd, path, argv, argc, out, &rc)) {
            if (err.code != RE_OK)
                tool_error(out, re_err_str(err.code), re_err_msg(&err), is_error);
            else
                tool_error(out, "no_response", "the command produced no response", is_error);
            re_arena_free(&work);
            return;
        }
        *is_error = rc != 0;
        re_arena_free(&work);
        return;
    }
    int first = 0;
    if (!re_cmd_parse(&ctx, argc, argv, &first, &err)) {
        tool_error(out, re_err_str(err.code), re_err_msg(&err), is_error);
        re_arena_free(&work);
        return;
    }
    const char *file = cmd->needs_path ? (first < argc ? argv[first] : path) : NULL;
    if (cmd->needs_path && !file) {
        tool_error(out, "usage", "no file: give path, or open_database / gui", is_error);
        re_arena_free(&work);
        return;
    }
    if (!run_captured(&ctx, cmd, file, argv + first, argc - first, out, &rc)) {
        if (err.code != RE_OK)
            tool_error(out, re_err_str(err.code), re_err_msg(&err), is_error);
        else
            tool_error(out, "no_response", "the command produced no response", is_error);
        re_arena_free(&work);
        return;
    }
    *is_error = rc != 0;
    re_arena_free(&work);
}
