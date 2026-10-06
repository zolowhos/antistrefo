// re_mcp_tools.cpp - argument translation and execution for the MCP tool surface.
// Module: mcp (C++17).
// Owns: the per command argument table and the run of one captured command.
// Depends: re_mcp_tools.h, re_cmds. Commands get the same argv shape the CLI passes.
#include "mcp/re_mcp_tools.h"

#include "cli/cmds/re_cmds.h"

#include <cstdio>
#include <cstring>

namespace {

// One argument a command reads beyond the file itself: the name it arrives under in
// a tool call, and the command line token it leaves as. A null flag means the value
// is positional and lands right after the file in argv. A command missing from the
// table takes no arguments beyond path, offset and limit, and its schema says so,
// which is the honest default.
struct ArgSpec {
    const char *json;
    const char *flag;
    const char *desc;
    bool is_num;
};

struct ToolSpec {
    const char *cmd;
    ArgSpec args[3];
};

constexpr ArgSpec kEnd = {NULL, NULL, NULL, false};
const ToolSpec kToolArgs[] = {
    {"disasm",
     {{"addr", NULL, "virtual address to start at; entry point when absent", false},
      {"len", "--len", "stop after this many instructions", true},
      kEnd}},
    {"decompile",
     {{"addr", NULL, "function to decompile; entry point when absent", false}, kEnd, kEnd}},
    {"cfg", {{"addr", NULL, "function to graph; entry point when absent", false}, kEnd, kEnd}},
    {"xrefs",
     {{"addr", NULL, "address to list references for; all when absent", false}, kEnd, kEnd}},
    {"funcs", {{"sigs", NULL, "a .pat signature file to name functions with", false}, kEnd, kEnd}},
    {"search",
     {{"pattern", NULL,
       "hex pairs with ? wildcards, or plain text; text:, imm: or sym: force a mode", false},
      kEnd,
      kEnd}},
    {"strings",
     {{"regex", "--regex", "case insensitive filter, applied to every string", false}, kEnd, kEnd}},
    {"demangle", {{"symbol", NULL, "the mangled symbol to demangle", false}, kEnd, kEnd}},
    {"hexdump",
     {{"off", "--off", "file offset to start at", true},
      {"rva", "--rva", "rva to start at", true},
      {"len", "--len", "how many bytes", true}}},
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

} // namespace

void mcp_tool_error(re_strbuf_t *out, const char *msg, bool *is_error) {
    tool_error(out, "tool_error", msg, is_error);
}

namespace {

// One numeric command line token at a time; the storage is the caller's because the
// argv outlives neither this call nor needs to.
char *num_tok(char (*tok)[24], int *n, long long v) {
    char *t = tok[(*n)++];
    std::snprintf(t, 24, "%lld", v);
    return t;
}

// Run the command with its output captured into a temporary file, the same seam the
// writer's FILE* interface forces everywhere else.
bool run_captured(re_ctx_t *ctx, const re_cmd_t *cmd, const char *path, char **argv, int argc,
                  re_strbuf_t *out) {
    FILE *sink = std::tmpfile();
    if (!sink)
        return false;
    ctx->stream = sink;
    cmd->fn(ctx, path, argc, argv);
    std::rewind(sink);
    char chunk[4096];
    size_t got;
    while ((got = std::fread(chunk, 1, sizeof(chunk), sink)) > 0)
        re_strbuf_append(out, chunk, got);
    std::fclose(sink);
    // A command ends its response with a newline, which is right on stdout and would
    // split a protocol frame here.
    while (out->len && (out->p[out->len - 1] == '\n' || out->p[out->len - 1] == '\r'))
        out->p[--out->len] = '\0';
    return out->len > 0;
}

} // namespace

void mcp_tool_schema(const re_cmd_t *cmd, re_strbuf_t *b) {
    bool first = true;
    re_strbuf_puts(b, "{\"type\":\"object\",\"properties\":{");
    if (cmd->needs_path) {
        prop(b, &first, "path", "string", "the file to read, an absolute or relative path");
        prop(b, &first, "session", "string", "a name from session_open, used instead of path");
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

// Build the argv the CLI would have built for this call: the file, then the one
// positional, then the paging flags, then the tool's own flags with their values.
// Returns how many tokens were written. tok is scratch for the numeric values.
int build_argv(const re_cmd_t *cmd, const char *path, const re_jr_t *args, re_arena_t *a,
               char **argv, char (*tok)[24]) {
    int argc = 0;
    int ntok = 0;
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
    // The tokens are assembled into the same argv the CLI would build, then parsed
    // once by the shared parser, so defaults, validation and the meaning of every
    // flag have exactly one implementation. argv[0] is the file for a path tool and
    // the one positional for a tool like demangle, which is what their commands read.
    char tok[8][24];
    char *argv[16];
    int argc = build_argv(cmd, path, args, a, argv, tok);
    re_ctx_t ctx;
    re_err_t err;
    re_arena_t work;
    std::memset(&ctx, 0, sizeof(ctx));
    re_arena_init(&work, 0);
    ctx.arena = &work;
    ctx.err = &err;
    ctx.out = RE_FMT_OUT_JSON;
    err.code = RE_OK;
    int first = 0;
    if (!re_cmd_parse(&ctx, argc, argv, &first, &err)) {
        tool_error(out, re_err_str(err.code), re_err_msg(&err), is_error);
        re_arena_free(&work);
        return;
    }
    const char *file = cmd->needs_path ? (first < argc ? argv[first] : NULL) : NULL;
    if (cmd->needs_path && !file) {
        tool_error(out, "usage", "no file: give path, or a session from session_open", is_error);
        re_arena_free(&work);
        return;
    }
    if (!run_captured(&ctx, cmd, file, argv + first, argc - first, out)) {
        if (err.code != RE_OK)
            tool_error(out, re_err_str(err.code), re_err_msg(&err), is_error);
        else
            tool_error(out, "no_response", "the command produced no response", is_error);
        re_arena_free(&work);
        return;
    }
    re_arena_free(&work);
    *is_error = false;
}
