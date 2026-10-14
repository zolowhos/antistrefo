// re_mcp_query.c - in-process op dispatch for execute_query (no Python).
// Module: mcp (C11).
// Owns: the allow-listed op table and captured re_cmd_* invocation.
// Depends: re_mcp_query.h, re_table, re_cmds. Calls commands, never shells out.
#include "mcp/re_mcp_query.h"

#include "utils/json/re_jr.h"
#include "utils/mem/re_arena.h"
#include "utils/text/re_str.h"
#include "cli/app/re_table.h"
#include "cli/cmds/re_cmds.h"

#include <stdio.h>
#include <string.h>

static char kFlagLen[] = "--len";
static char kFlagOff[] = "--off";
static char kFlagRva[] = "--rva";
static char kFlagRegex[] = "--regex";
static char kFlagLimit[] = "--limit";
static char kFlagOffset[] = "--offset";

static bool op_allowed(const char *op) {
    static const char *kOps[] = {"info",    "triage", "sections", "imports", "exports",
                                 "strings", "funcs",  "xrefs",    "disasm",  "decompile",
                                 "cfg",     "search", "hexdump",  "regions", "jtables",
                                 "entropy", "rules",  "vtables",  "analyze", "demangle"};
    for (size_t i = 0; i < sizeof(kOps) / sizeof(kOps[0]); i++) {
        if (re_str_eq_cstr(re_str(op), kOps[i]))
            return true;
    }
    return false;
}

static void err_json(re_strbuf_t *out, const char *code, const char *msg) {
    re_strbuf_puts(out, "{\"error\":{\"code\":");
    re_jr_escape(out, re_str(code));
    re_strbuf_puts(out, ",\"message\":");
    re_jr_escape(out, re_str(msg));
    re_strbuf_puts(out, "}}");
}

static int push_u64(char **argv, int argc, char (*tok)[24], int *ntok, char *flag, uint64_t v) {
    char *t = tok[(*ntok)++];
    snprintf(t, 24, "%llu", (unsigned long long)v);
    argv[argc++] = flag;
    argv[argc++] = t;
    return argc;
}

static bool capture_cmd(const re_cmd_t *cmd, const char *path, char **argv, int argc, re_arena_t *a,
                        re_strbuf_t *out, re_err_t *err) {
    re_ctx_t ctx;
    FILE *sink;
    char chunk[4096];
    size_t got;
    int first = 0;
    memset(&ctx, 0, sizeof(ctx));
    ctx.arena = a;
    ctx.err = err;
    ctx.out = RE_FMT_OUT_JSON;
    err->code = RE_OK;
    if (!re_cmd_parse(&ctx, argc, argv, &first, err))
        return false;
    sink = tmpfile();
    if (!sink) {
        RE_ERR_SET(err, RE_E_IO, "cannot capture query output");
        return false;
    }
    ctx.stream = sink;
    cmd->fn(&ctx, path, argc - first, argv + first);
    rewind(sink);
    while ((got = fread(chunk, 1, sizeof(chunk), sink)) > 0)
        re_strbuf_append(out, chunk, got);
    fclose(sink);
    while (out->len && (out->p[out->len - 1] == '\n' || out->p[out->len - 1] == '\r'))
        out->p[--out->len] = '\0';
    return out->len > 0 && err->code == RE_OK;
}

bool re_mcp_query_run(re_arena_t *a, const char *db_path, const char *op, const char *arg,
                      uint64_t len, uint64_t off, uint64_t rva, bool has_len, bool has_off,
                      bool has_rva, const char *regex, size_t limit, size_t offset,
                      re_strbuf_t *out, re_err_t *err) {
    const re_cmd_t *cmd;
    char *argv[16];
    char tok[8][24];
    int argc = 0;
    int ntok = 0;
    if (!op || !op[0] || !op_allowed(op)) {
        err_json(out, "usage", "unknown op - see reference(query)");
        RE_ERR_SET(err, RE_E_USAGE, "unknown execute_query op");
        return false;
    }
    cmd = re_cmd_find(op);
    if (!cmd || !cmd->fn) {
        err_json(out, "internal", "op has no command entry");
        RE_ERR_SET(err, RE_E_INTERNAL, "missing command");
        return false;
    }
    if (cmd->needs_path && (!db_path || !db_path[0])) {
        err_json(out, "usage", "no database - call open_database first");
        RE_ERR_SET(err, RE_E_USAGE, "no database");
        return false;
    }
    if (cmd->needs_path)
        argv[argc++] = re_arena_strdup(a, db_path);
    if (arg && arg[0] && !re_str_eq_cstr(re_str(op), "hexdump"))
        argv[argc++] = re_arena_strdup(a, arg);
    if (has_len)
        argc = push_u64(argv, argc, tok, &ntok, kFlagLen, len);
    if (has_off)
        argc = push_u64(argv, argc, tok, &ntok, kFlagOff, off);
    if (has_rva)
        argc = push_u64(argv, argc, tok, &ntok, kFlagRva, rva);
    if (regex && regex[0]) {
        argv[argc++] = kFlagRegex;
        argv[argc++] = re_arena_strdup(a, regex);
    }
    if (limit)
        argc = push_u64(argv, argc, tok, &ntok, kFlagLimit, (uint64_t)limit);
    if (offset)
        argc = push_u64(argv, argc, tok, &ntok, kFlagOffset, (uint64_t)offset);
    if (!capture_cmd(cmd, cmd->needs_path ? db_path : NULL, argv, argc, a, out, err)) {
        if (err->code == RE_OK)
            err_json(out, "no_response", "query produced no response");
        else
            err_json(out, re_err_str(err->code), re_err_msg(err));
        return false;
    }
    return true;
}

const char *re_mcp_query_reference(const char *query) {
    static const char kDefault[] =
        "execute_query ops (native, no Python):\n"
        "  info triage sections imports exports strings funcs xrefs\n"
        "  disasm decompile cfg search hexdump regions jtables\n"
        "  entropy rules vtables analyze demangle\n"
        "Args: op, optional addr/pattern, len, off, rva, regex, limit, offset.\n"
        "Example: op=decompile addr=0x180001000\n"
        "Example: op=strings regex=http\n"
        "open_database first. save_database is unsupported.\n";
    static const char kDecomp[] = "Decompile: execute_query op=decompile addr=<ea>\n"
                                  "Returns Tier B C-like source in result.source.\n";
    static const char kXref[] = "Xrefs: execute_query op=xrefs addr=<ea>\n";
    static const char kStr[] = "Strings: execute_query op=strings [regex=<filter>]\n";
    if (!query || !query[0])
        return kDefault;
    {
        re_str_t q = re_str(query);
        if (re_str_find_cstr(q, "decomp", 0) >= 0 || re_str_find_cstr(q, "hexray", 0) >= 0)
            return kDecomp;
        if (re_str_find_cstr(q, "xref", 0) >= 0)
            return kXref;
        if (re_str_find_cstr(q, "string", 0) >= 0)
            return kStr;
    }
    return kDefault;
}
