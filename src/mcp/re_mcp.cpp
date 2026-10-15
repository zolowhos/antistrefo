// re_mcp.cpp - MCP JSON-RPC server, C++17 shell over the C11 core.
// Module: mcp (C++17).
// Owns: framing, the JSON-RPC dispatch, and ida-mcp tool list filtering.
// Depends: re_mcp.h, re_jr, re_table, re_cmds, re_mcp_live, re_mcp_db.
#include "mcp/re_mcp.h"

#include "utils/json/re_jr.h"
#include "utils/text/re_util.h"
#include "cli/app/re_table.h"
#include "cli/cmds/re_cmds.h"
#include "mcp/re_mcp_db.h"
#include "mcp/re_mcp_live.h"
#include "mcp/re_mcp_tools.h"

#include <cstdio>
#include <cstring>
#include <string>

#if defined(_WIN32)
#    include <fcntl.h>
#    include <io.h>
#else
#    include <unistd.h>
#endif

namespace {

// MCP uses newline delimited JSON-RPC, not the Content-Length framing that LSP
// style transports use. Getting this wrong silently corrupts the stream.
constexpr const char *kProtocolVersion = "2025-06-18";
constexpr const char *kName = "antistrefo";
constexpr const char *kVersion = "0.1.0";
constexpr const char *kInstructions =
    "antistrefo static analysis with an ida-mcp style tool surface (ELF, PE): "
    "open_database, then execute_query with op=funcs|disasm|decompile|xrefs|strings|.... "
    "Call reference(query) for ops. No Python. GUI live files appear in list_databases.";
// Note: avoid ASCII ';' in MCP JSON strings. CMake tests store frames in lists
// and treat ';' as a list separator.
constexpr int kFrameMax = 1 << 20;

static size_t text_len(const char *s) {
    size_t n = 0;
    while (s[n])
        n++;
    return n;
}

constexpr int kErrParse = -32700;
constexpr int kErrInvalid = -32600;
constexpr int kErrNoMethod = -32601;

struct Server {
    re_arena_t arena;
    void *wctx;
    re_mcp_write_fn write;
};

void write_frame(Server *srv, const char *json, size_t n) {
    if (srv && srv->write)
        srv->write(srv->wctx, json, n);
}

void send_error(Server *srv, re_arena_t *a, double id, int code, const char *msg) {
    re_strbuf_t b;
    re_strbuf_init(&b, a);
    re_strbuf_puts(&b, "{\"jsonrpc\":\"2.0\",\"id\":");
    re_strbuf_appendf(&b, "%lld", (long long)id);
    re_strbuf_puts(&b, ",\"error\":{\"code\":");
    re_strbuf_appendf(&b, "%d", code);
    re_strbuf_puts(&b, ",\"message\":");
    re_jr_escape(&b, re_str(msg));
    re_strbuf_puts(&b, "}}");
    write_frame(srv, b.p ? b.p : "{}", b.len);
}

void send_result(Server *srv, re_arena_t *a, double id, re_strbuf_t *result) {
    re_strbuf_t b;
    re_strbuf_init(&b, a);
    re_strbuf_puts(&b, "{\"jsonrpc\":\"2.0\",\"id\":");
    re_strbuf_appendf(&b, "%lld", (long long)id);
    re_strbuf_puts(&b, ",\"result\":");
    re_strbuf_append(&b, result->p ? result->p : "", result->len);
    re_strbuf_puts(&b, "}");
    write_frame(srv, b.p ? b.p : "{}", b.len);
}

void send_tool_result(Server *srv, re_arena_t *a, double id, re_strbuf_t *structured,
                      bool is_error) {
    re_strbuf_t b;
    re_str_t prose = re_str(structured->p ? structured->p : "");
    // Prefer object.text as the human-readable content when present.
    {
        re_jr_t root;
        if (structured->p && structured->len &&
            re_jr_parse(a, structured->p, structured->len, &root) && root.kind == RE_JR_OBJ) {
            re_str_t t = re_jr_str(re_jr_get(&root, "text"), "");
            if (t.n)
                prose = t;
        }
    }
    re_strbuf_init(&b, a);
    re_strbuf_puts(&b, "{\"jsonrpc\":\"2.0\",\"id\":");
    re_strbuf_appendf(&b, "%lld", (long long)id);
    re_strbuf_puts(&b, ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":");
    re_jr_escape(&b, prose);
    re_strbuf_puts(&b, "}],\"structuredContent\":");
    re_strbuf_append(&b, structured->p ? structured->p : "{}", structured->len);
    if (is_error)
        re_strbuf_puts(&b, ",\"isError\":true");
    re_strbuf_puts(&b, "}}");
    write_frame(srv, b.p ? b.p : "{}", b.len);
}

void handle_initialize(Server *srv, re_arena_t *a, double id) {
    re_strbuf_t b;
    re_strbuf_init(&b, a);
    re_strbuf_puts(&b, "{\"protocolVersion\":\"");
    re_strbuf_puts(&b, kProtocolVersion);
    re_strbuf_puts(&b, "\",\"capabilities\":{\"tools\":{\"listChanged\":false}}");
    re_strbuf_puts(&b, ",\"serverInfo\":{\"name\":\"");
    re_strbuf_puts(&b, kName);
    re_strbuf_puts(&b, "\",\"version\":\"");
    re_strbuf_puts(&b, kVersion);
    re_strbuf_puts(&b, "\"},\"instructions\":");
    re_jr_escape(&b, re_str(kInstructions));
    re_strbuf_puts(&b, "}");
    send_result(srv, a, id, &b);
}

static void handle_tools_call(Server *s, re_arena_t *a, double id, const re_jr_t *params) {
    re_str_t name = re_jr_str(re_jr_get(params, "name"), "");
    const re_jr_t *args = re_jr_get(params, "arguments");
    const re_cmd_t *cmd = re_cmd_find(name.p ? name.p : "");
    re_strbuf_t out;
    re_strbuf_init(&out, a);
    bool is_error = false;
    // Refresh GUI current on every tool dispatch so list_databases/status stay live.
    re_mcp_db_sync_live();
    if (!cmd || !cmd->mcp || !cmd->fn) {
        mcp_tool_error(&out, "no such tool", &is_error);
        send_tool_result(s, a, id, &out, is_error);
        return;
    }
    if (cmd->interactive) {
        mcp_tool_error(&out, "interactive tools are not available over MCP", &is_error);
        send_tool_result(s, a, id, &out, is_error);
        return;
    }
    const char *path = nullptr;
    if (args) {
        re_str_t direct = re_jr_str(re_jr_get(args, "path"), "");
        re_str_t iid = re_jr_str(re_jr_get(args, "instance_id"), "");
        // Honor instance_id when passed; otherwise fall through to GUI/current.
        if (iid.n) {
            const char *inst = re_arena_strndup(a, iid.p, iid.n);
            const char *p = re_mcp_db_path(inst);
            if (p)
                path = re_arena_strdup(a, p);
        }
        if (!path && direct.n)
            path = re_arena_strdup(a, direct.p);
    }
    if (!path) {
        const char *live = re_mcp_live_path();
        if (live)
            path = re_arena_strdup(a, live);
    }
    if (!path) {
        const char *cur = re_mcp_db_path(nullptr);
        if (cur)
            path = re_arena_strdup(a, cur);
    }
    if (cmd->needs_path && !path) {
        mcp_tool_error(&out, "no file: give path, open_database, or open one in the gui",
                       &is_error);
        send_tool_result(s, a, id, &out, is_error);
        return;
    }
    mcp_run_tool(cmd, path, args, a, &out, &is_error);
    send_tool_result(s, a, id, &out, is_error);
}

static const re_jr_t *params_of(const re_jr_t *req) {
    const re_jr_t *p = re_jr_get(req, "params");
    return p ? p : req;
}

static void handle_tools_list(Server *srv, re_arena_t *a, double id) {
    re_strbuf_t b;
    size_t n = 0;
    const re_cmd_t *table = re_cmd_table(&n);
    re_strbuf_init(&b, a);
    re_strbuf_puts(&b, "{\"tools\":[");
    size_t emitted = 0;
    for (size_t i = 0; i < n; i++) {
        if (!table[i].fn || table[i].interactive || !table[i].mcp)
            continue;
        if (emitted++)
            re_strbuf_putc(&b, ',');
        re_strbuf_puts(&b, "{\"name\":");
        re_jr_escape(&b, re_strn(table[i].name, text_len(table[i].name)));
        re_strbuf_puts(&b, ",\"description\":");
        re_jr_escape(&b, re_strn(table[i].summary, text_len(table[i].summary)));
        re_strbuf_puts(&b, ",\"inputSchema\":");
        mcp_tool_schema(&table[i], &b);
        re_strbuf_putc(&b, '}');
    }
    re_strbuf_puts(&b, "]}");
    send_result(srv, a, id, &b);
}

static void serve_frame(Server *srv, const char *line, size_t n) {
    re_arena_t req;
    re_jr_t root;
    re_arena_init(&req, 0);
    if (!re_jr_parse(&req, line, n, &root) || root.kind != RE_JR_OBJ) {
        send_error(srv, &req, 0, kErrParse, "malformed request");
        re_arena_free(&req);
        return;
    }
    double id = 0.0;
    const re_jr_t *idv = re_jr_get(&root, "id");
    bool is_notification = idv == nullptr;
    if (idv)
        id = (double)re_jr_i64(idv, 0);
    re_str_t method = re_jr_str(re_jr_get(&root, "method"), "");
    if (re_str_eq_cstr(method, "initialize"))
        handle_initialize(srv, &req, id);
    else if (re_str_eq_cstr(method, "tools/list"))
        handle_tools_list(srv, &req, id);
    else if (re_str_eq_cstr(method, "tools/call"))
        handle_tools_call(srv, &req, id, params_of(&root));
    else if (re_str_eq_cstr(method, "ping")) {
        re_strbuf_t empty;
        re_strbuf_init(&empty, &req);
        re_strbuf_putc(&empty, '{');
        re_strbuf_putc(&empty, '}');
        send_result(srv, &req, id, &empty);
    } else if (!is_notification) {
        send_error(srv, &req, id, kErrNoMethod, "method not implemented");
    }
    re_arena_free(&req);
}

size_t file_read_cb(void *ctx, char *buf, size_t cap) {
    // Go around stdio on purpose: fread waits for a full buffer or EOF, which
    // deadlocks an interactive client that keeps the stream open while it
    // waits for a response. read returns as soon as any bytes arrive.
#if defined(_WIN32)
    int n = _read(_fileno((FILE *)ctx), buf, (unsigned)cap);
#else
    ssize_t n = read(fileno((FILE *)ctx), buf, cap);
#endif
    return n > 0 ? (size_t)n : 0;
}

bool file_write_cb(void *ctx, const char *data, size_t n) {
    FILE *out = (FILE *)ctx;
    if (std::fwrite(data, 1, n, out) != n || std::fputc('\n', out) == EOF)
        return false;
    std::fflush(out);
    return true;
}

static int serve_loop(void *rctx, re_mcp_read_fn rf, void *wctx, re_mcp_write_fn wf) {
    Server srv;
    re_arena_init(&srv.arena, 256u * 1024u);
    srv.wctx = wctx;
    srv.write = wf;
    std::string line;
    line.reserve(4096);
    char buf[4096];
    size_t got;
    while ((got = rf(rctx, buf, sizeof(buf))) > 0) {
        for (size_t i = 0; i < got; i++) {
            if (buf[i] != '\n') {
                line.push_back(buf[i]);
                if (line.size() > (size_t)kFrameMax) {
                    send_error(&srv, &srv.arena, 0, kErrInvalid, "frame too large");
                    line.clear();
                }
                continue;
            }
            if (line.empty())
                continue;
            serve_frame(&srv, line.data(), line.size());
            line.clear();
        }
    }
    re_arena_free(&srv.arena);
    return 0;
}

} // namespace

const char *re_mcp_protocol_version(void) {
    return kProtocolVersion;
}

int re_mcp_serve_files(FILE *in, FILE *out) {
    FILE *src = in ? in : stdin;
    FILE *dst = out ? out : stdout;
    return serve_loop(src, file_read_cb, dst, file_write_cb);
}

int re_mcp_serve_callbacks(void *rctx, re_mcp_read_fn rf, void *wctx, re_mcp_write_fn wf) {
    if (!rf || !wf)
        return 2;
    return serve_loop(rctx, rf, wctx, wf);
}

int re_mcp_main(void) {
    // Mute logging outright. stdout carries protocol frames, so a stray write
    // there looks like a protocol violation to the client.
    re_log_set_mute(true);
#if defined(_WIN32)
    // Text mode would translate newlines on the protocol stream both ways.
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    return re_mcp_serve_files(stdin, stdout);
}
