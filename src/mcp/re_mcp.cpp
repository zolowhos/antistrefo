// re_mcp.cpp - MCP JSON-RPC server, C++17 shell over the C11 core.
// Module: mcp (C++17).
// Owns: framing, the JSON-RPC dispatch, and the session registry.
// Depends: re_mcp.h, re_jr, re_table, re_cmds, re_mcp_live. Frames on the given out.
#include "mcp/re_mcp.h"

#include "utils/json/re_jr.h"
#include "utils/text/re_util.h"
#include "cli/app/re_table.h"
#include "cli/cmds/re_cmds.h"
#include "mcp/re_mcp_live.h"
#include "mcp/re_mcp_tools.h"

#include <cstdio>
#include <cstring>
#include <string>

namespace {

// MCP uses newline delimited JSON-RPC, not the Content-Length framing that LSP
// style transports use. Getting this wrong silently corrupts the stream.
constexpr const char *kProtocolVersion = "2025-06-18";
constexpr const char *kName = "antistrefo";
constexpr const char *kVersion = "0.1.0";
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
constexpr int kErrParams = -32602;

struct Session {
    const char *name;
    const char *path;
};

struct Server {
    re_arena_t arena;
    Session sessions[16];
    size_t n_sessions;
    FILE *out;
};

void write_frame(Server *srv, const char *json, size_t n) {
    FILE *out = srv && srv->out ? srv->out : stdout;
    std::fwrite(json, 1, n, out);
    std::fputc('\n', out);
    std::fflush(out);
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
    re_strbuf_init(&b, a);
    re_strbuf_puts(&b, "{\"jsonrpc\":\"2.0\",\"id\":");
    re_strbuf_appendf(&b, "%lld", (long long)id);
    re_strbuf_puts(&b, ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":");
    re_jr_escape(&b, re_str(structured->p ? structured->p : ""));
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
    re_strbuf_puts(&b, "\"}}");
    send_result(srv, a, id, &b);
}

static const char *session_path(const Server &s, re_str_t name) {
    for (size_t i = 0; i < s.n_sessions; i++)
        if (re_str_eq(re_str(s.sessions[i].name), name))
            return s.sessions[i].path;
    return nullptr;
}

static void sessions_json(const Server &s, re_arena_t *a, re_strbuf_t *b) {
    (void)a;
    re_strbuf_puts(b, "{\"sessions\":[");
    for (size_t i = 0; i < s.n_sessions; i++) {
        if (i)
            re_strbuf_putc(b, ',');
        re_strbuf_puts(b, "{\"name\":");
        re_jr_escape(b, re_str(s.sessions[i].name));
        re_strbuf_puts(b, ",\"path\":");
        re_jr_escape(b, re_str(s.sessions[i].path));
        re_strbuf_putc(b, '}');
    }
    re_strbuf_puts(b, "]}");
}

static void session_open_json(Server *s, re_arena_t *a, const re_jr_t *args, re_strbuf_t *b,
                              const char **errmsg) {
    *errmsg = nullptr;
    re_str_t name = re_jr_str(re_jr_get(args, "name"), "");
    re_str_t path = re_jr_str(re_jr_get(args, "path"), "");
    if (!name.n || !path.n) {
        *errmsg = "session_open needs name and path";
        return;
    }
    if (session_path(*s, name)) {
        *errmsg = "that session name is already open";
        return;
    }
    if (s->n_sessions >= sizeof(s->sessions) / sizeof(s->sessions[0])) {
        *errmsg = "too many sessions open";
        return;
    }
    s->sessions[s->n_sessions].name = re_arena_strdup(&s->arena, name.p);
    s->sessions[s->n_sessions].path = re_arena_strdup(&s->arena, path.p);
    s->n_sessions++;
    sessions_json(*s, a, b);
}

static void handle_session_open(Server *s, re_arena_t *a, double id, const re_jr_t *args) {
    re_strbuf_t b;
    re_strbuf_init(&b, a);
    const char *errmsg = nullptr;
    session_open_json(s, a, args, &b, &errmsg);
    if (errmsg)
        send_error(s, a, id, kErrParams, errmsg);
    else
        send_result(s, a, id, &b);
}

static void handle_session_list(Server *s, re_arena_t *a, double id) {
    re_strbuf_t b;
    re_strbuf_init(&b, a);
    sessions_json(*s, a, &b);
    send_result(s, a, id, &b);
}

static bool call_session_tool(Server *s, re_arena_t *a, double id, re_str_t name,
                              const re_jr_t *args) {
    re_strbuf_t b;
    re_strbuf_init(&b, a);
    bool is_error = false;
    if (re_str_eq_cstr(name, "session_open")) {
        const char *errmsg = nullptr;
        session_open_json(s, a, args, &b, &errmsg);
        if (errmsg)
            mcp_tool_error(&b, errmsg, &is_error);
    } else if (re_str_eq_cstr(name, "session_list")) {
        sessions_json(*s, a, &b);
    } else {
        return false;
    }
    send_tool_result(s, a, id, &b, is_error);
    return true;
}

static void handle_tools_call(Server *s, re_arena_t *a, double id, const re_jr_t *params) {
    re_str_t name = re_jr_str(re_jr_get(params, "name"), "");
    const re_jr_t *args = re_jr_get(params, "arguments");
    if (call_session_tool(s, a, id, name, args))
        return;
    const re_cmd_t *cmd = re_cmd_find(name.p ? name.p : "");
    re_strbuf_t out;
    re_strbuf_init(&out, a);
    bool is_error = false;
    if (!cmd) {
        mcp_tool_error(&out, "no such tool", &is_error);
        send_tool_result(s, a, id, &out, is_error);
        return;
    }
    if (cmd->interactive) {
        re_strbuf_t msg;
        re_strbuf_init(&msg, a);
        re_jr_escape(&msg, name);
        re_strbuf_puts(&msg, " is interactive, and is not available over MCP");
        mcp_tool_error(&out, msg.p ? msg.p : "interactive", &is_error);
        send_tool_result(s, a, id, &out, is_error);
        return;
    }
    const char *path = nullptr;
    if (args) {
        re_str_t direct = re_jr_str(re_jr_get(args, "path"), "");
        re_str_t sess = re_jr_str(re_jr_get(args, "session"), "");
        if (direct.n)
            path = re_arena_strdup(a, direct.p);
        else if (sess.n)
            path = session_path(*s, sess);
    }
    // GUI-hosted MCP publishes the open file; tools may omit path and use it.
    if (!path) {
        const char *live = re_mcp_live_path();
        if (live)
            path = re_arena_strdup(a, live);
    }
    if (cmd->needs_path && !path) {
        mcp_tool_error(&out, "no file: give path, a session, or open one in the gui", &is_error);
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

static void session_tools(re_strbuf_t *b) {
    re_strbuf_puts(b, ",");
    re_strbuf_puts(b, "{");
    re_strbuf_puts(b, "\"name\":\"session_open\",");
    re_strbuf_puts(b, "\"description\":");
    re_jr_escape(b, re_str("register a file under a name, so later calls can pass the name"));
    re_strbuf_puts(b, ",");
    re_strbuf_puts(b, "\"inputSchema\":{");
    re_strbuf_puts(b, "\"type\":\"object\",");
    re_strbuf_puts(b, "\"properties\":{");
    re_strbuf_puts(b, "\"name\":{\"type\":\"string\"},");
    re_strbuf_puts(b, "\"path\":{\"type\":\"string\"}}");
    re_strbuf_puts(b, ",\"required\":[\"name\",\"path\"]}}");
    re_strbuf_puts(b, ",");
    re_strbuf_puts(b, "{");
    re_strbuf_puts(b, "\"name\":\"session_list\",");
    re_strbuf_puts(b, "\"description\":");
    re_jr_escape(b, re_str("list the files currently registered by session_open"));
    re_strbuf_puts(b, ",");
    re_strbuf_puts(b, "\"inputSchema\":{");
    re_strbuf_puts(b, "\"type\":\"object\",\"properties\":{},\"required\":[]}}");
}

static void handle_tools_list(Server *srv, re_arena_t *a, double id) {
    re_strbuf_t b;
    size_t n = 0;
    const re_cmd_t *table = re_cmd_table(&n);
    re_strbuf_init(&b, a);
    re_strbuf_puts(&b, "{\"tools\":[");
    size_t emitted = 0;
    for (size_t i = 0; i < n; i++) {
        if (!table[i].fn || table[i].interactive)
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
    session_tools(&b);
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
    else if (re_str_eq_cstr(method, "session/open"))
        handle_session_open(srv, &req, id, params_of(&root));
    else if (re_str_eq_cstr(method, "session/list"))
        handle_session_list(srv, &req, id);
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

static int serve_loop(FILE *in, FILE *out) {
    Server srv;
    re_arena_init(&srv.arena, 256u * 1024u);
    srv.n_sessions = 0;
    srv.out = out ? out : stdout;
    std::string line;
    line.reserve(4096);
    int c;
    FILE *src = in ? in : stdin;
    while ((c = std::fgetc(src)) != EOF) {
        if (c != '\n') {
            line.push_back((char)c);
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
    re_arena_free(&srv.arena);
    return 0;
}

} // namespace

const char *re_mcp_protocol_version(void) {
    return kProtocolVersion;
}

int re_mcp_serve_files(FILE *in, FILE *out) {
    return serve_loop(in, out);
}

int re_mcp_main(void) {
    // Mute logging outright. stdout carries protocol frames, so a stray write
    // there looks like a protocol violation to the client.
    re_log_set_mute(true);
    return serve_loop(stdin, stdout);
}
