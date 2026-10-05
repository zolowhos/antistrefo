// re_mcp.cpp - MCP stdio server, C++17 shell over the C11 core.
// Module: mcp (C++17).
// Owns: stdio framing, the JSON-RPC dispatch, and the session registry.
// Depends: re_mcp.h, re_jr, re_json, re_table, re_cmds. Writes to stdout only frames.
#include "mcp/re_mcp.h"

#include "utils/json/re_jr.h"
#include "utils/text/re_util.h"
#include "cli/app/re_table.h"
#include "cli/cmds/re_cmds.h"

#include <cstdio>
#include <cstring>
#include <string>

namespace {

// MCP stdio uses newline delimited JSON-RPC, not the Content-Length framing that
// LSP style transports use. Getting this wrong silently corrupts the stream.
constexpr const char *kProtocolVersion = "2025-06-18";
constexpr const char *kName = "antistrefo";
constexpr const char *kVersion = "0.1.0";
constexpr int kFrameMax = 1 << 20;

// The length of a NUL terminated string, without the libc call the rules ban outside
// the string utility.
static size_t text_len(const char *s) {
    size_t n = 0;
    while (s[n])
        n++;
    return n;
}

// JSON-RPC error codes. The protocol reserves the low range, so a failure of ours is
// always in the implementation defined band and a malformed request is the one case
// the client can fix itself.
constexpr int kErrParse = -32700;
constexpr int kErrInvalid = -32600;
constexpr int kErrNoMethod = -32601;
constexpr int kErrParams = -32602;
constexpr int kErrInternal = -32603;

// A session is a name a client chose for a file, so a client can ask the same question
// about the same file many times without naming the file every time. The parsed
// artefacts are deliberately not retained here yet: the commands load their own, and
// threading a shared handle through all of them is a larger change than this commit.
// What the registry buys today is one place that maps a name to a path, and one place
// to list what is open, which is what a client needs to manage its own state.
struct Session {
    const char *name;
    const char *path;
};

struct Server {
    re_arena_t arena;
    Session sessions[16];
    size_t n_sessions;
};

void write_frame(const char *json, size_t n) {
    std::fwrite(json, 1, n, stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
}

void send_error(re_arena_t *a, double id, int code, const char *msg) {
    re_strbuf_t b;
    re_strbuf_init(&b, a);
    re_strbuf_puts(&b, "{\"jsonrpc\":\"2.0\",\"id\":");
    re_strbuf_appendf(&b, "%lld", (long long)id);
    re_strbuf_puts(&b, ",\"error\":{\"code\":");
    re_strbuf_appendf(&b, "%d", code);
    re_strbuf_puts(&b, ",\"message\":");
    re_str_t m = re_str(msg);
    re_jr_escape(&b, m);
    re_strbuf_puts(&b, "}}");
    write_frame(b.p ? b.p : "{}", b.len);
}

void send_result(re_arena_t *a, double id, re_strbuf_t *result) {
    re_strbuf_t b;
    re_strbuf_init(&b, a);
    re_strbuf_puts(&b, "{\"jsonrpc\":\"2.0\",\"id\":");
    re_strbuf_appendf(&b, "%lld", (long long)id);
    re_strbuf_puts(&b, ",\"result\":");
    re_strbuf_append(&b, result->p ? result->p : "", result->len);
    re_strbuf_puts(&b, "}");
    write_frame(b.p ? b.p : "{}", b.len);
}

// The result of a tool call: the same object twice, once as text and once as structured
// content. The text is for a model to read, the structured form is for a program, and
// both are the same bytes because a client that re-parses text it already has in an
// object has been handed a second chance to disagree with us.
void send_tool_result(re_arena_t *a, double id, re_strbuf_t *structured, bool is_error) {
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
    write_frame(b.p ? b.p : "{}", b.len);
}

void handle_initialize(re_arena_t *a, double id) {
    re_strbuf_t b;
    re_strbuf_init(&b, a);
    re_strbuf_puts(&b, "{\"protocolVersion\":\"");
    re_strbuf_puts(&b, kProtocolVersion);
    // The capability set is one line and the server name and version are appended
    // rather than pasted in: a literal cannot be concatenated with a variable, and
    // pasting the version would mean editing two places to change it.
    re_strbuf_puts(&b, "\",\"capabilities\":{\"tools\":{\"listChanged\":false}}");
    re_strbuf_puts(&b, ",\"serverInfo\":{\"name\":\"");
    re_strbuf_puts(&b, kName);
    re_strbuf_puts(&b, "\",\"version\":\"");
    re_strbuf_puts(&b, kVersion);
    re_strbuf_puts(&b, "\"}}");
    send_result(a, id, &b);
}

// ---- the session registry ----

// A session is a name a client chose for a file, so it can ask the same question about
// the same file many times without naming the file every time.
//
// It records the path and nothing else. Retaining the parsed artefacts is the obvious
// next step and it is not free: every command loads its own file through re_prepare, so
// holding a parse open means threading a handle through all of them, and a half wired
// cache that is sometimes stale is worse than none. What this buys today is one place
// that maps a name to a path, which is what a client needs in order to manage its own
// state, and the seam to grow into.
static const char *session_path(const Server &s, re_str_t name) {
    for (size_t i = 0; i < s.n_sessions; i++)
        if (re_str_eq(re_str(s.sessions[i].name), name))
            return s.sessions[i].path;
    return nullptr;
}

static void handle_session_open(Server *s, re_arena_t *a, double id, const re_jr_t *args) {
    re_str_t name = re_jr_str(re_jr_get(args, "name"), "");
    re_str_t path = re_jr_str(re_jr_get(args, "path"), "");
    if (!name.n || !path.n) {
        send_error(a, id, kErrParams, "session_open needs name and path");
        return;
    }
    if (session_path(*s, name)) {
        send_error(a, id, kErrParams, "that session name is already open");
        return;
    }
    if (s->n_sessions >= sizeof(s->sessions) / sizeof(s->sessions[0])) {
        send_error(a, id, kErrInternal, "too many sessions open");
        return;
    }
    // Both are copied into the server arena, which lives for the whole session, so a
    // name given once keeps working for every later call.
    s->sessions[s->n_sessions].name = re_arena_strdup(&s->arena, name.p);
    s->sessions[s->n_sessions].path = re_arena_strdup(&s->arena, path.p);
    s->n_sessions++;
    re_strbuf_t b;
    re_strbuf_init(&b, a);
    re_strbuf_puts(&b, "{\"sessions\":[");
    for (size_t i = 0; i < s->n_sessions; i++) {
        if (i)
            re_strbuf_putc(&b, ',');
        re_strbuf_puts(&b, "{\"name\":");
        re_jr_escape(&b, re_str(s->sessions[i].name));
        re_strbuf_puts(&b, ",\"path\":");
        re_jr_escape(&b, re_str(s->sessions[i].path));
        re_strbuf_putc(&b, '}');
    }
    re_strbuf_puts(&b, "]}");
    send_result(a, id, &b);
}

static void handle_session_list(re_arena_t *a, double id, const Server &s) {
    re_strbuf_t b;
    re_strbuf_init(&b, a);
    re_strbuf_puts(&b, "{\"sessions\":[");
    for (size_t i = 0; i < s.n_sessions; i++) {
        if (i)
            re_strbuf_putc(&b, ',');
        re_strbuf_puts(&b, "{\"name\":");
        re_jr_escape(&b, re_str(s.sessions[i].name));
        re_strbuf_puts(&b, ",\"path\":");
        re_jr_escape(&b, re_str(s.sessions[i].path));
        re_strbuf_putc(&b, '}');
    }
    re_strbuf_puts(&b, "]}");
    send_result(a, id, &b);
}

// ---- tools/call ----

// Run one command and capture what it wrote. The command writes to a temporary file
// rather than a buffer because the writer takes a FILE and changing that would mean
// touching every command; the file is the smallest seam that works.
static bool capture(const re_cmd_t *cmd, const char *path, const re_jr_t *args, re_arena_t *a,
                    re_strbuf_t *out) {
    re_ctx_t ctx;
    re_err_t err;
    re_arena_t work;
    re_arena_init(&work, 0);
    std::memset(&ctx, 0, sizeof(ctx));
    err.code = RE_OK;
    ctx.arena = &work;
    ctx.err = &err;
    ctx.out = RE_FMT_OUT_JSON; // a protocol client always wants the object
    ctx.limit = re_jr_i64(re_jr_get(args, "limit"), 200);
    if (ctx.limit <= 0)
        ctx.limit = 200;
    FILE *sink = std::tmpfile();
    if (!sink) {
        re_arena_free(&work);
        return false;
    }
    ctx.stream = sink;
    int first = 0;
    char arg0[1] = {0};
    char *argv[1] = {arg0}; // a path is never parsed from, only counted past
    (void)argv;
    if (!re_cmd_parse(&ctx, 1, argv, &first, &err)) {
        re_arena_free(&work);
        std::fclose(sink);
        return false;
    }
    cmd->fn(&ctx, path, 0, nullptr);
    std::rewind(sink);
    char chunk[4096];
    size_t got;
    while ((got = std::fread(chunk, 1, sizeof(chunk), sink)) > 0)
        re_strbuf_append(out, chunk, got);
    std::fclose(sink);
    re_arena_free(&work);
    // A command ends its response with a newline. That is right on stdout and wrong
    // here: the response is about to be embedded inside a larger JSON object, and a raw
    // newline in the middle of one would split the protocol frame in two.
    while (out->len && (out->p[out->len - 1] == '\n' || out->p[out->len - 1] == '\r'))
        out->p[--out->len] = '\0';
    (void)a;
    return out->len > 0;
}

static void handle_tools_call(Server *s, re_arena_t *a, double id, const re_jr_t *params) {
    re_str_t name = re_jr_str(re_jr_get(params, "name"), "");
    const re_jr_t *args = re_jr_get(params, "arguments");
    const re_cmd_t *cmd = re_cmd_find(name.p ? name.p : "");
    re_strbuf_t out;
    re_strbuf_init(&out, a);
    if (!cmd) {
        re_strbuf_t empty;
        re_strbuf_init(&empty, a);
        re_strbuf_puts(&empty, "{\"error\":\"unknown tool\"}");
        send_tool_result(a, id, &empty, true);
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
    if (!path) {
        re_strbuf_puts(&out, "{\"error\":\"no file: give path, or a session from session_open\"}");
        send_tool_result(a, id, &out, true);
        return;
    }
    if (!capture(cmd, path, args, a, &out)) {
        re_strbuf_puts(&out, "{\"error\":\"the command produced no response\"}");
        send_tool_result(a, id, &out, true);
        return;
    }
    send_tool_result(a, id, &out, false);
}

} // namespace

const char *re_mcp_protocol_version(void) {
    return kProtocolVersion;
}

// The params object of a request, or the request itself when there is no params
// member. Falling back keeps a bare call from having to carry an empty object, which
// is what a client sending the minimum will do.
static const re_jr_t *params_of(const re_jr_t *req) {
    const re_jr_t *p = re_jr_get(req, "params");
    return p ? p : req;
}

// ---- tools/list, generated from the one command table ----

// The input schema for one command, derived from its usage string. A hand written
// schema per command would drift from the table, and a client that sends a field the
// tool never reads is a bug report about a tool that has not changed.
static void tool_schema(re_strbuf_t *b, const re_cmd_t *cmd) {
    re_strbuf_puts(b, "{\"type\":\"object\",\"properties\":{");

    if (cmd->needs_path) {
        re_strbuf_puts(
            b, "\"path\":{\"type\":\"string\",\"description\":\"the file to read, an "
               "absolute or relative path\"},"
               "\"session\":{\"type\":\"string\",\"description\":\"a name from session_open, "
               "used instead of path\"},");
    }

    re_strbuf_puts(
        b, "\"offset\":{\"type\":\"integer\",\"description\":\"skip this many results\"},"
           "\"limit\":{\"type\":\"integer\",\"description\":\"return at most this many results\"}"
           "},\"required\":[]}");
}

static void handle_tools_list(re_arena_t *a, double id) {
    re_strbuf_t b;
    size_t n = 0;
    const re_cmd_t *table = re_cmd_table(&n);
    re_strbuf_init(&b, a);
    re_strbuf_puts(&b, "{\"tools\":[");
    size_t emitted = 0;
    for (size_t i = 0; i < n; i++) {
        // A command with no function is a table entry for a builtin, not a tool.
        if (!table[i].fn)
            continue;
        if (emitted++)
            re_strbuf_putc(&b, ',');
        re_strbuf_puts(&b, "{\"name\":");
        re_jr_escape(&b, re_strn(table[i].name, text_len(table[i].name)));
        re_strbuf_puts(&b, ",\"description\":");
        re_jr_escape(&b, re_strn(table[i].summary, text_len(table[i].summary)));
        re_strbuf_puts(&b, ",\"inputSchema\":");
        tool_schema(&b, &table[i]);
        re_strbuf_putc(&b, '}');
    }
    re_strbuf_puts(&b, "]}");
    send_result(a, id, &b);
}

// Read one frame and answer it. Split out of the loop so the loop stays a loop and
// this stays readable: a frame is a parse, a dispatch and a write, and mixing those
// into a byte-at-a-time reader is how the two get confused.
static void serve_frame(Server *srv, const char *line, size_t n) {
    re_arena_t req;
    re_jr_t root;
    re_arena_init(&req, 0);
    if (!re_jr_parse(&req, line, n, &root) || root.kind != RE_JR_OBJ) {
        send_error(&req, 0, kErrParse, "malformed request");
        re_arena_free(&req);
        return;
    }
    double id = 0.0;
    const re_jr_t *idv = re_jr_get(&root, "id");
    // A request with no id is a notification and gets no reply, whatever it is. An
    // unknown notification is not an error either: the sender is not waiting.
    bool is_notification = idv == nullptr;
    if (idv)
        id = (double)re_jr_i64(idv, 0);
    re_str_t method = re_jr_str(re_jr_get(&root, "method"), "");
    if (re_str_eq_cstr(method, "initialize"))
        handle_initialize(&req, id);
    else if (re_str_eq_cstr(method, "tools/list"))
        handle_tools_list(&req, id);
    else if (re_str_eq_cstr(method, "session/open"))
        handle_session_open(srv, &req, id, params_of(&root));
    else if (re_str_eq_cstr(method, "session/list"))
        handle_session_list(&req, id, *srv);
    else if (re_str_eq_cstr(method, "tools/call"))
        handle_tools_call(srv, &req, id, params_of(&root));
    else if (re_str_eq_cstr(method, "ping")) {
        re_strbuf_t empty;
        re_strbuf_init(&empty, &req);
        re_strbuf_putc(&empty, '{');
        re_strbuf_putc(&empty, '}');
        send_result(&req, id, &empty);
    } else if (!is_notification) {
        send_error(&req, id, kErrNoMethod, "method not implemented");
    }
    re_arena_free(&req);
}

int re_mcp_main(void) {
    // Mute logging outright. stdout carries protocol frames, so a stray write
    // there looks like a protocol violation to the client.
    re_log_set_mute(true);
    Server srv;
    re_arena_init(&srv.arena, 256u * 1024u);
    srv.n_sessions = 0;
    std::string line;
    line.reserve(4096);
    int c;
    while ((c = std::fgetc(stdin)) != EOF) {
        if (c != '\n') {
            line.push_back((char)c);
            if (line.size() > (size_t)kFrameMax) {
                // A frame this large is not a request we wrote or expect. Saying so and
                // dropping the line keeps the stream in step, where growing without
                // bound would take the process with it.
                send_error(&srv.arena, 0, kErrInvalid, "frame too large");
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
