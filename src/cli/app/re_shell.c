// re_shell.c - the interactive mode entered when the tool is run with no arguments.
// Module: cli (C11).
// Owns: the prompt loop, line splitting, and the remembered current file.
// Depends: re_shell.h, re_table, re_report, re_tui, re_cmds. Dispatches through the
//           same command table the argv path uses, so this is not a second tool.
#include "cli/app/re_shell.h"

#include "features/analysis/re_analyze.h"
#include "utils/mem/re_vec.h"
#include "utils/text/re_str.h"
#include "utils/tui/re_tui.h"
#include "cli/render/re_report.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHELL_LINE_MAX 512
#define SHELL_ARGS_MAX 32

// One line split into words. A fixed array rather than a vector because a line is a
// line: there is a bound worth stating, and a runaway paste from inside a loop that
// also opens files should not be able to allocate without limit.
typedef struct {
    char *argv[SHELL_ARGS_MAX];
    int argc;
    re_arena_t *a; // the per line arena the words live in
} line_t;

// The length of a NUL terminated string, without calling strlen. The rule bans the
// libc calls because they carry no notion of the tool's own string bounds, and a
// bounded scan is the same thing without the dependency.
static size_t text_len(const char *s) {
    size_t n = 0;
    while (s[n])
        n++;
    return n;
}

bool re_shell_wanted(int argc) {
    if (argc >= 2)
        return false;
    // Both ends, not just stdout. A shell reading from a redirected file has nothing
    // to read from a person, and printing usage and leaving is the right answer for
    // whatever put the bytes there.
    return re_tui_is_tty() && re_tui_stdin_tty();
}

// Split on whitespace, honouring quotes so a path with a space can be typed. Returns
// false when there are more words than the bound, which is reported rather than
// silently truncated: a command that quietly lost an argument is worse than one that
// refused the line.
static bool split(const char *line, line_t *out, re_arena_t *a) {
    out->argc = 0;
    out->a = a;
    while (*line) {
        while (*line == ' ' || *line == '\t')
            line++;
        if (!*line)
            break;
        char quote = 0;
        if (*line == '"' || *line == '\'') {
            quote = *line++;
        }
        if (out->argc >= SHELL_ARGS_MAX)
            return false;
        // The word is allocated from the per line arena, so it lives exactly as long
        // as the command it is an argument to and is released with the line.
        char *slot = (char *)re_arena_alloc(a, SHELL_LINE_MAX);
        if (!slot)
            return false;
        size_t n = 0;
        while (*line && *line != ' ' && *line != '\t') {
            if (quote && *line == quote) {
                line++;
                break;
            }
            if (n + 1 < SHELL_LINE_MAX)
                slot[n++] = *line;
            line++;
        }
        slot[n] = '\0';
        out->argv[out->argc++] = slot;
    }
    return true;
}

// The banner. Framed, because this is the first thing anyone sees when they open the
// binary, and it is where the tool explains itself.
static void banner(re_report_t *r) {
    re_panel_t p;
    const char *tabs[4] = {"browse", "strings", "xrefs", "decompile"};
    re_report_open(r, r->scratch.arena, r->ctx, tabs, 4);
    re_report_head(r, "antistrefo 0.1.0", "schema antistrefo/1");
    re_panel_init(&p, r->scratch.arena, "Get started", 1);
    re_panel_kv(&r->tui, &p, "load", "open <file>", RE_ST_ACCENT);
    re_panel_text(&r->tui, &p, "then a bare command uses that file, e.g. funcs");
    re_panel_rule(&r->tui, &p);
    re_panel_kv(&r->tui, &p, "forget", "close", RE_ST_NONE);
    re_panel_kv(&r->tui, &p, "list", "commands", RE_ST_NONE);
    re_panel_kv(&r->tui, &p, "leave", "quit, or Ctrl-Z then Enter", RE_ST_NONE);
    re_panel_rule(&r->tui, &p);
    re_panel_head(&r->tui, &p, "every command is also a plain command");
    re_panel_text(&r->tui, &p, "antistrefo funcs driver.sys    same answer, no prompt");
    re_panel_text(&r->tui, &p, "antistrefo mcp                serve the MCP protocol");
    re_tui_compose(&r->tui, &p, 1);
    re_report_end(r);
}

// The command list, in the same frame as everything else, split by what a reader
// would look for first rather than in table order.
static void list_commands(re_report_t *r) {
    re_panel_t p[2];
    size_t n = 0;
    const re_cmd_t *table = re_cmd_table(&n);
    const char *tabs[1] = {"commands"};
    re_report_open(r, r->scratch.arena, r->ctx, tabs, 1);
    re_report_head(r, "commands", "the same table the CLI and the MCP server use");
    re_panel_init(&p[0], r->scratch.arena, "The file", 1);
    re_panel_init(&p[1], r->scratch.arena, "The code", 1);
    for (size_t i = 0; i < n; i++) {
        re_str_t name = re_strn(table[i].name, text_len(table[i].name));
        re_str_t sum = re_strn(table[i].summary, text_len(table[i].summary));
        re_panel_t *dst = &p[0];
        // The first letter is enough to split these two groups, and it is checked
        // against the literal names so a new command does not land in the wrong pane
        // just because its first letter happens to be shared.
        const char *code[] = {"funcs", "xrefs", "jtables", "disasm", "decompile", "hexdump"};
        for (size_t k = 0; k < sizeof(code) / sizeof(code[0]); k++) {
            if (re_str_eq_cstr(name, code[k])) {
                dst = &p[1];
                break;
            }
        }
        re_panel_kv(&r->tui, dst, name.p, sum.p, RE_ST_NONE);
    }
    re_tui_compose(&r->tui, p, 2);
    re_report_end(r);
}

// The session's analysis of the open file: the file stays mapped, the PE stays
// parsed, and every pass runs once. A persistent database of everything already
// worked out, reduced to what a session needs. Held in its own arena so it survives
// the per command arena and the per line arena, both of which are reset underneath.
typedef struct {
    re_arena_t arena;
    re_analysis_t an;
    bool open;
} session_t;

static void session_drop(session_t *s) {
    if (s->open) {
        re_analysis_close(&s->an);
        re_arena_free(&s->arena);
        s->open = false;
    }
}

// Opening builds the analysis immediately rather than remembering only the path, so
// the cost is paid once at open where the user is already waiting for it, and every
// later command reads the result.
static bool session_open(session_t *s, re_ctx_t *ctx, const char *path, const char **current,
                         re_report_t *r) {
    session_drop(s);
    re_arena_init(&s->arena, 1u << 22);
    if (!re_analysis_open(&s->an, &s->arena, path) || !re_analysis_run_all(&s->an)) {
        re_analysis_close(&s->an);
        re_arena_free(&s->arena);
        re_report_note(r, RE_ST_BAD, path);
        return false;
    }
    s->open = true;
    *current = re_arena_strdup(r->scratch.arena, path);
    ctx->session = &s->an;
    char msg[200];
    snprintf(msg, sizeof(msg), "%s  %zu functions, %zu xrefs, %zu regions", path,
             RE_VEC_LEN(&s->an.scan.funcs), RE_VEC_LEN(&s->an.xs.fwd), RE_VEC_LEN(&s->an.regions));
    re_report_note(r, RE_ST_GOOD, msg);
    return true;
}

// Run one command from a typed line. The first word is the command; the rest are its
// arguments, with the file taken from the first bare word or from the remembered one.
static int run(re_ctx_t *ctx, re_report_t *r, line_t *l, const char **current, session_t *s) {
    re_err_t err = {};
    re_str_t word = re_strn(l->argv[0], text_len(l->argv[0]));
    err.code = RE_OK;
    if (re_str_eq_cstr(word, "quit") || re_str_eq_cstr(word, "exit"))
        return 1;
    if (re_str_eq_cstr(word, "commands") || re_str_eq_cstr(word, "help")) {
        list_commands(r);
        return 0;
    }
    if (re_str_eq_cstr(word, "close")) {
        session_drop(s);
        ctx->session = NULL;
        *current = NULL;
        return 0;
    }
    if (re_str_eq_cstr(word, "version")) {
        re_report_note(r, RE_ST_NONE, "antistrefo 0.1.0  schema antistrefo/1");
        return 0;
    }
    // open is a shell word rather than a table command, so the remembered file is a
    // shell concern and does not have to exist in the table the argv path shares.
    if (re_str_eq_cstr(word, "open")) {
        if (l->argc < 2) {
            re_report_note(r, RE_ST_BAD, "open needs a file");
            return 0;
        }
        return session_open(s, ctx, l->argv[1], current, r) ? 0 : 0;
    }
    const re_cmd_t *cmd = re_cmd_find(l->argv[0]);
    if (!cmd) {
        char msg[160];
        snprintf(msg, sizeof(msg), "unknown command '%s'. Type 'commands' for the list.",
                 l->argv[0]);
        re_report_note(r, RE_ST_BAD, msg);
        return 0;
    }
    // The first bare word is the file. A flag may come before it, which is why this
    // cannot simply be argv[1]. A word starting with a dash is not a path.
    int argi = 0;
    for (int i = 1; i < l->argc; i++) {
        if (l->argv[i][0] != '-' || l->argv[i][1] == '\0') {
            argi = i;
            break;
        }
    }
    const char *path = argi ? l->argv[argi] : *current;
    if (cmd->needs_path && !path) {
        re_report_note(r, RE_ST_BAD, "no file. Use 'open <file>' or name one on the line.");
        return 0;
    }
    if (!re_cmd_parse(ctx, l->argc - 1, l->argv + 1, &argi, &err)) {
        re_report_note(r, RE_ST_BAD, re_err_msg(&err));
        return 0;
    }
    // re_cmd_parse resets the output format to JSON on every call, because from the
    // argv path that is the right default. In a shell it is not, so it is set again
    // here, after parsing, or every command in the session prints raw JSON.
    ctx->out = RE_FMT_OUT_TEXT;
    cmd->fn(ctx, path ? path : "", l->argc - 1, l->argv + 1);
    return 0;
}

int re_cmd_shell(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    (void)path;
    (void)argc;
    (void)argv;
    if (!re_shell_wanted(1)) {
        fprintf(stderr, "shell needs a terminal on both ends\n");
        return 2;
    }
    return re_shell_run(ctx);
}

int re_shell_run(re_ctx_t *ctx) {
    char line[SHELL_LINE_MAX];
    re_report_t r;
    re_arena_t shell;
    re_arena_t words;
    const char *current = NULL;
    session_t session;
    session.open = false;
    bool first_prompt = true;
    re_arena_init(&shell, 0);
    re_arena_init(&words, 0);
    // The report is reinitialised per line, so each command starts from a clean
    // buffer. The report's arena is separate from the command arena because the
    // command arena is reset per command and the report outlives several of them.
    ctx->out = RE_FMT_OUT_TEXT; // a shell is a terminal, so the framed report is right
    r.scratch.arena = &shell;
    r.ctx = ctx;
    banner(&r);
    for (;;) {
        // A command that printed a report leaves the cursor at the end of a table, so
        // the prompt needs a line of its own. The first does not, because the banner
        // already ended one.
        if (!first_prompt)
            re_report_newline(&r);
        first_prompt = false;
        re_report_prompt(&r, current ? "antistrefo \\ " : "antistrefo * ");
        if (!fgets(line, sizeof(line), stdin))
            break; // end of input: leave cleanly, which is what closes the window
        size_t n = text_len(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = '\0';
        if (!n)
            continue;
        line_t l;
        if (!split(line, &l, &words)) {
            re_report_note(&r, RE_ST_BAD, "too many arguments on one line");
            continue;
        }
        int done = run(ctx, &r, &l, &current, &session);
        // The words are released here and not before, because the command was handed
        // pointers into them.
        re_arena_reset(&words);
        if (done)
            break;
    }
    session_drop(&session);
    re_arena_free(&words);
    re_arena_free(&shell);
    return 0;
}
