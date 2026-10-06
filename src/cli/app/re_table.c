// re_table.c - the command table and the shared flag parser, the single source
// Module: cli (C11).
// Owns: command metadata and the shared flag parsing for every command.
// Depends: re_table.h and the command entry points. No I/O beyond stdout.
#include "cli/app/re_table.h"

#include "cli/cmds/re_cmds3.h"

#include <string.h>

#include "cli/app/re_shell.h"
#include "cli/cmds/re_analyze_cmd.h"
#include "cli/cmds/re_cmds.h"
#include "cli/screen/re_gui.h"
static const re_cmd_t kCommands[] = {
    {"gui", "full screen view of the functions, in the terminal", "gui [file]", re_cmd_gui, false,
     true},
    {"shell", "line oriented prompt for driving the report commands", "shell", re_cmd_shell, false,
     true},
    {"info", "format, architecture, hashes and layout summary", "info <file>", re_cmd_info, true,
     false},
    {"triage", "one call ingest view: layout, imports, devices, risk, capabilities",
     "triage <file>", re_cmd_triage, true, false},
    {"sections", "section table with per section entropy", "sections <file>", re_cmd_sections, true,
     false},
    {"imports", "imported modules and symbols, demangled when possible", "imports <file>",
     re_cmd_imports, true, false},
    {"exports", "exported symbols, demangled when possible", "exports <file>", re_cmd_exports, true,
     false},
    {"strings", "printable strings, ascii and utf-16, with a regex filter",
     "strings <file> [--regex R]", re_cmd_strings, true, false},
    {"vtables", "C++ class tables, named from the image's own RTTI where it has any",
     "vtables <file>", re_cmd_vtables, true, false},
    {"search", "find text, an immediate value, or a hex pattern with wildcards",
     "search <file> <pattern>", re_cmd_search, true, false},
    {"rules", "capability findings with the evidence that fired each rule", "rules <file>",
     re_cmd_rules, true, false},
    {"entropy", "windowed entropy, to locate packed or encrypted regions",
     "entropy <file> [--win N] [--step N]", re_cmd_entropy, true, false},
    {"funcs", "recovered functions with size, frame and call counts", "funcs <file> [sigs.pat]",
     re_cmd_funcs, true, false},
    {"xrefs", "cross references, with imports, exports and strings named", "xrefs <file> [addr]",
     re_cmd_xrefs, true, false},
    {"jtables", "jump tables behind an indirect branch, with case targets", "jtables <file>",
     re_cmd_jtables, true, false},
    {"disasm", "disassemble a function or an address range", "disasm <file> [addr] [--len N]",
     re_cmd_disasm, true, false},
    {"decompile", "one function as C-like source, with its calls named", "decompile <file> [addr]",
     re_cmd_decompile, true, false},
    {"regions", "classify each window as code, data, rdata or pad, with evidence", "regions <file>",
     re_cmd_regions, true, false},
    {"analyze", "every pass over one file, with per pass timing and what it could not tell",
     "analyze <file>", re_cmd_analyze, true, false},
    {"cfg", "control flow graph of one function: blocks, terminators, edges", "cfg <file> [addr]",
     re_cmd_cfg, true, false},
    {"demangle", "demangle one C++ symbol, no file needed", "demangle <symbol>", re_cmd_demangle,
     false, false},
    {"hexdump", "raw bytes at a file offset or an rva",
     "hexdump <file> (--off N | --rva N) --len N", re_cmd_hexdump, true, false},
    {"mcp", "run the MCP server over stdio", "mcp", NULL, false, false},
    {"help", "list commands", "help", NULL, false, false},
    {"version", "print the version and schema", "version", NULL, false, false},
};
const re_cmd_t *re_cmd_table(size_t *count) {
    if (count)
        *count = sizeof(kCommands) / sizeof(kCommands[0]);
    return kCommands;
}

const re_cmd_t *re_cmd_find(const char *name) {
    size_t n = 0;
    const re_cmd_t *t = re_cmd_table(&n);
    for (size_t i = 0; i < n; i++) {
        if (re_str_eq_cstr(re_str(t[i].name), name))
            return &t[i];
    }
    return NULL;
}

static bool parse_u64(const char *s, uint64_t *out) {
    re_str_t v = re_str(s);
    if (v.n == 0)
        return false;
    uint64_t base = 10;
    size_t i = 0;
    if (v.n > 2 && v.p[0] == '0' && (v.p[1] == 'x' || v.p[1] == 'X')) {
        base = 16;
        i = 2;
    }
    uint64_t acc = 0;
    for (; i < v.n; i++) {
        int d = re_hex_val(v.p[i]);
        if (d < 0 || (uint64_t)d >= base)
            return false;
        acc = acc * base + (uint64_t)d;
    }
    *out = acc;
    return true;
}
// Apply one shared flag to the context. Returns 0 when the flag was not ours.
static bool apply_flag(re_ctx_t *ctx, re_str_t a, const char *val, re_err_t *err) {
    if (re_str_starts_cstr(a, "--format")) {
        re_str_t v = re_str(val);
        if (re_str_eq_cstr(v, "text"))
            ctx->out = RE_FMT_OUT_TEXT;
        else if (re_str_eq_cstr(v, "json"))
            ctx->out = RE_FMT_OUT_JSON;
        else {
            RE_ERR_SETF(err, RE_E_USAGE, "--format must be json or text, got %s", val);
            return false;
        }
        return true;
    }
    if (re_str_starts_cstr(a, "--regex")) {
        ctx->regex = re_str(val);
        ctx->has_regex = true;
        return true;
    }
    bool is_off = re_str_starts_cstr(a, "--off");
    bool is_len = re_str_starts_cstr(a, "--len");
    // --rva lands in the same field as --off because only the hexdump command
    // distinguishes them, and it does so by looking at argv. Both are a start
    // address; which one it is depends on the command, not on the parser.
    bool is_rva = re_str_starts_cstr(a, "--rva");
    if (!re_str_starts_cstr(a, "--limit") && !re_str_starts_cstr(a, "--offset") && !is_off &&
        !is_len && !is_rva)
        return false;
    uint64_t n = 0;
    if (!parse_u64(val, &n)) {
        RE_ERR_SETF(err, RE_E_USAGE, "expected a number, got %s", val);
        return false;
    }
    if (re_str_starts_cstr(a, "--limit"))
        ctx->limit = (size_t)n;
    else if (re_str_starts_cstr(a, "--offset"))
        ctx->offset = (size_t)n;
    else if (is_len)
        ctx->len = n;
    else
        ctx->off = n;
    return true;
}

bool re_cmd_parse(re_ctx_t *ctx, int argc, char **argv, int *first_positional, re_err_t *err) {
    ctx->out = RE_FMT_OUT_JSON;
    ctx->limit = 200;
    ctx->offset = 0;
    ctx->off = 0;
    ctx->len = 256;
    ctx->has_regex = false;
    ctx->no_color = false;
    int pos = argc;
    for (int i = 0; i < argc; i++) {
        re_str_t a = re_str(argv[i]);
        if (!re_str_starts_cstr(a, "--")) {
            if (pos == argc)
                pos = i;
            continue;
        }
        // Prefer the --flag=value form so a value never looks like a flag.
        const char *val = NULL;
        if (re_str_starts_cstr(a, "--format="))
            val = argv[i] + 9;
        else if (re_str_starts_cstr(a, "--regex="))
            val = argv[i] + 8;
        else if (re_str_starts_cstr(a, "--len="))
            val = argv[i] + 6;
        else if (re_str_starts_cstr(a, "--off="))
            val = argv[i] + 6;
        else if (re_str_starts_cstr(a, "--limit="))
            val = argv[i] + 8;
        else if (re_str_starts_cstr(a, "--offset="))
            val = argv[i] + 9;
        else if (re_str_eq_cstr(a, "--format") || re_str_eq_cstr(a, "--regex") ||
                 re_str_eq_cstr(a, "--limit") || re_str_eq_cstr(a, "--offset") ||
                 re_str_eq_cstr(a, "--off") || re_str_eq_cstr(a, "--rva") ||
                 re_str_eq_cstr(a, "--len")) {
            if (i + 1 >= argc) {
                RE_ERR_SETF(err, RE_E_USAGE, "flag %s needs a value", argv[i]);
                return false;
            }
            val = argv[++i];
        } else if (re_str_eq_cstr(a, "--no-color")) {
            // The one flag with no value, because a flag that can be spelled two ways
            // for the same thing is a flag someone will get wrong.
            ctx->no_color = true;
            continue;
        } else {
            RE_ERR_SETF(err, RE_E_USAGE, "unknown flag %s", argv[i]);
            return false;
        }
        if (val && !apply_flag(ctx, a, val, err))
            return false;
    }
    *first_positional = pos;
    return true;
}

const char *re_cmd_positional(int argc, char **argv, int from) {
    int i = from;
    while (i < argc) {
        re_str_t a = re_str(argv[i]);
        if (re_str_starts_cstr(a, "--")) {
            i += 2; // the flag and the value it consumed
            continue;
        }
        return argv[i];
    }
    return NULL;
}
