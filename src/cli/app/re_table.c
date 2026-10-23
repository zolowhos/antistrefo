// re_table.c - the command table and the shared flag parser, the single source
// Module: cli (C11).
// Owns: command metadata and the shared flag parsing for every command.
// Depends: re_table.h and the command entry points. No I/O beyond stdout.
#include "cli/app/re_table.h"

#include <string.h>

#include "cli/app/re_shell.h"
#include "cli/cmds/re_analyze_cmd.h"
#include "cli/cmds/re_cmds.h"
#include "cli/cmds/re_cmds3.h"
#include "cli/cmds/re_ida_cmds.h"
#include "cli/screen/re_gui.h"
#include "mcp/re_mcp_ida.h"
static const re_cmd_t kCommands[] = {
    {"gui", "full screen view of the functions, in the terminal", "gui [file]", re_cmd_gui, false,
     true, false},
    {"shell", "line oriented prompt for driving the report commands", "shell", re_cmd_shell, false,
     true, false},
    {"info", "format, architecture, hashes and layout summary", "info <file>", re_cmd_info, true,
     false, false},
    {"triage", "one call ingest view: layout, imports, devices, risk, capabilities",
     "triage <file>", re_cmd_triage, true, false, false},
    {"sections", "section table with per section entropy", "sections <file>", re_cmd_sections, true,
     false, false},
    {"imports", "imported modules and symbols, demangled when possible", "imports <file>",
     re_cmd_imports, true, false, false},
    {"exports", "exported symbols, demangled when possible", "exports <file>", re_cmd_exports, true,
     false, false},
    {"strings", "printable strings; --pattern literal, --regex regex",
     "strings <file> [--pattern P] [--regex R]", re_cmd_strings, true, false, false},
    {"vtables", "C++ class tables, named from the image's own RTTI where it has any",
     "vtables <file>", re_cmd_vtables, true, false, false},
    {"search", "find text:, imm:, raw:/hex, or sym: with VA and insn text",
     "search <file> <pattern>", re_cmd_search, true, false, false},
    {"rules", "capability findings with the evidence that fired each rule", "rules <file>",
     re_cmd_rules, true, false, false},
    {"entropy", "windowed entropy, to locate packed or encrypted regions",
     "entropy <file> [--win N] [--step N]", re_cmd_entropy, true, false, false},
    {"funcs", "recovered functions; address arg returns that one function",
     "funcs <file> [addr|sigs.pat]", re_cmd_funcs, true, false, false},
    {"rename", "set a display name for a function; persists in <file>.alt",
     "rename <file> <addr|name> <new>", re_cmd_rename, true, false, true},
    {"list_names", "list user renames from the sidecar .alt mapping", "list_names <file>",
     re_cmd_list_names, true, false, true},
    {"xrefs", "cross references, with imports, exports and strings named", "xrefs <file> [addr]",
     re_cmd_xrefs, true, false, false},
    {"namerefs", "RIP-relative loads of an exact name list, in order",
     "namerefs <file> --exports <pe>|--names <f>", re_cmd_namerefs, true, false, false},
    {"jtables", "jump tables behind an indirect branch, with case targets", "jtables <file>",
     re_cmd_jtables, true, false, false},
    {"disasm", "disassemble a function or an address range", "disasm <file> [addr] [--len N]",
     re_cmd_disasm, true, false, false},
    {"decompile", "one function as C-like source, with its calls named", "decompile <file> [addr]",
     re_cmd_decompile, true, false, false},
    {"regions", "classify each window as code, data, rdata or pad, with evidence", "regions <file>",
     re_cmd_regions, true, false, false},
    {"analyze", "every pass over one file, with per pass timing and what it could not tell",
     "analyze <file>", re_cmd_analyze, true, false, false},
    {"deep", "the deep tier, written to <file>.asdb for later instant opens", "deep <file>",
     re_cmd_deep, true, false, true},
    {"cfg", "control flow graph of one function: blocks, terminators, edges", "cfg <file> [addr]",
     re_cmd_cfg, true, false, false},
    {"demangle", "demangle one C++ symbol, no file needed", "demangle <symbol>", re_cmd_demangle,
     false, false, false},
    {"hexdump", "raw bytes at a file offset or an rva",
     "hexdump <file> (--off N | --rva N) --len N", re_cmd_hexdump, true, false, false},
    {"open_database", "open a binary as an ida-mcp style database instance", "open_database <file>",
     re_cmd_open_database, true, false, true},
    {"list_databases", "list open ida-mcp style database instances", "list_databases",
     re_cmd_list_databases, false, false, true},
    {"close_database", "release an ida-mcp style database instance", "close_database [id]",
     re_cmd_close_database, false, false, true},
    {"save_database", "unsupported: antistrefo does not persist an IDB", "save_database [id]",
     re_cmd_save_database, false, false, true},
    {"execute_query", "run a native analysis op against the current database",
     "execute_query <file> <op> [arg]", re_cmd_execute_query, true, false, true},
    {"reference", "search the execute_query op reference", "reference <query>", re_cmd_reference,
     false, false, true},
    {"context", "live GUI session: open file, format, arch, selection, mcp endpoint", "context",
     re_cmd_context, false, false, true},
    /* Discrete ida-pro-mcp Tier A (aliases share CLI ops where shapes match). */
    {"check_connection", "mcp ping: session is reachable", "check_connection",
     re_cmd_check_connection, false, false, true},
    {"get_metadata", "binary metadata (format, arch, entry)", "get_metadata <file>",
     re_cmd_get_metadata, true, false, true},
    {"get_function_by_name", "one function by display name", "get_function_by_name <file> <name>",
     re_cmd_get_function_by_name, true, false, true},
    {"get_function_by_address", "one function containing an address",
     "get_function_by_address <f> <a>", re_cmd_get_function_by_address, true, false, true},
    {"get_current_address", "GUI selection address from live context", "get_current_address",
     re_cmd_get_current_address, false, false, true},
    {"get_current_function", "GUI current function from live context", "get_current_function",
     re_cmd_get_current_function, false, false, true},
    {"convert_number", "decimal / hex / binary forms of a number", "convert_number <n>",
     re_cmd_convert_number, false, false, true},
    {"list_functions", "recovered functions (alias of funcs)", "list_functions <file>",
     re_cmd_funcs, true, false, true},
    {"list_globals_filter", "exports filtered by regex", "list_globals_filter <file>",
     re_cmd_exports, true, false, true},
    {"list_globals", "exported symbols as globals", "list_globals <file>", re_cmd_exports, true,
     false, true},
    {"list_imports", "imported modules and symbols", "list_imports <file>", re_cmd_imports, true,
     false, true},
    {"list_strings_filter", "strings filtered by regex", "list_strings_filter <file>",
     re_cmd_strings, true, false, true},
    {"list_strings", "printable strings (pattern=literal substring)", "list_strings <file>",
     re_cmd_strings, true, false, true},
    {"decompile_function", "C-like decompile of one function", "decompile_function <file> [a]",
     re_cmd_decompile, true, false, true},
    {"disassemble_function", "disassemble one function", "disassemble_function <file> [a]",
     re_cmd_disasm, true, false, true},
    {"get_xrefs_to", "cross references to an address", "get_xrefs_to <file> [addr]", re_cmd_xrefs,
     true, false, true},
    {"get_callees", "callees of a function", "get_callees <file> <addr>", re_cmd_get_callees, true,
     false, true},
    {"get_callers", "callers of a function", "get_callers <file> <addr>", re_cmd_get_callers, true,
     false, true},
    {"get_entry_points", "image entry point list", "get_entry_points <file>",
     re_cmd_get_entry_points, true, false, true},
    {"rename_function", "rename a function via .alt sidecar", "rename_function <f> <t> <n>",
     re_cmd_rename_function, true, false, true},
    {"read_memory_bytes", "raw bytes at an address", "read_memory_bytes <file> <a> [n]",
     re_cmd_read_memory_bytes, true, false, true},
    {"data_read_byte", "read one byte at an address", "data_read_byte <file> <addr>",
     re_cmd_data_read_byte, true, false, true},
    {"data_read_word", "read one word at an address", "data_read_word <file> <addr>",
     re_cmd_data_read_word, true, false, true},
    {"data_read_dword", "read one dword at an address", "data_read_dword <file> <addr>",
     re_cmd_data_read_dword, true, false, true},
    {"data_read_qword", "read one qword at an address", "data_read_qword <file> <addr>",
     re_cmd_data_read_qword, true, false, true},
    {"data_read_string", "read a C string at an address", "data_read_string <file> <addr>",
     re_cmd_data_read_string, true, false, true},
    {"get_global_variable_value_by_name", "read bytes at a named export",
     "get_global_variable_value_by_name <f> <n>", re_cmd_get_global_variable_value_by_name, true,
     false, true},
    {"get_global_variable_value_at_address", "read qword at an address",
     "get_global_variable_value_at_address <f> <a>", re_cmd_get_global_variable_value_at_address,
     true, false, true},
    {"get_stack_frame_variables", "inferred stack slots for a function",
     "get_stack_frame_variables <f> <a>", re_cmd_get_stack_frame_variables, true, false, true},
    /* Tier B stubs: unsupported, never fake success. */
    {"list_local_types", "unsupported: no type library", "list_local_types",
     re_cmd_list_local_types, false, false, true},
    {"set_comment", "unsupported: no comment store", "set_comment", re_cmd_set_comment, false,
     false, true},
    {"rename_local_variable", "unsupported", "rename_local_variable", re_cmd_rename_local_variable,
     false, false, true},
    {"rename_global_variable", "unsupported: use rename_function", "rename_global_variable",
     re_cmd_rename_global_variable, false, false, true},
    {"set_global_variable_type", "unsupported", "set_global_variable_type",
     re_cmd_set_global_variable_type, false, false, true},
    {"patch_address_assembles", "unsupported: read-only analyzer", "patch_address_assembles",
     re_cmd_patch_address_assembles, false, false, true},
    {"set_function_prototype", "unsupported", "set_function_prototype",
     re_cmd_set_function_prototype, false, false, true},
    {"declare_c_type", "unsupported: no type DB", "declare_c_type", re_cmd_declare_c_type, false,
     false, true},
    {"set_local_variable_type", "unsupported", "set_local_variable_type",
     re_cmd_set_local_variable_type, false, false, true},
    {"get_defined_structures", "unsupported", "get_defined_structures",
     re_cmd_get_defined_structures, false, false, true},
    {"analyze_struct_detailed", "unsupported", "analyze_struct_detailed",
     re_cmd_analyze_struct_detailed, false, false, true},
    {"get_struct_at_address", "unsupported", "get_struct_at_address", re_cmd_get_struct_at_address,
     false, false, true},
    {"get_struct_info_simple", "unsupported", "get_struct_info_simple",
     re_cmd_get_struct_info_simple, false, false, true},
    {"search_structures", "unsupported", "search_structures", re_cmd_search_structures, false,
     false, true},
    {"rename_stack_frame_variable", "unsupported", "rename_stack_frame_variable",
     re_cmd_rename_stack_frame_variable, false, false, true},
    {"create_stack_frame_variable", "unsupported", "create_stack_frame_variable",
     re_cmd_create_stack_frame_variable, false, false, true},
    {"set_stack_frame_variable_type", "unsupported", "set_stack_frame_variable_type",
     re_cmd_set_stack_frame_variable_type, false, false, true},
    {"delete_stack_frame_variable", "unsupported", "delete_stack_frame_variable",
     re_cmd_delete_stack_frame_variable, false, false, true},
    {"get_xrefs_to_field", "unsupported: no struct fields", "get_xrefs_to_field",
     re_cmd_get_xrefs_to_field, false, false, true},
    {"mcp", "run the MCP server over stdio (or --attach to a gui side channel)", "mcp", NULL, false,
     false, false},
    {"help", "list commands", "help", NULL, false, false, false},
    {"version", "print the version and schema", "version", NULL, false, false, false},
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
// Path flags used by namerefs. Returns false when the flag is not one of them.
static bool apply_path(re_ctx_t *ctx, re_str_t a, const char *val) {
    if (re_str_starts_cstr(a, "--exports"))
        ctx->exports_path = re_str(val);
    else if (re_str_starts_cstr(a, "--names"))
        ctx->names_path = re_str(val);
    else if (re_str_starts_cstr(a, "--order"))
        ctx->order_path = re_str(val);
    else
        return false;
    return true;
}

static bool takes_value(re_str_t a) {
    return re_str_eq_cstr(a, "--format") || re_str_eq_cstr(a, "--regex") ||
           re_str_eq_cstr(a, "--pattern") || re_str_eq_cstr(a, "--limit") ||
           re_str_eq_cstr(a, "--offset") || re_str_eq_cstr(a, "--context") ||
           re_str_eq_cstr(a, "--off") || re_str_eq_cstr(a, "--rva") || re_str_eq_cstr(a, "--len") ||
           re_str_eq_cstr(a, "--exports") || re_str_eq_cstr(a, "--names") ||
           re_str_eq_cstr(a, "--order");
}

static const char *glued_value(re_str_t a) {
    if (re_str_starts_cstr(a, "--format="))
        return a.p + 9;
    if (re_str_starts_cstr(a, "--regex="))
        return a.p + 8;
    if (re_str_starts_cstr(a, "--pattern="))
        return a.p + 10;
    if (re_str_starts_cstr(a, "--len="))
        return a.p + 6;
    if (re_str_starts_cstr(a, "--off="))
        return a.p + 6;
    if (re_str_starts_cstr(a, "--limit="))
        return a.p + 8;
    if (re_str_starts_cstr(a, "--offset="))
        return a.p + 9;
    if (re_str_starts_cstr(a, "--context="))
        return a.p + 10;
    if (re_str_starts_cstr(a, "--exports="))
        return a.p + 10;
    if (re_str_starts_cstr(a, "--names="))
        return a.p + 8;
    if (re_str_starts_cstr(a, "--order="))
        return a.p + 8;
    return NULL;
}

// Apply one shared flag to the context. Returns false when the flag was not ours.
static bool apply_flag(re_ctx_t *ctx, re_str_t a, const char *val, re_err_t *err) {
    if (apply_path(ctx, a, val))
        return true;
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
    if (re_str_starts_cstr(a, "--pattern")) {
        ctx->pattern = re_str(val);
        ctx->has_pattern = true;
        return true;
    }
    bool is_off = re_str_starts_cstr(a, "--off");
    bool is_len = re_str_starts_cstr(a, "--len");
    bool is_context = re_str_starts_cstr(a, "--context");
    // --rva lands in the same field as --off because only the hexdump command
    // distinguishes them, and it does so by looking at argv. Both are a start
    // address; which one it is depends on the command, not on the parser.
    bool is_rva = re_str_starts_cstr(a, "--rva");
    if (!re_str_starts_cstr(a, "--limit") && !re_str_starts_cstr(a, "--offset") && !is_off &&
        !is_len && !is_rva && !is_context)
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
    else if (is_context)
        ctx->context = (size_t)n;
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
    ctx->context = 0;
    ctx->off = 0;
    ctx->len = 256;
    ctx->has_regex = false;
    ctx->has_pattern = false;
    ctx->pattern = re_str(NULL);
    ctx->no_color = false;
    ctx->exports_path = re_str(NULL);
    ctx->names_path = re_str(NULL);
    ctx->order_path = re_str(NULL);
    int pos = argc;
    for (int i = 0; i < argc; i++) {
        re_str_t a = re_str(argv[i]);
        const char *val;
        if (!re_str_starts_cstr(a, "--")) {
            if (pos == argc)
                pos = i;
            continue;
        }
        // Prefer the --flag=value form so a value never looks like a flag.
        val = glued_value(a);
        if (!val && takes_value(a)) {
            if (i + 1 >= argc) {
                RE_ERR_SETF(err, RE_E_USAGE, "flag %s needs a value", argv[i]);
                return false;
            }
            val = argv[++i];
        } else if (!val && re_str_eq_cstr(a, "--no-color")) {
            ctx->no_color = true;
            continue;
        } else if (!val) {
            RE_ERR_SETF(err, RE_E_USAGE, "unknown flag %s", argv[i]);
            return false;
        }
        if (!apply_flag(ctx, a, val, err))
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
