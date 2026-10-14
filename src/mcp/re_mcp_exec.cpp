// re_mcp_exec.cpp - python3 bridge for ida-mcp execute_python compatibility.
// Module: mcp (C++17).
// Owns: shim path resolution, process spawn, and reference blurb selection.
// Depends: re_mcp_exec.h, re_mcp_db, re_jr. Spawns python3; never talks stdio MCP.
#include "mcp/re_mcp_exec.h"

#include "utils/json/re_jr.h"
#include "utils/text/re_str.h"
#include "utils/text/re_strbuf.h"
#include "mcp/re_mcp_db.h"

#include <cstdio>
#include <cstring>
#include <string>

#if defined(_WIN32)
#    include <windows.h>
#    define RE_POPEN _popen
#    define RE_PCLOSE _pclose
#else
#    include <stdlib.h>
#    include <unistd.h>
#    define RE_POPEN popen
#    define RE_PCLOSE pclose
#endif

namespace {

char g_scripts[512];

bool write_temp(const char *text, char *path, size_t path_n) {
#if defined(_WIN32)
    char dir[MAX_PATH];
    if (!GetTempPathA((DWORD)sizeof(dir), dir))
        return false;
    if (path_n < MAX_PATH)
        return false;
    if (!GetTempFileNameA(dir, "repy", 0, path))
        return false;
#else
    if (path_n < 32)
        return false;
    std::snprintf(path, path_n, "/tmp/antistrefo-py-XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0)
        return false;
    FILE *tf = fdopen(fd, "w");
    if (!tf) {
        close(fd);
        return false;
    }
    std::fputs(text ? text : "", tf);
    std::fclose(tf);
    return true;
#endif
#if defined(_WIN32)
    FILE *tf = std::fopen(path, "wb");
    if (!tf)
        return false;
    std::fputs(text ? text : "", tf);
    std::fclose(tf);
    return true;
#endif
}

bool shim_path(char *out, size_t n) {
    if (g_scripts[0]) {
        std::snprintf(out, n, "%s/ida_mcp_shim.py", g_scripts);
        if (FILE *f = std::fopen(out, "rb")) {
            std::fclose(f);
            return true;
        }
    }
    const char *env = std::getenv("ANTISTREFO_SHIM");
    if (env && env[0]) {
        std::snprintf(out, n, "%s", env);
        return true;
    }
    return false;
}

void tool_err(re_strbuf_t *out, const char *msg) {
    re_strbuf_puts(out, "{\"error\":{\"code\":\"unsupported\",\"message\":");
    re_jr_escape(out, re_str(msg));
    re_strbuf_puts(out, "}}");
}

bool set_exe_env(const char *exe) {
#if defined(_WIN32)
    return _putenv_s("ANTISTREFO", exe) == 0;
#else
    return setenv("ANTISTREFO", exe, 1) == 0;
#endif
}

bool run_shim(const char *shim, const char *db_path, const char *code_path, re_strbuf_t *out) {
    std::string cmd = "python3 \"";
    cmd += shim;
    cmd += "\" \"";
    cmd += db_path;
    cmd += "\" \"";
    cmd += code_path;
    cmd += "\"";
    FILE *pipe = RE_POPEN(cmd.c_str(), "r");
    if (!pipe)
        return false;
    char chunk[4096];
    while (std::fgets(chunk, sizeof(chunk), pipe))
        re_strbuf_puts(out, chunk);
    RE_PCLOSE(pipe);
    while (out->len && (out->p[out->len - 1] == '\n' || out->p[out->len - 1] == '\r'))
        out->p[--out->len] = '\0';
    return out->len > 0;
}

} // namespace

void re_mcp_exec_set_scripts(const char *dir) {
    if (!dir)
        return;
    std::snprintf(g_scripts, sizeof(g_scripts), "%s", dir);
}

bool re_mcp_exec_python(const char *db_path, const char *code, re_strbuf_t *out) {
    char shim[512];
    char code_path[512];
    const char *exe = re_mcp_db_exe();
    if (!db_path || !db_path[0]) {
        tool_err(out, "no database: call open_database first");
        return false;
    }
    if (!exe) {
        tool_err(out, "ANTISTREFO executable path is unknown");
        return false;
    }
    if (!shim_path(shim, sizeof(shim))) {
        tool_err(out, "ida_mcp_shim.py not found - set ANTISTREFO_SHIM");
        return false;
    }
    if (!write_temp(code ? code : "", code_path, sizeof(code_path))) {
        tool_err(out, "cannot write temporary code file");
        return false;
    }
    if (!set_exe_env(exe)) {
        std::remove(code_path);
        tool_err(out, "cannot set ANTISTREFO");
        return false;
    }
    bool ok = run_shim(shim, db_path, code_path, out);
    std::remove(code_path);
    if (!ok) {
        tool_err(out, "execute_python produced no response");
        return false;
    }
    return true;
}

const char *re_mcp_reference_text(const char *query) {
    static const char kDefault[] =
        "antistrefo ida-mcp shim (subset of ida-domain):\n"
        "  db.functions.get_all() / get_at(ea) / iter -> start_ea,end_ea,name,size .decompile()\n"
        "  db.strings -> address,length,text\n"
        "  db.segments.get_all() -> section rows\n"
        "  db.xrefs.to_ea(ea) / from_ea(ea)\n"
        "  db.entries.get_all() -> exports\n"
        "  db.disasm(ea, length=32)\n"
        "  ida_hexrays.decompile(ea) -> Tier B C-like source string\n"
        "Mutating APIs (rename, patch, types, save) are unsupported.\n";
    static const char kDecomp[] =
        "Decompile: fn = db.functions.get_at(ea) then src = fn.decompile()\n"
        "Or: ida_hexrays.decompile(ea)\n"
        "Returns Tier B C-like text from antistrefo decompile, not Hex-Rays.\n";
    static const char kXref[] = "Xrefs: db.xrefs.to_ea(ea) or db.xrefs.from_ea(ea)\n"
                                "Also accepted: db.xrefs.to(ea)\n";
    static const char kStr[] = "Strings: for s in db.strings: print(hex(s.address), str(s))\n";
    if (!query || !query[0])
        return kDefault;
    re_str_t q = re_str(query);
    if (re_str_find_cstr(q, "decomp", 0) >= 0 || re_str_find_cstr(q, "hexray", 0) >= 0)
        return kDecomp;
    if (re_str_find_cstr(q, "xref", 0) >= 0)
        return kXref;
    if (re_str_find_cstr(q, "string", 0) >= 0)
        return kStr;
    return kDefault;
}
