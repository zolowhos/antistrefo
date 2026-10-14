// test_mcp_live.c - GUI load console line and live MCP context snapshot.
// Module: test (C11).
// Owns: assertions for re_mcp_live publish helpers used by the GUI.
// Depends: re_test, re_mcp_live, re_console, re_analyze.
#include "re_test.h"

#include "features/analysis/re_analyze.h"
#include "utils/tui/re_console.h"
#include "mcp/re_mcp_live.h"

#include <stdio.h>
#include <string.h>

int re_test_count = 0;
int re_test_fail = 0;

static void test_load_console_line(void) {
    re_console_t c;
    re_analysis_t an;
    re_mcp_live_t live;
    const char *view[RE_CONSOLE_VIEW];
    size_t n;
    size_t i;
    int found = 0;
    memset(&an, 0, sizeof(an));
    re_console_init(&c);
    re_mcp_live_clear_file();
    re_mcp_live_note_load(&c, "/var/tmp/sample/foo.exe", &an, 0);
    n = re_console_view(&c, view);
    RE_CHECK(n > 0);
    for (i = 0; i < n; i++) {
        if (view[i] && strcmp(view[i], "loaded foo.exe into antistrefo") == 0)
            found = 1;
    }
    RE_CHECK(found);
    re_mcp_live_snapshot(&live);
    RE_CHECK(live.loaded);
    RE_CHECK_EQ_STR(live.name, "foo.exe");
    RE_CHECK(strstr(live.path, "foo.exe") != NULL);
}

static void test_mcp_endpoint_line(void) {
    re_console_t c;
    re_mcp_live_t live;
    const char *view[RE_CONSOLE_VIEW];
    size_t n;
    size_t i;
    int found = 0;
    re_console_init(&c);
    re_mcp_live_note_mcp(&c, "unix:/tmp/antistrefo-mcp-1.sock", true);
    n = re_console_view(&c, view);
    for (i = 0; i < n; i++) {
        if (view[i] && strcmp(view[i], "mcp unix:/tmp/antistrefo-mcp-1.sock") == 0)
            found = 1;
    }
    RE_CHECK(found);
    re_mcp_live_snapshot(&live);
    RE_CHECK(live.mcp_up);
    RE_CHECK_EQ_STR(live.mcp_endpoint, "unix:/tmp/antistrefo-mcp-1.sock");
    re_mcp_live_clear_file();
}

int main(void) {
    test_load_console_line();
    test_mcp_endpoint_line();
    return re_test_report("mcp_live");
}
