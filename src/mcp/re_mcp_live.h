// re_mcp_live.h - GUI session snapshot for MCP agents alongside the TUI.
// Module: mcp (C11).
// Owns: the published open-file context and console load / endpoint lines.
// Depends: re_console, re_analyze. Double-buffered; no heap, no I/O here.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/analysis/re_analyze.h"
#include "utils/tui/re_console.h"

#define RE_MCP_LIVE_PATH 512u
#define RE_MCP_LIVE_NAME 96u
#define RE_MCP_LIVE_SHORT 32u
#define RE_MCP_LIVE_EP 256u

typedef struct {
    char path[RE_MCP_LIVE_PATH];
    char name[RE_MCP_LIVE_NAME];
    char format[RE_MCP_LIVE_SHORT];
    char arch[RE_MCP_LIVE_SHORT];
    char func_name[RE_MCP_LIVE_NAME];
    char mcp_endpoint[RE_MCP_LIVE_EP];
    uint64_t func_rva;
    size_t sel;
    bool loaded;
    bool mcp_up;
    uint32_t gen;
} re_mcp_live_t;

// Copy the published snapshot into out. Safe to call from any thread.
void re_mcp_live_snapshot(re_mcp_live_t *out);

// Path of the GUI-open file, or NULL when none is loaded. Valid until the next
// publish that clears or replaces it; callers that keep it must copy.
const char *re_mcp_live_path(void);

// Publish analysis + selection. Also pushes "loaded <name> into antistrefo".
void re_mcp_live_note_load(re_console_t *console, const char *path, const re_analysis_t *an,
                           size_t sel);

// Refresh selection fields without a load line.
void re_mcp_live_note_sel(const re_analysis_t *an, size_t sel, bool loaded);

// Record the side-channel endpoint and push "mcp <endpoint>" to the console.
void re_mcp_live_note_mcp(re_console_t *console, const char *endpoint, bool up);

// Clear the published GUI file (quit / failed open leaves agents honest).
void re_mcp_live_clear_file(void);

#ifdef __cplusplus
}
#endif
