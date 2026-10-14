// re_mcp_side.h - MCP side channel so the GUI can keep the terminal.
// Module: mcp (C++17).
// Owns: listen/accept thread and the stdio attach bridge for agents.
// Depends: re_mcp. Protocol frames never touch the GUI's stdout.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>

// Start a background MCP server on a local transport. Writes an endpoint string
// such as "unix:/tmp/antistrefo-mcp-<pid>.sock" or "tcp:127.0.0.1:<port>" into
// endpoint. Returns false when the listen socket could not be created.
bool re_mcp_side_start(char *endpoint, size_t cap);

// Stop the background server and unlink a unix socket when one was used.
void re_mcp_side_stop(void);

// Bridge stdin/stdout to an existing side-channel endpoint so agents that only
// speak stdio MCP can attach to a running GUI. endpoint may be NULL to use
// ANTISTREFO_MCP or the path file written by the GUI.
int re_mcp_attach_main(const char *endpoint);

#ifdef __cplusplus
}
#endif
