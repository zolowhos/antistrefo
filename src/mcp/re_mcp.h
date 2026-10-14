// re_mcp.h - entry point for the MCP JSON-RPC server.
// Module: mcp (C++17).
// Owns: the start of the server loop over stdio or caller-owned streams.
// Depends: re_utils. main() in src/cli/main.cpp owns the dispatch into this.
#pragma once

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif
// Protocol revision this build speaks. Reported in the initialize response.
const char *re_mcp_protocol_version(void);

// Serve until stdin reaches EOF, then return 0. Mutes logging before the first
// read, because stdout is the protocol stream from that point on.
int re_mcp_main(void);

// Same protocol loop on caller-owned streams. Used by the GUI side channel so
// the TUI can keep the process terminal. Does not mute logging itself.
int re_mcp_serve_files(FILE *in, FILE *out);

#ifdef __cplusplus
}
#endif
