// re_mcp.h - entry point for the MCP JSON-RPC server.
// Module: mcp (C++17).
// Owns: the start of the server loop over stdio or caller-owned streams.
// Depends: re_utils. main() in src/cli/main.cpp owns the dispatch into this.
#pragma once

#include <stdbool.h>
#include <stddef.h>
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

// Byte pump hooks for transports with no working FILE * wrapper, such as
// Winsock sockets (ReadFile on a socket fails on modern Windows, so CRT fds
// cannot carry the protocol there). read returns the byte count, 0 on EOF.
// write gets one frame without its newline and returns false when the peer is
// gone; the transport appends the newline.
typedef size_t (*re_mcp_read_fn)(void *ctx, char *buf, size_t cap);
typedef bool (*re_mcp_write_fn)(void *ctx, const char *data, size_t n);

// Same protocol loop over caller-owned byte pumps. Returns 2 for null hooks.
int re_mcp_serve_callbacks(void *rctx, re_mcp_read_fn rf, void *wctx, re_mcp_write_fn wf);

#ifdef __cplusplus
}
#endif
