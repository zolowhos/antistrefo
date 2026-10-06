// re_mcp_tools.h - the tools/call half of the MCP server, split from the transport.
// Module: mcp (C++17).
// Owns: per tool argument translation, schema generation and command execution.
// Depends: re_table, re_jr, re_strbuf. Runs commands; never touches stdio.
#pragma once

#include "utils/json/re_jr.h"
#include "utils/text/re_strbuf.h"
#include "cli/app/re_table.h"

// One tools/list entry for a command: name, summary, and an input schema derived
// from what this tool actually reads rather than from a template.
void mcp_tool_schema(const re_cmd_t *cmd, re_strbuf_t *b);

// The error envelope every tool failure carries, so a caller is told why and not
// just that something did not answer.
void mcp_tool_error(re_strbuf_t *out, const char *msg, bool *is_error);

// Run one tool call end to end. path is the resolved file, or null for a tool that
// needs none. On any failure out carries an error envelope and is_error is true, so
// a caller that shows the text shows the reason too.
void mcp_run_tool(const re_cmd_t *cmd, const char *path, const re_jr_t *args, re_arena_t *a,
                  re_strbuf_t *out, bool *is_error);
