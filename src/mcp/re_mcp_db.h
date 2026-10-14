// re_mcp_db.h - open-database registry matching the ida-mcp instance model.
// Module: mcp (C11).
// Owns: instance ids, current target, path lookup for execute_query.
// Depends: re_mcp_live. Process-local; no I/O, no heap beyond static slots.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>

#define RE_MCP_DB_MAX 16
#define RE_MCP_DB_ID 16
#define RE_MCP_DB_PATH 512
#define RE_MCP_DB_BACKEND 16

typedef struct {
    char id[RE_MCP_DB_ID];
    char path[RE_MCP_DB_PATH];
    char backend[RE_MCP_DB_BACKEND];
    bool used;
    bool current;
} re_mcp_db_t;

// Open or attach path. Writes the instance into *out. set_current selects it.
// backend is "gui" or "idalib". Returns false when the table is full.
bool re_mcp_db_open(const char *path, bool set_current, const char *backend, re_mcp_db_t *out);

// Resolve instance_id, or the current target when id is null/empty.
const re_mcp_db_t *re_mcp_db_get(const char *instance_id);

// Path for instance_id or current; NULL when none.
const char *re_mcp_db_path(const char *instance_id);

bool re_mcp_db_close(const char *instance_id, bool *closed);

// Fill dst[0..cap) with used instances; returns count. Syncs the GUI live path in.
size_t re_mcp_db_list(re_mcp_db_t *dst, size_t cap);

// Ensure the GUI-open file appears as a gui backend instance.
void re_mcp_db_sync_live(void);

#ifdef __cplusplus
}
#endif
