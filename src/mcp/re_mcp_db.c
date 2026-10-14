// re_mcp_db.c - process-local database instances for the ida-mcp tool surface.
// Module: mcp (C11).
// Owns: the instance table and current pointer.
// Depends: re_mcp_db.h, re_mcp_live, re_str. No heap.
#include "mcp/re_mcp_db.h"

#include "utils/text/re_str.h"
#include "mcp/re_mcp_live.h"

#include <stdio.h>
#include <string.h>

static re_mcp_db_t g_db[RE_MCP_DB_MAX];
static unsigned g_seq;

static void clear_current(void) {
    for (size_t i = 0; i < RE_MCP_DB_MAX; i++)
        g_db[i].current = false;
}

static re_mcp_db_t *find_path(const char *path) {
    for (size_t i = 0; i < RE_MCP_DB_MAX; i++) {
        if (g_db[i].used && re_str_eq_cstr(re_str(g_db[i].path), path))
            return &g_db[i];
    }
    return NULL;
}

static re_mcp_db_t *find_id(const char *id) {
    if (!id || !id[0])
        return NULL;
    for (size_t i = 0; i < RE_MCP_DB_MAX; i++) {
        if (g_db[i].used && re_str_eq_cstr(re_str(g_db[i].id), id))
            return &g_db[i];
    }
    return NULL;
}

static re_mcp_db_t *current_slot(void) {
    for (size_t i = 0; i < RE_MCP_DB_MAX; i++) {
        if (g_db[i].used && g_db[i].current)
            return &g_db[i];
    }
    return NULL;
}

static re_mcp_db_t *alloc_slot(void) {
    for (size_t i = 0; i < RE_MCP_DB_MAX; i++) {
        if (!g_db[i].used)
            return &g_db[i];
    }
    return NULL;
}

static void mint_id(char *dst, size_t n) {
    snprintf(dst, n, "a%08x", (unsigned)(++g_seq * 2654435761u));
}

bool re_mcp_db_open(const char *path, bool set_current, const char *backend, re_mcp_db_t *out) {
    re_mcp_db_t *slot;
    if (!path || !path[0] || !out)
        return false;
    slot = find_path(path);
    if (!slot) {
        slot = alloc_slot();
        if (!slot)
            return false;
        memset(slot, 0, sizeof(*slot));
        mint_id(slot->id, sizeof(slot->id));
        snprintf(slot->path, sizeof(slot->path), "%s", path);
        snprintf(slot->backend, sizeof(slot->backend), "%s", backend ? backend : "idalib");
        slot->used = true;
    } else if (backend && backend[0]) {
        snprintf(slot->backend, sizeof(slot->backend), "%s", backend);
    }
    if (set_current) {
        clear_current();
        slot->current = true;
    }
    *out = *slot;
    return true;
}

const re_mcp_db_t *re_mcp_db_get(const char *instance_id) {
    re_mcp_db_sync_live();
    if (instance_id && instance_id[0])
        return find_id(instance_id);
    return current_slot();
}

const char *re_mcp_db_path(const char *instance_id) {
    const re_mcp_db_t *d = re_mcp_db_get(instance_id);
    return d ? d->path : NULL;
}

bool re_mcp_db_close(const char *instance_id, bool *closed) {
    re_mcp_db_t *slot;
    if (closed)
        *closed = false;
    re_mcp_db_sync_live();
    slot = (instance_id && instance_id[0]) ? find_id(instance_id) : current_slot();
    if (!slot)
        return false;
    if (re_str_eq_cstr(re_str(slot->backend), "gui")) {
        slot->current = false;
        if (closed)
            *closed = true;
        return true;
    }
    memset(slot, 0, sizeof(*slot));
    if (closed)
        *closed = true;
    return true;
}

void re_mcp_db_sync_live(void) {
    const char *live = re_mcp_live_path();
    re_mcp_db_t *slot;
    if (!live || !live[0])
        return;
    slot = find_path(live);
    if (!slot) {
        re_mcp_db_t tmp;
        (void)re_mcp_db_open(live, current_slot() == NULL, "gui", &tmp);
        return;
    }
    snprintf(slot->backend, sizeof(slot->backend), "%s", "gui");
}

size_t re_mcp_db_list(re_mcp_db_t *dst, size_t cap) {
    size_t n = 0;
    re_mcp_db_sync_live();
    for (size_t i = 0; i < RE_MCP_DB_MAX && n < cap; i++) {
        if (!g_db[i].used)
            continue;
        dst[n++] = g_db[i];
    }
    return n;
}
