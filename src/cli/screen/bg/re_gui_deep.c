// re_gui_deep.c - the background deep pass behind the interactive view.
// Module: cli (C11).
// Owns: the worker thread, its progress line, and the swap onto the database.
// Depends: re_gui_priv.h, re_deep, re_thread. The worker never touches the live view.
#include "cli/screen/bg/re_gui_priv.h"

#include "features/analysis/re_analyze.h"

#include <stdio.h>

static void deep_worker(void *arg) {
    gui_t *g = (gui_t *)arg;
    if (re_analysis_open(&g->deep_an, &g->deep_arena, g->path))
        re_deep_run(&g->deep_an, &g->deep_ctrl);
    // Published last, and only from here, so the view's read of it needs no lock.
    re_atomic_set(&g->deep_ctrl.progress, re_deep_progress(RE_DEEP_PHASES, 1));
}

static void deep_status(gui_t *g) {
    static const char *const kPhase[] = {"classify", "functions", "symbols", "xrefs",
                                         "jtables",  "strings",   "regions", "flirt",
                                         "names",    "score",     "database"};
    int64_t p = re_atomic_get(&g->deep_ctrl.progress);
    uint8_t ph = re_deep_phase(p);
    char msg[96];
    if (!g->deep_running || ph >= RE_DEEP_PHASES || ph == g->deep_logged)
        return;
    g->deep_logged = ph;
    snprintf(msg, sizeof(msg), "deep %u/%u %s", (unsigned)(ph + 1u), (unsigned)RE_DEEP_PHASES,
             ph < sizeof(kPhase) / sizeof(kPhase[0]) ? kPhase[ph] : "working");
    re_console_push(&g->console, msg);
}

void re_gui_arm_deep(gui_t *g) {
    if (g->an.db || !g->an.has_code)
        return;
    re_atomic_set(&g->deep_ctrl.progress, 0);
    re_atomic_set(&g->deep_ctrl.cancel, 0);
    g->deep_logged = 0xFFu;
    g->deep_done = false;
    g->deep_running = re_thread_start(&g->deep_thread, deep_worker, g);
}

void re_gui_stop_deep(gui_t *g) {
    if (!g->deep_running)
        return;
    re_atomic_set(&g->deep_ctrl.cancel, 1);
    re_thread_join(&g->deep_thread);
    re_analysis_close(&g->deep_an);
    re_arena_free(&g->deep_arena);
    g->deep_running = false;
    g->deep_done = false;
}

// The worker has written the database. Close the entry tier and reopen, which reads
// the database, so the view becomes the deep tier's without sharing its memory.
static void swap_deep(gui_t *g, re_arena_t *a, re_gui_funcs_t *list) {
    char path[512];
    size_t n = 0;
    while (g->path[n] && n + 1u < sizeof(path)) {
        path[n] = g->path[n];
        n++;
    }
    path[n] = '\0';
    re_gui_stop_deep(g);
    re_analysis_close(&g->an);
    re_arena_free(&g->fana);
    re_arena_init(&g->fana, 1u << 23);
    if (re_analysis_open(&g->an, &g->fana, path)) {
        list->n = 0;
        re_gui_funcs_fill(list, a, &g->an);
        re_console_push(&g->console, g->an.db ? "deep analysis loaded" : "deep analysis kept");
    }
    g->repaint = true;
}

void re_gui_pump_deep(gui_t *g, re_arena_t *a, re_gui_funcs_t *list) {
    if (g->deep_running && re_deep_phase(re_atomic_get(&g->deep_ctrl.progress)) >= RE_DEEP_PHASES)
        g->deep_done = true;
    if (g->deep_done)
        swap_deep(g, a, list);
    deep_status(g);
}
