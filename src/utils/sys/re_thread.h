// re_thread.h - one worker thread plus the atomics a worker and its owner share.
// Module: util (C11).
// Owns: thread start and join, a 64-bit atomic cell, and the logical CPU count.
// Depends: Win32 or pthreads. No globals; the caller owns every re_thread_t.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stdint.h>

typedef void (*re_thread_fn)(void *arg);

// The caller keeps this alive until re_thread_join returns, because the start
// trampoline reads fn and arg out of it on the new thread.
typedef struct {
    void *handle;
    re_thread_fn fn;
    void *arg;
    bool started;
} re_thread_t;

bool re_thread_start(re_thread_t *t, re_thread_fn fn, void *arg);
void re_thread_join(re_thread_t *t);

// Logical processors, at least 1.
unsigned re_thread_cpus(void);

// Installed physical memory in bytes, 0 when the platform will not say.
uint64_t re_thread_phys_mem(void);

// A cell two threads may read and write without a lock. Sequentially consistent.
typedef struct {
    volatile int64_t v;
} re_atomic_t;

int64_t re_atomic_get(const re_atomic_t *a);
void re_atomic_set(re_atomic_t *a, int64_t v);
int64_t re_atomic_add(re_atomic_t *a, int64_t d); // returns the new value
#ifdef __cplusplus
}
#endif
