// re_thread.c - Win32 and pthread bodies behind re_thread.h.
// Module: util (C11).
// Owns: the start trampoline, join, the CPU count, and the atomic cell.
// Depends: re_thread.h, windows.h or pthread.h. No allocation: the record is the caller's.
#include "utils/sys/re_thread.h"

#if defined(_WIN32)
#    include <windows.h>
#else
#    include <pthread.h>
#    include <unistd.h>
#endif

#if defined(_WIN32)

static DWORD WINAPI trampoline(LPVOID p) {
    re_thread_t *t = (re_thread_t *)p;
    t->fn(t->arg);
    return 0;
}

bool re_thread_start(re_thread_t *t, re_thread_fn fn, void *arg) {
    t->fn = fn;
    t->arg = arg;
    t->handle = CreateThread(NULL, 0, trampoline, t, 0, NULL);
    t->started = t->handle != NULL;
    return t->started;
}

void re_thread_join(re_thread_t *t) {
    if (!t || !t->started)
        return;
    WaitForSingleObject((HANDLE)t->handle, INFINITE);
    CloseHandle((HANDLE)t->handle);
    t->started = false;
    t->handle = NULL;
}

unsigned re_thread_cpus(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors ? (unsigned)si.dwNumberOfProcessors : 1u;
}

uint64_t re_thread_phys_mem(void) {
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    return GlobalMemoryStatusEx(&ms) ? (uint64_t)ms.ullTotalPhys : 0u;
}

int64_t re_atomic_get(const re_atomic_t *a) {
    return (int64_t)InterlockedCompareExchange64((volatile LONG64 *)&a->v, 0, 0);
}

void re_atomic_set(re_atomic_t *a, int64_t v) {
    InterlockedExchange64((volatile LONG64 *)&a->v, (LONG64)v);
}

int64_t re_atomic_add(re_atomic_t *a, int64_t d) {
    return (int64_t)InterlockedAdd64((volatile LONG64 *)&a->v, (LONG64)d);
}

#else

static void *trampoline(void *p) {
    re_thread_t *t = (re_thread_t *)p;
    t->fn(t->arg);
    return NULL;
}

bool re_thread_start(re_thread_t *t, re_thread_fn fn, void *arg) {
    pthread_t *h = (pthread_t *)&t->handle;
    t->fn = fn;
    t->arg = arg;
    t->started = sizeof(pthread_t) <= sizeof(void *) && pthread_create(h, NULL, trampoline, t) == 0;
    return t->started;
}

void re_thread_join(re_thread_t *t) {
    if (!t || !t->started)
        return;
    pthread_join(*(pthread_t *)&t->handle, NULL);
    t->started = false;
}

unsigned re_thread_cpus(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (unsigned)n : 1u;
}

uint64_t re_thread_phys_mem(void) {
    long pages = sysconf(_SC_PHYS_PAGES);
    long size = sysconf(_SC_PAGESIZE);
    return pages > 0 && size > 0 ? (uint64_t)pages * (uint64_t)size : 0u;
}

int64_t re_atomic_get(const re_atomic_t *a) {
    return __atomic_load_n(&a->v, __ATOMIC_SEQ_CST);
}

void re_atomic_set(re_atomic_t *a, int64_t v) {
    __atomic_store_n(&a->v, v, __ATOMIC_SEQ_CST);
}

int64_t re_atomic_add(re_atomic_t *a, int64_t d) {
    return __atomic_add_fetch(&a->v, d, __ATOMIC_SEQ_CST);
}

#endif
