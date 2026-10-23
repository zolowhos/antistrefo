// re_vec.h - byte oriented growable array, one implementation for every element type.
// Module: util (C11).
// Owns: typed push, reserve, index, clear, truncate, sort and search over an arena.
// Depends: re_arena and re_sort only. No I/O, no globals, never frees one element.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>

#include "utils/algo/re_sort.h"
#include "utils/mem/re_arena.h"

typedef struct {
    unsigned char *base;
    size_t len;
    size_t cap;
    size_t esz;
} re_vec_t;

typedef int (*re_cmp_fn)(const void *a, const void *b, void *ctx);
typedef bool (*re_eq_fn)(const void *elem, const void *key, void *ctx);

static inline void re_vec_init(re_vec_t *v, size_t esz) {
    v->base = NULL;
    v->len = 0;
    v->cap = 0;
    v->esz = esz ? esz : 1;
}

static inline bool re_vec_reserve(re_vec_t *v, re_arena_t *a, size_t want) {
    if (v->cap >= want)
        return true;
    size_t cap = v->cap ? v->cap : 8;
    while (cap < want)
        cap *= 2;
    unsigned char *nb = (unsigned char *)re_arena_alloc(a, cap * v->esz);
    if (!nb)
        return false;
    if (v->base && v->len)
        memcpy(nb, v->base, v->len * v->esz);
    v->base = nb;
    v->cap = cap;
    return true;
}

static inline bool re_vec_push_(re_vec_t *v, re_arena_t *a, const void *elem, size_t esz) {
    if (!re_vec_reserve(v, a, v->len + 1))
        return false;
    memcpy(v->base + v->len * v->esz, elem, esz);
    v->len++;
    return true;
}

static inline void *re_vec_at(const re_vec_t *v, size_t i) {
    if (i >= v->len)
        return NULL;
    return v->base + i * v->esz;
}

static inline void re_vec_clear(re_vec_t *v) {
    v->len = 0;
}

static inline void re_vec_truncate(re_vec_t *v, size_t n) {
    v->len = n < v->len ? n : v->len;
}

static inline void re_vec_sort(re_vec_t *v, re_cmp_fn cmp, void *ctx) {
    re_sort_(v->base, v->len, v->esz, cmp, ctx);
}

static inline bool re_vec_find(const re_vec_t *v, const void *key, re_eq_fn eq, void *ctx,
                               size_t *out_idx) {
    for (size_t i = 0; i < v->len; i++) {
        if (eq(v->base + i * v->esz, key, ctx)) {
            if (out_idx)
                *out_idx = i;
            return true;
        }
    }
    return false;
}

// Heap backed reserve: uses malloc and free instead of the arena. Old storage is
// freed on every growth, so a vector that doubles twenty times holds one
// allocation rather than twenty one. Use this for the few vectors that grow to
// millions of elements and would otherwise abandon gigabytes in the arena.
static inline bool re_vec_reserve_heap(re_vec_t *v, size_t want) {
    if (v->cap >= want)
        return true;
    size_t cap = v->cap ? v->cap : 8;
    while (cap < want)
        cap *= 2;
    unsigned char *nb = (unsigned char *)malloc(cap * v->esz);
    if (!nb)
        return false;
    if (v->base && v->len)
        memcpy(nb, v->base, v->len * v->esz);
    if (v->base)
        free(v->base);
    v->base = nb;
    v->cap = cap;
    return true;
}

static inline void re_vec_free_heap(re_vec_t *v) {
    if (v->base)
        free(v->base);
    v->base = NULL;
    v->len = 0;
    v->cap = 0;
}

static inline bool re_vec_push_heap_(re_vec_t *v, const void *elem, size_t esz) {
    if (!re_vec_reserve_heap(v, v->len + 1))
        return false;
    memcpy(v->base + v->len * v->esz, elem, esz);
    v->len++;
    return true;
}

#define RE_VEC_PUSH(v, a, x) re_vec_push_((v), (a), &(x), sizeof(x))
#define RE_VEC_PUSH_HEAP(v, x) re_vec_push_heap_((v), &(x), sizeof(x))
#define RE_VEC_AT(v, T, i) (*(T *)(void *)re_vec_at((v), (i)))
#define RE_VEC_PTR(v, T, i) ((T *)(void *)re_vec_at((v), (i)))
#define RE_VEC_LEN(v) ((v)->len)
#ifdef __cplusplus
}
#endif
