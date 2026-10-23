// re_sort.c - introsort over raw bytes, shared by every container in the project.
// Module: util (C11).
// Owns: quicksort with median of three, heapsort fallback, insertion sort base case.
// Depends: re_sort.h only. No I/O, no globals, no allocation, not stable.
#include "utils/algo/re_sort.h"

#include <stdint.h>
#include <string.h>

#define RE_SORT_INSERT_MAX 16
#define RE_SORT_DEPTH_MAX 24

// Eight bytes at a time through a word, then the tail a byte at a time: a decoded
// instruction is over a hundred bytes, and a byte loop made every swap the sort's cost.
static void swap_el(unsigned char *a, unsigned char *b, size_t esz) {
    size_t i = 0;
    for (; i + 8 <= esz; i += 8) {
        uint64_t t, u;
        memcpy(&t, a + i, 8);
        memcpy(&u, b + i, 8);
        memcpy(a + i, &u, 8);
        memcpy(b + i, &t, 8);
    }
    for (; i < esz; i++) {
        unsigned char t = a[i];
        a[i] = b[i];
        b[i] = t;
    }
}

static void insertion_sort(unsigned char *base, size_t n, size_t esz, re_cmp_fn cmp, void *ctx) {
    for (size_t i = 1; i < n; i++) {
        unsigned char tmp[256];
        unsigned char *cur = base + i * esz;
        if (esz > sizeof(tmp))
            return;
        memcpy(tmp, cur, esz);
        size_t j = i;
        while (j > 0 && cmp(base + (j - 1) * esz, tmp, ctx) > 0) {
            memcpy(base + j * esz, base + (j - 1) * esz, esz);
            j--;
        }
        memcpy(base + j * esz, tmp, esz);
    }
}

static void sift_down(unsigned char *base, size_t n, size_t root, size_t esz, re_cmp_fn cmp,
                      void *ctx) {
    for (;;) {
        size_t big = root;
        size_t l = root * 2 + 1;
        size_t r = l + 1;
        if (l < n && cmp(base + l * esz, base + big * esz, ctx) > 0)
            big = l;
        if (r < n && cmp(base + r * esz, base + big * esz, ctx) > 0)
            big = r;
        if (big == root)
            return;
        swap_el(base + root * esz, base + big * esz, esz);
        root = big;
    }
}

static void heap_sort(unsigned char *base, size_t n, size_t esz, re_cmp_fn cmp, void *ctx) {
    for (size_t i = n / 2; i > 0; i--)
        sift_down(base, n, i - 1, esz, cmp, ctx);
    for (size_t i = n; i > 1; i--) {
        swap_el(base, base + (i - 1) * esz, esz);
        sift_down(base, i - 1, 0, esz, cmp, ctx);
    }
}

// Place the median of first, middle and last at the front, used as the pivot.
static unsigned char *median3(unsigned char *base, size_t n, size_t esz, re_cmp_fn cmp, void *ctx) {
    size_t mid = n / 2;
    size_t last = n - 1;
    if (cmp(base + mid * esz, base, ctx) < 0)
        swap_el(base, base + mid * esz, esz);
    if (cmp(base + last * esz, base, ctx) < 0)
        swap_el(base, base + last * esz, esz);
    if (cmp(base + last * esz, base + mid * esz, ctx) < 0)
        swap_el(base + last * esz, base + mid * esz, esz);
    swap_el(base, base + mid * esz, esz);
    return base;
}

static void intro_sort(unsigned char *base, size_t n, size_t esz, re_cmp_fn cmp, void *ctx,
                       int depth) {
    while (n > RE_SORT_INSERT_MAX) {
        if (depth <= 0) {
            heap_sort(base, n, esz, cmp, ctx);
            return;
        }
        depth--;
        unsigned char *piv = median3(base, n, esz, cmp, ctx);
        size_t i = 0;
        size_t j = n - 1;
        while (i <= j) {
            while (i < n && cmp(base + i * esz, piv, ctx) < 0)
                i++;
            while (cmp(base + j * esz, piv, ctx) > 0 && j > 0)
                j--;
            if (i <= j) {
                if (i != j)
                    swap_el(base + i * esz, base + j * esz, esz);
                i++;
                if (j > 0)
                    j--;
            }
        }
        swap_el(base, base + j * esz, esz);
        intro_sort(base, j, esz, cmp, ctx, depth);
        base += (j + 1) * esz;
        n -= (j + 1);
    }
    insertion_sort(base, n, esz, cmp, ctx);
}

void re_sort_(void *base, size_t n, size_t esz, re_cmp_fn cmp, void *ctx) {
    if (!base || n < 2 || esz == 0)
        return;
    if (esz > 256) {
        // Elements too large for the stack scratch buffer fall back to heapsort,
        // which needs no temporary storage at all.
        heap_sort((unsigned char *)base, n, esz, cmp, ctx);
        return;
    }
    intro_sort((unsigned char *)base, n, esz, cmp, ctx, RE_SORT_DEPTH_MAX);
}
