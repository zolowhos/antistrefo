// re_fsave.c - temp file, streamed write, atomic replace, in-place patch.
// Module: util (C11).
// Owns: the bodies behind re_fsave.h.
// Depends: re_fsave.h, stdio, windows.h or stdio rename. 64-bit seeks on both.
#include "utils/sys/re_fsave.h"

#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#    include <windows.h>
#    define RE_FSEEK _fseeki64
#else
#    define RE_FSEEK fseeko
#endif

static bool copy_path(char *dst, size_t cap, const char *src, const char *suffix) {
    size_t n = 0;
    size_t k = 0;
    while (src[n])
        n++;
    while (suffix[k])
        k++;
    if (n + k + 1u > cap)
        return false;
    memcpy(dst, src, n);
    memcpy(dst + n, suffix, k + 1u);
    return true;
}

bool re_fsave_open(re_fsave_t *s, const char *path) {
    memset(s, 0, sizeof(*s));
    if (!path || !copy_path(s->dst, sizeof(s->dst), path, "") ||
        !copy_path(s->tmp, sizeof(s->tmp), path, ".tmp"))
        return false;
    s->fp = fopen(s->tmp, "wb");
    s->ok = s->fp != NULL;
    return s->ok;
}

bool re_fsave_write(re_fsave_t *s, const void *p, size_t n) {
    if (!s->ok)
        return false;
    if (n && fwrite(p, 1, n, (FILE *)s->fp) != n)
        s->ok = false;
    else
        s->pos += n;
    return s->ok;
}

bool re_fsave_align(re_fsave_t *s, uint64_t align) {
    static const uint8_t zero[64] = {0};
    while (s->ok && align && (s->pos % align) != 0) {
        uint64_t need = align - (s->pos % align);
        re_fsave_write(s, zero, (size_t)(need < sizeof(zero) ? need : sizeof(zero)));
    }
    return s->ok;
}

bool re_fsave_patch_at(re_fsave_t *s, uint64_t off, const void *p, size_t n) {
    FILE *fp = (FILE *)s->fp;
    if (!s->ok || off + n > s->pos)
        return false;
    if (RE_FSEEK(fp, (long long)off, SEEK_SET) != 0 || fwrite(p, 1, n, fp) != n ||
        RE_FSEEK(fp, (long long)s->pos, SEEK_SET) != 0)
        s->ok = false;
    return s->ok;
}

static bool replace_file(const char *from, const char *to) {
#if defined(_WIN32)
    return MoveFileExA(from, to, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
    return rename(from, to) == 0;
#endif
}

bool re_fsave_commit(re_fsave_t *s) {
    bool ok = s->ok && s->fp && fflush((FILE *)s->fp) == 0;
    if (s->fp && fclose((FILE *)s->fp) != 0)
        ok = false;
    s->fp = NULL;
    if (ok)
        ok = replace_file(s->tmp, s->dst);
    if (!ok)
        remove(s->tmp);
    s->ok = ok;
    return ok;
}

void re_fsave_abort(re_fsave_t *s) {
    if (s->fp)
        fclose((FILE *)s->fp);
    s->fp = NULL;
    s->ok = false;
    remove(s->tmp);
}

bool re_fsave_patch(const char *path, uint64_t off, const void *p, size_t n) {
    FILE *fp = fopen(path, "r+b");
    bool ok;
    if (!fp)
        return false;
    ok = RE_FSEEK(fp, (long long)off, SEEK_SET) == 0 && fwrite(p, 1, n, fp) == n;
    if (fclose(fp) != 0)
        ok = false;
    return ok;
}
