// re_fsave.h - write a file so a reader never sees half of it, and patch one in place.
// Module: util (C11).
// Owns: the temp file, streamed writes, header patching, atomic replace, in-place patch.
// Depends: stdio, Win32 MoveFileExA or POSIX rename. Paths are bounded by RE_FSAVE_PATH.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RE_FSAVE_PATH 1024

// Streams into "<path>.tmp". Nothing at <path> changes until commit succeeds, so a
// crash or a full disk leaves the old file, or none, never a torn one.
typedef struct {
    void *fp;
    char dst[RE_FSAVE_PATH];
    char tmp[RE_FSAVE_PATH + 8];
    uint64_t pos; // bytes written so far, which is the offset of the next write
    bool ok;      // false after any failed write; commit then refuses
} re_fsave_t;

bool re_fsave_open(re_fsave_t *s, const char *path);
bool re_fsave_write(re_fsave_t *s, const void *p, size_t n);
// Write zero bytes until pos is a multiple of align.
bool re_fsave_align(re_fsave_t *s, uint64_t align);
// Overwrite bytes already written, such as a header whose offsets were not known
// when it went out first. The stream position is restored afterwards.
bool re_fsave_patch_at(re_fsave_t *s, uint64_t off, const void *p, size_t n);
// Flush, close and atomically replace <path>. False leaves <path> untouched.
bool re_fsave_commit(re_fsave_t *s);
// Close and delete the temp file.
void re_fsave_abort(re_fsave_t *s);

// Overwrite n bytes at off inside an existing file without truncating or replacing
// it. A reader that has the file mapped keeps its mapping and sees the new bytes.
bool re_fsave_patch(const char *path, uint64_t off, const void *p, size_t n);
#ifdef __cplusplus
}
#endif
