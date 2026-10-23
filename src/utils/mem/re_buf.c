// re_buf.c - the mmap loader plus the two string readers, nothing else.
// Module: util (C11).
// Owns: file mapping, bounded C string reads, fixed width name reads.
// Depends: re_buf.h only. No globals, no caching, no trust in file headers.
#include "utils/mem/re_buf.h"

#include "utils/text/re_str.h"

#include <string.h>

#if defined(_WIN32)
#    include <windows.h>
#else
#    include <fcntl.h>
#    include <unistd.h>
#    include <sys/mman.h>
#    include <sys/stat.h>
#endif

bool re_rd_cstr(re_span_t s, uint64_t off, uint64_t max, re_span_t *out) {
    if (off >= s.n)
        return false;
    uint64_t avail = s.n - off;
    if (max > avail)
        max = avail;
    const uint8_t *start = s.p + off;
    const uint8_t *nul = (const uint8_t *)memchr(start, 0, (size_t)max);
    *out = nul ? re_span(start, (size_t)(nul - start)) : re_span(start, (size_t)max);
    return nul != NULL;
}

void re_rd_fixed_str(re_span_t s, uint64_t off, size_t width, re_span_t *out) {
    re_span_t v = re_span_sub(s, off, width);
    if (!re_span_valid(v)) {
        *out = re_span_none();
        return;
    }
    size_t len = 0;
    while (len < v.n && v.p[len] != 0)
        len++;
    *out = re_span(v.p, len);
}

#if defined(_WIN32)

static re_err_code_t map_win(const char *path, re_file_t *out) {
    // Sharing write and delete lets another process patch an .asdb's user section in
    // place, or replace it, while this one still has it mapped for reading.
    HANDLE fh =
        CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE)
        return RE_E_IO;
    LARGE_INTEGER li;
    if (!GetFileSizeEx(fh, &li) || li.QuadPart < 0) {
        CloseHandle(fh);
        return RE_E_IO;
    }
    uint64_t size = (uint64_t)li.QuadPart;
    if (size == 0) {
        CloseHandle(fh);
        out->whole = re_span_none();
        out->size = 0;
        return RE_OK;
    }
    HANDLE mh = CreateFileMappingA(fh, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!mh) {
        CloseHandle(fh);
        return RE_E_IO;
    }
    const uint8_t *base = (const uint8_t *)MapViewOfFile(mh, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(fh);
    if (!base) {
        CloseHandle(mh);
        return RE_E_IO;
    }
    out->whole = re_span(base, (size_t)size);
    out->size = size;
    out->map = mh;
    return RE_OK;
}

#else

static re_err_code_t map_posix(const char *path, re_file_t *out) {
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return RE_E_IO;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0) {
        close(fd);
        return RE_E_IO;
    }
    if (st.st_size == 0) {
        close(fd);
        out->whole = re_span_none();
        out->size = 0;
        return RE_OK;
    }
    void *p = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED)
        return RE_E_IO;
    out->whole = re_span(p, (size_t)st.st_size);
    out->size = (uint64_t)st.st_size;
    out->map = p;
    return RE_OK;
}

#endif

re_err_code_t re_file_open(const char *path, re_arena_t *a, re_file_t *out) {
    (void)a;
    memset(out, 0, sizeof(*out));
    re_str_t p = re_str(path);
    out->path = re_span(p.p, p.n);
#if defined(_WIN32)
    return map_win(path, out);
#else
    return map_posix(path, out);
#endif
}

void re_file_close(re_file_t *f) {
    if (!f)
        return;
    if (f->map) {
#if defined(_WIN32)
        UnmapViewOfFile((const void *)f->whole.p);
        CloseHandle((HANDLE)f->map);
#else
        munmap(f->map, (size_t)f->size);
#endif
        f->map = NULL;
    }
    f->whole = re_span_none();
    f->size = 0;
}
