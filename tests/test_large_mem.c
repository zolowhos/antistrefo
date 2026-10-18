// test_large_mem.c - open/map a large synthetic PE without a second image copy.
// Module: test (C11).
// Owns: sparse large-PE fixture and arena-growth assertions for map+idle open.
// Depends: re_analyze, re_buf, re_pe. No real game binary; synthetic sparse file only.
#include "re_test.h"

#include <stdio.h>
#include <string.h>

#include "features/analysis/re_analyze.h"
#include "features/code/re_func.h"
#include "features/data/re_strings.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_buf.h"

#if defined(_WIN32)
#    include <windows.h>
#endif

int re_test_count = 0;
int re_test_fail = 0;

// ~32MiB keeps CI fast while still violating a "second full copy" if one exists.
#define LARGE_RAW (32u * 1024u * 1024u)
#define LARGE_PATH "re_test_large_mem.sys"

static void put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void put64(uint8_t *p, uint64_t v) {
    put32(p, (uint32_t)v);
    put32(p + 4, (uint32_t)(v >> 32));
}

static void fill_large_headers(uint8_t *hdr, size_t raw, uint32_t hdrs, uint32_t text_rva) {
    uint8_t *coff = hdr + 0x44;
    uint8_t *opt = coff + 20;
    uint8_t *sec = hdr + 0x148;
    memset(hdr, 0, 0x400);
    put16(hdr, 0x5A4D);
    put32(hdr + 0x3C, 0x40);
    put32(hdr + 0x40, 0x00004550u);
    put16(coff + 0, 0x8664);
    put16(coff + 2, 1);
    put16(coff + 16, 0xF0);
    put16(coff + 18, 0x0022);
    put16(opt, 0x20B);
    put32(opt + 16, text_rva);
    put64(opt + 24, 0x180000000ull);
    put32(opt + 56, text_rva + (uint32_t)raw);
    put16(opt + 68, 3);
    put32(opt + 108, 16);
    memcpy(sec, ".text", 5);
    put32(sec + 8, (uint32_t)raw);
    put32(sec + 12, text_rva);
    put32(sec + 16, (uint32_t)raw);
    put32(sec + 20, hdrs);
    put32(sec + 36, 0x60000020u);
    hdr[hdrs] = 0xC3; // one ret for a trivial function walk
}

static int extend_sparse(const char *path, size_t total) {
#if defined(_WIN32)
    HANDLE h =
        CreateFileA(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    LARGE_INTEGER li;
    if (h == INVALID_HANDLE_VALUE)
        return 0;
    li.QuadPart = (LONGLONG)total;
    if (!SetFilePointerEx(h, li, NULL, FILE_BEGIN) || !SetEndOfFile(h)) {
        CloseHandle(h);
        return 0;
    }
    CloseHandle(h);
    return 1;
#else
    {
        FILE *fh = fopen(path, "r+b");
        int ok = 0;
        if (!fh)
            return 0;
        if (total > 0 && fseek(fh, (long)(total - 1u), SEEK_SET) == 0 && fputc(0, fh) != EOF)
            ok = 1;
        fclose(fh);
        return ok;
    }
#endif
}

// Minimal PE32+ with one huge raw .text section. Headers stay small; the body is
// grown with a sparse extend so disk and CI stay cheap.
static int write_large_pe(const char *path, size_t raw) {
    uint8_t hdr[0x400];
    FILE *fh;
    const uint32_t text_rva = 0x1000u;
    const uint32_t hdrs = 0x200u;
    fill_large_headers(hdr, raw, hdrs, text_rva);
    fh = fopen(path, "wb");
    if (!fh)
        return 0;
    if (fwrite(hdr, 1, hdrs + 1, fh) != hdrs + 1) {
        fclose(fh);
        return 0;
    }
    fclose(fh);
    return extend_sparse(path, hdrs + raw);
}

static void check_map_no_copy(void) {
    re_arena_t a;
    re_file_t f;
    size_t before;
    RE_CHECK(write_large_pe(LARGE_PATH, LARGE_RAW));
    re_arena_init(&a, 1u << 16);
    before = a.total;
    RE_CHECK(re_file_open(LARGE_PATH, &a, &f) == RE_OK);
    RE_CHECK(f.map != NULL);
    RE_CHECK(f.heap == NULL);
    RE_CHECK_EQ_U(f.size, 0x200u + LARGE_RAW);
    // Mapping must not copy the image into the arena. A few path bytes are fine.
    RE_CHECK(a.total - before < 4096u);
    RE_CHECK(a.total < LARGE_RAW / 64u);
    re_file_close(&f);
    re_arena_free(&a);
}

static void check_open_idle(void) {
    re_arena_t a;
    re_analysis_t an;
    size_t after_open;
    size_t after_funcs;
    RE_CHECK(write_large_pe(LARGE_PATH, LARGE_RAW));
    re_arena_init(&a, 1u << 20);
    RE_CHECK(re_analysis_open(&an, &a, LARGE_PATH));
    RE_CHECK(an.ok);
    RE_CHECK(an.file.map != NULL);
    after_open = a.total;
    // Format-only open: PE tables + code bitset (1 bit/byte of .text), never a
    // second full image copy into the arena.
    RE_CHECK(after_open < LARGE_RAW / 2u);
    RE_CHECK(re_analysis_pass(&an, RE_PASS_FORMAT) != NULL);
    RE_CHECK(re_analysis_pass(&an, RE_PASS_FUNCS) == NULL);
    RE_CHECK(re_analysis_ensure(&an, RE_PASS_FUNCS));
    after_funcs = a.total;
    RE_CHECK(after_funcs < LARGE_RAW / 2u);
    // Strings must not strndup the whole image into the arena either.
    {
        re_strings_t st;
        size_t before = a.total;
        re_strings_init(&st);
        re_strings_scan(an.file.whole, 4, 20000, &a, &st);
        // Cap stores at most 20k hits; without views this used to clone every run.
        RE_CHECK(a.total - before < LARGE_RAW / 8u);
    }
    re_analysis_close(&an);
    re_arena_free(&a);
    remove(LARGE_PATH);
}

// Dense push rbp; ret every two bytes. Without reusing the per-function blocks
// vector this retained O(n_funcs) abandoned grow-arrays (multi-GB on real DLLs).
#define DENSE_RAW (2u * 1024u * 1024u)
#define DENSE_PATH "re_test_dense_funcs.sys"

static int write_dense_pe(const char *path, size_t raw) {
    uint8_t hdr[0x400];
    uint8_t chunk[4096];
    FILE *fh;
    const uint32_t text_rva = 0x1000u;
    const uint32_t hdrs = 0x200u;
    size_t left = raw;
    size_t i;
    fill_large_headers(hdr, raw, hdrs, text_rva);
    for (i = 0; i < sizeof(chunk); i += 2u) {
        chunk[i] = 0x55u;
        chunk[i + 1u] = 0xC3u;
    }
    fh = fopen(path, "wb");
    if (!fh)
        return 0;
    if (fwrite(hdr, 1, hdrs, fh) != hdrs) {
        fclose(fh);
        return 0;
    }
    while (left) {
        size_t n = left < sizeof(chunk) ? left : sizeof(chunk);
        if (fwrite(chunk, 1, n, fh) != n) {
            fclose(fh);
            return 0;
        }
        left -= n;
    }
    fclose(fh);
    return 1;
}

static void check_dense_funcs_bounded(void) {
    re_arena_t a;
    re_analysis_t an;
    size_t after;
    RE_CHECK(write_dense_pe(DENSE_PATH, DENSE_RAW));
    re_arena_init(&a, 1u << 20);
    RE_CHECK(re_analysis_open(&an, &a, DENSE_PATH));
    RE_CHECK(re_analysis_ensure(&an, RE_PASS_FUNCS));
    after = a.total;
    RE_CHECK(RE_VEC_LEN(&an.scan.funcs) <= RE_FUNC_MAX);
    RE_CHECK(an.scan.truncated);
    // Cap + reused blocks: well under a second full image, never multi-GB.
    RE_CHECK(after < 64u * 1024u * 1024u);
    re_analysis_close(&an);
    re_arena_free(&a);
    remove(DENSE_PATH);
}

int main(void) {
    check_map_no_copy();
    check_open_idle();
    check_dense_funcs_bounded();
    remove(LARGE_PATH);
    remove(DENSE_PATH);
    return re_test_report("large_mem");
}
