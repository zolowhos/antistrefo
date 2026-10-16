// emit_imm_page.c - write a PE with a known number of identical imm32 loads.
// Module: test (C11).
// Owns: a five-hit imm: fixture used by run_imm_truncated.cmake.
// Depends: stdio only. Layout mirrors re_pe_fixture.h with a different .text body.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define IMAGE_BASE 0x180000000ull
#define TEXT_RVA 0x1000u
#define HDRS 0x200u
#define OPT_SIZE 0xF0u

// Five "mov eax, imm32" then ret. The constant is rare in headers so hit count is
// exactly five after dedupe (LE dword form only; BE and qword do not appear).
static const uint8_t kCode[] = {
    0xb8, 0xd4, 0xc3, 0xb2, 0xa1, // mov eax, 0xA1B2C3D4
    0xb8, 0xd4, 0xc3, 0xb2, 0xa1, // mov eax, 0xA1B2C3D4
    0xb8, 0xd4, 0xc3, 0xb2, 0xa1, // mov eax, 0xA1B2C3D4
    0xb8, 0xd4, 0xc3, 0xb2, 0xa1, // mov eax, 0xA1B2C3D4
    0xb8, 0xd4, 0xc3, 0xb2, 0xa1, // mov eax, 0xA1B2C3D4
    0xc3,                         // ret
};

#define IMG_BYTES (HDRS + sizeof(kCode))

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

static void build_pe(uint8_t *img) {
    uint8_t *coff;
    uint8_t *opt;
    uint8_t *sec;
    memset(img, 0, IMG_BYTES);
    put16(img, 0x5A4D);
    put32(img + 0x3C, 0x40);
    put32(img + 0x40, 0x00004550u);
    coff = img + 0x44;
    put16(coff + 0, 0x8664);
    put16(coff + 2, 1);
    put16(coff + 16, OPT_SIZE);
    put16(coff + 18, 0x0022);
    opt = coff + 20;
    put16(opt, 0x20B);
    put32(opt + 16, TEXT_RVA);
    put64(opt + 24, IMAGE_BASE);
    put32(opt + 56, TEXT_RVA * 2);
    put16(opt + 68, 1);
    put32(opt + 108, 16);
    sec = img + 0x148;
    memcpy(sec, ".text", 5);
    put32(sec + 8, (uint32_t)sizeof(kCode));
    put32(sec + 12, TEXT_RVA);
    put32(sec + 16, (uint32_t)sizeof(kCode));
    put32(sec + 20, HDRS);
    put32(sec + 36, 0x60000020u);
    memcpy(img + HDRS, kCode, sizeof(kCode));
}

int main(int argc, char **argv) {
    uint8_t img[IMG_BYTES];
    FILE *fh;
    if (argc != 2) {
        fprintf(stderr, "usage: emit_imm_page <path>\n");
        return 2;
    }
    build_pe(img);
    fh = fopen(argv[1], "wb");
    if (!fh)
        return 3;
    if (fwrite(img, 1, sizeof(img), fh) != sizeof(img)) {
        fclose(fh);
        return 4;
    }
    fclose(fh);
    return 0;
}
