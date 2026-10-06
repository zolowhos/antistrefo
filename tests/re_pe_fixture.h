// re_pe_fixture.h - one hand built PE shared by the suites that parse it.
// Module: test (C11).
// Owns: the byte layout of a minimal image with a real export directory.
// Depends: re_pe through its public header. Static inline throughout, so two
//           translation units may include it without a second definition.
#pragma once

#include <stdint.h>
#include <string.h>

#include "features/pe/re_pe.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_buf.h"

#define IMAGE_BASE 0x180000000ull
#define TEXT_RVA 0x1000u
#define EDATA_RVA 0x2000u
#define EDATA_SIZE 0x160u
#define HDRS 0x200u
#define OPT_SIZE 0xF0u
#define IMG_BYTES (HDRS + sizeof(kCode) + EDATA_SIZE)

// A four block function chosen so every edge kind is unambiguous:
//
//   1000  cmp rax, 1
//   1004  je  0x100D            taken -> block 2, fall -> block 1
//   1006  mov eax, 1
//   100B  jmp 0x1013            taken -> block 3
//   100D  mov eax, 2
//   1012  ret
//   1013  ret
//
// Under the bug this suite exists for, only the first block was decoded and the
// graph came back as one block, so "more than one block" is the load bearing check.
//
// Then a second function at +20 whose third byte is a "sub rsp, 0x20" that no
// prologue test can tell from an entry point. Both are described in the exception
// table, so a scanner that trusts the table must report one function there and not
// two, which is the only way to catch a split back out of a known function body.
static const uint8_t kCode[] = {
    0x48, 0x83, 0xf8, 0x01,       // 1000 cmp rax,1
    0x74, 0x07,                   // 1004 je +7 -> 100D
    0xb8, 0x01, 0x00, 0x00, 0x00, // 1006 mov eax,1
    0xeb, 0x06,                   // 100B jmp +6 -> 1013
    0xb8, 0x02, 0x00, 0x00, 0x00, // 100D mov eax,2
    0xc3,                         // 1012 ret
    0xc3,                         // 1013 ret
    0x53,                         // 1014 push rbx
    0x48, 0x83, 0xec, 0x20,       // 1015 sub rsp,0x20  <- looks like a prologue
    0x5d,                         // 1019 pop rbx
    0xc3,                         // 101A ret
};
#define CODE_FN1_END (TEXT_RVA + 20u)
#define CODE_FN2_END (TEXT_RVA + 27u)

static inline void put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static inline void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline void put64(uint8_t *p, uint64_t v) {
    put32(p, (uint32_t)v);
    put32(p + 4, (uint32_t)(v >> 32));
}

static inline void build_exports(uint8_t *ed);
static inline void build_unwind(uint8_t *ed);
static inline void build_rtti(uint8_t *ed);

// The smallest PE the parser accepts: a DOS stub, a COFF header, a PE32+ optional
// header with sixteen empty data directories, and one executable section. Every
// field the parser reads is written here, and nothing else, so a parser change that
// starts requiring a new field shows up as a failing test rather than as a silently
// different fixture.
static inline void build_pe(uint8_t *img) {
    // The whole image is zeroed, not just the headers: the RTTI and export layouts
    // below write every field they care about and nothing else, and a reader that
    // widens a read (the 8 byte vtable slots do) must see zeroes there, not whatever
    // the caller's stack happened to hold. A fixture full of stack garbage makes the
    // pass under test look nondeterministic, which is exactly what it did.
    memset(img, 0, IMG_BYTES);
    put16(img, 0x5A4D);             // MZ
    put32(img + 0x3C, 0x40);        // e_lfanew
    put32(img + 0x40, 0x00004550u); // PE\0\0
    uint8_t *coff = img + 0x44;
    put16(coff + 0, 0x8664);    // machine x64
    put16(coff + 2, 1);         // one section
    put16(coff + 16, OPT_SIZE); // SizeOfOptionalHeader
    put16(coff + 18, 0x0022);   // executable, large address aware
    uint8_t *opt = coff + 20;
    put16(opt, 0x20B);             // PE32+
    put32(opt + 16, TEXT_RVA);     // AddressOfEntryPoint
    put64(opt + 24, IMAGE_BASE);   // ImageBase
    put32(opt + 56, TEXT_RVA * 2); // SizeOfImage
    put16(opt + 68, 1);            // subsystem native
    put32(opt + 108, 16);          // NumberOfRvaAndSizes
    put32(opt + 112, EDATA_RVA);   // export directory
    put32(opt + 116, EDATA_SIZE);
    // The exception directory, pointed into the same data section rather than a
    // third one. Directory i lives at optional header offset 112 + i * 8, so the
    // exception table is index 3 and sits at 136. It carries one RUNTIME_FUNCTION
    // covering the whole of .text, which is what lets a test prove both that the
    // table parses and that the function scanner takes its end from the compiler
    // rather than from where a walk stopped.
    put32(opt + 136, EDATA_RVA + 0xB0);
    put32(opt + 140, 24);
    uint8_t *sec = img + 0x148; // lfanew + 4 + 20 + SizeOfOptionalHeader
    memcpy(sec, ".text", 5);
    put32(sec + 8, (uint32_t)sizeof(kCode));  // VirtualSize
    put32(sec + 12, TEXT_RVA);                // VirtualAddress
    put32(sec + 16, (uint32_t)sizeof(kCode)); // SizeOfRawData
    put32(sec + 20, HDRS);                    // PointerToRawData
    put32(sec + 36, 0x60000020u);             // code, execute, read
    memcpy(img + HDRS, kCode, sizeof(kCode));
    uint8_t *ed = img + 0x148 + 40; // the second section header
    memcpy(ed, ".edata", 6);
    put32(ed + 8, EDATA_SIZE);            // VirtualSize
    put32(ed + 12, EDATA_RVA);            // VirtualAddress
    put32(ed + 16, EDATA_SIZE);           // SizeOfRawData
    put32(ed + 20, HDRS + sizeof(kCode)); // PointerToRawData
    put32(ed + 36, 0x40000040u);          // initialised data, read
    put16(coff + 2, 2);                   // two sections, now that there are two
    build_exports(img + HDRS + sizeof(kCode));
}

// The export directory, laid out exactly as the spec has it, because the whole point
// is that the parser reads the fields at the offsets they actually occupy:
//
//   +16 Base  +20 NumberOfFunctions  +24 NumberOfNames
//   +28 AddressOfFunctions  +32 AddressOfNames  +36 AddressOfNameOrdinals
//
// Getting +28 and +32 the wrong way round is the bug that made every export name
// come back as the opening bytes of a function, and a count-only test cannot see it:
// the number of names parsed correctly either way. So the names here are fixed text,
// and the assertions below compare them.
static inline void build_exports(uint8_t *ed) {
    // The fourth export points at a string inside the export directory rather than at
    // code, which is exactly what a forwarder is. It is here so the classification
    // below has one of each to tell apart: code, data, and a forwarder. The three
    // arrays are laid out to clear each other: four names need 16 bytes for the name
    // pointers, and the 3 name fixture fitted them exactly against the ordinals.
    // An array, not a pointer: sizeof on "const char *const" is 8, which silently
    // truncated this string to its first eight characters and made the test assert a
    // forwarder name that the fixture had never contained.
    static const char kFwd[] = "KERNEL32.Sleep";
    const char *names[4] = {"AlphaFunc", "BetaFunc", "GammaFunc", "FwdFunc"};
    const uint32_t rvas[4] = {TEXT_RVA, TEXT_RVA + 6, TEXT_RVA + 19, EDATA_RVA + 0x94};
    size_t n = sizeof(names) / sizeof(names[0]);
    put32(ed + 0, 0);                 // Characteristics
    put32(ed + 12, EDATA_RVA + 0x60); // Name, the module
    put32(ed + 16, 1);                // Base: ordinals are 1, 2, 3
    put32(ed + 20, (uint32_t)n);      // NumberOfFunctions
    put32(ed + 24, (uint32_t)n);      // NumberOfNames
    put32(ed + 28, EDATA_RVA + 0x28); // AddressOfFunctions, 4 entries to 0x38
    put32(ed + 32, EDATA_RVA + 0x3C); // AddressOfNames, 4 entries to 0x4C
    put32(ed + 36, EDATA_RVA + 0x4C); // AddressOfNameOrdinals, 4 entries to 0x54
    size_t str = 0x60;
    memcpy(ed + str, "testmod.dll", 11);
    str += 12;
    for (size_t i = 0; i < n; i++) {
        put32(ed + 0x28 + i * 4, rvas[i]);
        put32(ed + 0x3C + i * 4, EDATA_RVA + (uint32_t)str);
        put16(ed + 0x4C + i * 2, (uint16_t)i);
        size_t len = 0;
        while (names[i][len])
            len++;
        memcpy(ed + str, names[i], len + 1);
        str += len + 1;
    }
    memcpy(ed + 0x94, kFwd, sizeof(kFwd)); // the forwarder string, NUL terminated
    build_unwind(ed);
    build_rtti(ed);
}

// The exception table, written second function first. Every linker emits this table
// already sorted, so the parser's own sort is otherwise never exercised: leaving it
// out passes every test here and then binary searches unsorted data on an image that
// did not.
static inline void build_unwind(uint8_t *ed) {
    put32(ed + 0xB0 + 0, CODE_FN1_END);
    put32(ed + 0xB0 + 4, CODE_FN2_END);
    put32(ed + 0xB0 + 8, EDATA_RVA + 0xC0);
    put32(ed + 0xB0 + 12, TEXT_RVA);
    put32(ed + 0xB0 + 16, CODE_FN1_END);
    put32(ed + 0xB0 + 20, EDATA_RVA + 0xC0);
}

// One C++ class, laid out the way MSVC writes RTTI: a TypeDescriptor holding the
// mangled name, a Complete Object Locator that names its own address, and a vtable
// whose slot before the first entry points at that locator. Every number is checked
// against the image, so a locator with a wrong pSelf cannot pass.
static inline void build_rtti(uint8_t *ed) {
    static const char kName[] = ".?AVProbe@@";
    put64(ed + 0xD0 + 0, EDATA_RVA + 0x120); // the two type_info pointers,
    put64(ed + 0xD8 + 0, EDATA_RVA + 0x128); // which the runtime compares
    memcpy(ed + 0xE0, kName, sizeof(kName));
    // The locator, at 0xF0. Signature 1 is the x64 form.
    put32(ed + 0xF0 + 0, 1);
    put32(ed + 0xF0 + 4, 0);                  // offset of the complete object
    put32(ed + 0xF0 + 8, 0);                  // constructor displacement
    put32(ed + 0xF0 + 12, EDATA_RVA + 0xD0);  // pTypeDescriptor
    put32(ed + 0xF0 + 16, EDATA_RVA + 0x108); // pClassDescriptor
    put32(ed + 0xF0 + 20, EDATA_RVA + 0xF0);  // pSelf, which must be this locator
    // The base class descriptor, naming the same class and one base.
    put32(ed + 0x108 + 0, EDATA_RVA + 0xD0);
    put32(ed + 0x108 + 4, 1); // number of contained bases
    put32(ed + 0x108 + 8, 0);
    put32(ed + 0x108 + 12, 0); // mdisp, base at offset zero
    put32(ed + 0x108 + 16, EDATA_RVA + 0xD0);
    // The vtable: the slot before the first entry points at the locator.
    put32(ed + 0x118, EDATA_RVA + 0xF0);
    put32(ed + 0x120, TEXT_RVA);
    put32(ed + 0x128, TEXT_RVA + 6);
    // A decoy locator: every field is well formed except pSelf, which names
    // somewhere else. Nothing else in a data section repeats an address like this, so
    // it is the one field that can tell a real locator from a coincidence.
    put32(ed + 0x148 + 0, 1);
    put32(ed + 0x148 + 4, 0);
    put32(ed + 0x148 + 8, 0);
    put32(ed + 0x148 + 12, EDATA_RVA + 0xD0);
    put32(ed + 0x148 + 16, EDATA_RVA + 0x108);
    put32(ed + 0x148 + 20, EDATA_RVA + 0x100); // pSelf, wrong on purpose
}
