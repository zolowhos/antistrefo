// re_pe.h - PE and COFF structure, parsed defensively into a flat arena record.
// Module: feature (C11).
// Owns: DOS and NT headers, sections, data directories, imports, exports, rva map.
// Depends: re_buf, re_vec, re_str, re_err. No globals, no I/O, no allocation.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils/mem/re_arena.h"
#include "utils/mem/re_buf.h"
#include "utils/mem/re_vec.h"
#include "utils/sys/re_entropy.h"
#include "utils/sys/re_err.h"
#include "utils/text/re_str.h"
#include "utils/text/re_strbuf.h"

#define RE_PE_MAX_SECTIONS 128
#define RE_PE_MAX_DIRS 16
#define RE_PE_DLL_NAME_MAX 96
#define RE_PE_IMPORT_LIMIT 4096
// Far above any real image. A directory claiming more entries than this is a number
// from a hostile file, and stopping is the only safe reading.
#define RE_PE_UNWIND_LIMIT 1000000u

typedef struct {
    char name[9];
    uint32_t vaddr;
    uint32_t vsize;
    uint32_t rsize;
    uint32_t rptr;
    uint32_t chars;
    double entropy;
} re_pe_section_t;

typedef struct {
    re_str_t dll;
    uint32_t first_sym; // index into re_pe_t::syms
    uint32_t n_syms;
    // RVA of this module's first IAT slot. Code reaches an import through
    // [rip+slot], so without this a call target cannot be named.
    uint32_t first_thunk;
} re_pe_imp_t;

typedef struct {
    uint32_t ordinal;
    uint32_t rva;
    re_str_t name;
} re_pe_exp_t;

// One RUNTIME_FUNCTION: the compiler's own statement of where a function starts and
// where it ends. On x64 every function that can throw or unwind has one, which makes
// this the closest thing a PE has to a function list. It is not complete - a leaf
// function that needs no frame has no entry - so it is evidence, not the truth.
typedef struct {
    uint32_t begin; // rva
    uint32_t end;   // rva, exclusive
    uint32_t unwind;
} re_pe_unwind_t;

typedef struct {
    bool valid;
    bool pe32plus;
    bool has_ascii;  // characteristics IMAGE_FILE_EXECUTABLE_IMAGE
    bool is_dll;     // characteristics IMAGE_FILE_DLL
    bool signed_hdr; // optional header directories[4] present
    uint16_t machine;
    uint16_t n_sec_field;
    uint16_t opt_size;
    uint16_t chars;
    uint16_t subsystem;
    uint16_t dll_chars;
    uint32_t timestamp;
    uint32_t entry_rva;
    uint64_t image_base;
    uint32_t size_of_image;
    uint32_t n_dirs;
    uint32_t dd_rva[RE_PE_MAX_DIRS];
    uint32_t dd_size[RE_PE_MAX_DIRS];
    re_pe_section_t sec[RE_PE_MAX_SECTIONS];
    uint16_t n_sec;
    re_vec_t imports; // re_pe_imp_t
    re_vec_t syms;    // re_str_t, flat, indexed by first_sym
    re_vec_t exports; // re_pe_exp_t
    re_vec_t unwind;  // re_pe_unwind_t, from the exception directory
    re_span_t img;    // the bytes this was parsed from, so a later pass can read them
    re_err_t err;
} re_pe_t;

// Parse a mapped image. Never reads past the span and never trusts a count that
// came from the file, so a truncated or hostile image yields an error, not a crash.
re_err_code_t re_pe_parse(re_span_t img, re_arena_t *a, re_pe_t *out);

// Translate a relative virtual address to a file offset. Returns false for an
// address outside every section, which is normal for headers and for relocations.
// IMAGE_SCN_CNT_CODE and IMAGE_SCN_MEM_EXECUTE, named here so no caller has to
// remember the numeric values. They live in the format layer because a section table
// states them, and answering "is this address code or data" is a question about the
// file, not about any particular analysis pass layered on top of it.
#define RE_SEC_CODE 0x00000020u
#define RE_SEC_BSS 0x00000080u
#define RE_SEC_EXEC 0x20000000u
#define RE_SEC_READ 0x40000000u
#define RE_SEC_WRITE 0x80000000u

bool re_pe_rva2off(const re_pe_t *pe, uint32_t rva, uint64_t *out);

// The section an rva falls in, or NULL when it falls in none. NULL is a real answer
// and not an error: a linker can leave a gap between sections, and an export that
// points into one is a data marker rather than a function. Reporting such an export
// as a function is how a tool ends up calling a GPU preference dword code.
const re_pe_section_t *re_pe_section_at_rva(const re_pe_t *pe, uint32_t rva);

// What an address in a section is: code, data, or neither. The distinction is what
// decides whether a symbol at that address can be called at all.
const char *re_pe_region_kind(const re_pe_section_t *s);

// A forwarder is an export whose target lands inside the export directory itself,
// where the linker has written the string naming the real target in another module.
// It reads as a data export until you notice the target is the directory itself, and
// calling it as an address lands in the middle of a string. Returns an empty string
// for anything that is not a forwarder.
re_str_t re_pe_export_forwarder(const re_pe_t *pe, uint32_t rva);

// The unwind entry covering an rva. Fills out and returns true when one does, so the
// caller gets a copy rather than a pointer into a vector that may still grow. A
// caller seeding a function can use this to refuse a start that lands inside a
// function the compiler already described, which is how a "sub rsp, 0x28" in the
// middle of a body stops being mistaken for a prologue.
bool re_pe_unwind_covering(const re_pe_t *pe, uint32_t rva, re_pe_unwind_t *out);

// The reverse mapping, for turning a file offset back into a virtual address.
bool re_pe_off2rva(const re_pe_t *pe, uint64_t off, uint32_t *out);

const char *re_pe_machine_name(uint16_t machine);
const char *re_pe_subsystem_name(uint16_t subsystem);
const char *re_pe_section_flags(uint32_t chars, re_strbuf_t *out);

// Data directory indices we actually consult, so no caller hardcodes a number.
enum {
    RE_PE_DD_EXPORT = 0,
    RE_PE_DD_IMPORT = 1,
    RE_PE_DD_RESOURCE = 2,
    RE_PE_DD_EXCEPTION = 3,
    RE_PE_DD_SECURITY = 4,
    RE_PE_DD_DEBUG = 6,
    RE_PE_DD_TLS = 9,
    RE_PE_DD_IAT = 12,
};
#ifdef __cplusplus
}
#endif
