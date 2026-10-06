// re_prep.h - the file open, PE parse and code map every code reading command needs.
// Module: cli (C11).
// Owns: the common preamble, so each command starts with one call, not five.
// Depends: re_table for re_ctx_t, re_file, re_pe, re_code, re_disasm, re_format, re_json.
//       them answers with and which therefore have to agree exactly.
// Depends: re_file, re_pe, re_code, re_disasm, re_format, re_json.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stdint.h>

#include "features/code/re_code.h"
#include "features/lib/re_flirt.h"
#include "features/meta/re_disasm.h"
#include "features/pe/re_pe.h"
#include "utils/json/re_json.h"
#include "utils/mem/re_arena.h"
#include "utils/text/re_str.h"
#include "cli/app/re_table.h"

#define RE_SCHEMA "antistrefo/1"

// Open path, parse the PE, and stand up the code map for the arch this build has.
// A failure is reported once through ctx->err, so a command has one error path.
bool re_prepare(re_ctx_t *ctx, const char *path, re_file_t *f, re_pe_t *pe, re_code_t *code);

// The same preamble for the commands that never decode an instruction: info, sections,
// imports, exports and strings read the parser's output and raw bytes only. When the
// build has no backend for the image's machine these still succeed, on a context bound
// for address math without a decoder, because "no disassembler for x86" is not an
// answer to a question about the section table.
bool re_prepare_loose(re_ctx_t *ctx, const char *path, re_file_t *f, re_pe_t *pe, re_code_t *code);

// The fields every command's JSON object starts with. The schema, the tool name and
// the arch are what let a caller parse one response without knowing which command
// produced it.
void re_envelope(re_jw_t *w, const char *tool, re_span_t img, const re_pe_t *pe);

// Name every function the image does not name itself, from the image's own function table
// when it has one and then from the built in signatures plus one file when a path is
// given. Every surface that shows a function name goes through here, so the report, the
// graph and the view cannot disagree about what a function is called. Returns how many it
// named.
size_t re_prep_names(re_ctx_t *ctx, const char *sigfile, re_code_t *code, re_fscan_t *scan,
                     re_flirt_load_stat_t *stat);

// Accepts a decimal or 0x hex address, as an RVA or already absolute. A value inside
// the image is taken as a virtual address and anything else as an RVA, because
// guessing by magnitude does not work: a driver mapped at 0x10000 has virtual
// addresses around 0x11000, which are just as small as the RVAs.
bool re_parse_addr(re_ctx_t *ctx, re_str_t s, const re_pe_t *pe, uint64_t *out);
#ifdef __cplusplus
}
#endif
