# rules.md - canonical rulebook for antistrefo. Read this before writing code.
# Module: rules (Markdown).
# Owns: every convention, layering rule, and output contract the project obeys.
# Depends: none. Authoritative; scripts/check.py enforces the mechanical subset.

## 0. Project

`antistrefo` is an AI driven static analyzer for reverse engineering applications,
libraries, or whatever you want. It is a lightweight, blazing-fast CLI that agents
drive through MCP. One binary, two modes:

    antistrefo <command> [args]    human / agent / shell usage
    antistrefo mcp                  MCP server over stdio

Static analysis only. No debugger, no decompiler, no persistent database. See
section 8 for the full scope verdict.

The C symbol prefix stays `re_` and the macro prefix `RE_`. That is deliberate and
not a leftover: the prefix is a link-time namespace guard against Capstone and zlib
symbols, `re` still reads correctly as reverse engineering, and it is short enough
to type hundreds of times per file. The product name is antistrefo; the C namespace
is `re_`. Do not unify them without a strong reason.

## 1. Locked conventions

| Rule | Value |
|---|---|
| Project name | `antistrefo` |
| Executable | `antistrefo.exe` |
| JSON schema id | `antistrefo/1` |
| C symbol prefix | `re_` / `RE_` (kept deliberately, see section 0) |
| Project root | `C:\Users\xyz\Pictures\RE` |
| Language core | C11 (`src/utils`, `src/features`) |
| Language shell | C++17 (`src/cli`, `src/mcp`) |
| License | MIT |
| Source charset | ASCII only - no smart quotes, no em-dash, no arrows in code |
| Line endings | LF, one final newline, no trailing whitespace, no tabs |
| Indent | 4 spaces |
| Braces | K&R (attach) |
| Column limit | 100 |
| File line cap | 500 (hard, enforced) |
| Function body cap | 60 lines / 4 nesting levels (hard, enforced) |
| Naming | `re_` prefix, `snake_case`, `_t` for types |

## 2. Layout

    .rules/rules.md      this file - canonical rulebook
    .clang-format        formatting truth
    .clang-tidy          naming advisory
    .editorconfig        editor parity
    .gitignore
    LICENSE              MIT
    CMakeLists.txt       C11/C++17, LTO; Clang/LLVM primary
    CMakePresets.json    clang-release, clang-debug (primary)
    docs/style.md        human-readable rules
    docs/util-catalog.md util lookup table (read before writing new code)
    scripts/check.py     the gate
    scripts/format.ps1   format wrapper
    src/utils/<cat>/      shared utilities, grouped: text mem algo sys json tui
    src/features/<cat>/   one directory per analysis area, e.g. code dec data pe lib meta
    src/cli/             argv dispatch, text rendering (C++17)
    src/mcp/             MCP stdio server (C++17)
    tests/               CTest targets
    Tools/               reserved, not ours

Include path root is `src/`, so utils are reached as `#include "utils/mem/re_arena.h"`
and features as `#include "features/pe/re_pe.h"`.

Rule: a folder holding more than 15 files is too cluttered and must be divided
into sub folders by category. Keep every folder at 15 or fewer. Enforced by
check.py over src/, so a folder that creeps past the cap fails the gate rather
than than being noticed months later.

Rule: never generalise from one test file. Every claim about coverage, matching,
performance or robustness is checked against all five files in the corpus before
it is believed or reported. A conclusion drawn from a single sample is not a
conclusion, and reporting one as a finding is a defect in its own right.

Rule: a test asserts content, not only counts. A parser that returns the right
number of wrong answers passes every count-based check, which is how an export
table that named each export after the opening bytes of a function survived two
validation passes and the whole gate. Where the correct value is knowable, pin
it. Where a bug can be reintroduced to prove the test catches it, do that before
believing the test.

## 3. Banner spec

Every file starts with exactly four comment lines, fixed slot order. C uses `//`,
scripts and text use `#`. `scripts/check.py` validates the shape.

    <c> <basename> - <one-line purpose, lowercase, no trailing period>
    <c> Module: <module> (<language>).
    <c> Owns: <what this file is responsible for>.
    <c> Depends: <deps or none>. <hard constraint or none>.

Line 4 always ends with the architectural constraint. That is deliberate: the
banner doubles as the contract.

    // re_arena.h - bump allocator: one malloc, one free per command.
    // Module: util (C11).
    // Owns: bump-pointer blocks, chunk list, reset and free.
    // Depends: none. No I/O, no globals, thread-unsafe by design.

    // re_pe.c - PE/COFF header and section parsing.
    // Module: feature (C11).
    // Owns: DOS and NT headers, section table, data directories, RVA to file offset.
    // Depends: utils/re_buf, utils/re_err. No globals, no I/O, reads via re_read().

`#pragma once` follows the banner in every header, exactly once.

## 4. Layering rules

| # | Rule | Type |
|---|---|---|
| 0 | check the util catalog before writing; function caps; forbidden-pattern scan | script + review |
| 1 | 500 lines per file | script |
| 2 | 4-line banner, fixed slots | script |
| 3 | `#pragma once` in every header, exactly once | script |
| 4 | ASCII-only source bytes | script |
| 5 | LF, one final newline, no trailing whitespace, no tabs | script |
| 6 | no `malloc`/`calloc`/`realloc`/`free`/`strdup` outside `src/utils` | script |
| 7 | no `printf`/`puts`/`fprintf(stdout)` outside `re_jw*`/`re_text*` | script |
| 8 | no `strcpy`/`strcat`/`sprintf`/`strtok`; `memcpy`/`memset`/`memcmp` on sized spans only | script |
| 9 | `re_` prefix on project symbols | clang-tidy (advisory) |
| 10 | clang-format clean | CTest |

Rule 6 enforces the one-alloc-per-command thesis. Rule 7 protects MCP stdio JSONL
stream purity, which is otherwise a silent, hard-to-debug corruption.

### Exceptions, and why each one exists

These were all found by running the gate, not decided in advance. Each is narrow
on purpose; none of them may become a blanket exemption.

| Exception | Reason |
|---|---|
| `CMakePresets.json` carries no banner | CMake validates the preset schema strictly and rejects unknown root keys, so no comment or metadata field is legal there. JSON has no comment syntax either. |
| `LICENSE` carries no banner, and may hold trailing spaces | It is legal text, and prepending editorial notes to a licence is wrong. |
| A `.py` file may put a shebang on line 1 | A shebang only works as the first line, so the banner shifts down one. The checker accounts for this. |
| `tests/` is exempt from rules 7 and 8 | Tests exist to call libc and print. They are still held to rules 0, 1, 2, 3, 5. |
| `src/utils/re_regex_priv.h` and `re_util.h` stay out of the aggregator | One is engine-private, one is the aggregator. Both still must appear in the util catalog. |
| `RE_VEC_PUSH` requires an lvalue | `re_vec_push_` takes the address of the element, so `RE_VEC_PUSH(v, a, f(x))` will not compile. Assign to a local first. |

## 5. Rule 0 - reuse first

Before writing any function past 60 lines or 4 nesting levels, read
`docs/util-catalog.md` and grep `src/utils/`. Do not reinvent what exists.

Forbidden patterns - each one means a util already exists:

| Pattern | Use instead |
|---|---|
| byte-by-byte copy loop | `re_memcpy` on a sized span |
| `realloc` or manual buffer doubling | `re_strbuf_*` |
| manual grow-array with capacity doubling | `re_vec_*` |
| `strlen`/`strcmp`/`strcat`/`strtok` | `re_str_*` |
| hex nibble arithmetic | `re_hex_*` |
| `sprintf`, manual int-to-decimal | `re_strbuf_appendf`, `re_fmt_*` |
| `while (x) { x &= x - 1; }` | `re_bits_*` |
| hand-rolled hash or CRC accumulation | `re_crc_*`, `re_hash_*` |
| splitting on `/` or `\` | `re_path_*` |
| `switch` emitting `{"k":` | `re_jw_*` |
| `fprintf(stderr, ...)` | `re_log_*` |

Escape hatch, so the rule does not bloat the codebase:

- used once, 15 lines or fewer, no loop over bytes -> stays `static` in the caller
- needed twice, or loops over bytes, or crosses a module -> becomes a util first
- never inline a would-be util into its consumer
- if a util would pass 500 lines, it splits; it is never absorbed

`scripts/check.py` verifies every header in `src/utils/` appears in both
`docs/util-catalog.md` and `src/utils/re_util.h`. An unregistered util fails the
build, which is what makes "check the catalog" trustworthy rather than aspirational.

## 6. Architecture

1. **C11 core, C++17 shell.** `src/utils` and `src/features` are pure C11 with
   `extern "C"` headers, no exceptions, no RTTI. `src/cli` and `src/mcp` are C++17
   and never reinterpret binary data themselves - they call `re_*` and render.
2. **Bounded reads only.** The job is parsing hostile input, so out-of-bounds reads
   are the primary exploit. Every byte access goes through `re_read`/`re_rd*`, which
   return failure or zero past the end. No raw pointer arithmetic into file data.
3. **mmap, never read the whole file.** `CreateFileMapping`/`MapViewOfFile`, with
   `mmap` under `#ifdef` for POSIX.
4. **One command table drives both the CLI and MCP.** A single table of
   `{name, summary, args, entry, schema}` feeds argv parsing and `tools/list`, so
   the two surfaces cannot drift.
5. **Heavy dependencies sit behind an opaque vtable.** `re_disasm_vtable` with a
   Capstone implementation in `src/features/disasm/`. Core has no compile-time
   Capstone dependency, so `RE_ENABLE_DISASM=OFF` yields a small parse-only build.
6. **No third-party C++ libraries.** No Boost, no nlohmann/json. The streaming
   writer in `src/utils/re_json.h` is the JSON emitter for the whole project.

## 7. Output contract

- stdout carries exactly one JSON object plus `\n`. Nothing else.
- In `mcp` mode, stdout is only newline-delimited JSON-RPC frames.
- stderr carries diagnostics. `re_log_*` is the only writer, and it is silent in
  mcp mode and when `RE_LOG=0`.
- Errors in JSON mode: `{"schema":"antistrefo/1","error":{"code":..,"message":..}}` on
  stderr, nonzero exit.
- Every response carries `"schema":"antistrefo/1"`.
- Collections carry `count` and `truncated` and accept `--offset`/`--limit`,
  default limit 200. An unbounded response will evict an agent's context.

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | internal error, the fallback for any code with no specific mapping |
| 2 | usage error |
| 3 | not a recognized binary |
| 4 | malformed binary, or a read that ran past the end |
| 5 | unsupported format or architecture |
| 6 | I/O error or out of memory |

## 8. Feature scope

| Capability | Verdict | Where |
|---|---|---|
| Layout, segments, entry points, compiler fingerprint | Build | feature/pe, feature/elf |
| Function detection, SP/stack analysis, jump tables, noret | Build | feature/code |
| FLIRT-style byte-pattern library identification | Build | feature/flirt |
| Disassembly | Build | feature/disasm |
| Cross-references, code and data | Build | feature/xref |
| Search: text, immediate, binary with wildcards | Build | feature/search |
| Demangling, itanium and MSVC | Build | feature/symbols |
| Capability rules, capa-lite | Build | feature/rules |
| Type libraries, library metadata services | Skip | needs a full database and type inference |
| Structs, enums, C header parse | Defer | post v1 |
| Decompiler, Tier A only | Skip | no pseudocode at all, summary only |
| **Decompiler, Tier B** | **Build** | a C-like emitter over a stack transfer IR, see section 8.1 |
| Debugger | Skip | static only |
| Embedded scripting languages, plugin loader | Skip | the CLI and MCP are the scriptable surface |
| Shared databases, multi-user merge, undo | Skip | use an in-memory LRU session cache |

The decompiler substitute for triage is a rich **function summary**: signature guess, callers,
callees, strings touched, constants, loop and switch counts, suspicious markers.
That is buildable from static analysis and answers the question an agent actually
has, which is where to look next.

### 8.1 Decompiler scope, Tier B

The goal is a much smaller and far faster analyser, not a research decompiler. That
target is reachable only in Tier B, and its quality bar is deliberately low:

- **In scope**: disassembly, function recovery, CFG and switch tables, stack frame
  recovery, calling convention inference, a register transfer IR, and a C-like
  emitter that gets control flow, locals and call names right.
- **Out of scope**: type inference, structure recovery, full C++ support, and anything
    of that kind. Wrong types are acceptable; wrong control flow is not.
  - **The advantage is speed, not quality.** `triage` must stay under 15ms on a 40KB
    driver, where the heavyweight analysers take 30 seconds to 2 minutes. antistrefo
    is the fast deterministic first stage of a pipeline, not the last one.

Consequences that are already binding:

  - The IR is a **register transfer language**: every instruction becomes a small,
  instruction lowers to side-effect-free operations on typed varnodes, with
  side effects written explicitly as LOAD and STORE. The IR contract is designed in
  task 1, before any disassembler exists, so the emitter can be added later without
  reworking the instruction pipeline.
- Capstone is reached only through the `re_disasm` vtable. Feature code never calls
  Capstone directly, so the IR and the emitter stay arch independent.
- Architectures land in order **x86-64, then ARM-64**. x86-32 follows if the corpus
  demands it. Capstone supports about fifteen; doing two well beats doing fifteen
  badly, and the IR contract has to be right once per architecture.

`src/features/re_ir.h` and `src/features/re_disasm.h` are the seam. Capstone is
reached only through the `re_disasm` vtable, so feature code never names a Capstone
type and `RE_ENABLE_DISASM=OFF` drops the whole table. The backend built in task 3
is a self contained x86-64 decoder in `src/features/disasm/` rather than Capstone,
because this environment has no vcpkg and no pkg-config; see `docs/util-catalog.md`
for what that costs and what it buys. The vtable is unchanged, so a Capstone backend
is a drop-in replacement.

Lead the surface with a single `antistrefo triage` that returns format, arch, compiler,
packer, sections, entry points, import summary, interesting strings and detected
capabilities in one call. Everything else is drill-down.

## 9. Tasks

| Task | Scope |
|---|---|
| 0 | conventions, utils, scripts, build wiring. Done |
| 1 | `re_buf` bounded reads, `re_json` writer, format detection, PE parser, command table, CLI, IR seam, fixtures. **in progress** |
| 2 | strings, entropy, exports, demangling, search, capability rules | Done |
| 3 | disasm backend, functions, stack and calling convention inference, jump tables, xrefs, FLIRT. Done: own x86-64 backend behind the vtable, recursive descent function recovery, RIP relative and import named xrefs, jump table detection, FLIRT with file loading, ms64 and sysv inference, and full operand text. |
| 4 | the C-like emitter over the IR, the function summary. Done: `re_ir` gained the arithmetic and comparison ops, `re_x64_lower` models the integer data flow subset including read modify writes to memory, `re_dc_walk` recovers a function's blocks and labels, `re_decompile` emits the C-like body with named locals and named calls, and `decompile` is a command. |
| 5 | MCP stdio, auto-generated schemas, session cache, structuredContent |
| 6 | stretch: delegate decompile to an external engine, ARM-64, emulation |

The task order changed once the decompiler goal was confirmed. The emitter moved to
its own task because it depends on everything above it, and the IR contract moved
into task 1 because retrofitting it would have reworked the whole pipeline.

## 10. Environment

| Item | Value |
|---|---|
| Primary compiler | Clang/LLVM (Linux `clang`/`clang++`; Windows `clang-cl` + static CRT, or `clang`) |
| Windows SDK | needed for `clang-cl` / legacy MSVC presets; `vcvarsall.bat x64` |
| Legacy MSVC | optional `msvc-release` / `msvc-debug` / `msvc-asan` only; not the ship path |
| Second compiler | `gcc-debug` (alias `mingw-debug`) |
| Build | CMake 3.25+, Ninja |
| clang-format / clang-tidy | system LLVM or VS `VC/Tools/Llvm/x64/bin`; tidy advisory |
| Sanitizers | `clang-asan` (`-fsanitize=address`). Legacy `msvc-asan` remains. |

Notes that matter:

- Ship with Clang/LLVM `-O2` + LTO. On Windows with the MSVC SDK, prefer
  `clang-cl` and `CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded`. MSVC `/MT /O2 /GL /LTCG`
  is legacy only.
- CMake 4.x errors on any dependency with `cmake_minimum_required` below 3.5. Keep
  `CMAKE_POLICY_VERSION_MINIMUM 3.5` as the escape hatch.
- CMake also rejects a **hidden test preset that has no `configurePreset`**, and
  reports it as `Invalid preset: "base"` with no hint about the real cause. Do not
  use a hidden base for test presets here.
- CMake presets reject unknown root keys, so no banner is possible in that file.
- No ELF cross compiler, so `scripts/gen_fixtures.py` must synthesize ELF. Treat it
  as a hard prerequisite of Task 1, not a nice-to-have.
- Defences are Clang `-Wall -Wextra -Werror`, a clean GCC second-compiler build,
  `clang-asan` where available, and the truncation sweep.
