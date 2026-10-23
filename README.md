<div align="center">
<img src="Antistrefo.png" width="50%">
<img src="Banner.png" width="50%">
</div>

<p align="center">
  <b>A Software Reverse Engineering Framework</b><br>
  Light Weight, Blazing Fast & Easy to setup and get started
</p>

<p align="center">
  <img src="https://img.shields.io/github/v/release/zolowhos/antistrefo?label=version" alt="version">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT licensed">
  <img src="https://img.shields.io/badge/language-C11%20%2B%20C%2B%2B17-blue" alt="C11 and C++17">
  <img src="https://img.shields.io/badge/tests-41%20targets-brightgreen" alt="41 test targets">
</p>

---

## What it is

Antistrefo opens a PE executable or library and shows you what it found. It has three
faces and they are the same program:

- **A full screen view** in the terminal, with a function list, a disassembly pane and a
  pseudo-source pane. Clickable, and fully usable from the keyboard. Opening a file
  recovers functions immediately.
- **Reports** on stdout, as a framed table for a person or JSON for a program.
- **An MCP server** over stdio, so an assistant can call the same passes as tools.

Analysis has two tiers. The **entry pass** is the fast one: it makes a file usable in
seconds, with the same caps the reports have always used. The **deep pass** lifts those
caps, reconciles the exception table, sweeps for functions nothing called, and writes a
`<file>.asdb` sidecar next to the binary. The next open of that file loads the sidecar
instead of scanning again, so the view, the CLI and MCP all read the same result.

A result is kept whole. A pass does not drop a function, a string, an edge, or
decompiled text because it crossed a fixed size.

## Quick start

```console
$ antistrefo                     # opens the view on its welcome screen
$ antistrefo triage driver.sys   # the fast first look
$ antistrefo deep driver.sys     # the deep tier, written to driver.sys.asdb
$ antistrefo gui driver.sys      # opens the view straight onto that file
```

Three ways in, and the first is usually what you want:

| | |
|---|---|
| **Run it** | Opens the view and asks for a file |
| **Drop a file on it** | Explorer passes the path; it opens straight away |
| **`antistrefo shell`** | A prompt, for driving the reports one at a time |

Inside the view: arrows move the selection, <kbd>Tab</kbd> moves between controls,
<kbd>Enter</kbd> opens, <kbd>←</kbd>/<kbd>→</kbd> switch panes, <kbd>q</kbd> leaves.
If your terminal reports mouse clicks, every button and tab is clickable too. If it
does not, nothing is lost.

## Building

Needs CMake 3.25+, Ninja, and **Clang/LLVM** (C11 + C++17). That is the primary
toolchain on Windows and Linux.

```console
$ cmake --preset clang-release         # -O2 + LTO; RE_ENABLE_DISASM=ON
$ cmake --build --preset clang-release
$ ctest --preset clang-release
```

On Windows with the MSVC SDK, prefer `clang-cl-release` (static CRT). Primary
presets: `clang-release`, `clang-debug`, `clang-asan`, `clang-cl-release`,
`clang-cl-debug`. Second compiler: `gcc-debug`. Legacy only (not the ship path):
`msvc-release`, `msvc-debug`, `msvc-asan`. The native x86-64 decoder needs only a
C11 compiler. With `RE_ENABLE_CAPSTONE` (default ON when disasm is enabled),
CMake fetches Capstone 5.0.3 for ARM-64 behind `re_disasm`. Use
`-DRE_ENABLE_DISASM=OFF` for a parse-only build, or `-DRE_ENABLE_CAPSTONE=OFF`
to keep native x86 without Capstone.

## Commands

Every command also works as a plain command, so nothing is locked inside a session.

| Command | What it answers |
|---|---|
| `gui [file]` | Full screen view of the functions, in the terminal |
| `shell` | Line oriented prompt for driving the report commands |
| `triage <file>` | One call ingest view: layout, imports, devices, risk, capabilities |
| `info <file>` | Format, architecture, hashes and layout summary |
| `sections <file>` | Section table with per section entropy |
| `imports <file>` | Imported modules and symbols, demangled when possible |
| `exports <file>` | Exported symbols, demangled when possible |
| `strings <file>` | ASCII and UTF-16 strings, with a regex filter |
| `search <file>` | Find text, an immediate value, or a hex pattern with wildcards. A bare pattern that cannot be hex pairs is searched as text; `text:`, `imm:` or `sym:` prefix the pattern to force a mode |
| `funcs <file>` | Recovered functions with size, frame and call counts |
| `xrefs <file>` | Cross references, with imports, exports and strings named |
| `jtables <file>` | Jump tables behind an indirect branch, with case targets |
| `disasm <file>` | Disassemble a function or an address range |
| `decompile <file>` | One function as C-like source, with its calls named |
| `cfg <file>` | Control flow graph of one function: blocks, terminators, edges |
| `regions <file>` | Classify each window as code, data, rdata or pad, with evidence |
| `vtables <file>` | C++ class tables, named from the image's own RTTI where it has any |
| `entropy <file>` | Windowed entropy, to locate packed or encrypted regions |
| `rules <file>` | Capability findings, with the evidence that fired each rule |
| `analyze <file>` | Every pass, with per pass timing and what it could not tell. Uses `<file>.asdb` when one matches this file |
| `deep <file>` | The deep tier, in the foreground, written to `<file>.asdb` |
| `hexdump <file>` | Raw bytes at a file offset or an rva |
| `demangle` | Demangle one C++ symbol, no file needed |
| `mcp` | Run the MCP server over stdio |

### Flags

| Flag | Meaning |
|---|---|
| `--format json\|text` | Output shape. JSON is the default; `text` is the framed report |
| `--no-color` | Plain output. The `NO_COLOR` convention is honoured regardless |
| `--limit N` | Cap the rows. Default 200, which is also the agent context guard |
| `--offset N` | Skip the first N rows |
| `--off N`, `--rva N` | Hexdump: start at a file offset or at a relative virtual address |
| `--len N` | Hexdump: how many bytes |

## The database

`<file>.asdb` sits beside the binary, the way an IDA database sits beside its input.
It is versioned, keyed to that file by size and SHA-256, and read only through a
mapped view with every access bounds-checked. A file that has changed, or a database
that is truncated or from another format version, is refused and the entry pass runs
instead.

`deep` writes it. The full screen view starts the same pass in the background after
the entry pass and swaps to the database when the write finishes. `decompile` reads
the precomputed text when the sidecar is present, and decompiles live when it is not.
Renames live in the database's user section, or in the `.alt` sidecar when no database
exists yet.

The deep pass also records what it will not invent: packed or encrypted ranges, a
flattened dispatcher, a virtualized function, and an API resolved from a hash. Encrypted
bytes are marked. They are not unpacked.

## Output

Two shapes, chosen by a person or by the thing on the other end.

A person gets a framed report, drawn with box characters and picked out in colour:

```
+-Image---------------+ +-Layout--------------+
| architecture   x64   | sections        7    |
| image base   0x140000000 | imports       1    |
| entry       0x140041610 | exports       0    |
+----------------+-----+-------------------+
```

A program gets JSON, one object per call, always carrying `schema` and `tool`:

```json
{"schema":"antistrefo/1","tool":"funcs","functions":[{"va":"0x140001000","size":68,
 "insns":22,"cc":"ms64","arg_regs":["rcx"],"flags":["returns","unwind"]}],"total":829}
```

The same shape is what the MCP server speaks, so nothing has to be re-parsed to move
between them.

## As an MCP server

```console
$ antistrefo mcp
```

Speaks MCP over stdio, one JSON object per call. Every report command is available as
a tool, so an assistant can run the passes and read the same fields the CLI prints.
Every argument a tool's schema advertises is honoured - `addr`, `pattern`, `symbol`,
`regex`, `--len`, paging and the rest reach the command exactly as the CLI would pass
them - and `--limit` stays the guard that keeps a whole-file answer from filling a
context window. A failing tool call returns the command's own error, so "no
disassembler for x86 in this build" reaches the caller instead of a silent empty
answer. The full screen view and the shell prompt are not tools: they need the
terminal stdio lives on.


## Development

```console
$ powershell -NoProfile -ExecutionPolicy Bypass -File scripts\format.ps1
$ python scripts\check.py .
$ cmake --build --preset clang-release
$ ctest  --preset clang-release
```

The product version is the `RE_VERSION` line in `src/re_version.h`. Usage text, the
screen mark, the MCP server version, and the CMake project version all read that line.
The release tag is `v` plus that same number.

The gate is mechanical and it is not advisory. 41 CTest targets, and a set of rules
covering line and function caps, file banners, ASCII-only source, arena-only
allocation, and where output is allowed to be written. Two of those cost real time the
first time and are written down in `.cursor/rules/`:

- Source is **ASCII only**. Box and bullet glyphs go in as byte escapes.
- The formatter **reflows long banner lines**, which can push the fourth line of a file
  banner off the top and fail the build.

`tests/` is exempt from the output and string-call rules, so tests may use `printf` and
`strcmp`. Everything else is expected to hold.

## Licence

MIT. See [LICENSE](LICENSE).
