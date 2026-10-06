<div align="center">
<img src="Antistrefo.png" width="50%">
<img src="Banner.png" width="50%">
</div>

<p align="center">
  <b>A Software Reverse Engineering Framework</b><br>
  Light Weight, Blazing Fast & Easy to setup and get started
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0-blue" alt="version 0.1.0">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT licensed">
  <img src="https://img.shields.io/badge/language-C11%20%2B%20C%2B%2B17-blue" alt="C11 and C++17">
  <img src="https://img.shields.io/badge/tests-47%2C656%20checks-brightgreen" alt="47656 checks">
</p>

---

## What it is

Antistrefo opens a PE executable or library, runs every analysis pass over one shared
context, and shows you what it found. It has three faces and they are the same program:

- **A full screen view** in the terminal, with a function list, a disassembly pane and a
  pseudo-source pane. Clickable, and fully usable from the keyboard.
- **Reports** on stdout, as a framed table for a person or JSON for a program.
- **An MCP server** over stdio, so an assistant can call the same passes as tools.

Because it is one binary and one shared analysis, the answer does not depend on how you
asked. `funcs` in the view, `antistrefo funcs file.sys`, and the MCP tool named `funcs`
all read the same recovered function list.

## Quick start

```console
$ antistrefo                     # opens the view on its welcome screen
$ antistrefo funcs driver.sys    # one report, JSON on stdout
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

Needs CMake 3.20+ and a C11 compiler. Visual Studio 2022 and MinGW are both wired up.

```console
$ cmake --preset msvc-release          # x64, static CRT, LTO
$ cmake --build --preset msvc-release
$ ctest --preset msvc-release
```

Presets: `msvc-debug`, `msvc-release`, `msvc-asan`, `mingw-debug`. There are no
third-party dependencies; the only requirement is that the compiler is C11.

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
| `analyze <file>` | Every pass, with per pass timing and what it could not tell |
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
$ cmake --build --preset msvc-release
$ ctest  --preset msvc-release
```

The gate is mechanical and it is not advisory. Twelve targets, 47,656 checks, and a set
of rules covering line and function caps, file banners, ASCII-only source, arena-only
allocation, and where output is allowed to be written. Two of those cost real time the
first time and are written down in `.cursor/rules/`:

- Source is **ASCII only**. Box and bullet glyphs go in as byte escapes.
- The formatter **reflows long banner lines**, which can push the fourth line of a file
  banner off the top and fail the build.

`tests/` is exempt from the output and string-call rules, so tests may use `printf` and
`strcmp`. Everything else is expected to hold.

## Licence

MIT. See [LICENSE](LICENSE).
