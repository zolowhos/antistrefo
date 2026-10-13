# autobuild-prompts.md - four self contained prompts that build the auto-analysis passes in order.
# Module: docs (Markdown).
# Owns: the shared context, the test corpus, and the four prompts.
# Depends: .rules/rules.md, docs/util-catalog.md, src/features, src/cli.

Send them in order. Each assumes the previous one is committed. Each repeats the
shared context on purpose, so any one of them works from a cold session.

Do not send prompt 2 before prompt 1 is committed, and so on: 2 depends on 1's
signature DB, 3 packages 1+2, 4 builds on 3's shared context.

---

## Shared context (repeated in every prompt)

**Repo:** `C:\Users\xyz\Pictures\RE` — branch `main`, C11 + C++17, CMake.
Two commits are unpushed at time of writing; push only when asked.

**Build (Clang/LLVM primary):**
```
cmake --preset clang-release && cmake --build --preset clang-release
ctest --preset clang-release --output-on-failure
```
Windows with MSVC SDK: `clang-cl-release` (static CRT; `vcvarsall.bat x64` first).
Other presets: `clang-debug`, `clang-asan`, `gcc-debug`. Legacy only:
`msvc-release`, `msvc-debug`, `msvc-asan`.

**The gate:** `python scripts\check.py .` must print `all rules pass` before every
commit. `--fix` only clears CRLF, trailing whitespace and EOF newline.

**Conventions** (`.rules/rules.md` is canonical — read §2 and §3):
- 4-line banner: `// name - purpose`, `// Module:`, `// Owns:`, `// Depends:`.
  Line 4 MUST start `Depends:`.
- ≤500 lines/file, ≤60-line function bodies, ≤4 nesting levels.
- K&R braces, 4-space indent, 100-column limit, ASCII-only source, LF endings,
  exactly one final newline.
- Include root is `src/`, so `#include "utils/mem/re_arena.h"` and
  `#include "features/pe/re_pe.h"`. Includes are always folder-qualified.
- Rule 0: read `docs/util-catalog.md` before writing anything new.
- Forbidden outside `src/utils`: `malloc`/`free`, libc string calls
  (`strlen`, `memcpy`, ...), any stdout write outside `re_jw*`/`re_text*`.
- `scripts/format.ps1` runs clang-format; run it and rebuild if the `format`
  ctest fails after edits that lengthen lines (this bites on include rewrites).
- Use the edit tool for multi-line replacements. PowerShell `.Replace`
  silently no-ops or corrupts C string literals. Write files with
  `[IO.File]::WriteAllText($p,$t,(New-Object System.Text.UTF8Encoding($false)))`
  — `Out-File -Encoding utf8` adds a BOM, `[IO.File]::WriteAllLines` emits CRLF.

**Layout** (already regrouped, ≤15 files per folder):
```
src/utils/    text mem algo sys json tui
src/features/ code dec data pe lib meta disasm
src/cli/      app cmds render
src/mcp/
```
`re_utils` and `re_core` glob `GLOB_RECURSE`; the `antistrefo` target lists its
sources explicitly in CMakeLists.txt.

**What already exists** — do not rebuild these:
- `features/code/`: `re_code.c` (recursive descent), `re_func.c` (boundaries,
  unconditional `jmp` treated as tail call), `re_xref.c`, `re_jtable.c`, `re_stack.c`
- `features/pe/`: `re_pe.c` (header, sections, data dirs, imports, exports),
  `re_format.c`. Export parsing was just fixed — `+28 AddressOfFunctions`,
  `+32 AddressOfNames`, `+36 AddressOfNameOrdinals` — and `e.rva` is now populated.
- `features/dec/`: `re_ir.c`, `re_dc_walk.c` (basic blocks + labels),
  `re_dc_print.c`, `re_decompile.c`. C-like emitter over the integer data-flow subset.
- `features/lib/`: `re_flirt.c`, `re_demangle.c`
- `features/data/`: `re_strings.c`, `re_search.c`, `re_rules.c`, `re_triage.c`
- 16 commands: info sections imports exports funcs xrefs jtables disasm decompile
  strings search triage entropy hexdump rules demangle
- Framed TUI renderer for info/sections/imports/funcs; `--no-color`; text when
  stdout is a TTY, JSON when piped, `--format` overrides.
- MCP stdio server, interactive shell.
- Test suites: `test_features.c` / `test_utils.c` (~46k checks), `test_disasm.c`
  (165), `test_tui.c` (431), `test_jr.c` (55). 6 ctest targets.

**Audit verdicts already established — trust these, don't re-derive:**
- `re_stack.c` is a **real pass**, not a stub. Sound under-approximation
  ("a register is an argument only when read before anything writes it; a miss
  costs a parameter, not a wrong one"). Handles MS x64 and SysV. Records
  argument reads at walk time, not at the end, so a call clobbering volatiles
  doesn't erase them. Needs coverage tests, not a rewrite.
- `re_flirt.c` has a **correct matcher but an effectively empty database**:
  exactly 3 built-in signatures, all compiler idioms (`gs_cookie_init`,
  `gs_cookie_read`, `guard_dispatch_icall`). **Zero real library functions.**
  `slack` is always 0 and unused.

**Test corpus** — 1 clean baseline + 4 hostile inputs. Quote every path; two
contain `[` and `]` which break PowerShell globs.

| File | What it exercises |
|---|---|
| `C:\Users\xyz\Downloads\vulnerable-drivers-main_[unknowncheats.me]_\vulnerable-drivers-main\cpqsysio64.sys` | Clean unobfuscated x64 kernel driver. The **control**: everything must work here, or the bug is ours. |
| `C:\Program Files (x86)\Steam\steamapps\common\VRChat - Copy\GameAssembly.dll` | 214 MB IL2CPP binary. 264 exports with **randomised names** (`ACQuTyPeorx`, `AKkysVEPyjh`). Tests name handling and scale. |
| `C:\Program Files (x86)\Steam\steamapps\common\VRChat - Copy\start_protected_game.exe` | Private packer/obfuscation. |
| `C:\Program Files (x86)\Steam\steamapps\common\SCP Secret Laboratory\GameAssembly.dll` | Second, different packer. Compare against VRChat. |
| `C:\Users\xyz\Downloads\xysc7n\loader.exe` | Third protection scheme. |

**Non-negotiable across all four prompts:** on a protected or malformed input the
tool must **never crash, hang, loop, or emit fabricated results**. It must report
what is genuinely knowable (PE structure, sections, entropy, imports) and
explicitly mark what is not recoverable. A wrong answer is worse than "unknown".
Add a regression test per fix. Report honestly what is and isn't done.

---

## Prompt 1 — FLIRT signature database, and honest degradation

```
Work in C:\Users\xyz\Pictures\RE on branch main.

CONTEXT
antistrefo is a static-analysis CLI and MCP server for reverse engineering,
written in C11/C++17 with CMake. It already has an x86-64 decoder, function
discovery, xrefs, jump tables, a stack-usage pass, a C-like decompiler emitter,
and a FLIRT-style signature matcher.

The FLIRT matcher (src/features/lib/re_flirt.c) is correct and carefully built:
byte-wise pattern matching with '?' wildcards, malformed patterns and patterns
running off the end of code treated as misses rather than silent wildcards, a
3-field line parser that arena-copies (because a string read out of a mapped
file dangles once the file closes), and a line walker handling LF, CRLF and a
missing final newline.

THE GAP: the signature database is effectively empty. There are exactly three
built-in signatures and all three are compiler idioms, not library functions:
  gs_cookie_init       msvc  488b05????????4883c8????33c5
  gs_cookie_read       msvc  488b0d????????33c0
  guard_dispatch_icall msvc  4c8d1d????????4985ff7405
There are zero signatures for any actual runtime library function. Also
re_sig_t::slack is set to 0 everywhere and never read - either give it meaning
or remove it.

YOUR TASK
1. Populate the built-in signature database with real library functions. Cover
   at minimum: the common compiler-recognised idioms (memcpy, memmove, memset,
   memcmp, strlen, strcpy, strncpy, strcmp, strcat) and the common Win32/CRT
   entry points a driver or application actually calls (VirtualAlloc,
   VirtualFree, VirtualProtect, CreateFileW, DeviceIoControl, WriteFile,
   ReadFile, CloseHandle, GetProcAddress, LoadLibraryW). Verify each pattern
   against real bytes before committing it - a pattern that does not match
   anything is worse than no pattern, because it looks like coverage. State in
   your final report how many signatures actually matched at least one function
   in the clean control binary, and for each library function matched.
2. Verify every signature you add by disassembling real functions from the
   control binary and reading their actual first bytes. Do not invent patterns
   from memory.
3. Expose FLIRT results: name and module per function, in the `funcs` output and
   in the framed text renderer. Functions with no signature must be visibly
   unnamed, never given a fabricated library name.
4. Add graceful degradation for protected inputs. On a packed or obfuscated
   binary the tool must not crash, hang or emit fabricated matches; report what
   is knowable and mark the rest unknown.
5. Wire the 15-file rule into scripts/check.py. It is currently written in
   .rules/rules.md section 2 but NOT enforced, so nothing stops a future folder
   from creeping past the limit. Add the check.

CONSTRAINTS
- Read .rules/rules.md first. Banner spec: line 4 of every file must start
  "Depends:". 100-column limit, K&R, 4-space, LF, ASCII only.
- Rule 0: read docs/util-catalog.md before writing anything.
- No malloc/free, no libc string calls, no stdout writes outside src/utils.
- The gate is `python scripts\check.py .` -> must print "all rules pass".
  Then `ctest --preset clang-release` -> 6/6.
- If the format test fails after your edits, run scripts\format.ps1 and rebuild.

TEST FILES (quote paths - two contain [ and ] which break globs)
  C:\Users\xyz\Downloads\vulnerable-drivers-main_[unknowncheats.me]_\vulnerable-drivers-main\cpqsysio64.sys
    clean control, must analyse correctly
  C:\Program Files (x86)\Steam\steamapps\common\VRChat - Copy\GameAssembly.dll
    214 MB IL2CPP, 264 exports with randomised names, scale test
  C:\Program Files (x86)\Steam\steamapps\common\VRChat - Copy\start_protected_game.exe
    private packer
  C:\Program Files (x86)\Steam\steamapps\common\SCP Secret Laboratory\GameAssembly.dll
    different packer
  C:\Users\xyz\Downloads\xysc7n\loader.exe
    third protection scheme

Every one must exit 0 or fail cleanly with a real diagnostic. None may crash,
hang, or loop. Run all five and report timing for each - the 214 MB binary is
the perf case.

DO NOT ask questions. Do not push. Commit when the gate and tests pass, then
report: what you added, what genuinely matched and what did not, per-file
timings, and an honest list of what remains undone.
```

---

## Prompt 2 — CFG command, and data detection

```
Work in C:\Users\xyz\Pictures\RE on branch main.
Assumes prompt 1 is committed (signature DB exists).

CONTEXT
antistrefo: C11/C++17 static-analysis CLI and MCP server for reverse
engineering, CMake, branch main.

Already built: x86-64 decoder, recursive-descent function discovery, xrefs,
jump tables, a sound stack-usage pass, a C-like decompiler emitter, a FLIRT
signature matcher with a populated library database (from prompt 1).

Two things exist internally but are NOT visible to the user:

1. CFG. src/features/dec/re_dc_walk.c already computes basic blocks and labels
   per function - but only as an intermediate step feeding the decompiler. There
   is no command that exposes a control flow graph. Anyone reading a binary
   (its Graph View is built on it).

2. Data detection. src/features/data/ has string extraction, search, rules and
   triage, but there is no systematic code-vs-data classification, and no
   xrefs from code to the data it references.

YOUR TASK
1. Add a `cfg` command that emits, per function: basic blocks with address
   ranges, block sizes, and the edges between them (fallthrough, conditional
   branch taken/not-taken, unconditional jump, tail call). Reuse re_dc_walk's
   block structure rather than building a second, divergent CFG. Emit JSON
   when piped and a framed text rendering in a terminal, matching the existing
   output policy: text when stdout is a TTY, JSON when piped, --format
   overrides, --no-color honoured.
2. Add a whole-image `blocks` view classifying each region as code, data,
   rdata or padding, with the evidence for each classification (is it a
   function start? reached by a branch? high entropy? read-only section?
   jump table? string?). This is the "code vs data" separation. Every region
   must carry an explicit confidence or "unknown" - never a bare guess.
3. Add data xrefs: for each string, constant and jump table, which functions
   reference it, at which instruction. This is the "String 'Hello' -> function
   sub_14001230" edge such a tool builds, and it is what makes a string finding
   actionable rather than just a list of offsets.
4. Graceful degradation on protected inputs: never crash, hang or loop; report
   what is knowable and mark the rest unknown. A wrong classification is worse
   than "unknown".
5. Regression test per fix, including the no-crash guarantee.

CONSTRAINTS
- Read .rules/rules.md first. Banner line 4 must start "Depends:". 100-column
  limit, K&R, 4-space, LF, ASCII only.
- Rule 0: read docs/util-catalog.md before writing anything.
- No malloc/free, no libc string calls, no stdout writes outside src/utils.
- Gate: `python scripts\check.py .` -> "all rules pass". Then
  `ctest --preset clang-release` -> 6/6.
- If the format test fails, run scripts\format.ps1 and rebuild.
- Keep every folder at 15 files or fewer.

TEST FILES (quote paths; two contain [ and ] which break globs)
  C:\Users\xyz\Downloads\vulnerable-drivers-main_[unknowncheats.me]_\vulnerable-drivers-main\cpqsysio64.sys
    clean control - the CFG and block classification must be CORRECT here.
    Verify by hand on at least three real functions: check block boundaries
    against the actual branches and that edges match the disassembly.
  C:\Program Files (x86)\Steam\steamapps\common\VRChat - Copy\GameAssembly.dll
    214 MB IL2CPP, 264 randomised export names, scale/perf
  C:\Program Files (x86)\Steam\steamapps\common\VRChat - Copy\start_protected_game.exe
    private packer
  C:\Program Files (x86)\Steam\steamapps\common\SCP Secret Laboratory\GameAssembly.dll
    different packer
  C:\Users\xyz\Downloads\xysc7n\loader.exe
    third protection

All five must exit 0 or fail cleanly with a real diagnostic; none may crash,
hang or loop. Report per-file timings and function counts.

DO NOT ask questions. Do not push. Commit when gate and tests pass, then report
honestly: what works, what is approximate, what remains undone, and the
hand-verification evidence for the control binary.
```

---

## Prompt 3 — the Auto-analysis driver

```
Work in C:\Users\xyz\Pictures\RE on branch main.
Assumes prompts 1 and 2 are committed.

CONTEXT
antistrefo: C11/C++17 static-analysis CLI and MCP server, CMake, branch main.

THE ARCHITECTURAL GAP
Every command currently re-opens and re-parses the target file and rediscovers
everything from scratch. Nothing is shared between commands, so no command can
show what another one found, and the report repeats the work every time.

Automatic analysis is fundamentally a scheduler over a persistent database: it
loads once, then runs ordered passes over shared state, with everything
cross-referencing everything else. The passes are roughly:
  FL  follow execution flow
  PR  create functions
  SP  analyze stack pointers
  TL  create function tails
  TP  apply type information
  FI  final pass

YOUR TASK
1. Add an `analyze` command that loads the file ONCE and runs the existing
   passes in order over a shared analysis context: PE/format, function
   discovery, xrefs, jump tables, data detection, stack usage, FLIRT, and CFG.
   Reuse the existing passes; the new work is the driver and the shared context.
   Do not fork the analysis logic.
2. Emit a single combined report: what was found, counts, per-section
   breakdown, notable functions (library-resolved, large frame, many xrefs),
   packer/obfuscation indicators, and anything the analysis could NOT determine.
   The "could not determine" section matters as much as the findings.
3. Make the shared context persistent within a session so it survives across
   commands - a persistent database analogue. The interactive shell (src/cli/app/re_shell.c)
   currently remembers only the opened path; have it retain the parsed file, PE
   structure, function scan and xrefs. A driver scan measures 9-62 ms today, so
   justify the design against that number and report what you measured.
4. Report pass-by-pass timing, so a slow pass is visible rather than a mystery.
5. Graceful degradation: a pass that cannot run must be reported as skipped
   with its reason, and must not abort the whole analysis or leave the context
   half-built.
6. Regression test per fix, including the no-crash guarantee on protected input.

CONSTRAINTS
- Read .rules/rules.md first. Banner line 4 must start "Depends:". 100-column
  limit, K&R, 4-space, LF, ASCII only.
- Rule 0: read docs/util-catalog.md before writing anything.
- No malloc/free, no libc string calls, no stdout writes outside src/utils.
- Gate: `python scripts\check.py .` -> "all rules pass". Then
  `ctest --preset clang-release` -> 6/6.
- Keep every folder at 15 files or fewer.
- Output policy unchanged: text when stdout is a TTY, JSON when piped,
  --format overrides, --no-color honoured. MCP must keep working.

TEST FILES (quote paths; two contain [ and ] which break globs)
  C:\Users\xyz\Downloads\vulnerable-drivers-main_[unknowncheats.me]_\vulnerable-drivers-main\cpqsysio64.sys
    clean control
  C:\Program Files (x86)\Steam\steamapps\common\VRChat - Copy\GameAssembly.dll
    214 MB IL2CPP, 264 randomised export names, scale/perf
  C:\Program Files (x86)\Steam\steamapps\common\VRChat - Copy\start_protected_game.exe
    private packer
  C:\Program Files (x86)\Steam\steamapps\common\SCP Secret Laboratory\GameAssembly.dll
    different packer
  C:\Users\xyz\Downloads\xysc7n\loader.exe
    third protection

All five must exit 0 or fail cleanly with a real diagnostic; none may crash,
hang or loop. Report per-pass and total timings for each, and confirm the
session cache actually saves work on a second command.

DO NOT ask questions. Do not push. Commit when gate and tests pass, then report
honestly what the report contains, what it refuses to claim, the measured
timings, and what remains undone.
```

---

## Prompt 4 — Types and stack-to-argument inference

```
Work in C:\Users\xyz\Pictures\RE on branch main.
Assumes prompts 1, 2 and 3 are committed.

CONTEXT
antistrefo: C11/C++17 static-analysis CLI and MCP server, CMake, branch main.

A NOTE ON SCOPE, because this prompt is the long pole. Automatic analysis
(items 1-5, 7-8) is NOT decompilation. Pseudocode is a separate, much
larger problem; argument recovery, calling convention inference and
stack-to-argument inference are the hardest thing in the list. Do not pretend
otherwise by shipping something that merely looks like type recovery - report
honestly what works.

Already built:
- src/features/code/re_stack.c is a REAL pass, not a stub. Sound
  under-approximation: a register counts as an argument only when read before
  anything written, so a miss costs a parameter rather than inventing one.
  Handles MS x64 (rcx/rdx/r8/r9) and SysV (rdi/rsi/rdx/rcx/r8/r9). Records
  argument reads at walk time, not at the end, because a call clobbers the
  volatile set and scoring afterwards would conclude every function takes zero
  arguments. It needs coverage tests, not a rewrite.
- src/features/dec/re_ir.c lowers an integer data-flow subset to the IR;
  re_dc_print.c renders it as C-like output.

YOUR TASK, in priority order. Do them in order and stop honestly if you do not
finish - a partial result reported as partial is fine, a partial result
reported as complete is not.
1. Coverage tests for re_stack.c. It is the best existing analysis and it is
   essentially untested. Build a fixture set with known argument counts and
   known frame sizes, and assert against them. Include the tricky cases: a
   function whose only argument read happens after a call; a function with a
   callee-saved register spilled in the prologue; tail-call thunks; a function
   that never touches its arguments.
2. Surface the stack analysis in output: per function, argument registers,
   frame size, and local slot count, in `funcs`, in the framed renderer, and in
   the decompiler's function signature. This is where the tool infers
   void Function(int arg1, int arg2)" item, and it is achievable now.
3. Extend the IR with a real type lattice - at minimum integer widths
   (i8/i16/i32/i64), pointer, and float - and propagate types through the
   existing data-flow lowering. Display types in decompiler output where
   confidence is high. Where confidence is low or types conflict, emit
   something honest like `int /* or ptr */` rather than a confident wrong type.
4. Struct/field recovery for stack slots that receive a single repeated pointer
   and are accessed at a consistent small displacement. This is the
   "player->health instead of qword ptr [rax+18]" item. Keep it conservative
   and label any recovered layout as inferred.

HARD CONSTRAINT on 3 and 4: a wrong type is worse than no type, because the
user cannot tell it apart from a right one. When unsure, say unsure.

CONSTRAINTS
- Read .rules/rules.md first. Banner line 4 must start "Depends:". 100-column
  limit, K&R, 4-space, LF, ASCII only.
- Rule 0: read docs/util-catalog.md before writing anything.
- No malloc/free, no libc string calls, no stdout writes outside src/utils.
- Gate: `python scripts\check.py .` -> "all rules pass". Then
  `ctest --preset clang-release` -> all pass.
- Keep every folder at 15 files or fewer.

TEST FILES (quote paths; two contain [ and ] which break globs)
  C:\Users\xyz\Downloads\vulnerable-drivers-main_[unknowncheats.me]_\vulnerable-drivers-main\cpqsysio64.sys
    clean control. Hand-verify recovered argument counts and frame sizes
    against the disassembly for at least five real functions, and show the
    evidence.
  C:\Program Files (x86)\Steam\steamapps\common\VRChat - Copy\GameAssembly.dll
    214 MB IL2CPP, 264 randomised export names
  C:\Program Files (x86)\Steam\steamapps\common\VRChat - Copy\start_protected_game.exe
    private packer
  C:\Program Files (x86)\Steam\steamapps\common\SCP Secret Laboratory\GameAssembly.dll
    different packer
  C:\Users\xyz\Downloads\xysc7n\loader.exe
    third protection

All five must exit 0 or fail cleanly; none may crash, hang or loop. Protected
binaries must degrade to "unknown", never to a confident wrong type.

DO NOT ask questions. Do not push. Commit each of items 1-2 and then as much of
3-4 as is genuinely working. Then report, per item: done, partial, or not
started - with the hand-verification evidence for the control binary.
```

---

## Why this split

| Prompt | Item | Why here |
|---|---|---|
| 1 | 4 FLIRT, + rule enforcement | Smallest, highest value: a working matcher with an empty database. Also pays the owed 15-file enforcement. |
| 2 | 2 CFG, 8 Data detection | Both partly exist internally and are simply invisible; exposing them is cheap and immediately useful. |
| 3 | The driver | Packages 1+2. Deliberately third: doing it first would present an empty FLIRT and a hidden CFG as one impressive report. |
| 4 | 5 Stack, 6 Types | Long pole. Split internally into achievable-now (tests + surfacing args) and hard (type lattice, struct recovery), with the honest-reporting constraint spelled out. |

## Not covered

The VRChat IL2CPP export-to-managed-method mapping is **not** in these prompts
and remains open. Findings so far: it's an IL2CPP build with no
`Assembly-CSharp.dll`; `UnityPlayer.dll` exports only `UnityMain`/`UnityMain2`
(so there is no `il2cpp_*` table to map); `GameAssembly.dll`'s 264 exports have
randomised names; and `global-metadata.dat` is encrypted (magic `0xE9998F90`
where IL2CPP writes `0xFAB11BAF`). The real method-to-RVA mapping lives in that
metadata and would need the protection reversed — a separate decision, not
assumed here.
