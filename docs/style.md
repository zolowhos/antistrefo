# style.md - the human readable form of the rules enforced by scripts/check.py.
# Module: docs (Markdown).
# Owns: the conventions and the reasoning behind each gate.
# Depends: .clang-format, .editorconfig, .clang-tidy, scripts/check.py, .rules/rules.md.

## Formatting

`clang-format` with `.clang-format` at the root decides everything mechanical.
Never hand format, and never argue with the tool in review.

| Setting | Value | Why |
|---|---|---|
| Indent | 4 spaces | fewer lines per function, which serves the file size cap |
| Braces | attach (K&R) | a line saved on every function and loop |
| Column | 100 | fits a function signature without wrapping on most screens |
| Tabs | never | `.editorconfig` and the checker both reject them |
| Alignment padding | off | it burns line budget and creates diff noise |
| Include sorting | on, case insensitive | makes a missing include obvious |

Run `cmake --build build/clang-release --target re_format` to format everything.
The `format` CTest test fails the build on any drift.

## The banner

Every file opens with exactly four comment lines, in this order:

```
<comment> <basename> - <one line purpose>
<comment> Module: <module> (<language>).
<comment> Owns: <what this file is responsible for>.
<comment> Depends: <dependencies or none>. <hard constraint or none>.
```

The fourth line is the one that earns its keep. It states the constraint that
makes the file safe to change, so a reader learns the rule without opening the
implementation.

Two files are exempt because their format forbids comments: `CMakePresets.json`,
whose schema CMake validates strictly, and `LICENSE`, which is legal text.

## Size caps

| Cap | Value | Gate |
|---|---|---|
| File | 500 lines | rule 1, enforced |
| Function body | 60 lines | rule 0, enforced |
| Nesting depth | 4 | rule 0, enforced |

When a file hits the cap the answer is to split it, never to raise the cap. When
a function hits 60 lines it is doing at least two things.

## Rule 0, reuse first

Read `docs/util-catalog.md` before writing anything substantial. The mechanical
half is enforced:

| Pattern | Use instead |
|---|---|
| `malloc`, `calloc`, `realloc`, `free` outside `src/utils` | `re_arena_*` |
| `strlen`, `strcmp`, `strcat`, `strcpy`, `sprintf`, `strtok` | `re_str_*`, `re_strbuf_*` |
| `realloc` | `re_strbuf_*` or `re_vec_*` |
| `printf`, `puts`, `fprintf(stdout, ...)` outside `re_jw*` and `re_text*` | `re_jw_*`, `re_text_*` |
| `x &= x - 1` bit clearing | `re_bits_*` |

The rest of the catalog, the hex nibble loops, the hand rolled hash accumulators,
the manual capacity doubling, is a review-time check. A regex cannot reliably
tell a deliberate byte loop from a reinvented utility.

### Escape hatch

Rule 0 without an exception produces bloat, which is worse than the duplication
it prevents. So:

- used once, 15 lines or fewer, no loop over bytes: stay `static` in the caller
- needed twice, or loops over bytes, or crosses a module: becomes a util first
- never inline a would be util into its consumer
- a util that would pass 500 lines splits, it is never absorbed

## The two rules that protect the architecture

Rules 6 and 7 look like style, but they are the load bearing ones.

**Rule 6, no allocation outside the arena.** A command allocates everything from
one bump allocator and frees it in a single call. Thousands of small allocations
per invocation turn into a handful. It also means ownership is a property of the
command, not of individual objects, which is why the containers have no free
functions and the set has no delete.

**Rule 7, nothing writes stdout except the emitters.** In `antistrefo mcp`, stdout is the
JSON-RPC stream. A stray `printf` inside a parser corrupts the protocol and the
symptom appears in the client, not in the tool. This is why `re_log_*` exists,
why it only ever writes stderr, and why the mcp entry point mutes it outright.

## Testing

CTest targets print only on failure. The utility suite checks published test
vectors, not self consistency, because a self consistent SHA-256 is still wrong.

Sanitizer coverage follows the Clang primary path. GCC remains a second-compiler
check. Legacy MSVC ASan is optional on Windows-only machines.

| Preset | What it actually does | Compiler |
|---|---|---|
| `clang-asan` | address sanitizer on the primary toolchain | Clang `-fsanitize=address` |
| `gcc-debug` | a second compiler, catching Clang-specific assumptions | GCC `-Wall -Wextra -Werror` |
| `msvc-asan` | legacy MSVC ASan only | MSVC `/fsanitize=address` |

So the memory safety story rests on three things instead of a fuzzer: Clang ASan,
a warning-clean build under Clang and GCC with `-Werror`, and the
truncation sweep below. Run all three before calling a task done.

For parsers, the truncation sweep is the highest value test in the project: cut
each fixture at every 512 byte boundary and assert a clean exit code rather than
a crash. Parsing hostile input is the entire job, so out of bounds reads are the
primary threat and the memory views must make them impossible.
