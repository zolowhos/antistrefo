# util-catalog.md - the lookup to read before writing a function. Rule 0 depends on it.
# Module: docs (Markdown).
# Owns: one row per utility, kept in sync with src/utils by scripts/check.py.
# Depends: none. If a header is missing from this table the build fails.

## How to use this

Before writing any function past 60 lines or 4 nesting levels, grep `src/utils/`
or scan the table below. If something here already does the job, use it. If not,
and the helper will be needed twice or loops over bytes, add it here first.

## Memory and strings

| Util | Gives you | Header |
|---|---|---|
| `re_arena_*` | bump allocation, one malloc and one free per command | `re_arena.h` |
| `re_buf_*` | bounds checked reads over an mmap'd file, the safety boundary | `re_buf.h` |
| `re_json_*` | the streaming JSON writer, the only sanctioned stdout writer | `re_json.h` |
| `re_strbuf_*` | growable buffer, `put_u64`, `put_hex64`, `appendf` | `re_strbuf.h` |
| `re_str_*` | `eq`, `icmp`, `find`, `rfind`, `trim`, `split`, `join` | `re_str.h` |
| `re_fmt_*` | signed ints, arbitrary base, column padding, byte sizes | `re_fmt.h` |
| `re_hex_*` | encode, decode with separators, nibble table | `re_hex.h` |
| `re_entropy_*` | Shannon entropy over a span, for packer detection | `re_entropy.h` |
| `re_time_*` | Unix timestamp to ISO date, build year, and a pass timer | `re_time.h` |

## Containers

| Util | Gives you | Header |
|---|---|---|
| `re_vec_*` | typed growable array, one implementation for every element | `re_vec.h` |
| `re_map_*` | string keyed open addressing map, arena backed | `re_map.h` |
| `re_set_*` | a set, which is a map that ignores its values | `re_set.h` |
| `re_sort_*` | introsort over raw bytes, shared by every container | `re_sort.h` |

## Bit and byte level

| Util | Gives you | Header |
|---|---|---|
| `re_bits_*` | popcount, ctz, clz, rotate, `align_up`, min and max | `re_bits.h` |
| `re_bswap*` | byte swap for the big endian ELF and Mach-O readers | `re_bits.h` |
| `re_crc_*` | CRC-16/X-25 and CRC-32/IEEE, call `re_crc_init` once | `re_crc.h` |
| `re_hash_*` | MD5 and SHA-256, one shot or streaming | `re_hash.h` |

## Search, paths and diagnostics

| Util | Gives you | Header |
|---|---|---|
| `re_rx_*` | backtracking regex, with a literal fast path and step caps | `re_regex.h` |
| `re_path_*` | absolute test, extension, dirname, join, normalize | `re_path.h` |
| `re_err_*` | error codes, the error record, exit code mapping | `re_err.h` |
| `re_log_*` | the only stderr writer, silent when muted or in mcp mode | `re_log.h` |
| `re_text_*` | fixed width table rendering for `--format text` | `re_text.h` |
| `re_jr_*` | reading JSON that arrived over a socket, and escaping on the way out | `re_jr.h` |
| `re_tui_*` | the framed report: header, rules, panels, boxes, styles, clipping | `re_tui.h` |
| `re_screen_*` | a cell grid and its widgets: tabs, legend, gutter, scrollbars, status, draw | `re_screen.h` |
| `re_syntax_*` | colour one C-like line: keywords, types, comments, strings, numbers, calls | `re_syntax.h` |
| `re_layout_*` | the reference screen arrangement, expressed as a struct and composed | `re_layout.h` |
| `re_console_*` | fixed ring of short GUI console lines with scrollback | `re_console.h` |
| `re_ui_*` | hover and click bindings over screen zones | `re_ui.h` |

## Aggregator

| Util | Gives you | Header |
|---|---|---|
| `re_util_*` | every header above in one include, for cli and mcp only | `re_util.h` |

## Private to the regex engine

`re_regex_priv.h` holds the instruction and node layouts. It is shared only by
`re_regex.c` and `re_regex_vm.c` and is never included by feature code.

## Not yet built

These are named in `.rules/rules.md` but do not exist yet. Do not add a second
implementation when you need one; build these first instead.

| Missing | Needed by | Replace with |
|---|---|---|
| `re_table.h` command table | the CLI and MCP tool list | duplicated argument parsing |

Built in task 1: `re_buf`, `re_json`, `re_entropy`, `re_text`, `re_pe`, `re_format`,
`re_strings`, `re_triage`, and the IR seam in `re_ir.h` plus `re_disasm.h`.
Built in task 2: `re_time`, plus the features `re_search`, `re_rules`, `re_demangle`
in `re_demangle.c` and `re_demangle_msvc.c`.
Built in task 3 so far: `re_ir` storage, `re_code` (the address and coverage map),
`re_func` (recursive descent), and the x86-64 backend under `src/features/disasm/`.
Built in task 4: `re_dc_walk` (the block structure of one function), `re_dc_print`
(the emitter's name tables and value renderer), `re_decompile` (the C-like emitter),
and the data flow half of `re_x64_lower`. Nothing is still missing.

## Code, data, and what an export actually is

`re_pe` answers three questions that a report cannot answer honestly without, because
conflating any two of them produces an answer that looks right:

- `re_pe_section_at_rva` returns the section an rva falls in, or NULL. NULL is a real
  answer rather than a failure: a linker can leave a gap between sections, and an
  export pointing into one is not code.
- `re_pe_region_kind` reports `code`, `data` or `unmapped`. Either `IMAGE_SCN_CNT_CODE`
  or `IMAGE_SCN_MEM_EXECUTE` counts as code, never both required. Requiring both made a
  whole protected image invisible: a real 98 MB `.text` had its execute bit stripped
  and given to `.rodata` instead. Both constants live in `re_pe.h` now, because a
  section table states them and this is a question about the file.
- `re_pe_export_forwarder` reports the module and function an export forwards to, or an
  empty string. A forwarder's target rva lands inside the export directory itself, where
  the linker wrote that string.

An export therefore has a `kind` of `code`, `forwarder` or `data`, and a forwarder also
carries `forwarder`. Real binaries need all three: `AmdPowerXpressRequestHighPerformance`
and `NvOptimusEnablement` are dwords a GPU driver reads, `VerLanguageNameA` in
`version.dll` is `KERNEL32.VerLanguageNameA`, and neither is an address to call.

## Disassembly, and the Capstone question

Rules 8.1 planned Capstone behind the `re_disasm` vtable. The native backend in
`src/features/disasm/` remains the self contained x86-64 / x86 decoder. Capstone is
fetched (tag 5.0.3) when `RE_ENABLE_CAPSTONE=ON` (default with `RE_ENABLE_DISASM`)
and covers the gap arch: ARM-64, registered as `arm64`. Feature code never includes
a Capstone header; only `src/features/disasm/cs/` does.

- `RE_ENABLE_DISASM=OFF` drops the whole table and does not fetch Capstone.
- `RE_ENABLE_CAPSTONE=OFF` keeps the native x86 backends and omits `arm64`.
- Capstone is linked only into `re_core`; the IR and emitter stay arch independent.
- ARM-64 lowering is not modelled yet (returns 0). Decode, flags, targets, prologue
  sniff and mnemonic render are in scope.

What this means in practice, stated plainly rather than buried:

- The decoder covers the integer and SSE subset: prefixes, REX, VEX2, VEX3, EVEX,
  ModRM, SIB, displacements, and the immediate width rules. Unknown opcodes are
  refused, which stops a walk rather than letting it desynchronise.
- Text rendering covers operands: registers, memory with base, index, scale and
  displacement, RIP relative addresses, and immediates.
- `re_x64_lower` models the integer data flow subset as well as control flow:
  moves, the arithmetic and logic group in both its register and immediate forms,
  the accumulator forms, `test`, `movzx`, `lea`, and loads and stores. A memory
  destination is a read modify write, so it lowers to a load, the operation and a
  store rather than to an op that pretends arithmetic can happen in place.
- Three things are deliberately not modelled, and say so by emitting nothing:
  the carry forms `adc` and `sbb`, because the flags are not in this IR; the
  shift and multiply forms, for the same reason until the IR carries flags; and
  every SSE instruction. An instruction the arch does not lower prints as a
  comment with its address and its text, so a gap is visible rather than silent.
- The emitter is pseudo C, not compilable output. Its job is that a reader
  recognises the function: the signature carries the inferred calling convention
  and parameter count, locals are named from the frame displacements the stack
  analysis found, calls are named from the import index, and a compare and the
  branch that reads its flags print as one expression.

Scope note: the Itanium demangler handles nested names, template arguments,
substitutions and the common builtin types, and renders unknown template
parameters as `auto` rather than guessing. It refuses anything it cannot parse
confidently, so an unsupported symbol keeps its raw name instead of getting a
plausible wrong one.
