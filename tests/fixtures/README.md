# fixtures/README.md - checked-in robustness corpus (packed and obfuscated).
# Module: test (Markdown).
# Owns: how to regenerate the synthetic PE/ELF samples under this directory.
# Depends: scripts/gen_fixtures.py. These are not product binaries.

## Purpose

Synthetic samples so developers can run `info` / `triage` / later passes against
**packed** and **obfuscated / malformed** PE without importing third-party game,
anti-cheat, or forum binaries. Robustness only: never crash, hang, or invent
results; report what is knowable.

## Files

| Path | Kind | Notes |
|---|---|---|
| `packed_pe.bin` | Packed PE | Custom stub (`.stub`) + zlib/xor high-entropy `.pack`. Marker `REPACK1`. |
| `obfuscated_pe.bin` | Obfuscated / hostile PE | High-entropy `.text`, fake imports, mid-image junk, broken overlay. |
| `minimal_elf.bin` | Minimal ELF64 | Synthesized ELF (no cross compiler). Format smoke only. |

Optional (not checked in unless UPX was available when regenerating):

| Path | Kind |
|---|---|
| `packed_pe_upx.bin` | Tiny PE compressed with system `upx` |

Sizes stay in the KB range on purpose.

## Regenerate

From the repo root:

```
python3 scripts/gen_fixtures.py
python3 scripts/gen_fixtures.py --out-dir tests/fixtures
```

No network, no third-party PE libraries. If `upx` is on `PATH`, the script also
writes `packed_pe_upx.bin`; otherwise the hand-crafted `packed_pe.bin` is enough.

## Smoke

CTest target `robustness_fixtures` runs `info` and `triage` on each PE fixture
and asserts a schema-bearing response (exit 0 success, or a clean nonzero error
envelope). It pins "does not crash," not full analysis quality.
