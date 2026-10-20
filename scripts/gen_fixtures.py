#!/usr/bin/env python3
# gen_fixtures.py - synthesize small PE/ELF robustness fixtures for the test corpus.
# Module: tool (Python 3).
# Owns: packed PE, obfuscated PE, and a minimal ELF used only as checked-in samples.
# Depends: stdlib only. No third-party packers required; UPX is optional if present.
"""Regenerate checked-in robustness fixtures under tests/fixtures/.

  python3 scripts/gen_fixtures.py
  python3 scripts/gen_fixtures.py --out-dir tests/fixtures

These binaries are for crash/robustness testing, not reverse-engineering a product.
If `upx` is on PATH, the packed sample is also written as packed_pe_upx.bin from a
tiny synthetic PE; otherwise only the hand-crafted packed_pe.bin is produced.
"""
from __future__ import annotations

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

IMAGE_BASE = 0x140000000
HDRS = 0x400
SECT_ALIGN = 0x1000
FILE_ALIGN = 0x200


def put16(b: bytearray, off: int, v: int) -> None:
    b[off : off + 2] = struct.pack("<H", v & 0xFFFF)


def put32(b: bytearray, off: int, v: int) -> None:
    b[off : off + 4] = struct.pack("<I", v & 0xFFFFFFFF)


def put64(b: bytearray, off: int, v: int) -> None:
    b[off : off + 8] = struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def align_up(n: int, a: int) -> int:
    return (n + a - 1) & ~(a - 1)


def prng_bytes(n: int, seed: int = 0xC0FFEE) -> bytes:
    """xorshift32 stream so the payload is high-entropy and reproducible."""
    x = seed & 0xFFFFFFFF
    out = bytearray(n)
    for i in range(n):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        out[i] = x & 0xFF
    return bytes(out)


def pe_headers(
    img: bytearray,
    *,
    nsec: int,
    entry_rva: int,
    size_of_image: int,
    size_of_headers: int,
    subsystem: int = 3,
) -> int:
    """Write MZ + PE32+ COFF/optional headers. Returns section-table file offset."""
    put16(img, 0, 0x5A4D)
    img[2:64] = b"antistrefo fixture\0".ljust(62, b"\0")
    put32(img, 0x3C, 0x80)
    put32(img, 0x80, 0x00004550)
    coff = 0x84
    put16(img, coff + 0, 0x8664)
    put16(img, coff + 2, nsec)
    put16(img, coff + 16, 0xF0)
    put16(img, coff + 18, 0x0022)
    opt = coff + 20
    put16(img, opt + 0, 0x20B)
    put32(img, opt + 16, entry_rva)
    put64(img, opt + 24, IMAGE_BASE)
    put32(img, opt + 32, SECT_ALIGN)
    put32(img, opt + 36, FILE_ALIGN)
    put16(img, opt + 40, 6)
    put16(img, opt + 42, 0)
    put32(img, opt + 56, size_of_image)
    put32(img, opt + 60, size_of_headers)
    put16(img, opt + 68, subsystem)
    put16(img, opt + 70, 0x8160)
    put64(img, opt + 72, 0x100000)
    put64(img, opt + 80, 0x1000)
    put64(img, opt + 88, 0x100000)
    put64(img, opt + 96, 0x1000)
    put32(img, opt + 108, 16)
    return opt + 112 + 16 * 8


def write_section(
    img: bytearray,
    sec_off: int,
    name: bytes,
    vsize: int,
    rva: int,
    raw_size: int,
    raw_off: int,
    chars: int,
) -> None:
    img[sec_off : sec_off + 8] = name.ljust(8, b"\0")[:8]
    put32(img, sec_off + 8, vsize)
    put32(img, sec_off + 12, rva)
    put32(img, sec_off + 16, raw_size)
    put32(img, sec_off + 20, raw_off)
    put32(img, sec_off + 36, chars)


def build_packed_pe() -> bytes:
    """Custom packer: tiny stub + zlib+xor high-entropy payload section.

    Marker ASCII `REPACK1` sits in the DOS stub area so packer heuristics can see
    a synthetic tag without claiming to be a real UPX image.
    """
    # Payload: compressible plaintext then zlib then xor, so entropy stays high.
    plain = (b"PACKED_PAYLOAD_v1:" + bytes(range(256))) * 8
    compressed = zlib.compress(plain, 9)
    key = 0xA5
    packed = bytes(b ^ key for b in compressed)
    packed = packed + prng_bytes(512, 0xBADC0DE)

    # Stub: xor-decode sketch then ret (never actually runs in analysis).
    stub = bytearray(
        [
            0x48,
            0x31,
            0xC0,  # xor rax, rax
            0xB0,
            key,  # mov al, key
            0x48,
            0x8D,
            0x35,
            0,
            0,
            0,
            0,  # lea rsi, [rip+0] placeholder
            0x48,
            0xC7,
            0xC1,
            0x00,
            0x04,
            0x00,
            0x00,  # mov rcx, 0x400
            0x30,
            0x06,  # xor [rsi], al
            0x48,
            0xFF,
            0xC6,  # inc rsi
            0xE2,
            0xF9,  # loop
            0xC3,  # ret
        ]
    )
    stub += b"REPACK1\0"
    stub += prng_bytes(64, 1)

    stub_raw = align_up(len(stub), FILE_ALIGN)
    pack_raw = align_up(len(packed), FILE_ALIGN)
    size_of_headers = align_up(0x200 + 2 * 40, FILE_ALIGN)
    stub_rva = SECT_ALIGN
    pack_rva = stub_rva + SECT_ALIGN
    size_of_image = pack_rva + SECT_ALIGN

    img = bytearray(size_of_headers + stub_raw + pack_raw)
    sec = pe_headers(
        img,
        nsec=2,
        entry_rva=stub_rva,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
    )
    img[0x40:0x48] = b"REPACK1\0"
    write_section(
        img, sec, b".stub", len(stub), stub_rva, stub_raw, size_of_headers, 0x60000020
    )
    write_section(
        img,
        sec + 40,
        b".pack",
        len(packed),
        pack_rva,
        pack_raw,
        size_of_headers + stub_raw,
        0xC0000040,
    )
    img[size_of_headers : size_of_headers + len(stub)] = stub
    img[size_of_headers + stub_raw : size_of_headers + stub_raw + len(packed)] = packed
    return bytes(img)


def build_tiny_clean_pe() -> bytes:
    """Minimal valid PE used as UPX input when upx is available."""
    code = bytes([0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3])  # mov eax,42; ret
    code_raw = align_up(len(code), FILE_ALIGN)
    size_of_headers = align_up(0x200 + 40, FILE_ALIGN)
    text_rva = SECT_ALIGN
    size_of_image = text_rva + SECT_ALIGN
    img = bytearray(size_of_headers + code_raw)
    sec = pe_headers(
        img,
        nsec=1,
        entry_rva=text_rva,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
    )
    write_section(
        img, sec, b".text", len(code), text_rva, code_raw, size_of_headers, 0x60000020
    )
    img[size_of_headers : size_of_headers + len(code)] = code
    return bytes(img)


def build_obfuscated_pe() -> bytes:
    """Hostile-but-synthetic PE: high-entropy .text, fake imports, mid-image junk.

    Still recognizable as PE so triage/info can report structure; overlays and
    directories are intentionally inconsistent enough to stress parsers.
    """
    # Mix of real x86-64 bytes and high-entropy junk so disasm must bail cleanly.
    text = bytearray()
    text += bytes([0x48, 0x83, 0xEC, 0x28])  # sub rsp, 0x28
    text += bytes([0x90, 0x90, 0xCC, 0xC3])  # nops, int3, ret
    text += prng_bytes(0x600, 0x0BF05C)
    text += bytes([0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3])  # call $+5; ret
    text += prng_bytes(0x200, 0xDEADC0DE)

    # Fake import / name blobs that look like an IAT but point into garbage RVAs.
    idata = bytearray(0x200)
    idata[0:4] = struct.pack("<I", 0x3000 + 0x40)  # OriginalFirstThunk (bogus)
    idata[12:16] = struct.pack("<I", 0x3000 + 0x80)  # Name RVA
    idata[16:20] = struct.pack("<I", 0x3000 + 0x100)  # FirstThunk
    idata[0x80:0x80 + 12] = b"kernel32.dll\0"
    idata[0xA0:0xA0 + 14] = b"\0\0VirtualAlloc\0"
    idata[0x100:0x108] = struct.pack("<Q", 0x3000 + 0xA0)
    idata[0x180:] = prng_bytes(0x80, 0x1111)

    # Mid-image garbage between section raw regions (not covered by any section).
    junk = prng_bytes(0x180, 0x51515151)
    overlay = b"BROKEN_OVERLAY" + prng_bytes(0x100, 0x2222) + b"\xff" * 32

    text_raw = align_up(len(text), FILE_ALIGN)
    idata_raw = align_up(len(idata), FILE_ALIGN)
    junk_pad = align_up(len(junk), FILE_ALIGN)
    size_of_headers = align_up(0x200 + 3 * 40, FILE_ALIGN)
    text_rva = SECT_ALIGN
    rdata_rva = text_rva + 2 * SECT_ALIGN  # gap in virtual space
    idata_rva = rdata_rva + SECT_ALIGN
    # SizeOfImage understates the last section on purpose (hostile).
    size_of_image = idata_rva + 0x200

    img = bytearray(size_of_headers + text_raw + junk_pad + idata_raw + len(overlay))
    sec = pe_headers(
        img,
        nsec=3,
        entry_rva=text_rva,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
    )
    # Data directories: claim imports at idata_rva, and a corrupt exception dir.
    opt = 0x84 + 20
    put32(img, opt + 112 + 1 * 8, idata_rva)  # import
    put32(img, opt + 112 + 1 * 8 + 4, len(idata))
    put32(img, opt + 112 + 3 * 8, 0xDEADBEEF)  # exception RVA nonsense
    put32(img, opt + 112 + 3 * 8 + 4, 0x40)
    put32(img, opt + 112 + 12 * 8, size_of_headers + text_raw + junk_pad + idata_raw)
    put32(img, opt + 112 + 12 * 8 + 4, len(overlay))  # claim overlay as IAT

    write_section(
        img, sec, b".text", len(text), text_rva, text_raw, size_of_headers, 0x60000020
    )
    # Second header names .junk but raw data is the mid-image garbage blob.
    write_section(
        img,
        sec + 40,
        b".junk",
        len(junk),
        text_rva + SECT_ALIGN,
        junk_pad,
        size_of_headers + text_raw,
        0xC0000000,
    )
    write_section(
        img,
        sec + 80,
        b".idata",
        len(idata),
        idata_rva,
        idata_raw,
        size_of_headers + text_raw + junk_pad,
        0xC0000040,
    )

    o = size_of_headers
    img[o : o + len(text)] = text
    o += text_raw
    img[o : o + len(junk)] = junk
    o += junk_pad
    img[o : o + len(idata)] = idata
    o += idata_raw
    img[o : o + len(overlay)] = overlay
    return bytes(img)


def build_minimal_elf() -> bytes:
    """Tiny little-endian ELF64 (ET_EXEC, EM_X86_64) with one PT_LOAD."""
    # e_ident + header + one program header + 8 bytes of code at file offset 0x80.
    code = bytes([0x48, 0x31, 0xC0, 0xC3])  # xor rax,rax; ret
    ehsize = 64
    phentsize = 56
    phoff = ehsize
    entry = 0x400080
    file_size = 0x80 + len(code)
    img = bytearray(file_size)
    img[0:4] = b"\x7fELF"
    img[4] = 2  # ELFCLASS64
    img[5] = 1  # ELFDATA2LSB
    img[6] = 1  # EV_CURRENT
    put16(img, 16, 2)  # ET_EXEC
    put16(img, 18, 62)  # EM_X86_64
    put32(img, 20, 1)  # EV_CURRENT
    put64(img, 24, entry)
    put64(img, 32, phoff)
    put64(img, 40, 0)  # shoff
    put32(img, 48, 0)
    put16(img, 52, ehsize)
    put16(img, 54, phentsize)
    put16(img, 56, 1)  # phnum
    put16(img, 58, 0)
    put16(img, 60, 0)
    put16(img, 62, 0)
    # PT_LOAD
    put32(img, phoff + 0, 1)
    put32(img, phoff + 4, 5)  # PF_R|PF_X
    put64(img, phoff + 8, 0)
    put64(img, phoff + 16, 0x400000)
    put64(img, phoff + 24, 0x400000)
    put64(img, phoff + 32, file_size)
    put64(img, phoff + 40, file_size)
    put64(img, phoff + 48, 0x1000)
    img[0x80 : 0x80 + len(code)] = code
    return bytes(img)


def try_upx(out_dir: str, clean: bytes) -> str | None:
    """If upx is installed, compress a tiny PE into packed_pe_upx.bin."""
    upx = shutil.which("upx")
    if not upx:
        return None
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "clean.exe")
        dst = os.path.join(out_dir, "packed_pe_upx.bin")
        with open(src, "wb") as f:
            f.write(clean)
        try:
            subprocess.run(
                [upx, "-q", "-o", dst, src],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except (subprocess.CalledProcessError, OSError):
            return None
        if os.path.isfile(dst):
            return dst
    return None


def write(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    print(f"wrote {path} ({len(data)} bytes)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--out-dir",
        default=os.path.join("tests", "fixtures"),
        help="directory for checked-in fixtures (default: tests/fixtures)",
    )
    args = ap.parse_args()
    out = args.out_dir
    os.makedirs(out, exist_ok=True)

    write(os.path.join(out, "packed_pe.bin"), build_packed_pe())
    write(os.path.join(out, "obfuscated_pe.bin"), build_obfuscated_pe())
    write(os.path.join(out, "minimal_elf.bin"), build_minimal_elf())

    upx_path = try_upx(out, build_tiny_clean_pe())
    if upx_path:
        print(f"also wrote UPX sample {upx_path}")
    else:
        print("upx not available; skipped packed_pe_upx.bin (hand-crafted packed_pe.bin is enough)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
