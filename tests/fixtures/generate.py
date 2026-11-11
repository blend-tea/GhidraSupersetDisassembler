#!/usr/bin/env python3
"""Generate small, reproducible x86 fixtures without a cross compiler.

The same instruction stream is embedded in raw, ELF, and PE files.  Its labels
are known by construction; no disassembler output is used as test ground truth.
"""
import argparse
import json
from pathlib import Path
import struct


def code(bits):
    # entry: push bp; mov bp,sp; call callee; xor ax,ax; pop bp; ret
    prefix = bytes.fromhex("55 48 89 e5 e8 0b 00 00 00 31 c0 5d c3") if bits == 64 else \
             bytes.fromhex("55 89 e5 e8 0c 00 00 00 31 c0 5d c3")
    # callee: push bx; xor ax,ax; pop bx; ret. Last 0f is incomplete.
    return prefix + b"\x90" * (20 - len(prefix)) + bytes.fromhex("53 31 c0 5b c3 0f")


def elf(bits, payload):
    offset = 0x1000
    address = 0x401000 if bits == 64 else 0x8049000
    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1, 1, 0]) + bytes(8)
    if bits == 64:
        header = ident + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, address, 64, 0, 0,
                                    64, 56, 1, 0, 0, 0)
        program = struct.pack("<IIQQQQQQ", 1, 5, offset, address, address,
                              len(payload), len(payload), 0x1000)
    else:
        header = ident + struct.pack("<HHIIIIIHHHHHH", 2, 3, 1, address, 52, 0, 0,
                                    52, 32, 1, 0, 0, 0)
        program = struct.pack("<IIIIIIII", 1, offset, address, address,
                              len(payload), len(payload), 5, 0x1000)
    return (header + program).ljust(offset, b"\x00") + payload, address


def pe(bits, payload):
    pe_offset, file_offset = 0x80, 0x200
    optional_size = 0xF0 if bits == 64 else 0xE0
    image_base = 0x140000000 if bits == 64 else 0x400000
    result = bytearray(file_offset + 0x200)
    result[0:2] = b"MZ"
    struct.pack_into("<I", result, 0x3C, pe_offset)
    result[pe_offset:pe_offset + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", result, pe_offset + 4,
                     0x8664 if bits == 64 else 0x14C, 1, 0, 0, 0, optional_size,
                     0x22 if bits == 64 else 0x102)
    opt = pe_offset + 24
    struct.pack_into("<H", result, opt, 0x20B if bits == 64 else 0x10B)
    struct.pack_into("<I", result, opt + 4, 0x200)  # SizeOfCode
    struct.pack_into("<II", result, opt + 16, 0x1000, 0x1000)
    if bits == 64:
        struct.pack_into("<Q", result, opt + 24, image_base)
    else:
        struct.pack_into("<II", result, opt + 24, 0, image_base)
    struct.pack_into("<II", result, opt + 32, 0x1000, 0x200)
    struct.pack_into("<HH", result, opt + 40, 6, 0)
    struct.pack_into("<HH", result, opt + 48, 6, 0)
    struct.pack_into("<II", result, opt + 56, 0x2000, file_offset)
    struct.pack_into("<HH", result, opt + 68, 3, 0)
    if bits == 64:
        struct.pack_into("<QQQQII", result, opt + 72,
                         0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    else:
        struct.pack_into("<IIIIII", result, opt + 72,
                         0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    section = opt + optional_size
    struct.pack_into("<8sIIIIIIHHI", result, section, b".text\0\0\0", len(payload),
                     0x1000, 0x200, file_offset, 0, 0, 0, 0, 0x60000020)
    result[file_offset:file_offset + len(payload)] = payload
    return bytes(result), image_base + 0x1000


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = []
    for bits in (32, 64):
        payload = code(bits)
        raw_entry = 0x100000000 if bits == 64 else 0x1000
        for kind in ("raw", "elf", "pe"):
            blob, entry = (payload, raw_entry) if kind == "raw" else \
                          elf(bits, payload) if kind == "elf" else pe(bits, payload)
            name = f"fixture{bits}.{kind}"
            (args.output / name).write_bytes(blob)
            manifest.append({"file": name, "bits": bits, "format": kind,
                             "entry": hex(entry), "size": len(payload),
                             "abi": ("WINDOWS_" if kind == "pe" else "SYSV_") +
                                    ("X64" if bits == 64 else "X86")})
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
