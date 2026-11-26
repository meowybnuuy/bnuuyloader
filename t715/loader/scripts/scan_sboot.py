#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0
# Parts derived from bnuuyloader (https://github.com/meowybnuuy/bnuuyloader), MIT,
# Copyright (c) 2026 meowybnuuy: see the comments that name "the Note 4 loader".

"""Scan a Samsung S-Boot image for the allocator code that bnuuyloader's heap trick targets.

bnuuyloader (meowybnuuy/bnuuyloader, MIT) finds, in the Note 4 N910C ``sboot.bin``,
the tail of S-Boot's large-heap split: four ARM32 instructions followed by a four-word
literal pool.  Its own search (``sboot_util.py``) keeps a hit only when the literals
have the N910C's values.  This one reports every hit with the code around it, so that
another device's S-Boot can be compared with the N910C's.

    python3 -I scan_sboot.py IMAGE
    python3 -I scan_sboot.py IMAGE --strings REGEX [--strings REGEX ...]
    python3 -I scan_sboot.py --selftest

Read-only: the image is opened for reading and nothing is written.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import struct
import sys
from pathlib import Path

# bnuuyloader's _SPLIT_TAIL_SIGNATURE (meowybnuuy/bnuuyloader, sboot_util.py, MIT), as published there
SIGNATURE = bytes.fromhex("10 20 42 e2 02 c0 6c e0 00 c0 83 e5 ee ff ff ea")
BEFORE = 52  # the trailing branch loops back 64 bytes from its own address: 12 + 52
AFTER = 16  # the literal pool
MIN_STRING = 6

N910C_HEAP_BASE = 0x24E00000
N910C_SENTINEL_RANGE = (0x23E00000, 0x24000000)

CONDITIONS = "eq ne cs cc mi pl vs vc hi ls ge lt gt le al nv".split()
DATA_OPS = ("and eor sub rsb add adc sbc rsc tst teq cmp cmn orr mov bic mvn").split()
SHIFTS = "lsl lsr asr ror".split()


def sext(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value & (sign - 1)) - (value & sign)


def disasm_arm(word: int, address: int, image: bytes) -> str:
    """Decode what an ARM32 function around a hit needs; ``???`` for the rest."""
    cond = CONDITIONS[word >> 28]
    suffix = "" if cond == "al" else cond
    kind = (word >> 25) & 7
    rd, rn = (word >> 12) & 0xF, (word >> 16) & 0xF
    if (word & 0x0FFFFFF0) == 0x012FFF10:
        return f"bx{suffix} r{word & 0xF}"
    if kind in (0, 1):  # data processing
        name = DATA_OPS[(word >> 21) & 0xF]
        flags = suffix + ("s" if word & (1 << 20) else "")
        if word & (1 << 25):
            immediate, rotate = word & 0xFF, (word >> 8) & 0xF
            value = (immediate >> (rotate * 2) | immediate << (32 - rotate * 2)) & 0xFFFFFFFF
            operand2 = f"#0x{value:x}"
        elif word & 0x10:
            operand2 = f"r{word & 0xF} {SHIFTS[(word >> 5) & 3]} r{(word >> 8) & 0xF}"
        else:
            amount, shift = (word >> 7) & 0x1F, (word >> 5) & 3
            operand2 = f"r{word & 0xF}" + (f", {SHIFTS[shift]} #{amount}" if amount or shift else "")
        return f"{name}{flags} r{rd}, r{rn}, {operand2}"
    if kind == 2:  # single data transfer
        displacement = word & 0xFFF if word & (1 << 23) else -(word & 0xFFF)
        pre, byte, write, load = (bool(word & (1 << bit)) for bit in (24, 22, 21, 20))
        if rn == 15 and pre and load:  # a literal: what the code loads is in the image
            target = address + 8 + displacement
            if 0 <= target <= len(image) - 4:
                return f"ldr{suffix} r{rd}, =0x{struct.unpack_from('<I', image, target)[0]:08x}"
        name = "ldr" if load else "str"
        base = f"r{rn}, " + (f"#{displacement:+#x}{'!' if write else ''}]" if pre else f"], #{displacement:+#x}")
        return f"{name}{suffix}{'b' if byte else ''}{'t' if not pre and load else ''} r{rd}, [{base}"
    if kind == 5:  # branch
        if cond == "nv":
            return "blx <immediate>" if word & (1 << 24) else "???"
        target = address + 8 + sext(word & 0xFFFFFF, 24) * 4
        return f"{'bl' if word & (1 << 24) else 'b'}{suffix} 0x{target:06x}"
    return "???"


def n910c_checks(sentinel: int, heap_base: int, mode_flag: int, small_sentinel: int) -> list[tuple[bool, str]]:
    low, high = N910C_SENTINEL_RANGE
    return [
        (sentinel % 4 == 0, "sentinel is a multiple of 4"),
        (small_sentinel == sentinel + 16, "small sentinel is the sentinel plus 16"),
        (heap_base == N910C_HEAP_BASE, f"heap base is 0x{N910C_HEAP_BASE:08x}"),
        (mode_flag % 4 == 0, "mode flag is a multiple of 4"),
        (low <= sentinel < high, f"sentinel is in [0x{low:08x}, 0x{high:08x})"),
    ]


def show_hit(image: bytes, hit: int, verbose: bool = True) -> bool:
    """Print one hit; true when its literals have the N910C's values."""
    print(f"\n--- hit at file offset 0x{hit:x} ({hit})")
    if hit + len(SIGNATURE) + AFTER > len(image):
        print("    too close to the end of the image for the literal pool")
        return False
    sentinel, heap_base, mode_flag, small_sentinel = struct.unpack_from("<4I", image, hit + len(SIGNATURE))
    checks = n910c_checks(sentinel, heap_base, mode_flag, small_sentinel)
    if verbose:
        print(f"    literal pool: sentinel=0x{sentinel:08x} heap_base=0x{heap_base:08x} "
              f"mode_flag=0x{mode_flag:08x} small_sentinel=0x{small_sentinel:08x}")
        start = max(0, hit - BEFORE)
        start -= start % 4
        for offset in range(start, min(len(image) - 3, hit + len(SIGNATURE) + AFTER), 4):
            (word,) = struct.unpack_from("<I", image, offset)
            if offset >= hit + len(SIGNATURE):
                text = f".word 0x{word:08x}          pool"
            else:
                text = disasm_arm(word, offset, image) + ("     <== signature" if offset == hit else "")
            print(f"    0x{offset:06x}: {word:08x}  {text}")
        for ok, text in checks:
            print(f"    {'holds   ' if ok else 'differs '} N910C: {text}")
    return all(ok for ok, _ in checks)


def scan(image: bytes, verbose: bool = True) -> tuple[int, int]:
    """Return the number of signature hits and how many of them have the N910C's literals."""
    hits, start = [], 0
    while (hit := image.find(SIGNATURE, start)) != -1:
        hits.append(hit)
        start = hit + 1
    kept = sum(show_hit(image, hit, verbose) for hit in hits)
    print(f"bnuuyloader's own scan would keep {kept} of {len(hits)} hit(s)")
    return len(hits), kept


def show_strings(image: bytes, pattern: str) -> None:
    count = 0
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % MIN_STRING, image):
        text = match.group().decode("ascii")
        if re.search(pattern, text, re.IGNORECASE):
            print(f"    0x{match.start():06x}: {text[:110]}")
            count += 1
    print(f"    {count} string(s) matching /{pattern}/i")


def selftest() -> int:
    """Synthetic images: the signature with the N910C's literals, with another heap base, none."""
    body = b"\x00\x00\xa0\xe1" * (BEFORE // 4)  # nops
    cases = (
        ("the N910C's literals", bytes(100) + body + SIGNATURE + struct.pack("<4I", 0x23F00000, N910C_HEAP_BASE, 4, 0x23F00010) + bytes(64), (1, 1)),
        ("another heap base", bytes(100) + body + SIGNATURE + struct.pack("<4I", 0x23F00000, 0x25000000, 4, 0x23F00010) + bytes(64), (1, 0)),
        ("no signature", bytes(4096), (0, 0)),
    )
    failures = 0
    for index, (name, image, expected) in enumerate(cases):
        print(f"=== self-test: {name}")
        got = scan(image, verbose=index == 0)
        if got == expected:
            print(f"PASS: {got[0]} hit(s), {got[1]} kept, as expected")
        else:
            failures += 1
            print(f"FAIL: got {got[0]} hit(s), {got[1]} kept; expected {expected[0]} and {expected[1]}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("image", nargs="?", type=Path)
    parser.add_argument("--strings", action="append", default=[], metavar="REGEX",
                        help="also print the ASCII strings matching this regular expression")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    if args.image is None:
        parser.error("an image is needed")
    image = args.image.read_bytes()
    print(f"{args.image}: {len(image)} bytes, SHA-256 {hashlib.sha256(image).hexdigest()}")
    scan(image)
    for pattern in args.strings:
        print(f"\n--- strings matching /{pattern}/i")
        show_strings(image, pattern)
    return 0


if __name__ == "__main__":
    sys.exit(main())
