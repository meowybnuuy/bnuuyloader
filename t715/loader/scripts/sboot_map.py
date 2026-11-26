#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Map a Samsung bootloader image before decompiling it.

    python3 -I sboot_map.py IMAGE --base [--block KIB]
    python3 -I sboot_map.py IMAGE --monitor [--from OFFSET] [--to OFFSET]
    python3 -I sboot_map.py IMAGE --literals VALUE [VALUE ...]

--base     for every block, the load base that absolute 32-bit literals agree on most:
           a literal at file offset o holding an address in DRAM means base + o.
--monitor  where the image builds or stores a secure monitor call 0x8200xxxx (ARM32
           movw/movt, AArch64 movz/movk, literal pools), and the negative slow-call IDs.
--literals the file offsets where the given little-endian 32-bit values are stored.

Read-only.
"""

from __future__ import annotations

import argparse
import struct
import sys
from collections import Counter
from pathlib import Path

DRAM_MIN, DRAM_MAX = 0x20000000, 0x30000000
MONITOR_MIN, MONITOR_MAX = 0x82000000, 0x82010000


def words(image: bytes, start: int = 0, end: int | None = None):
    end = len(image) if end is None else end
    start -= start % 4
    for offset in range(start, end - 3, 4):
        (word,) = struct.unpack_from("<I", image, offset)
        yield offset, word


def show_bases(image: bytes, block: int) -> None:
    print(f"block       size      load base candidates (count of literals agreeing), for literals in "
          f"[0x{DRAM_MIN:08x}, 0x{DRAM_MAX:08x})")
    for start in range(0, len(image), block):
        counter = Counter(word - offset for offset, word in words(image, start, min(len(image), start + block))
                          if DRAM_MIN <= word < DRAM_MAX)
        if not counter:
            continue
        top = ", ".join(f"0x{base:08x} ({count})" for base, count in counter.most_common(3))
        print(f"0x{start:06x}  {min(block, len(image) - start):>6}  {top}")


def arm32_movw_movt(image: bytes, start: int, end: int, high: int) -> list[tuple[int, int, int, str]]:
    """movw/movt pairs loading a value whose top half is ``high``: (offset, value, register, kind)."""
    found = []
    for offset, word in words(image, start, end):
        if word >> 28 not in (0xE, 0xF) or (word >> 20) & 0xFF != 0x34 or (word >> 16) & 0xF != high >> 12 or word & 0xFFF != high & 0xFFF:
            continue
        register = (word >> 12) & 0xF
        for back in range(4, 36, 4):
            low_offset, low = offset - back, None
            if low_offset < start:
                break
            (low,) = struct.unpack_from("<I", image, low_offset)
            if low >> 28 == word >> 28 and (low >> 20) & 0xFF == 0x30 and (low >> 12) & 0xF == register:
                low16 = ((low >> 4) & 0xF000) | (low & 0xFFF)
                found.append((offset, high << 16 | low16, register, f"movw r{register}, #0x{low16:04x} at 0x{low_offset:x}, movt"))
                break
    return found


def aarch64_movz_movk(image: bytes, start: int, end: int, high: int) -> list[tuple[int, int, str, str]]:
    """movz/movk pairs (32- or 64-bit registers) loading a value whose bits 16..31 are ``high``."""
    found = []
    for offset, word in words(image, start, end):
        if word & 0xFF800000 not in (0x52800000, 0xD2800000) or (word >> 21) & 3 != 1 or (word >> 5) & 0xFFFF != high:
            continue
        register, width = word & 0x1F, "w" if word >> 31 == 0 else "x"
        for back in range(4, 28, 4):
            low_offset = offset - back
            if low_offset < start:
                break
            (low,) = struct.unpack_from("<I", image, low_offset)
            if low & 0xFFE00000 == (word & 0xFFE00000) - 0x00200000 and low & 0x1F == register and (low >> 21) & 3 == 0:
                found.append((offset, high << 16 | (low >> 5) & 0xFFFF, register,
                              f"movz {width}{register}, #0x{(low >> 5) & 0xFFFF:04x} at 0x{low_offset:x}, movk"))
                break
    return found


def show_monitor(image: bytes, start: int, end: int) -> None:
    print(f"--- literal pools holding 0x8200xxxx, in [0x{start:x}, 0x{end:x})")
    values = Counter()
    for offset, word in words(image, start, end):
        if MONITOR_MIN <= word < MONITOR_MAX:
            values[word] += 1
            print(f"    0x{offset:06x}: 0x{word:08x}")
    print(f"    {sum(values.values())} literal(s), {len(values)} distinct")
    print("--- ARM32 movw/movt building 0x8200xxxx")
    for offset, value, _, how in arm32_movw_movt(image, start, end, 0x8200):
        print(f"    0x{offset:06x}: r?=0x{value:08x}  {how}")
    print("--- AArch64 movz/movk building 0x8200xxxx")
    for offset, value, register, how in aarch64_movz_movk(image, start, end, 0x8200):
        print(f"    0x{offset:06x}: 0x{value:08x}  {how}")
    print("--- negative small integers in literal pools (slow-call IDs -n)")
    negative = Counter(word for _, word in words(image, start, end) if 0xFFFFF800 <= word <= 0xFFFFFFFF)
    for word, count in sorted(negative.items()):
        print(f"    0x{word:08x} ({word - (1 << 32):5d}) x{count}")


def show_literals(image: bytes, values: list[int]) -> None:
    for value in values:
        needle = struct.pack("<I", value)
        offsets, at = [], image.find(needle)
        while at != -1:
            offsets.append(at)
            at = image.find(needle, at + 1)
        print(f"0x{value:08x}: {len(offsets)} occurrence(s)" +
              "".join(f" 0x{o:x}" + ("" if o % 4 == 0 else "(unaligned)") for o in offsets[:24]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("image", type=Path)
    parser.add_argument("--base", action="store_true")
    parser.add_argument("--block", type=int, default=65536, help="block size in bytes for --base (default 64 KiB)")
    parser.add_argument("--monitor", action="store_true")
    parser.add_argument("--literals", nargs="+", type=lambda text: int(text, 0))
    parser.add_argument("--from", dest="start", type=lambda text: int(text, 0), default=0)
    parser.add_argument("--to", dest="end", type=lambda text: int(text, 0))
    args = parser.parse_args()
    if not (args.base or args.monitor or args.literals):
        parser.error("choose --base, --monitor or --literals")
    image = args.image.read_bytes()
    end = len(image) if args.end is None else min(args.end, len(image))
    if args.base:
        show_bases(image, args.block)
    if args.monitor:
        show_monitor(image, args.start, end)
    if args.literals:
        show_literals(image, args.literals)
    return 0


if __name__ == "__main__":
    sys.exit(main())
