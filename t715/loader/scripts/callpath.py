#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Every static call path from a function to a target, with the stack depth.

    venv/bin/python -I scripts/callpath.py ROOT [ROOT ...] [--to 0x23e071d8] [--sp 0x23ec00b8]

ROOT is a runtime address. Functions are what `bl` instructions target (plus the roots); a call
site belongs to the nearest function start below it. Each function's frame is what it takes off
the stack before its first call (push, `sub sp`, `str rX, [sp, #-N]!`). For a path to the target
the tool prints the stack pointer at the target's entry, starting from --sp at the root's entry.
Calls through registers cannot be followed: paths stop there.
"""

from __future__ import annotations

import argparse
import bisect
import struct
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs

BASE = 0x23DE2000
IMAGE = Path(__file__).resolve().parent.parent / "dumps" / "mmcblk0boot0.bin"
NAMES = {0x23E07080: "malloc", 0x23E071D8: "malloc_large", 0x23E071FC: "free", 0x23E06FA4: "after_hook",
         0x23E07BF8: "scr_draw_image", 0x23E05820: "printf", 0x23E042A0: "memset", 0x23E03C40: "strcmp",
         0x23E03C70: "strncmp", 0x23E03CF8: "strlen", 0x23E0A4BC: "load_file"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("roots", nargs="+", type=lambda t: int(t, 0))
    parser.add_argument("--to", type=lambda t: int(t, 0), default=0x23E071D8)
    parser.add_argument("--sp", type=lambda t: int(t, 0), default=0x23EC00B8, help="stack pointer at the roots' entry")
    parser.add_argument("--max-depth", type=int, default=16)
    parser.add_argument("--all", action="store_true", help="do not stop at the first hit of a branch")
    args = parser.parse_args()
    img = IMAGE.read_bytes()
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)

    sites: dict[int, int] = {}
    starts = set(args.roots) | {args.to}
    for off in range(0, len(img) - 3, 4):
        w = struct.unpack_from("<I", img, off)[0]
        if w & 0x0F000000 == 0x0B000000:
            imm = w & 0xFFFFFF
            if imm & 0x800000:
                imm -= 1 << 24
            t = BASE + off + 8 + imm * 4
            if BASE <= t < BASE + len(img):
                sites[BASE + off] = t
                starts.add(t)
    for off in range(0, len(img) - 3, 4):                 # a push of several registers with lr opens a function too
        w = struct.unpack_from("<I", img, off)[0]
        if w & 0xFFFF0000 == 0xE92D0000 and w & 0x100:
            starts.add(BASE + off)
    starts = sorted(starts)

    def owner(site):
        i = bisect.bisect_right(starts, site) - 1
        return starts[i]

    cache: dict[int, int] = {}

    def frame(function):
        """Bytes the function takes off the stack before its first call."""
        if function in cache:
            return cache[function]
        depth = 0
        for ins in md.disasm(img[function - BASE:function - BASE + 0x100], function):
            text = ins.op_str
            if ins.mnemonic == "push":
                depth += 4 * len(text.strip("{} ").split(","))
            elif ins.mnemonic == "sub" and text.startswith("sp, sp, #"):
                depth += int(text.rsplit("#", 1)[-1], 0)
            elif ins.mnemonic.startswith("str") and "[sp, #-" in text and "]!" in text:
                depth += int(text.split("#-")[1].rstrip("]!"), 0)
            elif ins.mnemonic in ("bl", "blx"):
                break
            elif (ins.mnemonic == "pop" and "pc" in text) or (ins.mnemonic == "bx" and text == "lr"):
                break
        cache[function] = depth
        return depth

    edges: dict[int, list[tuple[int, int]]] = {}
    for site, target in sorted(sites.items()):
        edges.setdefault(owner(site), []).append((site, target))

    found = [0]
    hits: list[tuple[int, tuple]] = []

    def walk(function, sp, path, depth):
        if depth > args.max_depth or len(path) > 40 or function in path[:-1]:
            return
        new_sp = sp - frame(function)
        for site, target in edges.get(function, ()):
            if target == args.to:
                found[0] += 1
                hits.append((new_sp, tuple(path + [target])))
                if not args.all:
                    return
            else:
                walk(target, new_sp, path + [target], depth + 1)

    for root in args.roots:
        hits.clear()
        found[0] = 0
        walk(root, args.sp, [root], 0)
        print(f"--- from {root:08x} {NAMES.get(root, '')}, stack pointer at its entry {args.sp:#010x}: "
              f"{found[0]} static path(s) to {args.to:08x} {NAMES.get(args.to, '')}")
        for sp, path in sorted(hits, key=lambda h: (-h[0], len(h[1]))):
            print(f"    sp {sp:#010x} at the target's entry (saved return address {sp - 4:#010x}):")
            print("        " + " > ".join(f"{f:08x}{('(' + NAMES[f] + ')') if f in NAMES else ''}[{frame(f):#x}]" for f in path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
