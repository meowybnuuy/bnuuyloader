#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Disassemble ARM32 words of a Samsung bootloader image at given file offsets.

    python3 -I arm32_peek.py IMAGE BASE_ADDRESS OFFSET [COUNT] [OFFSET [COUNT] ...]

BASE_ADDRESS is the runtime address of file offset 0 of the image the offsets refer to;
offsets may be file offsets (0x...) or addresses (0x23...); an address is recognised when
it is not smaller than BASE_ADDRESS and falls inside the image.

Read-only.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_sboot import disasm_arm  # noqa: E402  (our own module, same directory)


def disasm_block_transfer(word: int) -> str:
    """stm/ldm with the register list, which scan_sboot's decoder leaves as ???."""
    if (word >> 25) & 7 != 4:
        return ""
    cond = "eq ne cs cc mi pl vs vc hi ls ge lt gt le al nv".split()[word >> 28]
    suffix = "" if cond == "al" else cond
    pre, up, write, load = (bool(word & (1 << bit)) for bit in (24, 23, 21, 20))
    name = "ldm" if load else "stm"
    if not pre and up:
        mode = "da"
    elif not pre and not up:
        mode = "ia" if not load else "db"  # ldmia with no write-back is the usual pop form
        mode = "ia"
    elif pre and up:
        mode = "ib"
    else:
        mode = "db"
    if word & (1 << 22) and not (word & (1 << 15)):
        name += "u" if up else "d"  # user-bank registers: treat as normal here
    base = "sp" if (word >> 16) & 0xF == 13 else f"r{(word >> 16) & 0xF}"
    regs = ",".join(("lr" if i == 14 else "pc" if i == 15 else f"r{i}") for i in range(16) if word >> i & 1)
    short = {"stmdb": "push", "ldmia": "pop"}.get(name + mode)
    text = f"{name}{mode}{suffix} {base}{'!' if write else ''}, {{{regs}}}"
    return f"{short}{suffix} {{{regs}}}   /* {text} */" if short and base == "sp" and write else text


def main() -> int:
    if len(sys.argv) < 5:
        print(__doc__.splitlines()[0])
        return 2
    image = Path(sys.argv[1]).read_bytes()
    base = int(sys.argv[2], 0)
    args = sys.argv[3:]
    for offset_arg, count_arg in zip(args[::2], args[1::2]):
        value = int(offset_arg, 0)
        offset = value - base if base <= value < base + len(image) else value
        count = int(count_arg, 0)
        print(f"--- file offset 0x{offset:x} (address 0x{base + offset:08x}), {count} instructions")
        for i in range(count):
            at = offset + 4 * i
            (word,) = struct.unpack_from("<I", image, at)
            # the decoder indexes the image with the "address" it is given: pass the file offset
            text = disasm_arm(word, at, image)
            if text.startswith("ldr") and "=0x" in text:
                text = text.replace("=0x", f"(0x{base + at:08x}) =0x")
            if text == "???":
                text = disasm_block_transfer(word) or text
            print(f"  0x{base + at:08x}: {word:08x}  {text}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
