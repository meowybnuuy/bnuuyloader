#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Disassemble a runtime range of the T715 S-Boot, with literal values and known names.

    venv/bin/python -I scripts/dis.py FROM..TO [extra:name ...]      runtime addresses (0x23DE2000 + file offset)
"""
import struct
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs

BASE = 0x23DE2000
IMAGE = Path(__file__).resolve().parent.parent / "dumps" / "mmcblk0boot0.bin"
NAMES = {0x23E07080: "malloc", 0x23E071D8: "malloc_large", 0x23E071FC: "free", 0x23E07B74: "load_logo",
         0x23E07BF8: "scr_draw_image", 0x23E14694: "jpeg_wrapper", 0x23E148D8: "decode_and_draw",
         0x23EC1048: "heap_head"}


def main() -> int:
    img = IMAGE.read_bytes()
    for extra in sys.argv[2:]:
        k, v = extra.split(":", 1)
        NAMES[int(k, 0)] = v
    start, end = (int(a, 0) for a in sys.argv[1].split(".."))
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    names = NAMES
    addr = start
    while addr < end:
        ins_list = list(md.disasm(img[addr - BASE:addr - BASE + 4], addr, 1))
        if not ins_list:                           # a literal-pool word: show it, go on
            (val,) = struct.unpack_from("<I", img, addr - BASE)
            print(f"{addr:08x}  .word     {val:08x}" + (f"  ; {names[val]}" if val in names else ""))
            addr += 4
            continue
        ins = ins_list[0]
        note = ""
        if ins.mnemonic.startswith("ldr") and "[pc" in ins.op_str:
            imm = int(ins.op_str.rsplit("#", 1)[-1].rstrip("]"), 0)
            lit = ((ins.address + 8) & ~3) + imm
            (val,) = struct.unpack_from("<I", img, lit - BASE)
            note = f"  ; [{lit:08x}] = {val:08x}" + (f" {names[val]}" if val in names else "")
        if ins.mnemonic in ("bl", "b", "blx", "bw"):
            try:
                t = int(ins.op_str.split()[-1], 0)
            except ValueError:
                t = None
            if t in names:
                note += f"  ; {names[t]}"
        print(f"{addr:08x}  {ins.mnemonic:8s} {ins.op_str}{note}")
        addr += 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
