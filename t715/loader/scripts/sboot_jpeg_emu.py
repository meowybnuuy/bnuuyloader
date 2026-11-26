#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Decode a logo file with S-Boot's own JPEG decoder, in a CPU emulator.

    venv/bin/python -I scripts/sboot_jpeg_emu.py LOGO_FILE OUT.bin [--peek ADDR:LEN ...]

Loads the T715 S-Boot image (dumps/mmcblk0boot0.bin at 0x23DE2000), puts the logo file in
S-Boot's file buffer 0x24200000, and calls the wrapper FUN_23E14694 that S-Boot uses for
'logo.jpg' (it creates the decompressor on its stack, decodes every row into 0x24300000 with
the stride (3*width+3)&~3, and fills the 44-byte image structure). What the decoder writes
past the decode buffer is what this writes: the heap at 0x24F00000 included. OUT.bin gets
[0x24300000, end of the last row + 64). Unmapped accesses (MMIO, if the decoder logs) are
mapped to zero pages on the fly; a read of an UART status register that returns 0 could loop,
so the instruction count is limited.

Ground truth (S-Boot's exception dump of 2026-11-24, image kentry): the bytes at
0x24F0000C came out as 01 00 21 23 where Pillow and djpeg both say 00 00 22 24.
"""
from __future__ import annotations

import argparse
import io
import struct
import sys
import time
from pathlib import Path

from unicorn import UC_ARCH_ARM, UC_MODE_ARM, Uc
from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP
from unicorn.unicorn_const import UC_HOOK_BLOCK, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED

ROOT = Path(__file__).resolve().parent.parent
IMAGE = ROOT / "dumps" / "mmcblk0boot0.bin"
BASE = 0x23DE2000
FILE_BUFFER = 0x24200000
DECODE_BUFFER = 0x24300000
WRAPPER = 0x23E14694
MALLOC = 0x23E07080
STACK_TOP = 0x23EBFF00                 # S-Boot's own stack area, below where its frames live
RETURN = 0x00001000                    # an address nothing maps: returning there ends the run


class SBoot:
    def __init__(self, image: bytes, fast: bool = False) -> None:
        """fast: guard with a block hook instead of an instruction hook (payload rehearsals run tight loops)."""
        self.fast = fast
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc = self.uc
        uc.mem_map(BASE, (len(image) + 0xFFFF) & ~0xFFFF)       # S-Boot's code, data, BSS, its stack and heaps
        uc.mem_write(BASE, image)
        uc.mem_map(FILE_BUFFER, 0x100000)                        # the file buffer
        uc.mem_map(DECODE_BUFFER, 0x1000000)                     # decode buffer, heap, bounce buffer
        self.extra: list[int] = []
        self.instructions = 0
        self.blocks: dict[int, int] = {}
        self.stuck = 0
        self.limit_total, self.limit_block = 5_000_000, 2_000_000   # a loop that runs longer is taken for stuck
        uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._unmapped)
        if fast:
            uc.hook_add(UC_HOOK_BLOCK, self._block)
        else:
            uc.hook_add(UC_HOOK_CODE, self._code)
        self.im = self.call(MALLOC, [0x2C])                      # the 44-byte image structure, as decode_and_draw does
        if not self.im:
            raise SystemExit("S-Boot's malloc returned 0")

    def _unmapped(self, uc, access, address, size, value, data=None):
        page = address & ~0xFFF
        uc.mem_map(page, 0x1000)
        self.extra.append(page)
        return True                                               # the access now goes to a zero page

    def _code(self, uc, address, size, data=None):
        self.instructions += 1
        if self.instructions > 400_000_000:
            uc.emu_stop()

    def _block(self, uc, address, size, data=None):
        self.instructions += 1
        self.blocks[address] = self.blocks.get(address, 0) + 1
        if self.instructions > self.limit_total or self.blocks[address] > self.limit_block:
            self.stuck = address
            uc.emu_stop()

    def call(self, entry: int, args: list[int], result: int = UC_ARM_REG_R0, sp: int = STACK_TOP, until: int = RETURN, lr: int = RETURN):
        uc = self.uc
        for reg, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1), args):
            uc.reg_write(reg, value)
        uc.reg_write(UC_ARM_REG_SP, sp)
        uc.reg_write(UC_ARM_REG_LR, lr)
        self.instructions = 0
        uc.emu_start(entry, until, timeout=0, count=0)
        pc = uc.reg_read(UC_ARM_REG_PC)
        if pc != until:
            raise SystemExit(f"run from {entry:#010x} stopped at pc {pc:#010x} after {self.instructions} instructions")
        return uc.reg_read(result)

    def decode(self, logo: bytes) -> dict:
        uc = self.uc
        uc.mem_write(FILE_BUFFER, bytes(logo) + bytes(max(0, 0x100000 - len(logo))))
        file_struct = 0x24FE0000                                    # {buffer, 0, size} as the logo loader builds it
        uc.mem_write(file_struct, struct.pack("<III", FILE_BUFFER, 0, len(logo)))
        uc.mem_write(self.im, bytes(0x2C))
        uc.mem_write(self.im + 0x20, struct.pack("<I", 0xFFFFFFFF))  # decode_and_draw's own initialisation
        started = time.time()
        self.call(WRAPPER, [file_struct, self.im])
        fields = struct.unpack("<11I", uc.mem_read(self.im, 0x2C))
        width, height = fields[0], fields[1]
        stride = fields[4]
        end = DECODE_BUFFER + stride * height
        memory = bytes(uc.mem_read(DECODE_BUFFER, end + 0x40 - DECODE_BUFFER))
        return {"width": width, "height": height, "stride": stride, "base": fields[10], "fields": fields,
                "memory": memory, "instructions": self.instructions, "seconds": time.time() - started}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("logo", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--peek", action="append", default=[], help="ADDR:LEN, to print bytes at an address (repeatable)")
    args = parser.parse_args()
    logo = args.logo.read_bytes()
    sboot = SBoot(IMAGE.read_bytes())
    result = sboot.decode(logo)
    print(f"S-Boot decoded {args.logo.name} ({len(logo)} bytes) as {result['width']}x{result['height']}, stride {result['stride']}, "
          f"{result['instructions']} instructions in {result['seconds']:.1f} s; image structure fields: "
          + " ".join(f"{f:#x}" for f in result["fields"]))
    args.out.write_bytes(result["memory"])
    print(f"wrote {len(result['memory'])} bytes to {args.out}")
    for peek in args.peek:
        address, length = (int(x, 0) for x in peek.split(":"))
        if DECODE_BUFFER <= address < DECODE_BUFFER + len(result["memory"]):
            data = result["memory"][address - DECODE_BUFFER: address - DECODE_BUFFER + length]
            print(f"  {address:#010x}: {data.hex(' ')}")
        else:
            print(f"  {address:#010x}: not written by the decoder")
    if sboot.extra:
        print(f"unmapped accesses mapped to zero pages: {[hex(p) for p in sboot.extra[:12]]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
