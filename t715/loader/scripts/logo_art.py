#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""A picture in the wide logo, with Huffman tables built for the file.

    venv/bin/python -I scripts/logo_art.py PICTURE --trap out/calibrated_block.json --out out/logo.jpg
                     [--luma-floor N] [--chroma-floor N] [--black N] [--order R,G,B] [--tables PLAN]
    venv/bin/python -I scripts/logo_art.py PICTURE --measure          the size of each plan, nothing written

The wide logo (build_ffree.py --geometry wide) is 2048 x 2049 pixels. S-Boot draws it from the
top left corner, a pixel at a time, with nothing cut off (decode_and_draw, read on 2026-11-25): the
1536 x 2048 the panel shows are its first 1536 columns, the other 512 columns fall into the next
row each time and are drawn over. The last row, 2048, starts at 0x24F00000: its first block is the
trapped one. So the picture goes in the first 2048 rows and the first 1536 columns; everything
else is black.

The probe for the screen is the same picture in a logo of 2048 rows (build_ffree.py --no-trap): its
last row ends at 0x24F00000, so nothing is written past the decode buffer and the heap is left as
it is. A logo of 2049 rows whose trapped block is black would write 16 zero bytes over the heap
head instead, and S-Boot's malloc would then follow a null pointer: never that.

The room is what it is: the logo file ends at the false free block (file offset 0x20000), and the
black alone takes 115 Ko with the tables of libjpeg. Two things give room back:

  * the tables. S-Boot's decoder reads the code lengths of the file (DHT) and takes the symbols
    in the standard order whatever the file lists (both measured in the emulator, 2026-11-25:
    scripts/logo_art.py is written for that). The symbols keep that order here, and their lengths
    are chosen for a logo that is black almost everywhere: category 0 of DC and EOB get short
    codes. The file stays a JPEG any decoder reads.
  * the picture. Its near-black background is made truly black (--black): a background that
    bristles between 0 and 5 costs more than the figure itself. Then the coefficients below
    --luma-floor and --chroma-floor are left out: that is the figure's simplification, a light
    one at 2 and 1, a plain one at 3 and 2.

The picture is scaled to the panel's height and centred in the 1536 columns. --order says which
of its channels the file's R, G and B carry; the default is the right one on this tablet.

The loader adds a mark of its own: its ARM32 code, once the forged heap has let it in, writes the
16 bytes of a block for S-Boot's later requests at 0x67B00000 (scripts/split_source.py, `go:`),
which is row 1877 of the screen, pixel 512: on the picture, one red pixel and three nearly black
ones below the figure, until the kernel's splash. Measured in the emulator on 2026-11-25: those
bytes are all it writes into the screen.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent))
import jpegforge as jf  # noqa: E402

WIDTH, HEIGHT = 2048, 2049
PROBE_HEIGHT = VISIBLE_HEIGHT = 2048                  # the probe: no last row, nothing reaches the heap
VISIBLE_WIDTH = 1536
ROWS, COLS = (HEIGHT + 7) // 8, (WIDTH + 7) // 8
BLOCK_ROW, BLOCK_COL = ROWS - 1, 0                      # the trapped block: the last row, its first block
assert (HEIGHT - 1) * ((WIDTH * 3 + 3) & ~3) == 0xC00000
FILE_LIMIT = 0x20000                                    # the JPEG must end before the false free block

C = np.array([(1 / np.sqrt(2) if u == 0 else 1) * np.cos((2 * x + 1) * u * np.pi / 16) / 2
              for u in range(8) for x in range(8)]).reshape(8, 8)
ZZ = np.array(jf.zigzag_order())
KEYS = ((0, 0), (1, 0), (0, 1), (1, 1))                 # DC luma, AC luma, DC chroma, AC chroma

# The symbols of the four standard tables, in the standard order.
STANDARD = {key: sorted(jf.HUFFMAN[key], key=lambda s, key=key: jf.HUFFMAN[key][s]) for key in KEYS}
STANDARD_LENGTH = {key: {s: jf.HUFFMAN[key][s][1] for s in STANDARD[key]} for key in KEYS}


# ---------------------------------------------------------------- the tables


def leading(key: tuple[int, int], given: list[int]) -> dict[int, int]:
    """Lengths for a table: the first symbols of the standard order get those of ``given``, and
    every other symbol keeps the standard table's shape, as deep as it must be to fit."""
    order = STANDARD[key]
    lengths = dict(zip(order, given))
    rest = order[len(given):]
    room = 1.0 - sum(2.0 ** -n for n in given)
    shift = 0
    while sum(2.0 ** -min(16, STANDARD_LENGTH[key][s] + shift) for s in rest) > room + 1e-9:
        shift += 1
    for s in rest:
        lengths[s] = max(given[-1], min(16, STANDARD_LENGTH[key][s] + shift))
    return lengths


def ladder(key: tuple[int, int]) -> dict[int, int]:
    """The first symbol of the standard order, category 0, gets one bit; then one more bit each."""
    return dict(zip(STANDARD[key], range(1, len(STANDARD[key]) + 1)))


STANDARD_LENGTHS = {key: dict(STANDARD_LENGTH[key]) for key in KEYS}
PLANS = {                                              # what the black of the logo costs, by block:
    "libjpeg": STANDARD_LENGTHS,                       # luma 6 bits, chroma 4: 14 bits an MCU
    "dc":       {**STANDARD_LENGTHS, (0, 0): ladder((0, 0)), (0, 1): ladder((0, 1))},          # 5, 3: 11
    "eob":      {**STANDARD_LENGTHS, (0, 0): ladder((0, 0)), (0, 1): ladder((0, 1)),           # 5, 2: 9
                 (1, 1): leading((1, 1), [1])},
    "all":      {**STANDARD_LENGTHS, (0, 0): ladder((0, 0)), (0, 1): ladder((0, 1)),            # 4, 2: 8
                 (1, 0): leading((1, 0), [2, 2, 2, 3]), (1, 1): leading((1, 1), [1])},
}


def tables_for(lengths: dict) -> tuple[dict, list[bytes]]:
    """(codes, DHT segments) for four tables whose symbols are in the standard order."""
    payload, codes = bytearray(), {}
    for key in KEYS:
        order = STANDARD[key]
        given = [lengths[key][s] for s in order]
        assert given == sorted(given), f"the lengths of table {key} must not decrease along the standard order"
        assert 1 <= given[0] and given[-1] <= 16, f"table {key}: a code of {given[-1]} bits"
        assert sum(2.0 ** -n for n in given) <= 1 + 1e-9, f"table {key}: more codes than the code space"
        bits = [0] * 16
        for n in given:
            bits[n - 1] += 1
        payload += bytes(((0x10 if key[0] else 0) | key[1],)) + bytes(bits) + bytes(order)
        code, table = 0, {}
        for n in range(1, 17):
            for s in order:
                if lengths[key][s] == n:
                    table[s] = (code, n)
                    code += 1
            code <<= 1
        codes[key] = table
    return codes, [jf._segment(0xC4, bytes(payload))]


# ---------------------------------------------------------------- the picture


def compose(path: Path, black: int = 14, order=(0, 1, 2), scale: float = 1.0) -> np.ndarray:
    """The picture on the panel's 1536 x 2048, float RGB 0..255: scaled to the height (times
    ``scale``), centred, on black. ``order``: the picture's channels that the file's R, G and B
    carry. S-Boot's writer stores a decoded pixel (r, g, b) as the bytes r, b, g of a 32 bits
    one, and the panel shows the decoded pixel as it is (read on the tablet on 2026-11-25: with
    a file ordered 2,0,1, the picture's pink came out green), so the default, 0,1,2, is the
    right one; the others are kept for a panel that would differ."""
    with Image.open(path) as source:
        img = source.convert("RGB")
    height = round(VISIBLE_HEIGHT * scale)
    new_width = round(img.width * height / img.height)
    if height > VISIBLE_HEIGHT or new_width > VISIBLE_WIDTH:
        raise SystemExit(f"{path.name}: too large for the panel once scaled ({new_width} x {height})")
    img = img.resize((new_width, height), Image.LANCZOS)
    rgb = np.zeros((VISIBLE_HEIGHT, VISIBLE_WIDTH, 3), dtype=np.float64)
    x0, y0 = (VISIBLE_WIDTH - new_width) // 2, (VISIBLE_HEIGHT - height) // 2
    rgb[y0:y0 + height, x0:x0 + new_width] = np.asarray(img, dtype=np.float64)[:, :, list(order)]
    near_black = rgb.max(axis=2) <= black
    rgb[near_black] = 0.0                                    # the background, made truly black
    return rgb


def coefficients(rgb: np.ndarray, luma_floor: int = 0, chroma_floor: int = 0) -> np.ndarray:
    """YCbCr, the 8 x 8 DCT, table 1: int64 [block row, block col, component, 64], natural order,
    over the whole logo; the coefficients below the floors are left out."""
    r, g, b = rgb[..., 0], rgb[..., 1], rgb[..., 2]
    planes = np.zeros((3, ROWS * 8, COLS * 8))
    planes[0, :VISIBLE_HEIGHT, :VISIBLE_WIDTH] = 0.299 * r + 0.587 * g + 0.114 * b - 128.0
    planes[1, :VISIBLE_HEIGHT, :VISIBLE_WIDTH] = -0.168736 * r - 0.331264 * g + 0.5 * b
    planes[2, :VISIBLE_HEIGHT, :VISIBLE_WIDTH] = 0.5 * r - 0.418688 * g - 0.081312 * b
    tiles = planes.reshape(3, ROWS, 8, COLS, 8).transpose(1, 3, 0, 2, 4)     # row, col, component, x, y
    coef = np.rint(C @ tiles @ C.T).astype(np.int64).reshape(ROWS, COLS, 3, 64)
    floors = np.array([luma_floor, chroma_floor, chroma_floor]).reshape(1, 1, 3, 1)
    drop = np.abs(coef) < floors
    drop[..., 0] = False                                     # never the DC
    coef[drop] = 0
    coef[:, VISIBLE_WIDTH // 8:] = 0                         # nothing past the panel's columns
    coef[VISIBLE_HEIGHT // 8:] = 0                           # nor in the last row: the loader's
    return coef


def count_symbols(coef: np.ndarray) -> dict:
    """How many of each Huffman symbol the coding of ``coef`` needs, per table."""
    zigzag = coef[..., ZZ]
    freq = {key: np.zeros(256, dtype=np.int64) for key in KEYS}
    dc = zigzag[..., 0]
    diff = np.empty_like(dc)
    diff[:, 1:] = dc[:, 1:] - dc[:, :-1]
    diff[1:, 0] = dc[1:, 0] - dc[:-1, -1]
    diff[0, 0] = dc[0, 0]                                 # the coder's predictor starts at 0
    sizes = np.array([int(v).bit_length() for v in range(-4096, 4097)])
    for c in range(3):
        size = sizes[diff[..., c] + 4096]
        freq[(0, 0 if c == 0 else 1)] += np.bincount(size.ravel(), minlength=256)
    nonzero = zigzag[..., 1:] != 0
    last = np.zeros((ROWS, COLS, 3), dtype=np.int64)
    for k in range(1, 64):
        here = nonzero[..., k - 1]
        run = k - last - 1
        size = sizes[zigzag[..., k] + 4096]
        for c in range(3):
            key = (1, 0 if c == 0 else 1)
            m = here[..., c]
            freq[key][0xF0] += int((run[..., c][m] // 16).sum())
            left = run[..., c][m] - 16 * (run[..., c][m] // 16)
            freq[key] += np.bincount(((left << 4) | size[..., c][m]).ravel(), minlength=256)
        last[here] = k
    for c in range(3):
        freq[(1, 0 if c == 0 else 1)][0x00] += int((last[..., c] < 63).sum())
    return freq


def cost(coef: np.ndarray, plan: str) -> tuple[int, int]:
    """(bits of codes, bits of the values that follow them) for the coding of ``coef``."""
    freq = count_symbols(coef)
    bits = extra = 0
    for key in KEYS:
        lengths = PLANS[plan][key]
        for symbol, n in enumerate(freq[key]):
            if n:
                bits += int(n) * lengths[symbol]
                extra += int(n) * (symbol & 15 if key[0] else symbol)   # a size for AC, a category for DC
    return bits, extra


def size_of(coef: np.ndarray, plan: str) -> int:
    """The bytes of entropy-coded data, to a few bytes: the stuffing of the 0xFF bytes is not counted."""
    bits, extra = cost(coef, plan)
    return (bits + extra + 7) // 8


def build_jpeg(coef: np.ndarray, trap: list | None, plan: str, height: int = HEIGHT) -> bytes:
    """The JPEG of the wide logo: the picture's blocks, black everywhere else, and the trapped block
    of the last row. ``trap`` None and ``height`` PROBE_HEIGHT: the probe, whose rows stop before
    the heap."""
    assert (trap is None) == (height == PROBE_HEIGHT), "only the probe has no trapped block, and it has no last row"
    codes, segments = tables_for(PLANS[plan])
    blocks = {}
    content = coef.reshape(ROWS, COLS, 3, 64).any(axis=(2, 3))
    for by, bx in zip(*np.nonzero(content)):
        blocks[(int(by), int(bx))] = [[int(v) for v in coef[by, bx, c]] for c in range(3)]
    if trap is not None:
        blocks[(BLOCK_ROW, BLOCK_COL)] = [list(c) for c in trap]
    return jf.encode_jpeg(WIDTH, height, blocks, tables=(codes, segments))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("picture", type=Path)
    parser.add_argument("--trap", type=Path, help="out/calibrated_block.json: the block that forges the heap head")
    parser.add_argument("--out", type=Path, help="the JPEG of the logo")
    parser.add_argument("--measure", action="store_true", help="print the size of each plan and stop")
    parser.add_argument("--tables", default="all", choices=sorted(PLANS), help="the code lengths (default: all, as build_ffree.py)")
    parser.add_argument("--luma-floor", type=int, default=3, help="the defaults are build_ffree.py's")
    parser.add_argument("--chroma-floor", type=int, default=2)
    parser.add_argument("--black", type=int, default=14, help="pixels whose brightest channel is at most this are black")
    parser.add_argument("--scale", type=float, default=1.0, help="the picture's height as a share of the panel's")
    parser.add_argument("--order", default="0,1,2",
                        help="the picture's channels the file's R, G, B carry (default: its own, the right ones on this tablet: "
                             "the panel shows a decoded pixel as it is)")
    args = parser.parse_args()
    import json
    order = tuple(int(v) for v in args.order.split(","))
    coef = coefficients(compose(args.picture, args.black, order, args.scale), args.luma_floor, args.chroma_floor)
    if args.measure:
        empty = coefficients(np.zeros((VISIBLE_HEIGHT, VISIBLE_WIDTH, 3)))
        for plan in sorted(PLANS):
            black, whole = size_of(empty, plan), size_of(coef, plan)
            print(f"tables {plan:8}: black {black:7,} bytes, with the picture {whole:7,} bytes "
                  f"(+{whole - black:6,}); the limit is {FILE_LIMIT:,}")
        return 0
    if not (args.trap and args.out):
        parser.error("--trap and --out, or --measure")
    trap = json.loads(args.trap.read_text())
    jpeg = build_jpeg(coef, trap, args.tables)
    print(f"{args.out.name}: {WIDTH} x {HEIGHT}, {len(jpeg):,} bytes with the tables {args.tables} "
          f"(luma floor {args.luma_floor}, chroma floor {args.chroma_floor}); the limit is {FILE_LIMIT:,}")
    if len(jpeg) >= FILE_LIMIT:
        raise SystemExit("the JPEG reaches the false free block: simplify more (--luma-floor, --chroma-floor) or change --tables")
    args.out.write_bytes(jpeg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
