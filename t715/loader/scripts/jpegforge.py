#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Generate baseline JPEGs with chosen DCT coefficients, for the S-Boot logo overflow.

    python3 -I jpegforge.py selftest

The file is written directly, with no encoder lossiness: JFIF header, quantization tables
of 1, the default Huffman tables of libjpeg (taken from a JPEG that Pillow encodes). A
block whose coefficients are all in its first row decodes to eight identical rows, so one
8-pixel group can be solved per component with a grayscale oracle (Pillow's libjpeg) and
hill-climbing; solve_block2d does the same for a full 8x8 block.

Pillow is only used as the oracle for the integer IDCT and the YCbCr->RGB conversion
of libjpeg; both are modelled here for the colour search.
"""

from __future__ import annotations

import io
import math
import struct
import sys
from functools import lru_cache

from PIL import Image

# ---------------------------------------------------------------- libjpeg colour conversion

SCALEBITS, ONE_HALF = 16, 1 << 15


def fix(x: float) -> int:
    return int(x * 65536 + 0.5)


_X = range(-128, 128)
CR_R = [(fix(1.40200) * x + ONE_HALF) >> SCALEBITS for x in _X]
CB_B = [(fix(1.77200) * x + ONE_HALF) >> SCALEBITS for x in _X]
CR_G = [-fix(0.71414) * x for x in _X]
CB_G = [-fix(0.34414) * x + ONE_HALF for x in _X]


def clamp(v: int) -> int:
    return 0 if v < 0 else 255 if v > 255 else v


def ycc_to_rgb(y: int, cb: int, cr: int) -> tuple[int, int, int]:
    """jdcolor.c ycc_rgb_convert with the range limit table."""
    return (clamp(y + CR_R[cr]), clamp(y + ((CB_G[cb] + CR_G[cr]) >> SCALEBITS)), clamp(y + CB_B[cb]))


@lru_cache(maxsize=None)  # the same colour comes back for every black pixel
def find_ycc(rgb: tuple[int, int, int], avoid_edge: bool = True):
    """A (Y, Cb, Cr) triple that libjpeg converts to exactly ``rgb``, or None."""
    r, g, b = rgb
    best = None
    for cr in range(256):
        r0 = CR_R[cr]
        if r == 0:
            ys = range(0, max(0, min(256, -r0 + 1)))
        elif r == 255:
            ys = range(max(0, 255 - r0), 256)
        else:
            y = r - r0
            ys = (y,) if 0 <= y <= 255 else ()
        for cb in range(256):
            g0 = (CB_G[cb] + CR_G[cr]) >> SCALEBITS
            b0 = CB_B[cb]
            for y in ys:
                if clamp(y + g0) == g and clamp(y + b0) == b:
                    edge = min(y + r0, y + g0, y + b0, 255 - (y + r0), 255 - (y + g0), 255 - (y + b0))
                    score = (edge if avoid_edge else 0, -abs(cb - 128) - abs(cr - 128))
                    if best is None or score > best[0]:
                        best = (score, (y, cb, cr))
    return best[1] if best else None


# ---------------------------------------------------------------- JPEG writer


def zigzag_order() -> list[int]:
    """Diagonals of the block; an even diagonal runs from its top to its right end."""
    order = []
    for s in range(15):
        cells = [(x, s - x) for x in range(s + 1) if x < 8 and s - x < 8]
        for x, y in (cells[::-1] if s % 2 else cells):
            order.append(y * 8 + x)
    return order


ZZ = zigzag_order()
assert ZZ[:8] == [0, 1, 8, 16, 9, 2, 3, 10] and len(set(ZZ)) == 64


def _standard_tables() -> tuple[list[bytes], dict[tuple[int, int], dict[int, tuple[int, int]]]]:
    """The Huffman tables libjpeg uses by default, taken from a JPEG Pillow encodes.

    Returns the DHT segments as written (to copy verbatim) and, per (class, id), the code
    and length of each symbol.
    """
    buffer = io.BytesIO()
    Image.new("RGB", (16, 16)).save(buffer, format="JPEG", quality=95)
    data = buffer.getvalue()
    segments, codes, at = [], {}, 2
    while data[at + 1] != 0xDA:
        length = int.from_bytes(data[at + 2:at + 4], "big")
        segment = data[at:at + 2 + length]
        if data[at + 1] == 0xC4:
            segments.append(segment)
            payload, i = segment[4:], 0
            while i < len(payload):
                key = (payload[i] >> 4, payload[i] & 15)
                counts, i = payload[i + 1:i + 17], i + 17
                symbols, i = payload[i:i + sum(counts)], i + sum(counts)
                code, table = 0, {}
                for size in range(1, 17):
                    for symbol in symbols[:counts[size - 1]]:
                        table[symbol] = (code, size)
                        code += 1
                    symbols = symbols[counts[size - 1]:]
                    code <<= 1
                codes[key] = table
        at += 2 + length
    return segments, codes


DHT_SEGMENTS, HUFFMAN = _standard_tables()


class Bits:
    def __init__(self) -> None:
        self.acc = 0
        self.n = 0
        self.out = bytearray()

    def put(self, value: int, length: int) -> None:
        self.acc = (self.acc << length) | (value & ((1 << length) - 1))
        self.n += length
        while self.n >= 8:
            self.n -= 8
            byte = (self.acc >> self.n) & 0xFF
            self.out.append(byte)
            if byte == 0xFF:
                self.out.append(0)

    def flush(self) -> None:
        if self.n:
            self.put((1 << (8 - self.n)) - 1, 8 - self.n)
        self.acc = 0


def magnitude(value: int) -> tuple[int, int]:
    """(size, additional bits) of a JPEG magnitude-coded value.

    The size is the bit length of the absolute value; a negative value sends value-1.
    """
    size = abs(value).bit_length()
    return size, (value - 1 if value < 0 else value) & ((1 << size) - 1)


def _extend(extra: int, size: int) -> int:
    """The decoder's side (HUFF_EXTEND), for the self-test."""
    if size == 0:
        return 0
    return extra if extra >= (1 << (size - 1)) else extra + 1 - (1 << size)


def encode_block(bits: Bits, block: list[int], prev_dc: list[int], component: int, codes=None) -> None:
    """codes: the Huffman tables to use, as HUFFMAN; None keeps the default tables of libjpeg."""
    codes = HUFFMAN if codes is None else codes
    dc, ac = codes[(0, 0 if component == 0 else 1)], codes[(1, 0 if component == 0 else 1)]
    diff = block[0] - prev_dc[component]
    prev_dc[component] = block[0]
    size, extra = magnitude(diff)
    assert size <= 11, "DC difference out of range"
    bits.put(*dc[size])
    if size:
        bits.put(extra, size)
    run = 0
    for k in range(1, 64):
        v = block[ZZ[k]]
        if v == 0:
            run += 1
            continue
        while run > 15:
            bits.put(*ac[0xF0])
            run -= 16
        size, extra = magnitude(v)
        assert size <= 10, "AC coefficient out of range"
        bits.put(*ac[(run << 4) | size])
        bits.put(extra, size)
        run = 0
    if run:
        bits.put(*ac[0x00])


def _segment(marker: int, payload: bytes) -> bytes:
    return bytes((0xFF, marker)) + struct.pack(">H", len(payload) + 2) + payload


def huffman_segment(tables: list[tuple[int, int, list[int]]]) -> bytes:
    payload = bytearray()
    for cls, ident, symbols in tables:
        counts = [0] * 16
        length = 4 if cls == 0 else 8
        counts[length - 1] = len(symbols)
        payload.append((cls << 4) | ident)
        payload += bytes(counts)
        payload += bytes(symbols)
    return _segment(0xC4, bytes(payload))


def encode_jpeg(width: int, height: int, blocks, components: int = 3, tables=None) -> bytes:
    """``blocks[(by, bx)][component]``: 64 coefficients in natural order, or None for black.

    tables: ``(codes, segments)``, Huffman tables built for this file (scripts/logo_art.py) instead
    of the default tables of libjpeg: S-Boot's decoder reads the tables of the file (checked in the
    emulator, 2026-11-25). None writes the same bytes as ever."""
    mcus_x, mcus_y = (width + 7) // 8, (height + 7) // 8
    codes, segments = (HUFFMAN, DHT_SEGMENTS) if tables is None else tables
    # SOI, JFIF 1.01 without thumbnail, two quantization tables of 1
    out = bytearray(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
    qt = bytes((1,) * 64)
    out += _segment(0xDB, b"\x00" + qt) + _segment(0xDB, b"\x01" + qt)
    sof = bytearray((8,)) + struct.pack(">HH", height, width) + bytes((components,))
    for ident in range(1, components + 1):
        sof += bytes((ident, 0x11, 0 if ident == 1 else 1))
    out += _segment(0xC0, bytes(sof))
    out += b"".join(segments)  # the default tables of libjpeg, as Pillow writes them, or the file's own
    sos = bytearray((components,))
    for ident in range(1, components + 1):
        sos += bytes((ident, 0x00 if ident == 1 else 0x11))
    sos += bytes((0, 63, 0))
    out += _segment(0xDA, bytes(sos))
    bits = Bits()
    prev_dc = [0] * components
    # black: luma 0 (DC -1024 gives the sample 0), chroma 128 (DC 0)
    blacks = [[-1024] + [0] * 63, [0] * 64]
    for by in range(mcus_y):
        for bx in range(mcus_x):
            for component in range(components):
                block = (blocks.get((by, bx)) or [None] * components)[component]
                encode_block(bits, blacks[min(component, 1)] if block is None else block, prev_dc, component, codes)
    bits.flush()
    out += bits.out + b"\xff\xd9"
    return bytes(out)


# ---------------------------------------------------------------- oracle and block solving


@lru_cache(maxsize=None)
def oracle_gray(coefs: tuple[int, ...]) -> tuple[int, ...]:
    """Decoded samples of the first row of a block whose coefficients are all in row 0."""
    block = [0] * 64
    for u, c in enumerate(coefs):
        block[u] = c
    data = encode_jpeg(8, 8, {(0, 0): [block]}, components=1)
    with Image.open(io.BytesIO(data)) as image:
        return tuple(image.getpixel((x, 0)) for x in range(8))


_COS = [[math.cos((2 * x + 1) * u * math.pi / 16) for x in range(8)] for u in range(8)]


def _initial(samples: tuple[int, ...]) -> tuple[int, ...]:
    v = [s - 128 for s in samples]
    return tuple(int(round(math.sqrt(2) * (1 if u else 1 / math.sqrt(2)) * sum(v[x] * _COS[u][x] for x in range(8))))
                 for u in range(8))


def solve_block(samples: tuple[int, ...], rounds: int = 200) -> tuple[int, ...] | None:
    """Coefficients of row 0 that decode to exactly ``samples`` (eight values)."""
    target = samples
    coefs = _initial(target)
    cache: dict[tuple[int, ...], tuple[int, ...]] = {}

    def decoded(c):
        if c not in cache:
            cache[c] = oracle_gray(c)
        return cache[c]

    def cost(c):
        d = decoded(c)
        return (sum(abs(a - b) for a, b in zip(d, target)), sum((a - b) ** 2 for a, b in zip(d, target)))

    best = cost(coefs)
    for _ in range(rounds):
        if best[0] == 0:
            return coefs
        improved = False
        for u in range(8):
            for delta in (1, -1):
                trial = list(coefs)
                trial[u] += delta
                trial = tuple(trial)
                if trial[0] < -2048 or trial[0] > 2047 or abs(trial[u]) > 1023:
                    continue
                c = cost(trial)
                if c < best:
                    best, coefs, improved = c, trial, True
        if not improved:
            return None
    return coefs if best[0] == 0 else None


def rgb_of(block_y, block_cb, block_cr) -> tuple[tuple[int, int, int], ...]:
    """The eight RGB pixels decoded from three solved component blocks."""
    data = encode_jpeg(8, 8, {(0, 0): [list(block_y), list(block_cb), list(block_cr)]})
    with Image.open(io.BytesIO(data)) as image:
        image.load()
        return tuple(image.getpixel((x, 0)) for x in range(8))


@lru_cache(maxsize=None)
def oracle_block(coefs: tuple[int, ...]) -> tuple[int, ...]:
    """The 64 decoded samples (row-major) of a grayscale block with these coefficients."""
    data = encode_jpeg(8, 8, {(0, 0): [list(coefs)]}, components=1)
    with Image.open(io.BytesIO(data)) as image:
        return tuple(image.getdata())


def _initial2d(samples: tuple[int, ...]) -> tuple[int, ...]:
    """Forward DCT of the centered samples: a first guess for solve_block2d."""
    f = [s - 128 for s in samples]
    out = []
    for v in range(8):
        for u in range(8):
            total = sum(f[y * 8 + x] * _COS[u][x] * _COS[v][y] for y in range(8) for x in range(8))
            out.append(int(round(0.25 * (1 if u else 1 / math.sqrt(2)) * (1 if v else 1 / math.sqrt(2)) * total)))
    return tuple(out)


def solve_block2d(samples: tuple[int, ...], rounds: int = 400) -> tuple[int, ...] | None:
    """Coefficients (natural order) that decode to exactly these 64 samples."""
    assert len(samples) == 64
    coefs = _initial2d(samples)
    cache: dict[tuple[int, ...], tuple[int, ...]] = {}

    def cost(c):
        if c not in cache:
            cache[c] = oracle_block(c)
        d = cache[c]
        return (sum(abs(a - b) for a, b in zip(d, samples)), sum((a - b) ** 2 for a, b in zip(d, samples)))

    best = cost(coefs)
    for _ in range(rounds):
        if best[0] == 0:
            return coefs
        improved = False
        for k in range(64):
            for delta in (1, -1):
                trial = list(coefs)
                trial[k] += delta
                trial = tuple(trial)
                if abs(trial[0]) > 2047 or any(abs(c) > 1023 for c in trial[1:]):
                    continue
                c = cost(trial)
                if c < best:
                    best, coefs, improved = c, trial, True
        if not improved:
            return None
    return coefs if best[0] == 0 else None


# ---------------------------------------------------------------- self-test


def selftest() -> int:
    failures = 0
    bad = [v for v in range(-2047, 2048) if _extend(*magnitude(v)[::-1]) != v]
    print(f"magnitude coding of every value in [-2047, 2047]: {'OK' if not bad else 'FAIL ' + str(bad[:8])}")
    failures += bool(bad)
    print("oracle, constant block:", oracle_gray((8 * 77,) + (0,) * 7))
    for samples in ((0,) * 8, (255,) * 8, (12, 200, 3, 99, 128, 250, 17, 64), (255, 0, 255, 0, 128, 7, 200, 33)):
        coefs = solve_block(samples)
        got = oracle_gray(coefs) if coefs else None
        print(f"solve {samples} -> {coefs} -> {got}", "OK" if got == samples else "FAIL")
        failures += got != samples
    triples = [(0, 0, 0), (255, 255, 255), (0x24, 0x24, 0x21), (0, 0, 0x24), (0xD4, 0x36, 0x0C), (0x23, 0, 0),
               (0xEC, 0x23, 0), (44, 0, 236), (200, 10, 90), (1, 2, 3), (0x58, 0x58, 0x58)]
    for rgb in triples:
        ycc = find_ycc(rgb)
        ok = ycc is not None and ycc_to_rgb(*ycc) == rgb
        print(f"colour {tuple(hex(c) for c in rgb)} -> {ycc}", "OK" if ok else "UNREACHABLE")
    return failures


if __name__ == "__main__":
    sys.exit(bool(selftest()))
