#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Calibrate forged bytes against S-Boot's own JPEG decoder (emulated), not against libjpeg-turbo.

    venv/bin/python -I scripts/sboot_calib.py diag
    venv/bin/python -I scripts/sboot_calib.py calibrate

S-Boot's decoder rounds differently from libjpeg-turbo: on the device, bytes meant as
`04 6a f5 fe 03 00 00 00 00 00 00 00 00 00 22 24` came out as
`0f 69 ef f9 05 05 06 00 00 00 00 01 01 00 21 23` (2026-11-24, confirmed by the emulator).
So an image is built with the usual exact model, then its block is corrected in a closed loop
against the emulator until S-Boot's decoder gives the wanted bytes.

The target: the heap head's 16 bytes at 0x24F00000 with an image of width 310, stride 932,
13501 rows: the head starts at row 13500, byte 912 = pixel 304, so it covers whole pixels:
  pixel 304 (b0 b1 b2)   size, low bytes: free
  pixel 305 (b3 b4 b5)   size high byte (free), free byte (0 = busy), prev byte 0 (free)
  pixel 306 (b6 b7 b8)   prev, bytes 1..3: free
  pixel 307 (b9 b10 b11)  prev byte 3 (free), next byte 0 (free), next byte 1 (free)
  pixel 308 (b12 b13 b14) next byte 0 (free), next byte 1 (free), next byte 2 = F's byte 2 (0x20..0x2f)
  pixel 309 (b15 b16 b17) next byte 3 = 0x24, then three spill bytes (free)
  pixels 310, 311        beyond the image's width: never decoded

The same block serves the logo of a whole screen (build_ffree.py --geometry wide: width 2048,
stride 6144, 2049 rows; the head starts at row 2048, byte 0, the first pixel of the last row, so
the block is the first of its row). The block is calibrated on an image of its own, where the
decoder's predictor starts at 0, and in both logos the block coded before it is black, so the same
coefficients give the same bytes: checked on the whole logo in the emulator (scripts/preview_logo.py
--decoder sboot gives the decoded rows, and the last one holds the head).
"""
from __future__ import annotations

import io
import itertools
import struct
import sys
from pathlib import Path

from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent))
import jpegforge as jf  # noqa: E402
import sboot_jpeg_emu as e  # noqa: E402

BLACK = (0, 128, 128)
WIDTH, ROWS = 310, 13501
STRIDE = (WIDTH * 3 + 3) & ~3
HEADER_ROW, HEADER_BYTE = ROWS - 1, 912
HEADER_PIXEL = HEADER_BYTE // 3
assert (HEADER_ROW * STRIDE + HEADER_BYTE) == 0x24F00000 - e.DECODE_BUFFER


def block_coefficients(pixels):
    """Three coefficient blocks for a band of eight identical rows of eight (Y, Cb, Cr) pixels."""
    out = []
    for c in range(3):
        samples = tuple(px[c] for _ in range(8) for px in pixels)
        coefs = jf.solve_block2d(samples)
        if coefs is None:
            raise ValueError(f"component {c}: no exact coefficients for these samples")
        out.append(list(coefs))
    return out


class Oracle:
    """S-Boot's decoder on a 64x8 image: the block under test is the second one."""

    def __init__(self) -> None:
        self.sboot = e.SBoot(e.IMAGE.read_bytes())
        self.runs = 0

    def row(self, pixels) -> bytes:
        blocks = {}
        empty = block_coefficients([BLACK] * 8)
        for bx in range(8):
            blocks[(0, bx)] = block_coefficients(pixels) if bx == 1 else empty
        logo = jf.encode_jpeg(64, 8, blocks)
        result = self.sboot.decode(logo)
        self.runs += 1
        assert result["stride"] == 64 * 3, result["stride"]
        return result["memory"][:64 * 3]

    def turbo(self, pixels) -> bytes:
        """The same image decoded by Pillow, for comparison."""
        blocks = {}
        empty = block_coefficients([BLACK] * 8)
        for bx in range(8):
            blocks[(0, bx)] = block_coefficients(pixels) if bx == 1 else empty
        logo = jf.encode_jpeg(64, 8, blocks)
        with Image.open(io.BytesIO(logo)) as image:
            image.load()
            return image.tobytes()[:64 * 3]



# ---------------------------------------------------------------- the solver

# (pixel index in the 8-pixel block, channel 0 = R, 1 = G, 2 = B) -> the byte S-Boot must decode
CRITICAL = {(1, 1): 0x00, (4, 2): 0x22, (5, 0): 0x24}
START = [BLACK, BLACK, BLACK, BLACK, (4, 145, 125), (36, 128, 128), BLACK, BLACK]


class BlockOracle:
    """S-Boot's decoder on an 8x8 image holding one block: the eight pixels of row 0."""

    def __init__(self) -> None:
        self.sboot = e.SBoot(e.IMAGE.read_bytes())
        self.runs = 0

    def pixels(self, coefs) -> list[tuple[int, int, int]]:
        logo = jf.encode_jpeg(8, 8, {(0, 0): [list(c) for c in coefs]})
        result = self.sboot.decode(logo)
        self.runs += 1
        memory = result["memory"]
        return [tuple(memory[3 * i: 3 * i + 3]) for i in range(8)]

    def turbo(self, coefs) -> list[tuple[int, int, int]]:
        logo = jf.encode_jpeg(8, 8, {(0, 0): [list(c) for c in coefs]})
        with Image.open(io.BytesIO(logo)) as image:
            image.load()
            return list(image.getdata())


def linear_jacobian():
    """d RGB(pixel x, channel) / d coefficient(component c, u), rows identical, quant table 1."""
    rows = []
    for (x, channel) in CRITICAL:
        row = []
        for c in range(3):
            for u in range(8):
                d_sample = (0.25 / 2 ** 0.5) * (1 / 2 ** 0.5 if u == 0 else 1.0) * _cos((2 * x + 1) * u * 3.141592653589793 / 16)
                slope = {0: (1.0, 0.0, 1.402), 1: (1.0, -0.34414, -0.71414), 2: (1.0, 1.772, 0.0)}[channel][c]
                row.append(d_sample * slope)
        rows.append(row)
    return rows


def _cos(v):
    import math
    return math.cos(v)


def solve(max_rounds: int = 60) -> tuple[list[list[int]], list[tuple[int, int, int]]] | None:
    o = BlockOracle()
    coefs = block_coefficients(START)
    targets = list(CRITICAL.items())

    def score(px):
        return tuple(px[x][c] - t for (x, c), t in targets)

    px = o.pixels(coefs)
    best_err = score(px)
    print(f"start: S-Boot decodes {px}; error on the critical bytes {best_err}; libjpeg-turbo says {o.turbo(coefs)}")
    if not any(best_err):
        return coefs, px
    jac = linear_jacobian()
    for round_ in range(max_rounds):
        # minimum-norm Newton step in the linear model, rounded to whole coefficients
        err = [-v for v in best_err]                           # the change wanted in the outputs
        jj = [[sum(a * b for a, b in zip(jac[i], jac[k])) for k in range(3)] for i in range(3)]
        # solve jj . y = err (3x3)
        import copy
        m = [row[:] + [err[i]] for i, row in enumerate(jj)]
        for i in range(3):
            pivot = max(range(i, 3), key=lambda r: abs(m[r][i]))
            if abs(m[pivot][i]) < 1e-12:
                break
            m[i], m[pivot] = m[pivot], m[i]
            for r in range(3):
                if r != i:
                    f = m[r][i] / m[i][i]
                    m[r] = [a - f * b for a, b in zip(m[r], m[i])]
        y = [m[i][3] / m[i][i] if abs(m[i][i]) > 1e-12 else 0 for i in range(3)]
        step = [sum(jac[k][j] * y[k] for k in range(3)) for j in range(24)]
        improved = False
        for gain in (1.0, 0.5, 1.5, 2.0, 0.25):
            trial = [list(c) for c in coefs]
            for j, s_ in enumerate(step):
                trial[j // 8][j % 8] += int(round(s_ * gain))
            tpx = o.pixels(trial)
            terr = score(tpx)
            if sum(abs(v) for v in terr) < sum(abs(v) for v in best_err):
                coefs, px, best_err, improved = trial, tpx, terr, True
                break
        if not improved:
            # coordinate search: nudge each coefficient, keep what helps
            for j in range(24):
                for delta in (1, -1, 2, -2, 3, -3, 4, -4, 6, -6, 8, -8):
                    trial = [list(c) for c in coefs]
                    trial[j // 8][j % 8] += delta
                    tpx = o.pixels(trial)
                    terr = score(tpx)
                    if sum(abs(v) for v in terr) < sum(abs(v) for v in best_err):
                        coefs, px, best_err, improved = trial, tpx, terr, True
                        break
                if improved:
                    break
        print(f"round {round_ + 1}: error {best_err}, {o.runs} decodes, pixels {px if not any(best_err) else ''}")
        if not any(best_err):
            return coefs, px
        if not improved:
            print("stuck")
            return None
    return None


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "diag":
        return diag()
    found = solve()
    if not found:
        print("FAIL: no coefficients found")
        return 1
    coefs, px = found
    out = Path(__file__).resolve().parent.parent / "out" / "calibrated_block.json"
    import json
    out.write_text(json.dumps(coefs))
    print(f"S-Boot decodes the calibrated block as {px}")
    print(f"the heap head's 16 bytes as S-Boot will have them: {b"".join(bytes(p) for p in px[:6]).hex(" ")}")
    print(f"coefficients written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
