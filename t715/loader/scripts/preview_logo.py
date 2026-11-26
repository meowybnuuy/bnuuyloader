#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""The screen as S-Boot's logo leaves it: a PNG of what a logo.jpg will show.

    venv/bin/python -I scripts/preview_logo.py LOGO.jpg OUT.png [--decoder pillow|sboot]
                     [--assume xrgb|xbgr|stored] [--crop X0,Y0,X1,Y1 OUT.png ...]

The logo is decoded, then drawn the way S-Boot's decode_and_draw draws it (read on 2026-11-25):
from the top left corner, a pixel at a time, into 32 bits at `0x67000000 + (1536 * y + x) * 4`,
each pixel stored as the bytes R, B, G of the decoded pixel, then zero. Nothing is cut: the
columns past 1536 fall into the next row and are drawn over. The panel is 1536 x 2048.

--decoder pillow reads the file with libjpeg (fast, and what the forging tools model); sboot runs
S-Boot's own decoder in the emulator (about two minutes; the truth).

--assume is what the panel makes of those 32 bits. Read on the tablet on 2026-11-25: stored,
the pixel as the decoder gave it (R, G, B), which is the default. The two others are kept for
a panel that would differ: xrgb, the format the kernel gives this framebuffer (the bytes are
B, G, R, so the panel shows the decoded pixel's G, B, R), and xbgr (the bytes are R, G, B:
R, B, G). A file built with logo_art.py's default --order is right under the default here.

What is not shown: the 16 bytes the loader's code writes at 0x67B00000 once it runs (row 1877,
pixel 512: a red pixel and three nearly black ones), until the kernel's splash.
"""
from __future__ import annotations

import argparse
import io
import sys
from pathlib import Path

import numpy as np
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent))

PANEL_WIDTH, PANEL_HEIGHT = 1536, 2048


def decode_pillow(path: Path) -> np.ndarray:
    with Image.open(path) as image:
        image.load()
        if image.mode != "RGB":
            raise SystemExit(f"{path.name}: not an RGB JPEG ({image.mode})")
        return np.asarray(image, dtype=np.uint8)


def decode_sboot(path: Path) -> np.ndarray:
    import sboot_jpeg_emu as e
    sboot = e.SBoot(e.IMAGE.read_bytes())
    result = sboot.decode(path.read_bytes())
    width, stride = result["width"], result["stride"]
    rows = result["height"]
    memory = np.frombuffer(result["memory"], dtype=np.uint8)[: stride * rows].reshape(rows, stride)
    print(f"S-Boot decoded {path.name}: {width} x {rows}, stride {stride}, {result['seconds']:.0f} s")
    return memory[:, : width * 3].reshape(rows, width, 3)


def screen(decoded: np.ndarray, assume: str) -> Image.Image:
    """The panel: S-Boot's writer's 32 bits for each of the first 1536 x 2048 pixels, read as ``assume``."""
    red, green, blue = (np.asarray(decoded[..., i], dtype=np.uint32) for i in range(3))
    stored = red | (blue << 8) | (green << 16)                  # the bytes R, B, G, in 32 bits
    memory = np.stack((stored & 0xFF, (stored >> 8) & 0xFF, (stored >> 16) & 0xFF), axis=-1).astype(np.uint8)
    if assume == "xrgb":                                   # the bytes are B, G, R
        panel = memory[..., ::-1]
    elif assume == "xbgr":                                 # the bytes are R, G, B
        panel = memory
    else:                                                  # stored: the decoded pixel as it came
        panel = decoded
    height = min(PANEL_HEIGHT, panel.shape[0])
    width = min(PANEL_WIDTH, panel.shape[1])
    if height < PANEL_HEIGHT or width < PANEL_WIDTH:
        raise SystemExit(f"the logo is {panel.shape[1]} x {panel.shape[0]}: smaller than the panel")
    return Image.fromarray(np.ascontiguousarray(panel[:height, :width]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("logo", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--decoder", default="pillow", choices=("pillow", "sboot"))
    parser.add_argument("--assume", default="stored", choices=("stored", "xrgb", "xbgr"))
    parser.add_argument("--crop", action="append", default=[], metavar="X0,Y0,X1,Y1:OUT")
    args = parser.parse_args()
    decoded = decode_sboot(args.logo) if args.decoder == "sboot" else decode_pillow(args.logo)
    if decoded.shape[1] < PANEL_WIDTH or decoded.shape[0] < PANEL_HEIGHT:
        raise SystemExit(f"{args.logo.name}: {decoded.shape[1]} x {decoded.shape[0]}, smaller than the panel: the narrow logo")
    panel = screen(decoded, args.assume)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    panel.save(args.out)
    print(f"{args.out}: the panel, 1536 x 2048, as S-Boot's logo leaves it (assumed {args.assume})")
    for crop in args.crop:
        box, _, name = crop.partition(":")
        x0, y0, x1, y1 = (int(v) for v in box.split(","))
        out = args.out.parent / name
        panel.crop((x0, y0, x1, y1)).save(out)
        print(f"{out}: the crop {box}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
