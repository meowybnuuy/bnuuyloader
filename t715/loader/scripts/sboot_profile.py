#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Profile S-Boot's decoder in the emulator on a small image: which code runs how often.

    venv/bin/python -I scripts/sboot_profile.py

Builds a 24x16 JPEG (9 blocks per component) with Pillow, decodes it with S-Boot's wrapper and
lists the code blocks executed in S-Boot's library range, grouped by the function they belong to
(the nearest preceding push {.., lr}), with their execution counts. Also finds the array of
inverse-DCT function pointers the library left on the stack.
"""
import io
import struct
import sys
from collections import Counter
from pathlib import Path

from PIL import Image
from unicorn import UC_ARCH_ARM, UC_MODE_ARM
from unicorn.unicorn_const import UC_HOOK_BLOCK
sys.path.insert(0, str(Path(__file__).resolve().parent))
import sboot_jpeg_emu as e
from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs

image = e.IMAGE.read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
starts = {}
for off in range(0x23E00000 - e.BASE, 0x23E53000 - e.BASE, 4):
    w = struct.unpack_from("<I", image, off)[0]
    if w & 0xFFFF0000 == 0xE92D0000 and w & 0x100:
        starts[e.BASE + off] = True

sboot = e.SBoot(image)
buf = io.BytesIO()
pixels = [(x * 37 % 256, y * 53 % 256, (x * y * 7) % 256) for y in range(16) for x in range(24)]
Image.new("RGB", (24, 16)).putdata(pixels)
Image.new("RGB", (24, 16)).putdata(pixels)
im = Image.new("RGB", (24, 16)); im.putdata(pixels)
im.save(buf, format="JPEG", quality=95, subsampling=0)
logo = buf.getvalue()
e.sboot = sboot
counts = Counter()
sboot.uc.hook_add(UC_HOOK_BLOCK, lambda uc, address, size, data: counts.__setitem__(address, counts[address] + 1))
result = sboot.decode(logo)
print(f"decoded {result['width']}x{result['height']} in {result['instructions']} instructions; {len(counts)} distinct blocks")
ordered = sorted(starts)
import bisect
funcs = Counter()
blocks = {}
for address, n in counts.items():
    if 0x23E00000 <= address < 0x23E53000:
        i = bisect.bisect_right(ordered, address) - 1
        f = ordered[i] if i >= 0 else 0
        funcs[f] += n
        blocks.setdefault(f, []).append((address, n))
print("hottest functions (block entries summed):")
for f, n in funcs.most_common(22):
    size = (ordered[bisect.bisect_right(ordered, f)] if bisect.bisect_right(ordered, f) < len(ordered) else f + 0x400) - f
    print(f"   {f:#010x} (+{size:#x}): {n} block entries, {len(blocks[f])} distinct blocks")
# the inverse-DCT pointer array left on the stack
stack = bytes(sboot.uc.mem_read(e.STACK_TOP - 0x2000, 0x2000))
for i in range(0, len(stack) - 40, 4):
    words = struct.unpack_from("<3I", stack, i)
    if words[0] == words[1] == words[2] and 0x23E00000 <= words[0] < 0x23E53000:
        print(f"inverse-DCT array at {e.STACK_TOP - 0x2000 + i:#010x}: {words[0]:#010x}")
