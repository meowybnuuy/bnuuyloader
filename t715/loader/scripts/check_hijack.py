#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Emulate S-Boot's free() and malloc() walk on a decoded hijack image.

    python3 -I check_hijack.py LOGO.jpg WIDTH

For every 16-aligned address the image writes past the decode buffer's end, play the free()
of the lowest libjpeg block as S-Boot's FUN_23e071FC does it, and say what would happen if
that were the real header: HIJACK (the loader's saved return address is overwritten), benign
(nothing outside the decode buffer is written), unknown (a slot cut by the row's pad bytes),
or something else, which is a bug. Then walk the heap list as malloc() does, from the head.
"""

from __future__ import annotations

import io
import struct
import sys
from pathlib import Path

from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_hijack as bh  # noqa: E402
import build_calib as bc  # noqa: E402

STALE = object()


def main() -> int:
    logo = Path(sys.argv[1]).read_bytes()
    layout = bh.Layout(int(sys.argv[2]))
    with Image.open(io.BytesIO(logo)) as image:
        image.load()
        raw = image.tobytes()
    n = layout.row_bytes
    writes: list[tuple[int, int]] = []

    overlay: dict[int, int] = {}               # what free() itself has written

    def read(address: int, size: int):
        data = peek(address, size)
        if data is None or data is STALE:
            return data
        return bytes(overlay.get(address + i, b) for i, b in enumerate(data))

    def store(address: int, value: int) -> None:
        writes.append((address, value))
        for i in range(4):
            overlay[address + i] = value >> (8 * i) & 0xFF

    def peek(address: int, size: int):
        if bc.DECODE_BUFFER <= address < bc.DECODE_BUFFER + layout.stride * layout.height:   # everything written
            row, offset = divmod(address - bc.DECODE_BUFFER, layout.stride)
            out = []
            for i in range(size):
                if offset + i >= n:
                    return STALE                       # a pad byte: never written by libjpeg
                out.append(raw[row * n + offset + i])
            return bytes(out)
        if bh.HEAP_HEAD <= address < bh.HEAP_HEAD + 16:   # the list head, in S-Boot's data
            return struct.pack("<IIII", 0, 0, 0, bh.HEAP_FREE_BLOCK)[address - bh.HEAP_HEAD:][:size]
        if bh.FILE_BUFFER <= address < bh.FILE_BUFFER + len(logo):
            return logo[address - bh.FILE_BUFFER:][:size]
        known = {bh.PREV: struct.pack("<I", 0x23EC00C0), bh.PREV + 4: b"\x68", bh.LR_SLOT: struct.pack("<I", 0x23E07C5C)}
        for start, data in known.items():
            if start <= address < start + len(data):
                return data[address - start:][:size]
        return None                                 # not mapped by this model

    def u32(address):
        data = read(address, 4)
        return data if data in (None, STALE) else struct.unpack("<I", data)[0]   # None: unmapped, STALE: a pad byte

    def free(pointer: int) -> str:
        del writes[:]
        overlay.clear()
        prev = u32(pointer - 8)
        if prev is None:
            return "FAULT"
        if prev is STALE:
            return "unknown"
        if read(pointer - 12, 1) is STALE:
            return "unknown"
        cur = pointer - 16
        if read(prev + 4, 1) not in (None, b"\0"):
            size, own = u32(prev), u32(pointer - 16)
            if size is None or own is None:
                return "FAULT"
            store(prev, size + own + 16)
            nxt = u32(pointer - 4)
            if nxt is None:
                return "FAULT"
            store(prev + 12, nxt)
            if read(nxt + 8, 4) is None:
                return "FAULT"
            store(nxt + 8, prev)
            cur = prev
        nxt = u32(cur + 12)
        if nxt is None:
            return "FAULT"
        if nxt is STALE:
            return "unknown"
        flag = read(nxt + 4, 1)
        if flag is None:
            return "FAULT"
        if flag != b"\0":
            return "ABSORB"                        # would go on: not wanted
        if not writes:
            return "benign"
        if writes == [(bh.PREV, 0x23EC00C0 + 16), (bh.LR_SLOT, u32(bh.PREV + 12)), (u32(bh.PREV + 12) + 8, bh.PREV)]:
            return "HIJACK"
        return "WRITES " + " ".join(f"[{a:#x}]={v:#x}" for a, v in writes)

    counts: dict[str, int] = {}
    odd: list[tuple[int, str]] = []
    first = layout.row_start(layout.first_forged_row)
    last = layout.row_start(layout.height - 1) + n
    for address in range(first, last, 16):
        outcome = free(address + 16)
        key = outcome if outcome in ("HIJACK", "benign", "unknown") else outcome.split()[0]
        counts[key] = counts.get(key, 0) + 1
        if key not in ("HIJACK", "benign"):
            odd.append((address, outcome))
    print(f"headers S-Boot could take for its lowest block, {first:#x}..{last:#x}: {counts}")
    for address, outcome in odd[:12]:
        print(f"  {address:#x}: {outcome}")
    forged = layout.estimate
    print(f"at the estimate {forged:#x}: {free(forged + 16)}; one slot lower: {free(forged + 16 - 16)}; one higher: {free(forged + 16 + 16)}")

    # the list walk of a later malloc(), as FUN_23e07080 does it
    node, seen = u32(bh.HEAP_HEAD + 12), []
    while node != bh.HEAP_HEAD and len(seen) < 16:
        seen.append(node)
        flag = read(node + 4, 1)
        if flag is None:
            break
        node = u32(node + 12)
        if node is None:
            break
    ok = node == bh.HEAP_HEAD and seen and seen[0] == bh.HEAP_FREE_BLOCK
    sizes = [(hex(a), hex(struct.unpack('<I', read(a, 4))[0])) for a in seen]
    print(f"malloc() walk from the head: {'closed loop' if ok else 'BROKEN'} through {sizes}")
    code = bh.FILE_BUFFER + logo.index(bytes.fromhex("020000ea"))
    print(f"free() would return into {code:#x}: first word {read(code, 4).hex()}, byte [+4] {read(code + 4, 1).hex()}")
    return 0 if ok and set(counts) <= {"HIJACK", "benign", "unknown"} and counts.get("unknown", 0) == layout.height - layout.first_forged_row else 1


if __name__ == "__main__":
    sys.exit(main())
