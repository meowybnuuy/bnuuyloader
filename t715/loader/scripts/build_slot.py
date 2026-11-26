#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Make what goes into a slot of the CACHE partition for the production loader.

    venv/bin/python -I scripts/build_slot.py --image Image --dtb DTB --gen N --out out/slot-genN.img [--corrupt]

A slot (64 MiB of CACHE, see build_ffree.py SLOT_REL) holds a 4 KiB header, then the uncompressed
arm64 Image in whole sectors, then the device tree blob in whole sectors. The loader
(split_source.py KBOOT_SOURCE) reads the header, checks it, reads the two, hashes them in ARM32
and compares with the header: a slot is used only if every byte is as its header says.

Header, little-endian words:
    0x00 magic "T7K1"      0x04 version 1         0x08 generation       0x0C flags (0)
    0x10 image bytes       0x14 where it goes     0x18 device tree bytes 0x1C where it goes
    0x20 image FNV-1a 64 (low, high)              0x28 device tree FNV-1a 64 (low, high)
    0x30 FNV-1a 64 of the header's first 0x30 bytes (low, high); the rest of the 4 KiB is zero.
The generation is what decides between two valid slots: the higher one is taken. An update writes
the slot that is not in use with a generation one higher, so a cut update never costs the kernel.

--corrupt changes one byte of the image after it was hashed: a slot whose header is fine but whose
bytes are not, for the rehearsals and the tests of the way back.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_ffree as bf  # noqa: E402

HEADER_WORDS = 0x0E          # 0x38 bytes: 0x30 hashed, then the hash itself


def fnv1a(data: bytes) -> tuple[int, int]:
    """(low word, high word) of the FNV-1a 64 of `data`: the loader's and stage 2's hash."""
    h = 0xCBF29CE484222325
    for byte in data:
        h = ((h ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h & 0xFFFFFFFF, h >> 32


def make_slot(image: bytes, dtb: bytes, generation: int, corrupt: bool = False) -> bytes:
    if struct.unpack_from("<I", image, 0x38)[0] != 0x644D5241 or struct.unpack_from("<Q", image, 8)[0] != 0:
        raise SystemExit("the kernel image has no arm64 header, or a text offset other than 0")
    if dtb[:4] != b"\xd0\x0d\xfe\xed":
        raise SystemExit("the device tree has no magic")
    image_pad = image + bytes(-len(image) % 512)
    dtb_pad = dtb + bytes(-len(dtb) % 512)
    if 0x1000 + len(image_pad) + len(dtb_pad) > bf.SLOT_SECTORS * 512:
        raise SystemExit(f"the kernel ({len(image)} bytes) and its tree do not fit a slot of {bf.SLOT_SECTORS * 512} bytes")
    header = struct.pack("<12I", bf.SLOT_MAGIC, 1, generation & 0xFFFFFFFF, 0, len(image_pad), bf.KERNEL_AT, len(dtb_pad), bf.DTB_AT,
                         *fnv1a(image_pad), *fnv1a(dtb_pad))
    header += struct.pack("<II", *fnv1a(header))
    if corrupt:   # after the hash, so that the header no longer says what the slot holds (until 2026-11-24 the
                  # byte was changed before the hash: the "corrupt" slot was a sound one, and a test of nothing)
        image_pad = image_pad[:0x20000] + bytes([image_pad[0x20000] ^ 0xFF]) + image_pad[0x20001:]
    return header + bytes(bf.SLOT_HEADER_BYTES - len(header)) + image_pad + dtb_pad


def read_slot(data: bytes) -> dict:
    """What a slot's header says (None if it is not one of ours)."""
    if len(data) < bf.SLOT_HEADER_BYTES:
        return None
    words = struct.unpack_from("<14I", data)
    if words[0] != bf.SLOT_MAGIC or words[1] != 1:
        return None
    if fnv1a(data[:0x30]) != (words[12], words[13]):
        return None
    return {"generation": words[2], "image": words[4], "image_at": words[5], "dtb": words[6], "dtb_at": words[7],
            "image_fnv": words[8] | words[9] << 32, "dtb_fnv": words[10] | words[11] << 32}


def slot_is_sound(data: bytes) -> bool:
    """Whether the bytes behind the header are the ones it hashes."""
    said = read_slot(data)
    if said is None:
        return False
    image = data[0x1000:0x1000 + said["image"]]
    tree = data[0x1000 + said["image"]:0x1000 + said["image"] + said["dtb"]]
    return fnv1a(image) == (said["image_fnv"] & 0xFFFFFFFF, said["image_fnv"] >> 32) \
        and fnv1a(tree) == (said["dtb_fnv"] & 0xFFFFFFFF, said["dtb_fnv"] >> 32)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--image", type=Path, required=True, help="the arm64 kernel (Image), uncompressed")
    parser.add_argument("--dtb", type=Path, required=True, help="its device tree blob")
    parser.add_argument("--gen", type=int, required=True, help="the generation: one more than the slot in use")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--corrupt", action="store_true", help="one byte of the image changed after it was hashed (for tests)")
    args = parser.parse_args()
    slot = make_slot(args.image.read_bytes(), args.dtb.read_bytes(), args.gen, args.corrupt)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(slot)
    image, tree = args.image.read_bytes(), args.dtb.read_bytes()
    good = slot_is_sound(slot)
    print(f"{args.out.name}: {len(slot)} bytes, sha256 {hashlib.sha256(slot).hexdigest()[:16]}; generation {args.gen}; "
          f"image {len(image)} bytes ({hashlib.sha256(image).hexdigest()[:16]}), device tree {len(tree)} bytes "
          f"({hashlib.sha256(tree).hexdigest()[:16]}); the bytes {'match' if good else 'DO NOT match'} the header"
          + (" (corrupted on purpose)" if args.corrupt else ""))
    return 0 if good != args.corrupt else 1


if __name__ == "__main__":
    sys.exit(main())
