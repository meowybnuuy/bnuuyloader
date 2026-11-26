#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""The kernel's slots in the CACHE partition of the tablet, over ssh.

    venv/bin/python -I scripts/slot.py backup FILE            the whole partition as it is, read and verified
    venv/bin/python -I scripts/slot.py shrink                 CACHE's ext4 shrunk to 64 MiB (Android keeps a /cache); the rest is raw
    venv/bin/python -I scripts/slot.py show                   what the two slots hold
    venv/bin/python -I scripts/slot.py write A GEN IMAGE DTB  a slot built from the kernel and its tree (build_slot.py), written, read back
    venv/bin/python -I scripts/slot.py erase A                a slot's header zeroed: the slot counts as never written

CACHE is /dev/mmcblk0p20 (200 MiB, unused by the owner's Linux). The first 64 MiB stay its ext4 (Android's
/cache); slot A starts at sector 131072 of the partition and slot B at 262144 (build_ffree.py SLOT_REL);
64 MiB each; each holds a 4 KiB header, the Image, the
device tree (build_slot.py). An update writes the slot that is not in use, with a generation one
higher than the other: the loader takes the valid one with the highest generation, so a write cut
half-way never costs the kernel (the half-written slot's header or hash does not check, and the
other one is still there).

The partition is written raw, through dd, in whole sectors, without touching anything else:
never the first 64 MiB (the filesystem), never the other slot. Everything written is read back
and hashed before the script says so. Run it only on a tablet you can afford to lose.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build_ffree as bf  # noqa: E402
import build_slot as bs  # noqa: E402

T = os.environ.get("T715_TSSH", str(Path(__file__).resolve().parents[4] / "omarchy-tab-s2" / "device" / "tssh"))      # omarchy-tab-s2's ssh wrapper to the tablet
PART = "/dev/mmcblk0p20"


def ssh(command: str, data: bytes | None = None, check: bool = True) -> str:
    result = subprocess.run([T, command], input=data, capture_output=True)
    text = (result.stdout + result.stderr).decode("latin1").replace("\r", "")
    if check and result.returncode != 0:
        raise SystemExit(f"the tablet answered {result.returncode}: {text.strip()[:300]}")
    return text


def on_tablet() -> bool:
    return "up" in ssh("echo up", check=False)


def slot_sectors(letter: str) -> tuple[int, int]:
    """(the slot's first sector in the partition, its length in sectors)."""
    return bf.SLOT_REL[letter], bf.SLOT_SECTORS


def setrw(on: bool) -> None:
    ssh(f"blockdev --set{'rw' if on else 'ro'} {PART}")


def backup(out: Path) -> int:
    result = subprocess.run([T, f"dd if={PART} bs=1M status=none"], capture_output=True)   # binary: a pipe of its own
    data = result.stdout
    there = ssh(f"sha256sum {PART} | cut -c1-64").strip()
    here = hashlib.sha256(data).hexdigest()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    print(f"{out.name}: {len(data)} bytes; sha256 here {here}; on the tablet {there}: "
          f"{'the same' if here == there else 'DIFFERENT'}")
    size = ssh(f"blockdev --getsize64 {PART}").strip()
    print(f"the partition is {size} bytes; the dump {'is whole' if str(len(data)) == size else 'is NOT whole'}")
    return 0 if here == there and str(len(data)) == size else 1


def shrink() -> int:
    """CACHE's ext4 is made 64 MiB (Android keeps a /cache): shrunk if it is bigger, grown back if it is smaller."""
    size = re.search(r"Block count:\s+(\d+)", ssh(f"tune2fs -l {PART} 2>/dev/null")).group(1)
    blocks = bf.CACHE_FS_SECTORS * 512 // 4096
    print(f"before: Block count {size}; wanted: {blocks} ({bf.CACHE_FS_SECTORS * 512 // 1048576} MiB)")
    if int(size) == blocks:
        print("already the right size: nothing done")
        return 0
    if int(size) > 51200:
        print("not the 200 MiB partition this script expects: nothing done")
        return 1
    if "mmcblk0p20" in ssh("grep mmcblk0p20 /proc/mounts || true"):
        print("CACHE is mounted: nothing done")
        return 1
    for tool in ("e2fsck", "resize2fs"):
        if not ssh(f"command -v {tool} || true").strip():
            print(f"{tool} is missing on the tablet: nothing done")
            return 1
    setrw(True)
    print("e2fsck -f:", ssh(f"e2fsck -f -y {PART} 2>&1 | tail -n 2 | tr '\n' ' ' | cut -c1-200").strip())
    print("resize2fs:", ssh(f"resize2fs {PART} {bf.CACHE_FS_SECTORS * 512 // 1048576}M 2>&1 | tail -n 2 | tr '\n' ' ' | cut -c1-200").strip())
    setrw(False)
    after = ssh(f"tune2fs -l {PART} 2>/dev/null | grep -E 'Block count|Free blocks|Filesystem state' | cut -c1-120")
    print("after:", after.strip().replace("\n", " | "))
    print("e2fsck -fn:", ssh(f"e2fsck -fn {PART} 2>&1 | tail -n 1 | cut -c1-200").strip())
    return 0 if f"Block count:              {blocks}" in after else 1


def read_range(first: int, sectors: int) -> bytes:
    return subprocess.run([T, f"dd if={PART} bs=512 skip={first} count={sectors} status=none"], capture_output=True).stdout


def show() -> int:
    for letter in bf.SLOT_REL:
        first, length = slot_sectors(letter)
        head = read_range(first, 8)
        said = bs.read_slot(head + bytes(0x1000 - len(head)))
        if said is None:
            print(f"slot {letter} (sector {first} of CACHE, absolute {bf.CACHE_SECTOR + first}): no header of ours "
                  f"(first words: {' '.join(f'{int(w):08x}' for w in struct.unpack_from('<4I', head)) if len(head) >= 16 else 'unreadable'})")
            continue
        data = read_range(first, min(length, 8 + (said["image"] + said["dtb"]) // 512))
        sound = bs.slot_is_sound(data)
        print(f"slot {letter} (sector {first} of CACHE, absolute {bf.CACHE_SECTOR + first}): generation {said['generation']}, "
              f"image {said['image']} bytes at {said['image_at']:#010x}, device tree {said['dtb']} bytes at {said['dtb_at']:#010x}: "
              f"{'the bytes are as the header says' if sound else 'THE BYTES ARE NOT AS THE HEADER SAYS'}")
    return 0


def write(letter: str, generation: int, image: Path, dtb: Path) -> int:
    first, length = slot_sectors(letter)
    data = bs.make_slot(image.read_bytes(), dtb.read_bytes(), generation)
    if len(data) > length * 512:
        raise SystemExit("it does not fit the slot")
    if not bs.slot_is_sound(data):
        raise SystemExit("the slot built here does not check: nothing written")
    print(f"slot {letter}, generation {generation}: {len(data)} bytes ({len(data) // 512} sectors of {length}) to write at sector {first}")
    current = read_range(first, 8)
    said = bs.read_slot(current + bytes(0x1000 - len(current)))
    if said is not None:
        print(f"  it holds generation {said['generation']} today: that kernel is replaced once this write is whole")
    setrw(True)
    result = subprocess.run([T, f"cat | dd of={PART} bs=512 seek={first} conv=notrunc status=none && sync"], input=data, capture_output=True)
    setrw(False)
    if result.returncode != 0:
        print(f"  the write failed ({(result.stderr or b'').decode('latin1')[:200]}): the other slot, if any, is untouched")
        return 1
    back = read_range(first, len(data) // 512)
    same = back == data
    print(f"  read back: {'every byte is as written' if same else 'NOT what was written'} "
          f"(sha256 {hashlib.sha256(back).hexdigest()[:16]} here, {hashlib.sha256(data).hexdigest()[:16]} written)")
    show()
    return 0 if same else 1


def erase(letter: str) -> int:
    first, _ = slot_sectors(letter)
    setrw(True)
    subprocess.run([T, f"dd if=/dev/zero of={PART} bs=512 seek={first} count=8 conv=notrunc status=none && sync"], capture_output=True)
    setrw(False)
    print(f"slot {letter}: its header zeroed; read back {'zeros' if not any(read_range(first, 8)) else 'NOT zeros'}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="what", required=True)
    p = sub.add_parser("backup")
    p.add_argument("file", type=Path)
    sub.add_parser("shrink")
    sub.add_parser("show")
    p = sub.add_parser("write")
    p.add_argument("slot", choices=list(bf.SLOT_REL))
    p.add_argument("generation", type=int)
    p.add_argument("image", type=Path)
    p.add_argument("dtb", type=Path)
    p = sub.add_parser("erase")
    p.add_argument("slot", choices=list(bf.SLOT_REL))
    args = parser.parse_args()
    if not on_tablet():
        print("the tablet does not answer over ssh: nothing done")
        return 1
    if args.what == "backup":
        return backup(args.file)
    if args.what == "shrink":
        return shrink()
    if args.what == "show":
        return show()
    if args.what == "write":
        return write(args.slot, args.generation, args.image, args.dtb)
    return erase(args.slot)


if __name__ == "__main__":
    sys.exit(main())
