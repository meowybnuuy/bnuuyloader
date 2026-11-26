#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Build everything that starts an arm64 kernel on the tablet through the loader, in the right order.

The production chain (the kernel lives in a slot of CACHE, the loader in PARAM):

    venv/bin/python -I scripts/build_kboot.py --prod --name kbootN [--image Image --dtb DTB --gen N [--corrupt]]

  1. stage 2 (--prod: no self-test; --slot: the kernel is checked against the record of the slot the
     ARM32 code chose, never against a hash of the build), out/stage2-NAME.bin;
  2. the PARAM image (scripts/build_ffree.py --payload kboot): the loader's ARM32 code (the ledger,
     the two slots read and hashed, the record for EL2, the hand-back to S-Boot on any failure) and
     its AArch64 entry, out/NAME.param and out/NAME-logo.jpg;
  3. with --image, --dtb and --gen, for convenience: what goes into a slot of CACHE
     (scripts/build_slot.py), out/slot-NAME-genN.img, to be written with scripts/slot.py into the
     slot that is not in use.
  The loader holds nothing of a kernel (since kboot4, 2026-11-24): the same PARAM image starts
  whatever valid kernel a slot holds, so updating a slot needs no new PARAM. Then rehearse
  (scripts/kboot_cases.py) before anything reaches the tablet. With --verify, the logo is also
  decoded by S-Boot's own decoder in the emulator before the image is accepted: it must leave the
  heap head the loader is forged for and write nothing past the last row.

A picture as the logo of the whole screen (--geometry wide, scripts/logo_art.py):

    venv/bin/python -I scripts/build_kboot.py --prod --name kbootN --geometry wide --art PICTURE --order 2,0,1
    venv/bin/python -I scripts/build_kboot.py --prod --name kbootN-probe --geometry wide --art PICTURE --no-trap

  The logo is 2048 x 2049 and shows the picture where the panel reads it. The loader's code is
  the same; only the logo changes. --no-trap builds the probe for the screen instead: the picture
  in a logo of 2048 rows, which reaches nothing of the heap, and no code: S-Boot boots its own
  kernel over the picture. Its file is out/NAME.param, to be written like a loader's and replaced
  by one afterwards.

The test chain (the kernel inside PARAM, for one self-resetting boot):

    venv/bin/python -I scripts/build_kboot.py --test --image Image --dtb DTB --id 0x7e5e70NN --name sresetN

  stage 2 first, with the hashes; then the bundle and the PARAM image (build_ffree.py --kernel
  --kernel-in-param), which stores the bundle inside PARAM. At the start, stage 2 hashes what
  S-Boot's reader put in the memory and starts the kernel only if every byte is as built.

The logs go to out/NAME-build.log.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
KERNEL_AT, DTB_AT = 0x42000000, 0x5F000000
MARKER = "KBOOT: EL2"                    # the prefix of the AArch64 code's lines (never "KBOOT: start" or "KBOOT: up")


def fnv1a(data: bytes) -> int:
    """The hash stage 2 and the loader's ARM32 code compute (stage2/stage2.c, split_source.py)."""
    h = 0xCBF29CE484222325
    for byte in data:
        h = ((h ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def run(log, command: list) -> None:
    log.write("$ " + " ".join(command) + "\n")
    log.flush()
    result = subprocess.run([sys.executable, "-I", str(HERE / command[0])] + command[1:], stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise SystemExit(f"{command[0]} failed: see the log")


def constants(elf: Path) -> set[int]:
    """The 64-bit values the code of the ELF builds into registers (mov/movz, then movk)."""
    import re
    text = subprocess.run(["/opt/homebrew/opt/llvm@22/bin/llvm-objdump", "-d", "--no-show-raw-insn", str(elf)],
                          capture_output=True, text=True, check=True).stdout
    registers: dict[str, int] = {}
    found: set[int] = set()
    step = re.compile(r"\b(movz|mov|movk)\s+(x\d+),\s*#(0x[0-9a-f]+)(?:,\s*lsl\s*#(0x[0-9a-f]+|\d+))?")
    for line in text.splitlines():
        m = step.search(line)
        if not m:
            continue
        kind, register, immediate, shift = m.groups()
        value = int(immediate, 16) << (int(shift, 0) if shift else 0)
        if kind != "movk":                              # mov and movz write a register from nothing
            registers[register] = value
        elif register in registers:
            registers[register] |= value
            if shift and int(shift, 0) == 48:
                found.add(registers[register])
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prod", action="store_true", help="the production chain: the loader in PARAM, the kernel in a slot of CACHE")
    mode.add_argument("--test", action="store_true", help="the test chain: the kernel inside PARAM, one self-resetting boot")
    parser.add_argument("--image", type=Path, help="the arm64 kernel (Image); prod: only for the slot image")
    parser.add_argument("--dtb", type=Path, help="its device tree blob; prod: only for the slot image")
    parser.add_argument("--name", required=True, help="kbootN or sresetN: the names of the files in out/")
    parser.add_argument("--gen", type=int, help="prod: the slot's generation (one more than the slot in use)")
    parser.add_argument("--corrupt", action="store_true", help="prod: one byte of the image changed after it was hashed (a test of the way back)")
    parser.add_argument("--id", type=lambda t: int(t, 0), help="test: the image's marker, 32 bits")
    parser.add_argument("--in-param", type=lambda t: int(t, 0), default=0x120000, help="test: where in PARAM the bundle is stored")
    parser.add_argument("--verify", action="store_true",
                        help="prod: the logo decoded by S-Boot's own decoder in the emulator must leave the heap head the loader is "
                             "forged for and write nothing past the last row (one to three minutes; for the probe: the heap untouched)")
    picture = parser.add_argument_group("the logo of a whole screen (prod; build_ffree.py --geometry wide)")
    picture.add_argument("--geometry", choices=["narrow", "wide"], default="narrow",
                         help="wide: a logo of 2048 x 2049 whose first 1536 columns and 2048 rows the panel shows")
    picture.add_argument("--art", type=Path, help="wide: the picture the logo shows (scripts/logo_art.py)")
    picture.add_argument("--no-trap", action="store_true",
                         help="wide: the probe for the screen, not a loader: the picture in a logo of 2048 rows, no code; S-Boot boots its own kernel")
    picture.add_argument("--tables", default="all", choices=["libjpeg", "dc", "eob", "all"])
    picture.add_argument("--luma-floor", type=int, default=3)
    picture.add_argument("--chroma-floor", type=int, default=2)
    picture.add_argument("--black", type=int, default=14)
    picture.add_argument("--scale", type=float, default=1.0)
    picture.add_argument("--order", default="0,1,2")
    args = parser.parse_args()
    with_kernel = args.image is not None or args.dtb is not None
    if with_kernel and (args.image is None or args.dtb is None):
        raise SystemExit("--image and --dtb go together")
    if args.test and not with_kernel:
        raise SystemExit("--test needs --image and --dtb")
    if args.prod and with_kernel != (args.gen is not None):
        raise SystemExit("--prod: --image, --dtb and --gen (the slot image) go together")
    if args.corrupt and not (args.prod and with_kernel):
        raise SystemExit("--corrupt is for the slot image of --prod")
    if args.test and args.id is None:
        raise SystemExit("--test needs --id")
    if args.verify and not args.prod:
        raise SystemExit("--verify is for --prod")
    wide = []
    if args.geometry == "wide" or args.art or args.no_trap:
        if not args.prod or args.geometry != "wide":
            raise SystemExit("--geometry wide, --art and --no-trap are for --prod, together")
        wide = ["--geometry", "wide"]
        if args.art:
            wide += ["--art", str(args.art), "--tables", args.tables, "--luma-floor", str(args.luma_floor),
                     "--chroma-floor", str(args.chroma_floor), "--black", str(args.black), "--scale", str(args.scale),
                     "--order", args.order]
        if args.no_trap:
            wide += ["--no-trap"]

    out = HERE.parent / "out"
    stock = str(HERE.parent / "dumps" / "PARAM-mmcblk0p8.bin")
    param, logo = out / f"{args.name}.param", out / f"{args.name}-logo.jpg"
    if args.no_trap:                                      # the probe: the logo alone, so neither stage 2 nor a slot image
        with (out / f"{args.name}-build.log").open("w") as handle:
            run(handle, ["build_ffree.py", stock, str(param), "--out-jpeg", str(logo)] + wide + (["--verify"] if args.verify else []))
        for line in (out / f"{args.name}-build.log").read_text().splitlines():
            if line.startswith(("the probe", "S-Boot's decoder", "    B0 = ", "    the heap head", "    the 64 bytes")):
                print(line[:220])
        print(f"{param.name}: {param.stat().st_size} bytes, sha256 {hashlib.sha256(param.read_bytes()).hexdigest()}")
        return 0

    import build_ffree as bf
    if with_kernel:
        image, tree = args.image.read_bytes(), args.dtb.read_bytes()
        if struct.unpack_from("<I", image, 0x38)[0] != 0x644D5241 or struct.unpack_from("<Q", image, 8)[0] != 0:
            raise SystemExit("the kernel image has no arm64 header, or a text offset other than 0")
        if tree[:4] != b"\xd0\x0d\xfe\xed":
            raise SystemExit("the device tree has no magic")
        image_sectors, tree_sectors = -(-len(image) // 512), -(-len(tree) // 512)
        image_bytes, tree_bytes = image_sectors * 512, tree_sectors * 512
        image_hash = fnv1a(image + bytes(image_bytes - len(image)))
        tree_hash = fnv1a(tree + bytes(tree_bytes - len(tree)))

    if args.prod:
        stage = out / f"stage2-{args.name}.bin"
        slot = out / f"slot-{args.name}-gen{args.gen}.img" if with_kernel else None
        commands = [
            ["build_stage2.py", str(stage), "--marker", MARKER, "--prod", "--handoff", "--watchdog-arm", "--slot"],
            ["build_ffree.py", stock, str(param), "--payload", "kboot", "--marker", MARKER, "--vectors", "--mmu",
             "--stage2", str(stage), "--out-jpeg", str(logo)] + wide + (["--verify"] if args.verify else []),
        ] + ([["build_slot.py", "--image", str(args.image), "--dtb", str(args.dtb), "--gen", str(args.gen), "--out", str(slot)]
              + (["--corrupt"] if args.corrupt else [])] if with_kernel else [])
    else:
        marker = f"HIJACK3: {args.id & 0xFFFFFFFF:08x}"
        stage = out / f"stage2-{args.name}.bin"
        bundle = out / f"bundle-{args.name}.bin"
        commands = [
            ["build_stage2.py", str(stage), "--marker", marker, "--emmc", "--handoff", "--watchdog-arm",
             "--kernel", hex(KERNEL_AT), hex(image_bytes), hex(DTB_AT), hex(tree_bytes),
             "--define", f"KERNEL_HASH={image_hash:#x}ull", "--define", f"DTB_HASH={tree_hash:#x}ull"],
            ["build_ffree.py", stock, str(param), "--payload", "sreset", "--id", hex(args.id), "--vectors", "--mmu",
             "--stage2", str(stage), "--emmc", "--kernel", str(args.image), "--dtb", str(args.dtb), "--bundle", str(bundle),
             "--kernel-in-param", hex(args.in_param), "--out-jpeg", str(logo)],
        ]
    log = out / f"{args.name}-build.log"
    with log.open("w") as handle:
        for command in commands:
            run(handle, command)

    held = constants(out / "stage2.elf")
    if args.test:
        if image_hash not in held or tree_hash not in held:
            raise SystemExit("stage 2 does not hold the hashes built here")
        print(f"stage 2 ({stage.name}, {stage.stat().st_size} bytes) holds both hashes")
    else:
        if with_kernel and (image_hash in held or tree_hash in held):
            raise SystemExit("the production stage 2 holds a hash of the kernel built here: it must hold none")
        print(f"stage 2 ({stage.name}, {stage.stat().st_size} bytes) holds no hash of a kernel: it checks the kernel against the "
              f"record of the slot the ARM32 code chose ({bf.KBOOT_RECORD_AT:#010x})")
    if with_kernel:
        print(f"kernel {args.image.name}: {len(image)} bytes ({hashlib.sha256(image).hexdigest()[:16]}), read as {image_bytes:#x} bytes "
              f"at {KERNEL_AT:#010x}, fnv1a {image_hash:#018x}")
        print(f"device tree {args.dtb.name}: {len(tree)} bytes ({hashlib.sha256(tree).hexdigest()[:16]}), read as {tree_bytes:#x} bytes "
              f"at {DTB_AT:#010x}, fnv1a {tree_hash:#018x}")
    for line in log.read_text().splitlines():
        if line.startswith(("the production loader", "bundle ", "the bundle is in PARAM", "marker of this image", "S-Boot's decoder",
                            "    B0 = ", "    the heap head", "    the 64 bytes")) or " the bytes " in line:
            print(line[:220])
    if args.prod:
        logo_bytes = logo.read_bytes()                 # the node at file offset 0x20000, the ARM32 code from 0x110 after it
        arm32 = logo_bytes[0x20000:0x20000 + bf.KBOOT_A64_OFF]
        for letter, rel in bf.SLOT_REL.items():
            if struct.pack("<I", bf.CACHE_SECTOR + rel) not in arm32:
                raise SystemExit(f"the loader's ARM32 code does not name slot {letter}'s first sector")
        for what, value in (("the record's address", bf.KBOOT_RECORD_AT), ("the record's magic", bf.KBOOT_RECORD_MAGIC)):
            if struct.pack("<I", value) not in arm32:
                raise SystemExit(f"the loader's ARM32 code does not hold {what} ({value:#010x})")
        if with_kernel:
            data = slot.read_bytes()
            print(f"slot: {slot.name}, {len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()}, generation {args.gen}"
                  + (" (corrupted on purpose)" if args.corrupt else ""))
    print(f"{param.name}: {param.stat().st_size} bytes, sha256 {hashlib.sha256(param.read_bytes()).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
