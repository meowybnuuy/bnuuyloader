#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Build the AArch64 test image for EL1 (el1/el1_test.S) into a raw binary linked at 0x40080000.

    venv/bin/python -I scripts/build_el1.py OUT.bin --marker "HIJACK3: 7e5e7007"

The same three tools as scripts/build_stage2.py. The image starts with a 16-byte header ("EL1T",
its size) that stage 2 checks after S-Boot's reader has loaded it; the code starts at 0x40080010.
"""
import argparse
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EL1 = HERE.parent / "el1"
LLVM = Path("/opt/homebrew/opt/llvm@22/bin")
LLD = Path("/opt/homebrew/opt/lld@22/bin/ld.lld")
BASE = 0x40080000
LIMIT = 0x20000


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("out", type=Path)
    parser.add_argument("--marker", required=True, help="the image's marker, e.g. HIJACK3: 7e5e7007")
    args = parser.parse_args()
    out = args.out.resolve()
    work = out.parent
    flags = ["clang", "--target=aarch64-none-elf", "-mcpu=cortex-a53", "-Wall", "-Werror", "-fno-asynchronous-unwind-tables",
             f'-DMARKER="{args.marker}"']
    source = work / "el1_test.S"                   # the marker goes in by text: the assembler's preprocessor pass is not relied on
    source.write_text((EL1 / "el1_test.S").read_text().replace("@MARKER@", args.marker))
    subprocess.run(flags + ["-c", "-o", str(work / "el1.o"), str(source)], check=True)
    elf = work / "el1.elf"
    subprocess.run([str(LLD), "-T", str(EL1 / "el1_test.ld"), "--entry", "el1_entry", "-o", str(elf), str(work / "el1.o")], check=True)
    subprocess.run([str(LLVM / "llvm-objcopy"), "-O", "binary", str(elf), str(out)], check=True)
    image = out.read_bytes()
    magic, size = struct.unpack_from("<II", image)
    if magic != 0x54314C45 or size != len(image) or args.marker.encode() not in image:
        raise SystemExit(f"the header says {magic:#x}, {size} bytes: the image is {len(image)} bytes")
    if len(image) > LIMIT:
        raise SystemExit(f"the image is {len(image):#x} bytes: too big")
    print(f"{out.name}: {len(image)} bytes ({len(image) / 512:.0f} sectors), linked at {BASE:#010x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
