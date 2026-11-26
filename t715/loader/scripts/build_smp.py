#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Build the image of the one-core experiment: a secondary core in 64 bits, without Linux (one boot that
resets the tablet by itself, as the other test images do).

    venv/bin/python -I scripts/build_smp.py --id 0x7e5e7021 --name smp1

  1. the two stubs the secondary core runs (scripts/build_smp_stubs.py): out/NAME/smp-stubs.bin and the
     C array stage 2 carries, out/NAME/smp_stubs.h;
  2. stage 2 with them (scripts/build_stage2.py --prod --watchdog-arm --smp-stubs): out/NAME/stage2.bin;
     it powers A53 core 1 on, waits on the watchdog's counter and resets the SoC;
  3. the PARAM image (scripts/build_ffree.py --payload sreset --smp): out/NAME.param and out/NAME-logo.jpg.
  Then rehearse before anything reaches the tablet: scripts/preflight.py --smp (with the two stubs on an
  emulated second core) and scripts/guard_cases.py.

  The logs go to out/NAME-build.log.
"""
import argparse
import hashlib
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def run(log, command: list) -> None:
    log.write("$ " + " ".join(command) + "\n")
    log.flush()
    result = subprocess.run([sys.executable, "-I", str(HERE / command[0])] + command[1:], stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise SystemExit(f"{command[0]} failed: see the log")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--id", type=lambda t: int(t, 0), required=True, help="the image's marker, 32 bits (a new one for each image)")
    parser.add_argument("--name", required=True, help="smpN: the name of the files in out/")
    args = parser.parse_args()
    out = HERE.parent / "out"
    work = out / args.name
    work.mkdir(parents=True, exist_ok=True)
    marker = f"HIJACK3: {args.id & 0xFFFFFFFF:08x}"
    stage, param, logo = work / "stage2.bin", out / f"{args.name}.param", out / f"{args.name}-logo.jpg"
    stubs, header = work / "smp-stubs.bin", work / "smp_stubs.h"
    with (out / f"{args.name}-build.log").open("w") as log:
        run(log, ["build_smp_stubs.py", str(stubs), "--marker", marker, "--header", str(header)])
        words = struct.unpack(f"<{stubs.stat().st_size // 4}I", stubs.read_bytes())
        run(log, ["build_stage2.py", str(stage), "--marker", marker, "--prod", "--watchdog-arm", "--smp-stubs", str(header),
                  "--define", f"SMP_STUBS_SUM={sum(words) & 0xFFFFFFFF:#x}u"])
        run(log, ["build_ffree.py", str(HERE.parent / "dumps" / "PARAM-mmcblk0p8.bin"), str(param), "--payload", "sreset",
                  "--id", hex(args.id), "--vectors", "--mmu", "--stage2", str(stage), "--smp", "--out-jpeg", str(logo)])
    print(f"marker: {marker}")
    print(f"the stubs: {stubs.name}, {stubs.stat().st_size:#x} bytes, the sum of their words {sum(words) & 0xFFFFFFFF:#010x}")
    print(f"stage 2: {stage.name}, {stage.stat().st_size:#x} bytes")
    print(f"{param.name}: {param.stat().st_size} bytes, sha256 {hashlib.sha256(param.read_bytes()).hexdigest()}")
    print(f"{logo.name}: {logo.stat().st_size} bytes, sha256 {hashlib.sha256(logo.read_bytes()).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
