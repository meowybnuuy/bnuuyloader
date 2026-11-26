#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Build stage 2, the C code the AArch64 entry calls at EL2, into a raw binary linked at 0x24224000.

    venv/bin/python -I scripts/build_stage2.py OUT.bin --marker "HIJACK3: 7e5e7005"

Apple's clang compiles for a bare AArch64 core, the LLVM linker from Homebrew links the object at
its address (Apple's own driver refuses another linker), llvm-objcopy makes the raw image. The
image holds .text, .rodata and .data; .bss is cleared by stage 2 itself. build_ffree.py places the
image at file offset 0x24000 of the logo, which is 0x24224000 once S-Boot has loaded it.

Two ways to check and start a kernel: --kernel (the test chain: the lengths and the hashes are those
of the build, --define KERNEL_HASH=... DTB_HASH=...) and --slot (the production loader, with --prod:
the lengths and the hashes are those of the slot the ARM32 code chose, from the record it hands over
at 0x40003000; nothing of a particular kernel is built in).
"""
import argparse
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
STAGE2 = HERE.parent / "stage2"
LLVM = Path("/opt/homebrew/opt/llvm@22/bin")
LLD = Path("/opt/homebrew/opt/lld@22/bin/ld.lld")
BASE = 0x24224000
LIMIT = 0xC000                                   # the image must end before 0x24230000, where the old rehearsal map ended


def sections(elf: Path) -> list[tuple[str, int, int, int]]:
    """Name, address, size and file offset of each section."""
    data = elf.read_bytes()
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    raw = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
    names = raw[shstrndx]
    out = []
    for section in raw:
        start = names[4] + section[0]
        out.append((data[start:data.index(b"\0", start)].decode(), section[3], section[5], section[4]))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("out", type=Path)
    parser.add_argument("--marker", required=True, help="the image's marker, e.g. HIJACK3: 7e5e7005")
    parser.add_argument("--emmc", action="store_true", help="also check (EMMC_CHECK) what S-Boot's reader put at 0x40000000")
    parser.add_argument("--el1", action="store_true", help="also enter EL1 (EL1_TEST) with the image S-Boot's reader put at 0x40080000")
    parser.add_argument("--handoff", action="store_true", help="also log (HANDOFF) the clock units, PMU and watchdog registers as S-Boot left them")
    parser.add_argument("--watchdog-proof", action="store_true", help="also arm (WATCHDOG_PROOF) the SoC watchdog for 4 s and let it reset the tablet, software reset as the fallback")
    parser.add_argument("--watchdog-arm", action="store_true", help="also arm (WATCHDOG_ARM) the SoC watchdog for 20 s before entering EL1: an image that hangs is reset")
    parser.add_argument("--kernel", nargs=4, metavar=("AT", "BYTES", "DTB_AT", "DTB_BYTES"),
                        help="also (KERNEL) check and start an arm64 Linux image and its device tree, read by S-Boot's reader to these addresses")
    parser.add_argument("--slot", action="store_true",
                        help="also (KERNEL, SLOT_RECORD) check and start the arm64 Linux image and device tree the production loader's ARM32 "
                             "code read from the slot it chose, at 0x42000000 and 0x5F000000, against the lengths and hashes of the "
                             "record it hands over at 0x40003000 (no hash of the build)")
    parser.add_argument("--prod", action="store_true", help="the production loader (PROD): no self-test, only the checks and the start")
    parser.add_argument("--smp-stubs", type=Path,
                        help="the one-core experiment (SMP_EXP): the C array scripts/build_smp_stubs.py wrote (--header), with its "
                             "directory on the include path")
    parser.add_argument("--define", action="append", default=[], metavar="NAME=VALUE",
                        help="a definition more for the C code (e.g. KERNEL_AT=0x42000000u); may be repeated")
    args = parser.parse_args()
    if args.slot and args.kernel:
        raise SystemExit("--slot and --kernel: one way to know the kernel, not both")
    if args.prod and args.kernel:
        raise SystemExit("--prod takes the kernel from the slot the ARM32 code chose (--slot), never from the build (--kernel)")
    if args.slot and any(d.split("=", 1)[0] in ("KERNEL_HASH", "DTB_HASH", "KERNEL_BYTES", "DTB_BYTES") for d in args.define):
        raise SystemExit("--slot takes the lengths and hashes from the slot's record, not from --define")
    out = args.out.resolve()
    work = out.parent
    flags = ["clang", "--target=aarch64-none-elf", "-mcpu=cortex-a53", "-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding",
             "-fno-builtin", "-fno-stack-protector", "-fno-common", "-mgeneral-regs-only", "-fno-pic",
             "-fno-asynchronous-unwind-tables", f'-DMARKER="{args.marker}"'] \
        + (["-DEMMC_CHECK"] if args.emmc or args.el1 else []) + (["-DEL1_TEST"] if args.el1 else []) \
        + (["-DHANDOFF"] if args.handoff else []) + (["-DWATCHDOG_PROOF"] if args.watchdog_proof else []) \
        + (["-DWATCHDOG_ARM"] if args.watchdog_arm else []) + (["-DPROD"] if args.prod else []) \
        + ["-D" + d for d in args.define] \
        + (["-DSMP_EXP", "-I" + str(args.smp_stubs.resolve().parent)] if args.smp_stubs else []) \
        + (["-DKERNEL", f"-DKERNEL_AT={args.kernel[0]}u", f"-DKERNEL_BYTES={args.kernel[1]}u",
            f"-DDTB_AT={args.kernel[2]}u", f"-DDTB_BYTES={args.kernel[3]}u"] if args.kernel else []) \
        + (["-DKERNEL", "-DSLOT_RECORD", "-DKERNEL_AT=0x42000000u", "-DDTB_AT=0x5F000000u"] if args.slot else [])
    subprocess.run(flags + ["-c", "-o", str(work / "stage2c.o"), str(STAGE2 / "stage2.c")], check=True)
    subprocess.run(flags + ["-c", "-o", str(work / "stage2s.o"), str(STAGE2 / "crt0.S")], check=True)
    objects = [str(work / "stage2c.o"), str(work / "stage2s.o")]
    if args.el1 or args.kernel or args.slot:
        subprocess.run(flags + ["-c", "-o", str(work / "stage2el1.o"), str(STAGE2 / "boot_el1.S")], check=True)
        objects.append(str(work / "stage2el1.o"))
    elf = work / "stage2.elf"
    subprocess.run([str(LLD), "-T", str(STAGE2 / "stage2.ld"), "--entry", "stage2_entry", "-o", str(elf)] + objects, check=True)
    subprocess.run([str(LLVM / "llvm-objcopy"), "-O", "binary", str(elf), str(out)], check=True)
    image = out.read_bytes()
    for name, address, size, _ in sections(elf):
        if name.startswith(".text") or name in (".rodata", ".data", ".bss"):
            print(f"    {name:12s} at {address:#010x}, {size:#x} bytes")
    symbols = subprocess.run([str(LLVM / "llvm-nm"), "-n", str(elf)], capture_output=True, text=True, check=True).stdout
    # The entry clears .bss with 64-bit stores: on the tablet a store to an address that is not a multiple
    # of 8 is an alignment fault (SCTLR_EL2.A = 1), which the emulator does not check (2026-11-24, image smp1).
    ends = {line.split()[2]: int(line.split()[0], 16) for line in symbols.splitlines() if line.strip() and line.split()[2] in ("__bss_start", "__bss_end")}
    if len(ends) != 2 or any(value % 8 for value in ends.values()):
        raise SystemExit(f".bss must begin and end on multiples of 8: {', '.join(f'{k}={v:#x}' for k, v in ends.items())}")
    print("    " + "  ".join(line.split()[2] + "=" + line.split()[0] for line in symbols.splitlines() if line.strip()
                         and not line.split()[2].startswith(("$x", "$d"))))
    if len(image) > LIMIT:
        raise SystemExit(f"the image is {len(image):#x} bytes: too big")
    if image[3] & 0x9F != 0x10:                      # ADR or ADRP: bits 31 (op) and 28 to 24; bits 30 and 29 are the immediate
        raise SystemExit("the image does not start with the entry's first instruction (an adr)")
    print(f"{out}: {len(image)} bytes, linked at {BASE:#010x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
