#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Build the two stubs a secondary core runs in the one-core experiment (stage2/stage2.c, SMP_EXP).

    venv/bin/python -I scripts/build_smp_stubs.py OUT.bin --marker "HIJACK3: 7e5e7021" [--header OUT.h]

  stage2/smp_stub32.S at STUB32 (0x41000000): ARM32, the entry the boot CPU writes into sysram-ns + 0x1c
      before A53 core 1 is powered on; it ends with the monitor's call to the second stub;
  stage2/smp_stub64.S at STUB64 (0x41000800): AArch64 at EL2, if the monitor switches this core too.
  Each is linked where it runs and padded to STUB_BYTES: OUT.bin holds what goes to 0x41000000 in the
  memory, and the scratch page follows at 0x41001000 (SP_EL1 at 0x41002000). The code is read back with
  capstone, and what it built is checked; --header writes the C array stage 2 carries.
"""
import argparse
import struct
import subprocess
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_ARM, Cs

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

STAGE2 = HERE.parent / "stage2"
LLD = Path("/opt/homebrew/opt/lld@22/bin/ld.lld")
OBJCOPY = Path("/opt/homebrew/opt/llvm@22/bin/llvm-objcopy")
STUB32, STUB64, STUB_BYTES = 0x41000000, 0x41000800, 0x800
SCRATCH, STACK_TOP = 0x41001000, 0x41002000


def build(source: Path, target: str, at: int, obj: Path, marker: str) -> bytes:
    command = ["clang", f"--target={target}", "-mcpu=cortex-a53", "-fno-asynchronous-unwind-tables", "-c", "-o", str(obj),
               str(source), f'-DMARKER="{marker}"', f"-DSTUB32={STUB32:#x}", f"-DSTUB64={STUB64:#x}",
               f"-DSCRATCH={SCRATCH:#x}", f"-DSTACK_TOP={STACK_TOP:#x}"]
    subprocess.run(command, check=True)
    # linked where it runs: the literal pool holds the addresses of its own texts
    elf, raw = obj.with_suffix(".elf"), obj.with_suffix(".raw")
    subprocess.run([str(LLD), f"-Ttext={at:#x}", f"--entry={source.stem}", "-o", str(elf), str(obj)], check=True)
    subprocess.run([str(OBJCOPY), "-O", "binary", str(elf), str(raw)], check=True)
    code = raw.read_bytes()
    if len(code) > STUB_BYTES:
        raise SystemExit(f"{source.name} is {len(code):#x} bytes: more than its {STUB_BYTES:#x}")
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("out", type=Path)
    parser.add_argument("--marker", required=True, help="the image's marker, e.g. HIJACK3: 7e5e7021")
    parser.add_argument("--header", type=Path, help="write the C array here (what stage 2 carries)")
    args = parser.parse_args()
    work = args.out.resolve().parent
    out = args.out.resolve()
    work.mkdir(parents=True, exist_ok=True)
    marker = args.marker

    a32 = build(STAGE2 / "smp_stub32.S", "arm-none-eabi", STUB32, work / "smp_stub32.o", marker)
    a64 = build(STAGE2 / "smp_stub64.S", "aarch64-none-elf", STUB64, work / "smp_stub64.o", marker)
    image = a32 + bytes(STUB_BYTES - len(a32)) + a64 + bytes(STUB_BYTES - len(a64))
    out.write_bytes(image)

    md32, md64 = Cs(CS_ARCH_ARM, CS_MODE_ARM), Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    ins32 = list(md32.disasm(a32, STUB32))
    code32 = a32.index(marker.encode())
    ins64 = list(md64.disasm(a64, STUB64))
    eret = [i for i in ins64 if i.mnemonic == "eret"]
    texts64 = a64.index(marker.encode())
    print(f"{STAGE2 / 'smp_stub32.S'}: {len(a32):#x} bytes at {STUB32:#010x} (the code and its literal pool {code32:#x}, then the texts), read back:")
    for ins in ins32:
        if ins.mnemonic == "smc" or ins.address == STUB32 or (ins.mnemonic == "movt" and "0x8200" in ins.op_str):
            print(f"    {ins.address:08x}  {ins.mnemonic:8s} {ins.op_str}")
    if ins32[0].mnemonic != "movw" or sum(i.mnemonic == "smc" for i in ins32) != 1:
        raise SystemExit("the ARM32 stub does not start with movw, or has not exactly one smc")
    print(f"{STAGE2 / 'smp_stub64.S'}: {len(a64):#x} bytes at {STUB64:#010x} (the code and its texts {texts64:#x}, the digits at the end), read back:")
    for ins in ins64:
        if ins.mnemonic in ("eret", "smc", "hvc") or ins.address == STUB64:
            print(f"    {ins.address:08x}  {ins.mnemonic:8s} {ins.op_str}")
    if ins64[0].mnemonic != "msr" or len(eret) != 1 or any(i.mnemonic in ("smc", "hvc") for i in ins64):
        raise SystemExit("the AArch64 stub does not start with msr, or has not exactly one eret and no other call")
    for base, code, listing in ((STUB32, a32, ins32), (STUB64, a64, ins64)):
        for ins in listing:                                         # AArch64 adr reaches anything near: its texts stay inside
            if ins.mnemonic == "adr":
                at = int(ins.op_str.split(", ")[1].lstrip("#"), 0)
                if not base <= at < base + len(code):
                    raise SystemExit(f"adr {ins.op_str} at {ins.address:#010x} leaves the stub")
    for name, data in (("the ARM32 stub", a32), ("the AArch64 stub", a64)):
        if data.count(marker.encode()) != (3 if data is a32 else 4):
            raise SystemExit(f"{name} does not carry the marker before each of its lines")
    words = struct.unpack(f"<{len(image) // 4}I", image)
    print(f"{out.name}: {len(image):#x} bytes (the scratch page at {SCRATCH:#010x}); the sum of its words as 32 bits: "
          f"{sum(words) & 0xFFFFFFFF:#010x}; sha256 ", end="")
    import hashlib
    print(hashlib.sha256(image).hexdigest()[:16])

    if args.header:
        lines = [f"/* Generated by scripts/build_smp_stubs.py: the two stubs of the one-core experiment as built, {len(image):#x} bytes",
                 f"   for 0x41000000 in the memory (smp_stub32.S at {STUB32:#010x}, smp_stub64.S at {STUB64:#010x}; the scratch page",
                 f"   follows at {SCRATCH:#010x}). The sum of the words as 32 bits: {sum(words) & 0xFFFFFFFF:#010x}. */",
                 "static const uint8_t smp_stubs[] __attribute__((aligned(8))) = {"]
        for at in range(0, len(image), 16):
            lines.append("    " + ", ".join(f"0x{byte:02x}" for byte in image[at:at + 16]) + ",")
        lines.append("};")
        args.header.write_text("\n".join(lines) + "\n")
        print(f"{args.header.name}: the array for stage 2")
    return 0


if __name__ == "__main__":
    sys.exit(main())
