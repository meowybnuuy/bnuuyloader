#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Split the sec_log ring into boots and show where each S-Boot log stops.

    venv/bin/python -I scripts/sbootlog.py RAW [--full N] [--mask]

RAW is the dump of [0x25fff000, 0x261ff000) read through tools/seclog_dump. The log is unwrapped
from the header's write pointer; each S-Boot log starts at "PARAM ENV VERSION" and ends at the
kernel's first line or at the next S-Boot log. Device identifiers (eMMC serial number, connie,
cordon, serial numbers, MAC addresses) are masked.
"""
import re
import struct
import sys
from pathlib import Path

BASE, SIZE = 0x26000000, 0x200000


def mask(text: str) -> str:
    text = re.sub(r"\{\{[0-9A-Fa-f]+\}\}", "{{…}}", text)
    text = re.sub(r"(connie=|cordon=|serialno=|androidboot\.serialno=)\S+", r"\1…", text)
    text = re.sub(r"(ATAG_SERIAL:\s*4\s+54410006\s+)\S+\s+\S+", r"\1… …", text)      # the serial number as two words
    text = re.sub(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", "…:…", text)
    return text


def main() -> int:
    raw = Path(sys.argv[1]).read_bytes()
    full = next((int(a) for a in sys.argv[2:] if a.isdigit()), None)
    start = BASE - 0x25FFF000
    ptr = struct.unpack_from("<I", raw, start - 4)[0] & (SIZE - 1)      # the write counter at 0x25FFFFFC (0x25FFFFF8 is "LOGM")
    ring = raw[start:]
    text = (ring[ptr:] + ring[:ptr]).decode("latin1")
    marks = [m.start() for m in re.finditer(r"PARAM ENV VERSION", text)]
    kernels = [m.start() for m in re.finditer(r"Booting Linux on physical CPU", text)]
    print(f"ring {SIZE:#x} bytes, write pointer {ptr:#x}, {len(marks)} S-Boot logs, {len(kernels)} kernel logs")
    for i, m in enumerate(marks):
        end = marks[i + 1] if i + 1 < len(marks) else len(text)
        boot = text[m:end]
        k = boot.find("Booting Linux on physical CPU")
        sboot = boot[:k] if k >= 0 else boot
        body = sboot.replace("\r", "")
        print(f"\n=== S-Boot log {i + 1}/{len(marks)} at ring+{(ptr + m) & (SIZE - 1):#08x}: {len(sboot)} characters, "
              f"{'kernel started' if k >= 0 else 'NO KERNEL LOG FOLLOWS'}")
        if full == i + 1 or full == 0:
            print(mask(body))
        else:
            lines = [l for l in body.split("\n") if l.strip()]
            print("   last lines:")
            for line in lines[-7:]:
                print("      " + mask(line)[:150])
    return 0


if __name__ == "__main__":
    sys.exit(main())
