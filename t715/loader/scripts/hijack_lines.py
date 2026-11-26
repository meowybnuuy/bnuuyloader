#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""List the lines the payloads wrote in S-Boot's log ring, each with the time of its boot.

    venv/bin/python -I scripts/hijack_lines.py RAW [PATTERN]

RAW is a dump made with tools/seclog_dump. Every line holding PATTERN (default "HIJACK") is shown
with the RTC time S-Boot logged at the start of the boot it belongs to, the PMIC power-on source and
reboot-mode lines of that boot, and whether the kernel's log follows it. Device identifiers are
masked. The ring's write counter is the word at 0x25FFFFFC; 0x25FFFFF8 is the magic "LOGM".
"""
import bisect
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sbootlog import BASE, SIZE, mask  # noqa: E402


def main() -> int:
    raw = Path(sys.argv[1]).read_bytes()
    pattern = sys.argv[2] if len(sys.argv) > 2 else "HIJACK"
    start = BASE - 0x25FFF000
    ptr = struct.unpack_from("<I", raw, start - 4)[0] & (SIZE - 1)
    ring = raw[start:]
    text = (ring[ptr:] + ring[:ptr]).decode("latin1")
    marks = [m.start() for m in re.finditer(r"PARAM ENV VERSION", text)]
    found = 0
    for m in re.finditer(r"[^\r\n]*" + re.escape(pattern) + r"[^\r\n]*", text):
        i = bisect.bisect_right(marks, m.start()) - 1
        if i < 0:
            continue
        boot = text[marks[i]: marks[i + 1] if i + 1 < len(marks) else len(text)]
        kernel = boot.find("Booting Linux on physical CPU")
        rtc = re.search(r"RTC TIME: ([^\r\n]*)", boot)
        pwr = re.search(r"PMIC_PWRONSRC\s*=\s*([^\r\n]*)", boot)
        mode = re.search(r"s5p_check_reboot_mode: ([^\r\n]*)", boot)
        exc = "EXCEPTION" if "Exception:" in boot[:kernel if kernel >= 0 else len(boot)] else "no exception"
        found += 1
        print(f"boot {i + 1}/{len(marks)}: {rtc.group(1) if rtc else '?'} | {pwr.group(1) if pwr else ''} | "
              f"{mode.group(1) if mode else ''} | {'kernel started' if kernel >= 0 else 'NO KERNEL LOG'} | {exc}\n"
              f"      {mask(m.group(0))}")
    print(f"write pointer {ptr:#x}; {len(marks)} S-Boot logs; {found} line(s) with {pattern!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
