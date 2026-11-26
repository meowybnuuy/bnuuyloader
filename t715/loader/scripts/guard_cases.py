#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Rehearse the guard of a `sreset` image against a real dump of S-Boot's log ring, in the cases it
must tell apart. Each case replays the payload at a moment of the past; the dump's texts stand in
for the image's marker (--needle): its old ARM32 line for the marker, its old AArch64 line for the
end of a test.

    venv/bin/python -I scripts/guard_cases.py LOGO_FILE RING_DUMP

The production loader's logo (scripts/build_kboot.py --prod: it holds "KBOOT: try") has no such
guard: its guard is the ledger. Then every decision the loader logged on the tablet that the dump
holds ("KBOOT: try: ..." when it went on, "KBOOT: fallback for this boot" when it gave the boot to
S-Boot's kernel; kboot1's "KBOOT: start: " for going on) is replayed: the ring as the dump has it,
the write counter just before that line, CACHE empty. Two models of the ledger, written here in
Python on the same ring: the rule the tablet's loaders had (kboot1 to kboot5: the boot before only)
must give what the tablet decided, which checks the replay itself; the rule of kboot6 (the two boots
before; a try counts unless that boot logged "KBOOT: up" or a hand-back of the loader) must give what
the loader decides. Then the same with the ring turned so that the boots before sit across the
start of the ring.

Prints one line per case and exits with 1 if any of them fails.
"""
import re
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
RING_MASK = 0x1FFFFF
NEEDLE = "HIJACK2: ARM32 pa"
RUN_LINE, A64_LINE = "HIJACK2: ARM32 payload", "CurrentEL=00000008"


def play(logo: Path, ring: Path, options: list[str]) -> str:
    command = [sys.executable, "-I", str(Path(__file__).resolve().parent / "preflight.py"), str(logo), "--payload", "sreset",
               "--ring", str(ring), "--needle", NEEDLE] + options
    return subprocess.run(command, capture_output=True, text=True).stdout


def verdict(out: str) -> str:
    return "RUN" if "THE TEST RUNS" in out else "SKIP" if "THE TEST IS SKIPPED" in out else "NEITHER"


def check(name: str, out: str, wanted: str, failures: int) -> int:
    got = verdict(out)
    logged = [line.split("log: ", 1)[1] for line in out.splitlines() if "printf would log" in line]
    ok = got == wanted
    print(f"{'PASS' if ok else 'FAIL'}  {name}: wanted {wanted}, got {got}; logged {logged[:1]}")
    if not ok:
        print("\n".join("      " + line[:200] for line in out.splitlines()[:12]))
    return failures + (not ok)


KBOOT_DECISIONS = (("KBOOT: try: the arm64 kernel of CACHE is tried this boot", "go"),
                   ("KBOOT: start: ", "go"),                   # kboot1's line for the same decision (2026-11-24)
                   ("KBOOT: fallback for this boot", "fallback"))


def ring_rfind(ring: bytes, frm: int, span: int, text: bytes) -> int:
    """The highest position p, frm - span <= p < frm (from 0 if that is below 0), where the ring (addressed by
    p & RING_MASK) holds `text`, its bytes possibly reaching past frm; 0 if none: the loader's rfind."""
    lowest = max(0, frm - span)
    count = frm - lowest + len(text) - 1
    at = lowest & RING_MASK
    window = ring[at:at + count] if at + count <= len(ring) else ring[at:] + ring[:count - (len(ring) - at)]
    found = window.rfind(text, 0, count)
    return lowest + found if found >= 0 else 0


def rule_then(ring: bytes, counter: int) -> str:
    """The ledger of kboot1 to kboot5: the boot before only; its last "KBOOT: try", then "KBOOT: u" (8 characters)."""
    start = ring_rfind(ring, counter, 0x20000, b"PARAM ENV VERSION")
    before = ring_rfind(ring, start, 0x180000, b"PARAM ENV VERSION") if start else 0
    tried = ring_rfind(ring, start, start - before, b"KBOOT: try") if before else 0
    return "fallback" if tried and not ring_rfind(ring, start, start - tried, b"KBOOT: u") else "go"


def rule_now(ring: bytes, counter: int) -> str:
    """The ledger since kboot6: the two boots before, no further back than 0x1F0000 bytes; a try counts unless that
    boot logged "KBOOT: up" or a hand-back of the loader ("S-Boot's kernel boots") after it."""
    lowest = max(0, counter - 0x1F0000)
    end = ring_rfind(ring, counter, 0x20000, b"PARAM ENV VERSION")
    for _ in range(2):
        if not end or end <= lowest:
            return "go"
        start = ring_rfind(ring, end, end - lowest, b"PARAM ENV VERSION")
        if not start:
            return "go"
        tried = ring_rfind(ring, end, end - start, b"KBOOT: try")
        if tried and not ring_rfind(ring, end, end - tried, b"KBOOT: up") \
                and not ring_rfind(ring, end, end - tried, b"S-Boot's kernel boots"):
            return "fallback"
        end = start
    return "go"


def kboot_play(logo: Path, ring: Path, options: list[str]) -> tuple[str, list[str]]:
    """The production loader at a moment of the dump, with CACHE empty: what it decided, and what it logged."""
    empty = Path(__file__).resolve().parent.parent / "out" / "kb" / "guard-empty.img"
    empty.parent.mkdir(parents=True, exist_ok=True)
    empty.write_bytes(b"")
    command = [sys.executable, "-I", str(Path(__file__).resolve().parent / "preflight.py"), str(logo), "--payload", "kboot",
               "--ring", str(ring), "--slot-a", str(empty), "--slot-b", str(empty), "--expect", "handback"] + options
    result = subprocess.run(command, capture_output=True, text=True)
    logged = [line.split("log: ", 1)[1].strip("'\"") for line in result.stdout.splitlines() if "printf would log" in line]
    got = ("fallback" if any(line.startswith("KBOOT: fallback for this boot") for line in logged)
           else "go" if any(line.startswith("KBOOT: try: the arm64") for line in logged) else "neither")
    if result.returncode:
        got = "failed: " + " ".join((result.stdout + result.stderr).strip().splitlines()[-1:])[:150]
    return got, logged


def kboot_main(logo: Path, ring: Path, full: bytes) -> int:
    decisions = sorted((m.start(), text, k + 1, wanted) for text, wanted in KBOOT_DECISIONS
                       for k, m in enumerate(re.finditer(re.escape(text.encode()), full)))
    print(f"{ring.name}: {len(decisions)} decision(s) of the production loader logged on the tablet "
          f"({sum(d[3] == 'go' for d in decisions)} to go on, {sum(d[3] == 'fallback' for d in decisions)} to fall back)")
    failures = 0
    for at, text, nth, tablet in decisions:         # the counter as preflight.py sets it: the line's offset in the ring
        then, now = rule_then(full, at), rule_now(full, at)
        got, logged = kboot_play(logo, ring, ["--before", text, "--nth", str(nth)])
        ok = then == tablet and got == now
        print(f"{'PASS' if ok else 'FAIL'}  the decision at ring offset {at:#x} ({text.strip()!r} #{nth}): the tablet decided {tablet} "
              f"(the rule it had, modelled: {then}); the rule of kboot6, modelled: {now}; the loader decides {got}; logged {logged[:1]}")
        failures += not ok
    if decisions:                                   # the moments again, the ring turned: that boot's start and the boots before
        for at, text, nth, tablet in [d for d in decisions if d[3] == "fallback"][:1] + decisions[-2:-1]:   # sit at the ring's end
            shift = (RING_MASK + 1 - (at & RING_MASK) + 0x300) & RING_MASK
            turned = full[-shift:] + full[:-shift]
            then, now = rule_then(turned, at + shift), rule_now(turned, at + shift)
            got, logged = kboot_play(logo, ring, ["--before", text, "--nth", str(nth), "--rotate", hex(shift)])
            ok = then == tablet and got == now
            print(f"{'PASS' if ok else 'FAIL'}  the decision at {at:#x} ({text.strip()!r} #{nth}) with the ring turned by {shift:#x} (the "
                  f"moment 0x300 into the ring, the boots before across its start): the tablet decided {tablet} (modelled: {then}); "
                  f"kboot6's rule: {now}; the loader decides {got}")
            failures += not ok
    else:
        print("FAIL  the dump holds no decision of the production loader: nothing to replay")
        failures += 1
    print(f"{failures} failure(s)")
    return 1 if failures else 0


def main() -> int:
    logo, ring = Path(sys.argv[1]), Path(sys.argv[2])
    raw = ring.read_bytes()
    full = bytearray(RING_MASK + 1)
    full[:len(raw) - 0x1000] = raw[0x1000:]
    full = bytes(full)
    if b"KBOOT: try" in logo.read_bytes():          # the production loader: its guard is the ledger
        return kboot_main(logo, ring, full)
    failures = 0
    # A test boot leaves "ARM32 payload running" (whatever the marker of that image), then, if it got
    # that far, "CurrentEL=". Count from the newest: the boot that follows it must skip.
    starts = [m.start() for m in re.finditer(b"ARM32 payload running", full)]
    reaches = [m.start() for m in re.finditer(b"CurrentEL=", full)]
    print(f"{ring.name}: {len(starts)} test boot(s) with the old payload line, {len(reaches)} that reached AArch64")
    for k in range(1, len(starts) + 1):
        start = starts[-k]
        after = [r for r in reaches if r > start]
        if not after:
            print(f"SKIP  test boot #{k}: it did not reach AArch64")
            continue
        marker = full[start - 18:start - 1].decode("latin1")          # "<marker> ARM32 payload running"
        if len(marker) != 17 or not marker.startswith("HIJACK"):
            print(f"SKIP  test boot #{k}: no 17-character marker before its line ({marker!r})")
            continue
        failures = check(f"test boot #{k} ({marker}), when its payload starts (the boot before it ran no test)",
                         play(logo, ring, ["--needle", marker, "--before", "ARM32 payload running", "--nth", str(len(starts) - k + 1)]), "RUN", failures)
        if not any(start - 0x6000 < m.start() < start for m in re.finditer(b"PARAM ENV VERSION", full)):
            print(f"SKIP  test boot #{k} ({marker}): the start of its S-Boot log is not in the dump (cut by the ring's end)")
            continue
        failures = check(f"test boot #{k} ({marker}), the boot that follows it (the test is in the boot before)",
                         play(logo, ring, ["--needle", marker, "--after", "CurrentEL=", "--nth", str(reaches.index(after[0]) + 1), "--then", "boot"]), "SKIP", failures)
    if starts:
        k = 1
        marker = full[starts[-k] - 18:starts[-k] - 1].decode("latin1")
        first = [r for r in reaches if r > starts[-1]][0]
        failures = check("after a boot that skipped, the next boot skips too",
                         play(logo, ring, ["--needle", marker, "--after", "CurrentEL=", "--nth", str(reaches.index(first) + 1), "--then", "boot,skip,boot"]), "SKIP", failures)
        # the same with the lines across the start of the ring: the counter lands 0x300 bytes into it
        after = first + len("CurrentEL=")
        starts_boot = max(m.start() for m in re.finditer(b"PARAM ENV VERSION", full) if m.start() < after)
        hit = [m.start() for m in re.finditer(b"ARM32 payload running", full) if m.start() > starts_boot]
        moment = after + hit[0] - starts_boot if hit else after
        shift = (RING_MASK + 1 - (moment & RING_MASK) + 0x300) & RING_MASK
        failures = check("the boot that follows a test, the lines wrapped across the start of the ring",
                         play(logo, ring, ["--needle", marker, "--after", "CurrentEL=", "--nth", str(reaches.index(first) + 1), "--then", "boot", "--rotate", hex(shift)]), "SKIP", failures)
    print(f"{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
