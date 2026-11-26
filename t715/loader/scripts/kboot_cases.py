#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Rehearse the production loader against every situation it must handle, in the emulator.

    venv/bin/python -I scripts/kboot_cases.py LOGO --slot-good FILE [--slot-other FILE] [--ring RAW]

LOGO is the loader's logo file (out/NAME-logo.jpg of a --prod build) and FILE a good slot image
(scripts/build_slot.py). Each case says what the log of the boot before holds (the ledger), what the
two slots of CACHE hold, and whether S-Boot maps the memory the loader needs; the loader must then
start the kernel from the expected slot, or hand S-Boot its own kernel. The slots are rebuilt for
each case from the good one (generations, a byte corrupted after hashing, never written). The ring
is a real dump (the latest by default) with the boots of the case logged after it.

Since kboot4 the loader holds nothing of a kernel: stage 2 checks the kernel against the record the
ARM32 code hands it (the chosen header). The cases marked "other" put a different kernel in a slot:
--slot-other (a good slot with another kernel), or by default the good one's kernel and tree with a
byte of each changed and hashed again (a valid kernel no build of the loader has seen). The "reset"
cases change what reaches EL2 (preflight.py --tamper): the record missing or corrupt, or the kernel
changed after the ARM32 code hashed it; stage 2 must refuse and reset the SoC, and the boot after it
is the second case's (the ledger's try without up: S-Boot's kernel boots).

The ledger's cases (since kboot6): the boots before this one, oldest first (preflight.py --ledger),
for the rule that a boot falls back if one of its two previous boots tried and logged neither
"KBOOT: up" nor a hand-back of the loader: the detour of a failed attempt (a watchdog reset, then
RECOVERY where the loader fell back, then BOOT), a try two boots back with its up, a hand-back, a
"KBOOT: u..." line that is not an up, and a ring with fewer than two boots (a cold power-on).

The "carry" case (since 2026-11-24): the ARM32 fnv64 routine added the carry of its 32-bit sum
for the high word back into it, which is bit 64 of the product and must be dropped; about one byte in
10 to 20 million showed it, and no kernel rehearsed until then had one. The good slot's kernel gets
three bytes chosen so that the routine as it was meets that carry (a model of it, searched with
numpy over the 2^24 choices); the loader must start that slot, the ARM32 hash equal to
build_slot.fnv1a's.

Exit codes: 0 every case passes, 1 a case fails.
"""
from __future__ import annotations

import argparse
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build_ffree as bf  # noqa: E402
import build_slot as bs  # noqa: E402

DUMPS = HERE.parent / "dumps" / "sbootlog"
WORK = HERE.parent / "out" / "kb" / "cases"
FIRST = {letter: bf.CACHE_SECTOR + rel for letter, rel in bf.SLOT_REL.items()}
IMAGE_AT = {letter: first + bf.SLOT_HEADER_BYTES // 512 for letter, first in FIRST.items()}   # where each slot's image starts


def variant(good: bytes, generation: int | None, corrupt: bool = False) -> bytes:
    """The same kernel in a slot with another generation (None: never written), its bytes corrupted or not."""
    if generation is None:
        return b""
    said = bs.read_slot(good)
    image = good[bf.SLOT_HEADER_BYTES: bf.SLOT_HEADER_BYTES + said["image"]]
    tree = good[bf.SLOT_HEADER_BYTES + said["image"]: bf.SLOT_HEADER_BYTES + said["image"] + said["dtb"]]
    return bs.make_slot(image, tree, generation, corrupt=corrupt)   # make_slot changes the byte after hashing


FNV_BASIS, M32 = 0xCBF29CE484222325, 0xFFFFFFFF


def fnv64_as_it_was(data: bytes, h: int = FNV_BASIS) -> int:
    """The ARM32 fnv64 routine until 2026-11-24, a byte at a time: the carry of high32(lo * 0x1B3) +
    low32(hi * 0x1B3) went back into the high word (`adds` then `adc`), where FNV-1a 64 drops it."""
    lo, hi = h & M32, h >> 32
    for byte in data:
        lo ^= byte
        product = lo * 0x1B3
        total = (product >> 32) + ((hi * 0x1B3) & M32)
        hi = ((lo << 8) + total + (total >> 32)) & M32
        lo = product & M32
    return hi << 32 | lo


def fnv64(data: bytes, h: int = FNV_BASIS) -> int:
    """FNV-1a 64 from a state: build_slot.fnv1a's, taken further."""
    for byte in data:
        h = ((h ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def carry_slot(good: bytes) -> tuple[bytes, str]:
    """The good slot with three bytes of its kernel changed, so that the routine as it was meets the carry it
    mishandled at one of them or the byte after: the slot's header is right (build_slot.fnv1a), and only a
    routine that drops that carry finds the image as its header says. The arm64 header is left alone."""
    import numpy as np
    said = bs.read_slot(good)
    image = bytearray(good[bf.SLOT_HEADER_BYTES: bf.SLOT_HEADER_BYTES + said["image"]])
    tree = good[bf.SLOT_HEADER_BYTES + said["image"]: bf.SLOT_HEADER_BYTES + said["image"] + said["dtb"]]
    mask, prime, every = np.uint64(M32), np.uint64(0x1B3), np.arange(256, dtype=np.uint64)

    def step(lo, hi, byte):                         # the correct step on 32-bit halves, and the carry the old one kept
        mixed = lo ^ byte
        product = mixed * prime
        total = (product >> np.uint64(32)) + ((hi * prime) & mask)
        return product & mask, (total + (mixed << np.uint64(8))) & mask, total >> np.uint64(32)

    for at in range(0x10000, 0x10000 + 0x40 * 0x1000, 0x1000):   # past the arm64 header; three bytes tried at each place
        before = fnv64(bytes(image[:at]))
        if fnv64_as_it_was(bytes(image[:at])) != before:   # the good one's kernel meets it already: it is the case
            return good, f"nothing changed: it meets the carry already before byte {at:#x}"
        lo0, hi0 = np.uint64(before & M32), np.uint64(before >> 32)
        nxt = np.uint64(image[at + 3])
        for b1 in range(256):
            lo1, hi1, c1 = step(lo0, hi0, np.uint64(b1))
            lo2, hi2, c2 = step(lo1, hi1, every)                         # over b2
            lo3, hi3, c3 = step(lo2[:, None], hi2[:, None], every[None, :])   # over b2, b3
            _, _, c4 = step(lo3, hi3, nxt)
            hit = (c3 | c4 | c2[:, None] | c1).nonzero()
            if hit[0].size:
                b2, b3 = int(hit[0][0]), int(hit[1][0])
                image[at:at + 3] = bytes([b1, b2, b3])
                where = next(k for k in range(1, 5) if fnv64_as_it_was(bytes(image[at:at + k]), before) != fnv64(bytes(image[at:at + k]), before))
                return bs.make_slot(bytes(image), tree, said["generation"]), f"image bytes {at:#x}..{at + 2:#x} set to " \
                    f"{b1:02x} {b2:02x} {b3:02x}: the carry at byte {at + where - 1:#x}"
    raise SystemExit("no carry found in the bytes searched")


def another(good: bytes) -> bytes:
    """A good slot with a kernel and a tree no build has seen: one byte of each changed, then hashed again
    (the image's arm64 header and the tree's own header are left as they are)."""
    said = bs.read_slot(good)
    image = bytearray(good[bf.SLOT_HEADER_BYTES: bf.SLOT_HEADER_BYTES + said["image"]])
    tree = bytearray(good[bf.SLOT_HEADER_BYTES + said["image"]: bf.SLOT_HEADER_BYTES + said["image"] + said["dtb"]])
    image[0x30000] ^= 0x5A
    tree[0x200] ^= 0x5A
    return bs.make_slot(bytes(image), bytes(tree), said["generation"])


CASES = [  # name, the boot before, slot A, slot B (generation, corrupt[, "other"]), S-Boot's table, what the loader must do,
           # the slot it takes, what changes on the way to EL2
    ("first boot: nothing is held against the kernel", "none", (1, False), None, True, "start", "A"),
    ("the boot before tried and never said it was up", "failed", (1, False), None, True, "handback", None),
    ("the boot before tried and was up", "up", (1, False), None, True, "start", "A"),
    ("slot A's bytes are not as its header says", "none", (2, True), (1, False), True, "start", "B"),
    ("slot A was never written", "none", None, (1, False), True, "start", "B"),
    ("nothing valid in CACHE", "none", None, None, True, "handback", None),
    ("both are valid and B is the newer", "none", (1, False), (2, False), True, "start", "B"),
    ("both are valid and A is the newer", "none", (4, False), (3, False), True, "start", "A"),
    ("both are corrupt", "none", (2, True), (1, True), True, "handback", None),
    ("the newer one is corrupt", "up", (1, False), (2, True), True, "start", "A"),
    ("the corrupt newer one, after a failed boot", "failed", (1, False), (2, True), True, "handback", None),
    ("S-Boot does not map the memory the loader needs", "none", (1, False), None, False, "handback", None),
    # since kboot4: the kernel is the slot's, whatever kernel the loader was built with
    ("slot A holds another kernel than the loader was built with", "none", (1, False, "other"), None, True, "start", "A"),
    ("slot B updated with another kernel, a generation higher, the same PARAM", "up", (1, False), (2, False, "other"), True, "start", "B"),
    # and what stage 2 checks of what the ARM32 code hands it: it resets, the next boot falls back by the ledger
    ("the record for EL2 is missing", "none", (1, False), None, True, "reset", "A", "record-missing"),
    ("the record for EL2 is corrupt (its generation, which only the header's own hash covers)", "none", (1, False), (2, False, "other"),
     True, "reset", "B", "record-corrupt"),
    ("the kernel changed in the memory after the ARM32 code hashed it", "none", (1, False), None, True, "reset", "A", "kernel-changed"),
    # the ARM32 hash as build_slot.fnv1a's, on a kernel whose hash meets the carry the routine mishandled before its fix
    ("a kernel whose hash meets the carry the ARM32 fnv64 once added back", "none", (1, False, "carry"), None, True, "start", "A"),
    # since kboot6: the ledger looks at the two boots before (the detour of kboot5, 2026-11-24)
    ("the detour: B1 tried and failed, B2 (RECOVERY) fell back: this boot (B3, BOOT) falls back too", "failed,fallback",
     (1, False), None, True, "handback", None),
    ("after the detour, B2 and B3 fell back: this boot (B4) tries again", "failed,fallback,fallback", (1, False), None, True, "start", "A"),
    ("a failed try two boots back, a plain boot between: this boot falls back", "failed,none", (1, False), None, True, "handback", None),
    ("a try two boots back, with its up: this boot tries", "up,none", (1, False), None, True, "start", "A"),
    ("the boot before tried and handed back by itself (no valid kernel): this boot tries", "handback", (1, False), None, True,
     "start", "A"),
    ("the boot before tried and logged 'KBOOT: u...' that is not 'KBOOT: up': this boot falls back", "failed-u", (1, False), None,
     True, "handback", None),
    ("a cold power-on: no boot before in the ring: this boot tries", "cold", (1, False), None, True, "start", "A"),
    ("a cold power-on, then one boot that tried and failed: this boot falls back", "cold,failed", (1, False), None, True,
     "handback", None),
    ("a cold power-on, then one boot that was up: this boot tries (one boot before only)", "cold,up", (1, False), None, True,
     "start", "A"),
]


def ledger_falls_back(before: str) -> bool:
    """The rule, on the boots of a case: one of the two before this one tried and logged neither up nor a hand-back."""
    boots = [kind for kind in before.split(",") if kind != "cold"]
    return any(kind in ("failed", "failed-u") for kind in boots[-2:])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("logo", type=Path)
    parser.add_argument("--slot-good", type=Path, required=True)
    parser.add_argument("--slot-other", type=Path, help="a good slot with another kernel than --slot-good (default: the good one's "
                                                        "kernel and tree with a byte of each changed, hashed again)")
    parser.add_argument("--ring", type=Path, default=None, help="a dump made with tools/seclog_dump (default: the latest)")
    args = parser.parse_args()
    ring = args.ring or max((p for p in DUMPS.glob("seclog-*.raw") if p.stat().st_size), key=lambda p: p.stat().st_mtime)
    if not ring.stat().st_size:
        raise SystemExit(f"{ring.name} is empty: a dump that failed; name one that is not with --ring")
    good = args.slot_good.read_bytes()
    other = args.slot_other.read_bytes() if args.slot_other else another(good)
    if not (bs.slot_is_sound(good) and bs.slot_is_sound(other)):
        raise SystemExit("--slot-good and the other slot must both be sound")
    if other[0x20:0x30] == good[0x20:0x30]:
        raise SystemExit("the other slot holds the same kernel and tree as the good one")
    carry, where = carry_slot(good)
    print(f"the carry slot: the good one's kernel with {where}; the routine as it was would make the image's hash "
          f"{fnv64_as_it_was(carry[bf.SLOT_HEADER_BYTES:bf.SLOT_HEADER_BYTES + bs.read_slot(carry)['image']]):016x}, "
          f"its header says {bs.read_slot(carry)['image_fnv']:016x}")
    pieces = max(-(-bs.read_slot(slot)["image"] // 0x400000) for slot in (good, other, carry))   # the reader's calls for a kernel
    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / "empty.img").write_bytes(b"")
    failures = 0
    for name, before, a, b, ttbr, expect, chosen, *rest in CASES:
        tamper = rest[0] if rest else "none"
        files = {}
        for letter, spec in (("a", a), ("b", b)):
            path = WORK / f"{letter}.img"
            if spec is None:
                path = WORK / "empty.img"
            else:
                path.write_bytes(variant({("other",): other, ("carry",): carry}.get(spec[2:], good), spec[0], spec[1]))
            files[letter] = path
        command = [sys.executable, "-I", str(HERE / "preflight.py"), str(args.logo), "--payload", "kboot", "--ring", str(ring),
                   "--ledger", before, "--slot-a", str(files["a"]), "--slot-b", str(files["b"]),
                   "--ttbr", "mapped" if ttbr else "zero", "--expect", expect, "--tamper", tamper]
        result = subprocess.run(command, capture_output=True, text=True)
        (WORK / "last.log").write_text(result.stdout + result.stderr)
        taken = re.findall(r"the kernel of slot ([AB]),", result.stdout)      # the slots whose kernel the loader read, in order
        line = next((l.strip() for l in result.stdout.splitlines() if l.startswith("KBOOT HANDS BACK")), "")
        counted = re.search(r"the storage was read (\d+) times", result.stdout)
        calls = int(counted.group(1)) if counted else 0
        problems = []
        if result.returncode != 0:
            problems.append("the rehearsal failed: " + " ".join((result.stdout + result.stderr).strip().splitlines()[-1:]))
        if expect in ("start", "reset"):
            if taken[-1:] != [chosen]:
                problems.append(f"the kernel was read last from {taken[-1:] or 'no slot'} where slot {chosen} was expected")
            if expect == "start" and "PASS: at EL2 the loader enters EL1" not in result.stdout:
                problems.append("EL2 did not enter EL1")
            if expect == "reset" and "PASS: at EL2 the loader resets the SoC" not in result.stdout:
                problems.append("EL2 did not reset the SoC")
        else:
            # no reason to touch the storage: 0; else two headers, then each slot's kernel in pieces of 4 MiB and its tree
            most = 0 if ledger_falls_back(before) or not ttbr else 2 + 2 * (pieces + 1)
            if calls > most:
                problems.append(f"the reader was called {calls} times")
        if expect == "start":
            detail = f"the kernel is started from slot {chosen} ({calls} reads of the storage)"
            said = re.search(r"checked against its header's hashes \(([0-9a-f]{16}), ([0-9a-f]{16})\)", result.stdout)
            if said:
                detail += f", checked at EL2 against its header's hashes {said.group(1)[:8]}…/{said.group(2)[:8]}…"
        elif expect == "reset":
            why = re.search(r"REFUSED, reason ([0-9a-f]{8})|(NOT every byte as the slot's header says)", result.stdout)
            detail = (f"the ARM32 code starts slot {chosen}, stage 2 refuses ("
                      + (f"the record, reason {int(why.group(1), 16):#x}" if why and why.group(1) else "the kernel's bytes" if why else "?")
                      + ") and resets the SoC; the next boot falls back by the ledger")
        else:
            detail = f"S-Boot's kernel boots ({line.split('(', 1)[-1].rstrip(')')[:100]}); {calls} reads of the storage"
        print(("PASS  " if not problems else "FAIL  ") + name + ": " + ("; ".join(problems) if problems else detail))
        failures += bool(problems)
    print(f"{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
