#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0

"""Rehearse an image in the emulator: its ARM32 payload from the forged heap to the monitor call (and
its guard against running twice), then its AArch64 entry in a 64-bit emulator.

    venv/bin/python -I scripts/preflight.py LOGO_FILE [--payload smc|sreset|kboot] [--node 0x24220000]
        [--ring RAW --needle TEXT (--before TEXT --nth N | --after TEXT --nth N) [--rotate K]]

ARM32 part. The logo goes into S-Boot's file buffer and the heap head is what S-Boot's decoder
leaves; then `boot`'s call is played: malloc_large(0x200) from the frame of 0x23e17b20, free() of
the buffer, the function's `pop {r3,r4,r5,pc}`, and so into the forged code. It runs until its `smc`
instruction, then from there to the hand-back at 0x23E069DC, and shows the registers and what it
would have logged. S-Boot's printf needs the console driver the real start-up sets up (it worked
on the device on 2026-11-24): its calls are skipped and their text printed instead; the long
loops and the cache instructions are skipped too. What the monitor does is not emulated. The places
where the rehearsal acts are found by decoding the ARM32 code, so they follow it when it changes.

The guard (--ring, `sreset` only). With a real dump of S-Boot's log ring in memory and its write
counter set to a moment of the past (just --before or just --after the N-th occurrence of a text,
in the order of the dump), the code must run the test, or skip it when the S-Boot log of the boot
before that moment holds its marker. --needle replaces the image's marker in memory by a text of
the same length that the dump holds. --then logs, after the moment, what the following boots
would ("boot": the S-Boot log of a boot up to where its payload starts; "skip": the line the
payload logs instead of the test), which is how the boot after a self-reset is replayed.
--rotate K moves the ring's content K bytes forward so that the moment sits across the start
of the ring.

AArch64 part. The entry runs in a 64-bit emulator with the log ring, the framebuffer, the display
controller's two registers and the power management unit mapped; the long loops are cut.

The production loader (--payload kboot, with --slot-a, --slot-b and --expect). The ARM32 part reads
the slots as S-Boot's reader would, and what it leaves for EL2 at 0x40003000 (the record: the chosen
header, its first sector, "T7KR") is checked against the slot it read the kernel from, then carried
into the AArch64 emulator with the kernel and the tree, where stage 2 checks them against it.
--tamper changes something between the two, to rehearse stage 2's own checks: the record missing (as
if the ARM32 code had written none), one byte of it changed, or one byte of the kernel changed after
the ARM32 code hashed it; stage 2 must then reset the SoC (--expect reset). The boot before is
--ledger (the real dump, then a boot logged after it), or the real dump alone at a moment of the past
(--before/--after TEXT --nth N, --rotate K: the replays of scripts/guard_cases.py).
"""
import argparse
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sboot_jpeg_emu as e
from unicorn import UC_HOOK_CODE, UcError
from unicorn.arm_const import (UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R12,
                               UC_ARM_REG_SP)

HEADER = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 01 00 00 00 22 24 24 24")
BACK, END = 0x00002000, 0x00003000            # where the calls "return to"
HAND_BACK = 0x23E069DC                        # boot, right after its call
RING, RING_MASK, COUNTER = 0x26000000, 0x1FFFFF, 0x25FFFFFC
PRINTABLE = set(range(32, 127)) | {0, 9, 10, 13}


def text_at(uc, address: int, limit: int = 160) -> str:
    out = bytearray()
    while len(out) < limit:
        (byte,) = bytes(uc.mem_read(address + len(out), 1))
        if byte == 0:
            break
        out.append(byte)
    return out.decode("latin1")


def find_places(logo: bytes, off: int, node: int, limit: int) -> dict:
    """In the ARM32 code (node + 0x110 .. node + limit): the printf calls, the data-cache clean loop,
    the barrier and cache instructions, the smc, and the call to S-Boot's reader (0x23E17808), found
    by the literal loaded into r4 just before it. Text and literals decode into nonsense, never into
    these (their words are not all printable, and carry another condition code)."""
    from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    places = {"printf": [], "clean": None, "skip": [], "smc": None, "mmc": [], "ttbr": []}
    reader_loaded = False
    for pos in range(0x110, limit - 3, 4):
        word = logo[off + pos: off + pos + 4]
        if all(b in PRINTABLE for b in word):
            continue
        got = list(md.disasm(word, node + pos))
        ins = got[0] if got else None
        if ins is None:
            continue
        if ins.mnemonic == "blx" and ins.op_str == "r4":
            if reader_loaded:
                places["mmc"].append(ins.address)
                reader_loaded = False
            else:
                places["printf"].append(ins.address)
        elif ins.mnemonic == "ldr" and ins.op_str.startswith("r4, [pc"):
            literal = ((ins.address + 8) & ~3) + int(ins.op_str.rsplit("#", 1)[-1].rstrip("]"), 0)
            (value,) = struct.unpack_from("<I", logo, off + literal - node)
            reader_loaded = value == 0x23E17808
        elif ins.mnemonic == "mcr" and ins.op_str.replace("#", "") == "p15, 0, r4, c7, c10, 1":
            places["clean"] = ins.address
        elif ins.mnemonic == "mrc" and ins.op_str.replace("#", "") == "p15, 0, r4, c2, c0, 0":
            places["ttbr"].append(ins.address)       # a read of the first-level table's address (kboot)
        elif ins.mnemonic in ("mcr", "mrc", "dsb", "isb", "dmb"):
            places["skip"].append(ins.address)
        elif ins.mnemonic == "smc":
            places["smc"] = ins.address
    return places


def rehearse_arm32(logo: bytes, node: int, a64_off: int | None, ring: bytes | None, counter: int | None,
                   slots: dict | None = None, ttbr: bool = True) -> list:
    """Returns the reader's calls as the ARM32 code makes them: (destination, first sector, bytes).
    With `slots` ({letter: the slot's bytes as written in CACHE}), the production loader is rehearsed
    for real: the reader's calls are answered with the slots' bytes, read into the memory where the
    code asked for them, and `ttbr` says whether S-Boot's first-level table is made to map what the
    code needs (a stand-in table, read in place of the TTBR0 the emulator has not)."""
    import build_ffree as bf
    sboot = e.SBoot(e.IMAGE.read_bytes(), fast=True)
    uc = sboot.uc
    off = node - e.FILE_BUFFER
    uc.mem_write(e.FILE_BUFFER, logo + bytes(max(0, 0x100000 - len(logo))))
    uc.mem_write(0x24F00000, HEADER + bytes(12))
    if ring is not None:
        try:
            uc.mem_map(0x25FFF000, 0x201000)
        except UcError:
            pass
        uc.mem_write(0x25FFF000, bytes(0x1000))
        uc.mem_write(RING, ring)
        uc.mem_write(COUNTER, struct.pack("<I", counter))
    places = find_places(logo, off, node, a64_off or 0x800)
    print(f"ARM32 code at {node + 0x110:#010x}: printf calls {[hex(a) for a in places['printf']]}, S-Boot's reader "
          f"{[hex(a) for a in places['mmc']] or 'not called'}, data-cache clean "
          f"{hex(places['clean']) if places['clean'] else None}, instructions skipped {len(places['skip'])}, smc "
          f"{hex(places['smc']) if places['smc'] else None}")
    if not places["printf"] or places["clean"] is None or places["smc"] is None:
        raise SystemExit("the ARM32 code does not have the expected shape")
    buffer = sboot.call(0x23E071D8, [0x200], sp=0x23EC0008, until=BACK, lr=BACK)
    print(f"malloc_large(0x200) returned {buffer:#010x} (wanted 0x23EC0018); the stack at 0x23EC0008: "
          f"{bytes(uc.mem_read(0x23EC0008, 16)).hex(' ')}")
    uc.mem_write(0x23EC0004, struct.pack("<I", END))
    sboot.call(0x23E071FC, [buffer], sp=0x23EC0008, until=END, lr=END)
    print(f"after free(): the stack at 0x23EC0008: {bytes(uc.mem_read(0x23EC0008, 16)).hex(' ')}; "
          f"false free block F: {bytes(uc.mem_read(0x24220000, 16)).hex(' ')}")
    # 0x23e17b68: pop {r3, r4, r5, pc}; then the payload, with its calls, loops and cache instructions cut
    uc.reg_write(UC_ARM_REG_SP, 0x23EC0008)
    uc.reg_write(UC_ARM_REG_LR, END)
    seen: dict[str, int] = {}
    logged: list[str] = []
    reads: list[tuple[int, int, int]] = []

    def aapcs_return(u, r0: int, ip: int):
        """S-Boot's functions are C: on return r0 holds the result and r1-r3 and r12 (ip) are the callee's
        to clobber (AAPCS).  The stand-ins clobber them too: on the tablet (2026-11-24, kboot2) the reader
        came back with r12 = 0, which the production loader had kept a slot's sector in, and the rehearsal,
        whose stand-ins left r12 alone, had not seen it."""
        u.reg_write(UC_ARM_REG_R0, r0 & 0xFFFFFFFF)
        for reg, junk in ((UC_ARM_REG_R1, 0xC1088E01), (UC_ARM_REG_R2, 0xC1088E02), (UC_ARM_REG_R3, 0xC1088E03)):
            u.reg_write(reg, junk)
        u.reg_write(UC_ARM_REG_R12, ip)

    def skip_printf(u, address, size, data=None):     # S-Boot's printf: the line is shown, its %d and %08x filled from r1 to r3
        seen["printf"] = seen.get("printf", 0) + 1
        args = [u.reg_read(reg) for reg in (UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
        text = re.sub(r"%(?:0?8)?[xd]|%c", lambda m: (format(args.pop(0), "08x") if "x" in m.group() else str(args.pop(0)) if m.group() == "%d"
                                                       else chr(args.pop(0))) if args else m.group(), text_at(u, u.reg_read(UC_ARM_REG_R0)))
        logged.append(text)
        aapcs_return(u, len(text), ip=0x0BADC0DE)
        u.reg_write(UC_ARM_REG_LR, address + 4)
        u.reg_write(UC_ARM_REG_PC, address + 4)

    def cut_clean(u, address, size, data=None):     # one pass of the loop: r4 reaches r5, and the loop ends
        seen["clean"] = seen.get("clean", 0) + 1
        u.reg_write(UC_ARM_REG_R4, u.reg_read(UC_ARM_REG_R5))
        u.reg_write(UC_ARM_REG_PC, address + 4)

    def skip_insn(u, address, size, data=None):
        u.reg_write(UC_ARM_REG_PC, address + 4)

    def read_slots(sector: int, count: int) -> bytes:
        """What CACHE holds from `sector` on, `count` sectors of it: the slots' bytes, zeros elsewhere.
        The slots start on multiples of 512 sectors, so a piece of 512 never straddles one."""
        out = bytearray()
        while count:
            letter = next((k for k, rel in bf.SLOT_REL.items()
                           if bf.CACHE_SECTOR + rel <= sector < bf.CACHE_SECTOR + rel + bf.SLOT_SECTORS), None)
            if letter is None:
                take = min(count, 512)               # outside the slots: the rest of the partition, zeros here
                out += bytes(take * 512)
            else:
                first = bf.CACHE_SECTOR + bf.SLOT_REL[letter]
                take = min(count, first + bf.SLOT_SECTORS - sector)
                data = (slots or {}).get(letter) or b""
                chunk = data[(sector - first) * 512:(sector - first + take) * 512]
                out += chunk + bytes(take * 512 - len(chunk))
            sector, count = sector + take, count - take
        return bytes(out)

    def skip_reader(u, address, size, data=None):   # S-Boot's reader needs the storage controller, which is not
        seen["mmc"] = seen.get("mmc", 0) + 1        # emulated: its call is shown, and its sectors stood in for
        dest, sector, count = u.reg_read(UC_ARM_REG_R0), u.reg_read(UC_ARM_REG_R1), u.reg_read(UC_ARM_REG_R2)
        reads.append((dest, sector, count))
        if slots is None:
            logged.append(f"S-Boot's reader 0x23E17808 called with destination {dest:#010x}, sector {sector}, {count:#x} bytes: "
                          "not emulated, said to have read them all")
        else:
            u.mem_write(dest, read_slots(sector, count // 512))   # what it would put there, read from the slots
            logged.append(f"S-Boot's reader 0x23E17808 called with destination {dest:#010x}, sector {sector}, {count:#x} bytes: "
                          "answered with CACHE's bytes")
        aapcs_return(u, count // 512, ip=0)
        u.reg_write(UC_ARM_REG_LR, address + 4)
        u.reg_write(UC_ARM_REG_PC, address + 4)

    def load_ttbr(u, address, size, data=None):     # the address of a first-level table of the emulator's own
        u.reg_write(UC_ARM_REG_R4, 0x90000000)
        u.reg_write(UC_ARM_REG_PC, address + 4)

    def stop(u, address, size, data=None):
        u.emu_stop()

    for at in places["printf"]:
        uc.hook_add(UC_HOOK_CODE, skip_printf, begin=at, end=at)
    for at in places["mmc"]:
        uc.hook_add(UC_HOOK_CODE, skip_reader, begin=at, end=at)
    uc.hook_add(UC_HOOK_CODE, cut_clean, begin=places["clean"], end=places["clean"])
    for at in places["skip"] + ([] if slots is not None else places["ttbr"]):   # the test payloads leave the register alone, as ever
        uc.hook_add(UC_HOOK_CODE, skip_insn, begin=at, end=at)
    for at in places["ttbr"] if slots is not None else []:
        uc.hook_add(UC_HOOK_CODE, load_ttbr, begin=at, end=at)
    uc.hook_add(UC_HOOK_CODE, stop, begin=HAND_BACK, end=HAND_BACK)
    if slots is not None:                           # the production loader: what its reads and writes need
        biggest = max(len(data) for data in slots.values())
        sboot.limit_block = max(sboot.limit_block, biggest // 2 + 1_000_000)    # the hash of both kernels: four bytes a round
        sboot.limit_total = max(sboot.limit_total, 4 * sboot.limit_block + 5_000_000)
        table = bytearray(0x4000)
        if ttbr:
            for index in (0x100, 0x105, 0x400, 0x420, 0x5F0):   # the watchdog, the PMU, the headers, the kernel, the tree
                struct.pack_into("<I", table, index * 4, 0x1002)
        image = max(len(data) for data in slots.values())
        for base, length, fill in ((0x90000000, 0x4000, bytes(table)), (0x10000000, 0x100000, b""), (0x105C0000, 0x10000, b""),
                                   (0x40000000, 0x40000, b""), (bf.KERNEL_AT, -(-image // 4096) * 4096 + 0x1000, b""),
                                   (bf.DTB_AT, 0x100000, b"")):
            try:
                uc.mem_map(base, length)
            except UcError:
                pass
            if fill:
                uc.mem_write(base, fill)
    blocks = sboot.instructions
    try:
        uc.emu_start(0x23E17B68, places["smc"], timeout=0, count=0)
    except Exception as error:
        print(f"the emulator stopped with {error!r}")
    pc = uc.reg_read(UC_ARM_REG_PC)
    regs = {name: uc.reg_read(reg) for name, reg in (("r0", UC_ARM_REG_R0), ("r1", UC_ARM_REG_R1), ("r2", UC_ARM_REG_R2),
                                                     ("r3", UC_ARM_REG_R3), ("r4", UC_ARM_REG_R4), ("r5", UC_ARM_REG_R5),
                                                     ("r6", UC_ARM_REG_R6), ("sp", UC_ARM_REG_SP), ("lr", UC_ARM_REG_LR))}
    for line in logged:
        print(f"   S-Boot's printf would log: {line.strip()!r}")
    outcome = "other"
    if pc == places["smc"]:
        outcome = "smc"
        print((f"THE KERNEL IS STARTED: reached the smc after {sboot.instructions - blocks} blocks; " if slots is not None
               else f"THE TEST RUNS: reached the smc after {sboot.instructions - blocks} blocks; ") + " ".join(f"{k}={v:#010x}" for k, v in regs.items()))
        # the monitor did not switch: play on from the instruction after the smc, to the hand-back
        uc.reg_write(UC_ARM_REG_PC, places["smc"] + 4)
        logged.clear()
        try:
            uc.emu_start(places["smc"] + 4, 0, timeout=0, count=0)
        except Exception as error:
            print(f"   the second part stopped with {error!r}")
    elif pc == HAND_BACK:
        outcome = "hand"
        print((f"KBOOT HANDS BACK: S-Boot's own kernel boots ({logged[-1].strip()[:70] if logged else 'no line'}) after "
               f"{sboot.instructions - blocks} blocks" if slots is not None else
               f"THE TEST IS SKIPPED: the guard handed straight back to boot after {sboot.instructions - blocks} blocks"))
    else:
        print(f"stopped at {pc:#010x}: neither the smc nor the hand-back" + (" (a loop taken for stuck: the emulator's limit)" if sboot.stuck else "")
              + "; " + " ".join(f"{k}={v:#010x}" for k, v in regs.items()))
    pc2 = uc.reg_read(UC_ARM_REG_PC)
    if pc2 == HAND_BACK:
        r5, r6, sp2 = uc.reg_read(UC_ARM_REG_R5), uc.reg_read(UC_ARM_REG_R6), uc.reg_read(UC_ARM_REG_SP)
        print(f"   back in boot: pc {pc2:#010x}, r5 {r5:#010x} ({'ok' if r5 == 0x23E8000C else 'WRONG'}), "
              f"r6 {r6:#010x}, sp {sp2:#010x} ({'ok' if sp2 == 0x23EC0018 else 'WRONG'})")
        print(f"   heap head now: {bytes(uc.mem_read(0x24F00000, 16)).hex(' ')}; "
              f"block at 0x67B00000: {bytes(uc.mem_read(0x67B00000, 16)).hex(' ')}")
        for line in logged:
            print(f"   S-Boot's printf would log: {line.strip()!r}")
    if ring is not None:
        print(f"   guard rehearsal: counter {counter:#010x} (ring offset {counter & RING_MASK:#x})")
    rehearse_arm32.outcome = outcome
    rehearse_arm32.record = None
    if slots is not None:                           # what the ARM32 code left for EL2 (the record), as it stands at the end
        rehearse_arm32.record = bytes(uc.mem_read(bf.KBOOT_RECORD_AT, 4 * bf.KBOOT_RECORD_WORDS))
        print(f"   the storage was read {len(reads)} times: " + ", ".join(
            f"{'the kernel' if d == bf.KERNEL_AT else 'the tree' if d == bf.DTB_AT else 'a header'} of slot "
            f"{next((k for k, rel in bf.SLOT_REL.items() if bf.CACHE_SECTOR + rel <= s < bf.CACHE_SECTOR + rel + bf.SLOT_SECTORS), '?')}, {c:#x} bytes"
            for d, s, c in reads))
    return reads

LEDGER_BOOTS = ("none", "failed", "up", "fallback", "handback", "failed-u")


def ledger_ring(raw: bytes, case: str) -> tuple[bytes, int]:
    """S-Boot's log ring as the production loader must find it. A real dump is kept as it is, and the boots
    of `case` are logged after it, oldest first, comma-separated: one that did not try (`none`); one that
    tried the arm64 kernel and never reported that it was up (`failed`: hung, reset by the watchdog,
    panicked), or did (`up`); one where the loader fell back by the ledger (`fallback`: S-Boot's kernel
    of that boot, RECOVERY's after a watchdog reset); one where the loader tried and handed back by itself
    (`handback`: no valid kernel, S-Boot's kernel booted); `failed-u`: as `failed`, with a line that
    starts "KBOOT: u" and is not "KBOOT: up". `cold` first: no dump, the ring empty and its counter at 0,
    as after a power-on. Then the start of this boot. Returns the ring and its write counter."""
    boots = case.split(",")
    cold = boots[0] == "cold"
    boots = boots[1:] if cold else boots
    if any(kind not in LEDGER_BOOTS for kind in boots):
        raise SystemExit(f"--ledger: boots are {', '.join(LEDGER_BOOTS)} (comma-separated, oldest first; 'cold' first: no dump)")
    ring = bytearray(RING_MASK + 1)
    if cold:
        counter = 0
    else:
        ring[:len(raw) - 0x1000] = raw[0x1000:]
        counter = struct.unpack_from("<I", raw, 0xFFC)[0] & RING_MASK
    lines = []
    for kind in boots:
        lines += ["[MMC] Set write protection (boot partition)", "PARAM ENV VERSION: 8"]
        if kind in ("failed", "up", "failed-u"):
            lines += ["KBOOT: try: the arm64 kernel of CACHE is tried this boot",
                      "KBOOT: slot at sector 6684672, generation 1: the image is 5545984 bytes",
                      "KBOOT: image at 42000000, device tree 79425 bytes at 5f000000: both read whole and hashed as the header says",
                      "KBOOT: EL2 MMU and caches on: SCTLR_EL2=30c5183f", "KBOOT: EL2 kernel: starting it at 42000000",
                      "[    0.000000] Booting Linux on physical CPU 0x0"]
            if kind == "up":
                lines.append("[    3.100000] KBOOT: up")
            if kind == "failed-u":
                lines.append("[    2.500000] KBOOT: unready")
        elif kind == "fallback":
            lines += ["KBOOT: fallback for this boot: an attempt in one of the two boots before did not report that it was up; "
                      "S-Boot's kernel boots", "[    0.000000] Booting Linux on physical CPU 0x0"]
        elif kind == "handback":
            lines += ["KBOOT: try: the arm64 kernel of CACHE is tried this boot",
                      "KBOOT: slot at sector 6684672: the reader put 8 sectors",
                      "KBOOT: no valid kernel in CACHE: S-Boot's kernel boots", "[    0.000000] Booting Linux on physical CPU 0x0"]
        if kind != "none":
            lines += ["", "Samsung S-Boot 4.0 for SM-T715"]
    lines += ["[MMC] Set write protection (boot partition)", "PARAM ENV VERSION: 8"]
    data = ("\r\n" + "\r\n".join(lines) + "\r\n").encode()
    at = counter & RING_MASK
    first = min(len(data), RING_MASK + 1 - at)
    ring[at:at + first] = data[:first]
    ring[:len(data) - first] = data[first:]
    return bytes(ring), counter + len(data)

def rehearse_a64(logo: bytes, node: int, payload: str, counter: int = 0xD0F02, loaded: bytes | None = None,
                bundle: Path | None = None, smp: str = "", stubs: bytes = b"", record: bytes | None = None) -> None:
    """Run the AArch64 entry in a 64-bit emulator, with S-Boot's log ring, the framebuffer, the display
    controller's two registers, the power management unit and the area of the page tables mapped; the
    long loops are cut. Stops at the halt loop or at the instruction that writes SWRESET. The emulator
    runs at EL1: reads of EL2 registers get stand-in values, writes to them and the TLB and cache
    maintenance are not emulated (nothing is patched where they stand), and the page tables and the
    vector table the code builds are checked here, by decoding them. `loaded` (the image's first
    bytes) stands at 0x40000000 for what S-Boot's reader puts there.

    smp ("secondary" or "none"): the one-core experiment (stage2.c SMP_EXP). The PMU and the monitor's
    sysram window hold what the tablet's kernel saw there, every write to them is traced, and when
    stage 2 powers the core on the two stubs are run on an emulated second core (rehearse_secondary),
    or nothing comes ("none": the watchdog's counter is made to count, so that the waits end). `stubs`
    is what scripts/build_smp_stubs.py built: it sits in stage 2's image as data, not as code to scan.
    `record` (kboot): what the ARM32 code left at 0x40003000 for stage 2, placed there."""
    from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_ARCH_ARM64, UC_MODE_ARM, Uc
    from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2
    from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
    import build_ffree as bf
    off = node - e.FILE_BUFFER
    code_off = {"sreset": bf.SRESET_A64_OFF, "kboot": bf.KBOOT_A64_OFF}.get(payload, bf.A64_CODE_OFF)
    if len(logo) < off + code_off + 4:
        print("no AArch64 entry in this image")
        return
    entry = node + code_off
    blob = bytearray(logo[off:off + 0x10000])
    size = 0x8000 if payload in ("sreset", "kboot") else 0x180   # the entry's code and texts, its vector table, stage 2's image
    code = bytes(logo[off + code_off: off + code_off + size])
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.skipdata = True                                # the texts sit between the code and the vector table
    ins = [i for i in md.disasm(code, entry) if i.mnemonic != ".byte"]
    if smp:                                           # the two stubs are data in stage 2's image: not this core's instructions
        at = blob.find(stubs[:64])
        if at < 0:
            raise SystemExit("FAIL: the stubs as built are not in stage 2's image")
        ins = [i for i in ins if not node + at <= i.address < node + at + len(stubs)]
    stand_ins = []
    NOP = 0xD503201F
    for i in ins:
        ops = i.op_str.split(", ")
        if i.mnemonic == "mrs" and len(ops) > 1 and ops[1].endswith("_el2"):
            # the emulator runs at EL1 and takes an exception on the EL2 registers: a distinctive stand-in instead
            n = len(stand_ins)
            rd = int(ops[0][1:])                       # the stand-in goes into the register the read was meant for
            struct.pack_into("<I", blob, i.address - node, 0xD2800000 | ((0xA000 + n) << 5) | rd)      # movz Xd, #0xA000 + n
            stand_ins.append(f"{ops[1].upper()} -> 0x{0xA000 + n:x}")
        elif (i.mnemonic == "msr" and ops[0].endswith("_el2")) or i.mnemonic in ("tlbi", "ic"):
            struct.pack_into("<I", blob, i.address - node, NOP)
    paint = next((i.address for i in ins if i.mnemonic == "str" and i.op_str == "w1, [x0], #4"), None)
    clean = next((i.address for i in ins if i.mnemonic == "dc" and i.op_str.endswith(", x0") and i.address < node + 0x4000), None)
    halt = next((i.address for i in ins if i.mnemonic == "b" and i.op_str.startswith("#") and int(i.op_str[1:], 0) == i.address), None)
    waits = [b.address for a, b in zip(ins, ins[1:]) if (a.mnemonic == "subs" and a.op_str == "x0, x0, #1" and b.mnemonic == "b.ne")
             or (a.mnemonic == "subs" and a.op_str == "x3, x3, #1" and b.mnemonic == "b.ne")]
    svc = next((i.address for i in ins if i.mnemonic == "svc"), None)      # the deliberate exception at the end
    eret = next((i.address for i in ins if i.mnemonic == "eret"), None)     # stage 2 leaving for EL1
    wfe = next((i.address for i in ins if i.address >= node + 0x4000 and i.mnemonic == "wfe"), None)   # after stage 2's software reset
    reset = None
    if payload in ("sreset", "kboot") and not smp:    # smp: the write of SWRESET is caught where it is made
        reset = [i.address for i in ins if i.mnemonic == "str" and i.op_str == "w1, [x0]"][-1]
    table_set = next((k for k, i in enumerate(ins) if i.mnemonic == "msr" and i.op_str.startswith("ttbr0_el2")), None)
    vector_set = next((k for k, i in enumerate(ins) if i.mnemonic == "msr" and i.op_str.startswith("vbar_el2")), None)
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(node, 0x40000)                        # the blob, and stage 2 with its 64 KiB of .bss
    u.mem_write(node, bytes(blob))
    if stand_ins:
        print("   the emulator cannot read the EL2 registers: " + ", ".join(stand_ins))
    u.mem_map(0x25FFF000, 0x201000)                  # S-Boot's log ring and its header
    u.mem_map(0x67000000, 0xC00000)                  # the framebuffer: 2048 rows of 6144 bytes
    u.mem_map(0x13801000, 0x2000)                    # DECON_UPDATE 0x13801410, DECON_TRIGGER 0x13802040
    if payload in ("sreset", "kboot"):
        u.mem_map(0x105C0000, 0x10000)               # the power management unit
        u.mem_write(0x105C080C, struct.pack("<I", 0x12345670))
        u.mem_map(0x90000000, 0x400000)              # where the page tables go, and above them stage 2's stack
        u.mem_map(0x40000000, 0x100000)              # where S-Boot's reader is made to load the start of PARAM
        if record is not None:                        # kboot: the record of the ARM32 code, in the memory as it left it
            u.mem_write(bf.KBOOT_RECORD_AT, record)
        if bundle is not None:                        # the kernel where stage 2 starts it, then its device tree
            data = bundle.read_bytes()
            kernel_end = -(-struct.unpack_from("<I", data, 0x10)[0] // 4096) * 4096 + 0x100000
            u.mem_map(0x42000000, max(0x800000, -(-max(struct.unpack_from("<I", data, 0x10)[0], len(data)) // 2**20) * 2**20))   # the kernel, whole
            u.mem_map(0x5F000000, 0x100000)           # the device tree
            marker = None                                 # the device tree is the last thing in the bundle, in whole sectors
            for offset in range((len(data) - 4) // 512 * 512, 0, -512):
                if struct.unpack_from(">I", data, offset)[0] == 0xD00DFEED and len(data) - offset >= struct.unpack_from(">I", data, offset + 4)[0] \
                        and len(data) - offset < struct.unpack_from(">I", data, offset + 4)[0] + 512:
                    marker = offset
                    break
            if marker is None:
                raise SystemExit("no device tree found at the end of the bundle")
            u.mem_write(0x42000000, data[:marker])   # the Image, as the reader writes it: whole sectors
            u.mem_write(0x5F000000, data[marker:])   # whole sectors, as the reader writes it
            print(f"   the bundle: Image {marker:#x} bytes at 0x42000000, device tree {len(data) - marker:#x} bytes at 0x5F000000")
        if loaded is not None:                        # the first read: PARAM's start; the second: the image for EL1
            u.mem_write(0x40000000, loaded[:0x100000])
            if struct.unpack_from("<I", loaded, 0xD1000)[0] == 0x54314C45:    # an image for EL1: where its reader call puts it
                sectors = -(-struct.unpack_from("<I", loaded, 0xD1004)[0] // 512)     # exactly what the reader writes: whole sectors
                u.mem_write(0x40080000, loaded[0xD1000:0xD1000 + sectors * 512])
        for base, length in ((0x10000000, 0x100000), (0x105B0000, 0x10000), (0x11800000, 0x200000)):
            try:                                     # what the handoff report reads: zeros here, so the watchdog
                u.mem_map(base, length)              # does not count in the rehearsal and its fallback runs
            except UcError:
                pass
    trace: list[tuple[int, int]] = []                # smp: what stage 2 writes into the PMU, the sysram window, the watchdog
    powered = []                                     # smp: the write that powers the core on stopped the emulator
    u.mem_write(COUNTER, struct.pack("<I", counter))
    passes: dict[str, int] = {}

    def cut_paint(uc, address, size, data=None):     # one store, at the last pixel, then the loop ends
        passes["paint"] = passes.get("paint", 0) + 1
        if passes["paint"] == 1:
            uc.reg_write(UC_ARM64_REG_X0, uc.reg_read(UC_ARM64_REG_X2) - 4)

    def cut_clean(uc, address, size, data=None):     # the cache maintenance is not emulated: the loop ends
        passes["clean"] = passes.get("clean", 0) + 1
        uc.reg_write(UC_ARM64_REG_X0, uc.reg_read(UC_ARM64_REG_X2) - 64)
        uc.reg_write(UC_ARM64_REG_PC, address + 4)

    def skip_insn(uc, address, size, data=None):     # a loop that only waits: left at once
        passes["waits"] = passes.get("waits", 0) + 1
        uc.reg_write(UC_ARM64_REG_PC, address + 4)

    def leave_out(uc, address, size, data=None):     # stage 2's cache maintenance: slow in the emulator, and emulated by nothing
        uc.reg_write(UC_ARM64_REG_PC, address + 4)

    def stop(uc, address, size, data=None):
        uc.emu_stop()

    def on_write(uc, access, address, size, value, data=None):    # smp: the registers of the power sequence, in order
        if 0x105C0000 <= address < 0x105D0000 or 0x0207B000 <= address < 0x0207C000 or 0x10020000 <= address < 0x10020010 \
                or address == 0x10040900:
            trace.append((address, value & 0xFFFFFFFF))
            if address == 0x105C2280 and value & 0xF == 0xF and not powered:   # A53 core 1's CONFIGURATION: the core starts
                powered.append(value)
                trace.pop()                          # the write is recorded when it is made, after the core's turn
                uc.emu_stop()
            if address == 0x105C0400:                 # SWRESET: on the tablet the restart follows
                uc.emu_stop()

    if smp:
        u.hook_add(UC_HOOK_MEM_WRITE, on_write)
        u.mem_map(0x41000000, 0x4000)                 # the stubs and the scratch page: without cache on the tablet
        u.mem_map(0x0207B000, 0x1000)                 # the monitor's window: the boot address, then the boot flags
        u.mem_write(0x0207B028, struct.pack("<8I", 4, 4, 4, 4, 1, 4, 4, 4))   # what the 32-bit kernel read there
        for address, value in ((0x105C2280, 0x80000000), (0x105C2284, 0x10380000), (0x105C2288, 0x10010103),
                               (0x105C2290, 0xFFFFFFFF), (0x105C2294, 0xFFFFFFFF), (0x105C2298, 0xFFFFFFFF),
                               (0x105C229C, 0xFFFFFFFF), (0x105C2428, 0x00020001), (0x105C0120, 0x00000000)):
            u.mem_write(address, struct.pack("<I", value))

        def count_down(uc, address, size, data=None):  # "none": nothing will come from the core, so the watchdog counts
            passes["ticks"] = passes.get("ticks", 0) + 1
            if passes["ticks"] % 250 == 0:             # 250 instructions a tick: three seconds in 1.5 million
                now = struct.unpack("<I", uc.mem_read(0x10020008, 4))[0]
                uc.mem_write(0x10020008, struct.pack("<I", max(now, 1) - 1))
        if smp == "none":
            u.hook_add(UC_HOOK_CODE, count_down)
    if paint:
        u.hook_add(UC_HOOK_CODE, cut_paint, begin=paint, end=paint)
    if clean:
        u.hook_add(UC_HOOK_CODE, cut_clean, begin=clean, end=clean)
    for at in waits:
        u.hook_add(UC_HOOK_CODE, skip_insn, begin=at, end=at)
    stage2 = [i.address for i in ins if i.address >= node + 0x4000 and i.mnemonic in ("dc", "ic", "dsb", "isb")]
    for at in stage2:
        u.hook_add(UC_HOOK_CODE, leave_out, begin=at, end=at)
    if reset:
        u.hook_add(UC_HOOK_CODE, stop, begin=reset, end=reset)
    if svc:                                          # the emulator cannot take the exception: stop just before it
        u.hook_add(UC_HOOK_CODE, stop, begin=svc, end=svc)
    if eret:                                         # nor change exception level: stop before the eret
        u.hook_add(UC_HOOK_CODE, stop, begin=eret, end=eret)
    if wfe:                                          # the software reset asked for, then the wait: the tablet restarts
        u.hook_add(UC_HOOK_CODE, stop, begin=wfe, end=wfe)
    try:
        u.emu_start(entry, halt or 0, timeout=120_000_000, count=0)     # no limit of blocks here: two minutes at most
    except UcError as error:
        pc = u.reg_read(UC_ARM64_REG_PC)
        print(f"the 64-bit emulator stopped with {error!r} at pc {pc:#010x} "
              f"({next((i.mnemonic + ' ' + i.op_str for i in ins if i.address == pc), '?')})")
    if powered:                                       # smp: the core is on; what it does is played on another emulator
        before = struct.unpack("<I", u.mem_read(COUNTER, 4))[0]
        u.mem_write(0x105C2284, struct.pack("<I", 0x2004000F))           # powered, as the stock kernel sees it 1 ms later
        if smp == "secondary":                         # the emulator's SP_EL0 is 0: one from the tablet's kind, so that the stub's
            u.mem_write(0x41001000 + 160, struct.pack("<Q", 0x0202F800))  # way back to SVC through System mode is taken (iRAM here, as S-Boot's may be)
        if smp == "secondary":
            rehearse_secondary(u)
        secondary = bytes(u.mem_read(RING + (before & RING_MASK), 0x2000)) if smp == "secondary" else b""
        try:
            u.emu_start(u.reg_read(UC_ARM64_REG_PC), halt or 0, timeout=120_000_000, count=0)
        except UcError as error:
            print(f"the 64-bit emulator stopped with {error!r} at pc {u.reg_read(UC_ARM64_REG_PC):#010x} after the power-on")
    pc = u.reg_read(UC_ARM64_REG_PC)
    after = struct.unpack("<I", u.mem_read(COUNTER, 4))[0]
    written = bytes(u.mem_read(RING + (counter & RING_MASK), min(after - counter, RING_MASK - (counter & RING_MASK) + 1)))
    reset_now = bool(reset and pc == reset) or bool(smp and trace and trace[-1] == (0x105C0400, 1))
    rehearse_a64.outcome = ("reset" if reset_now else "svc" if svc and pc == svc else "eret" if eret and pc == eret
                           else "wfe" if wfe and pc == wfe else "other")
    print(f"AArch64 entry: stopped at pc {pc:#010x} "
          + (f"(the instruction that writes SWRESET: x0 {u.reg_read(UC_ARM64_REG_X0):#010x}, x1 {u.reg_read(UC_ARM64_REG_X1):#x})" if reset_now
             else " (the deliberate exception: on the tablet the handler takes it)" if svc and pc == svc
             else " (the eret into EL1: on the tablet the image there takes over)" if eret and pc == eret
             else " (the software reset asked for: on the tablet the restart follows)" if wfe and pc == wfe
             else f"({'the halt loop' if halt and pc == halt else 'NOT the halt loop'})")
          + f"; log counter {counter:#x} -> {after:#x}; loops cut: {passes}; stage 2's cache instructions left out: {len(stage2)}")
    rehearse_a64.lines = []
    for line in written.replace(bytes([13]), b"").split(bytes([10])):
        if line.strip():
            print("   logged: " + line.decode("latin1"))
            rehearse_a64.lines.append(line.decode("latin1"))
    update, trigger = struct.unpack("<II", u.mem_read(0x13801410, 4) + u.mem_read(0x13802040, 4))
    if payload == "kboot":                          # the production loader never paints
        if update or trigger or any(u.mem_read(0x67000000, 0x1000)):
            rehearse_a64.outcome = "painted"
            print("FAIL: the production loader touched the screen")
        else:
            print("   the screen: untouched, as the production loader must leave it")
    else:
        print(f"   framebuffer: {bytes(u.mem_read(0x67000000, 8)).hex(' ')} .. {bytes(u.mem_read(0x675FFFF8, 8)).hex(' ')}; "
              f"DECON_UPDATE {update:#010x} ({'ok' if update & 1 else 'WRONG'}), DECON_TRIGGER {trigger:#010x} ({'ok' if trigger == 0xE0000003 else 'WRONG'})")
    # kboot too, since kboot4 (2026-11-24): the page tables, the eret (the kernel's entry, the tree's address handed in x0,
    # the PMU markers, the watchdog) and the exception handler are checked as for the test images
    if wfe and pc == wfe:
        if struct.unpack("<I", u.mem_read(0x105C0400, 4))[0] != 1:
            print("   WRONG: the software reset register was not written")
        return
    if table_set is not None:                        # the tables as the code left them, decoded independently
        wrong = []
        level1 = struct.unpack("<512Q", u.mem_read(0x90000000, 0x1000))
        if any(level1[4:]):
            wrong.append("level-1 entries above 3 are not zero")
        for gigabyte in range(4):
            if level1[gigabyte] != (0x90001000 + gigabyte * 0x1000) | 3:
                wrong.append(f"level-1 entry {gigabyte} = {level1[gigabyte]:#018x}")
            level2 = struct.unpack("<512Q", u.mem_read(0x90001000 + gigabyte * 0x1000, 0x1000))
            for block, descriptor in enumerate(level2):
                at = (gigabyte << 30) | (block << 21)
                uncached = 0x25C00000 <= at < 0x26400000 or bool(smp) and at == 0x41000000
                wanted = at | (0x709 if uncached else 0x705 if 0x20000000 <= at < 0xDE800000 else 0x701)
                if descriptor != wanted:
                    wrong.append(f"block {at:#010x} = {descriptor:#018x}, wanted {wanted:#018x}")
        print(f"   page tables at 0x90000000 as built: " + ("ok (4 level-1 descriptors, 2048 blocks: the memory 0x20000000..0xde800000 write-back, "
                                                         "0x25c00000..0x26400000 around the log not cached" + (", 0x41000000..0x41200000 too" if smp else "")
                                                         + ", the rest device)"
                                                         if not wrong else "WRONG: " + "; ".join(wrong[:5])))
    if smp:
        check_smp(u, trace, secondary if smp == "secondary" else None, written)
    if eret and pc == eret:                          # what the eret would load, as the code holds it: x9 the entry, x10 the SPSR
        from unicorn.arm64_const import UC_ARM64_REG_X9, UC_ARM64_REG_X10
        entry_el1, spsr_el1 = u.reg_read(UC_ARM64_REG_X9), u.reg_read(UC_ARM64_REG_X10)
        from unicorn.arm64_const import UC_ARM64_REG_X14
        tree_at = u.reg_read(UC_ARM64_REG_X14)
        print(f"   the eret: ELR {entry_el1:#010x}, SPSR {spsr_el1:#010x} ({'EL1h, all masked' if spsr_el1 == 0x3c5 else 'WRONG'}), "
              f"device tree in x14 {tree_at:#010x}")
        if bundle is None:
            rehearse_el1(u, md, loaded, entry_el1)
        else:                                         # a Linux image: the emulator cannot run it; on the tablet the kernel takes over
            if (entry_el1, spsr_el1, tree_at) != (0x42000000, 0x3C5, 0x5F000000):
                raise SystemExit(f"FAIL: the eret enters {entry_el1:#010x} with SPSR {spsr_el1:#010x} and the device tree at {tree_at:#010x}, "
                                 "not the kernel at 0x42000000 with the device tree at 0x5f000000")
            if bytes(u.mem_read(0x105C0808, 8)) != struct.pack("<II", 0x12345678, 0x12345670):
                raise SystemExit("FAIL: the PMU markers of a normal boot were not written before the eret")
            con, cnt = int.from_bytes(u.mem_read(0x10020000, 4), "little"), int.from_bytes(u.mem_read(0x10020008, 4), "little")
            if not con & 0x21 or not cnt or int.from_bytes(u.mem_read(0x105C040C, 4), "little") & (1 << 24) \
                    or int.from_bytes(u.mem_read(0x105C0408, 4), "little") & ((1 << 24) | (1 << 23)):
                raise SystemExit(f"FAIL: the watchdog is not counting with its reset enabled and let through, at the eret "
                                 f"(WTCON {con:08x}, WTCNT {cnt:#x})")
            print(f"   (a Linux image: the emulator cannot run it; on the tablet the kernel takes over from here); before it: the PMU markers "
                  f"INFORM2/INFORM3 of a normal boot are written, the watchdog is on (WTCON {struct.unpack('<I', u.mem_read(0x10020000, 4))[0]:08x}, "
                  f"WTCNT {struct.unpack('<I', u.mem_read(0x10020008, 4))[0]}) and its reset is let through")
    if vector_set is not None:
        adr = next(i for i in reversed(ins[:vector_set]) if i.mnemonic == "adr")
        table = int(adr.op_str.split(", ")[1][1:], 0)
        slots = [next(md.disasm(bytes(u.mem_read(table + k * 0x80, 4)), table + k * 0x80)) for k in range(16)]
        targets = {int(s.op_str[1:], 0) for s in slots if s.mnemonic == "b"}
        print(f"   vector table at {table:#010x} as placed by {adr.mnemonic} {adr.op_str}: "
              + ("ok (16 slots to the handler at " + hex(targets.pop()) + ")" if not table & 0x7FF and len(targets) == 1 and all(s.mnemonic == "b" for s in slots)
                 else f"WRONG (slots: {[s.mnemonic for s in slots]})"))
        handler = int(slots[0].op_str[1:], 0)
        before = struct.unpack("<I", u.mem_read(COUNTER, 4))[0]      # the emulator cannot take an exception at
        u.emu_start(handler, 0, timeout=30_000_000, count=0)          # EL2: the handler is run from its first instruction
        pc = u.reg_read(UC_ARM64_REG_PC)
        after = struct.unpack("<I", u.mem_read(COUNTER, 4))[0]
        lines = [line.decode("latin1") for line in bytes(u.mem_read(RING + (before & RING_MASK), after - before)).replace(bytes([13]), b"").split(bytes([10])) if line.strip()]
        writes_reset = bool(reset and pc == reset) or bool(smp and u.reg_read(UC_ARM64_REG_X0) == 0x105C0400 and u.reg_read(UC_ARM64_REG_X1) == 1)
        print(f"   the exception handler, run on its own: stopped at pc {pc:#010x} "
              f"({'the instruction that writes SWRESET' if writes_reset else 'NOT the instruction that writes SWRESET'}); logged: {lines}")
        if not writes_reset:
            raise SystemExit("FAIL: the exception handler does not end in the software reset")


def rehearse_secondary(main) -> None:
    """The core the emulator has not (the one-core experiment). Stage 2 has just written 0xF into A53 core 1's
    CONFIGURATION, and the entry point is in the monitor's boot-address register. The ARM32 stub runs in a
    32-bit emulator from that entry up to its `smc`: its arguments are checked. Then the AArch64 stub runs
    from the entry they name in a 64-bit emulator: as at EL2 first (the emulator stays at EL1, so the EL2
    registers and CurrentEL get stand-in values, as for the entry) up to its `eret`, then from the EL1 entry
    it names up to its park loop. What the core writes (S-Boot's log ring, the scratch page) is copied back
    into the main emulator's memory. What is only assumed: that the monitor switches this core as it does
    the boot CPU's. On the tablet that is exactly what is being tested."""
    from unicorn import UC_HOOK_CODE, UC_ARCH_ARM, UC_ARCH_ARM64, UC_MODE_ARM, Uc
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_PC, UC_ARM_REG_CPSR, UC_ARM_REG_SP
    from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X0, UC_ARM64_REG_X9, UC_ARM64_REG_X10
    from capstone import CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_ARM, Cs
    import build_smp_stubs as bs
    regions = ((0x41000000, 0x4000), (0x25FFF000, 0x201000))         # the stubs with the scratch page, the log ring
    entry = struct.unpack("<I", main.mem_read(0x0207B01C, 4))[0]
    if entry != bs.STUB32:
        raise SystemExit(f"FAIL: the boot-address register holds {entry:#010x}, not the ARM32 stub ({bs.STUB32:#010x})")
    a = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    for base, length in regions:
        a.mem_map(base, length)
        a.mem_write(base, bytes(main.mem_read(base, length)))
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    listing = list(md.disasm(bytes(a.mem_read(bs.STUB32, bs.STUB_BYTES)), bs.STUB32))
    smc = next((i.address for i in listing if i.mnemonic == "smc"), None)
    stand_ins = {"c0, c0, #5": ("MPIDR", 0x80000101), "c1, c0, #0": ("SCTLR", 0x30C50830), "c1, c0, #2": ("CPACR", 0),
                 "c1, c1, #2": ("NSACR", 0), "c12, c0, #0": ("VBAR", 0), "c2, c0, #0": ("TTBR0", 0)}

    def skip_read(uc, address, size, data=None):     # the emulator cannot read these: stand-ins, as for the entry
        uc.reg_write(UC_ARM_REG_R0 + data[1], data[2])
        uc.reg_write(UC_ARM_REG_PC, address + 4)

    shown = []
    for i in listing:
        parts = i.op_str.split(", ")
        key = ", ".join(parts[3:]) if i.mnemonic == "mrc" and len(parts) == 6 else None
        if key in stand_ins:
            name, value = stand_ins[key]
            a.hook_add(UC_HOOK_CODE, skip_read, begin=i.address, end=i.address, user_data=(name, int(parts[2][1:]), value))
            if name not in shown:
                shown.append(name)
        elif i.mnemonic == "mrs" and len(parts) == 2 and parts[1] in ("cpsr", "apsr"):
            a.hook_add(UC_HOOK_CODE, skip_read, begin=i.address, end=i.address, user_data=("CPSR", int(parts[0][1:]), 0x1D3))
    if smc is None:
        raise SystemExit("FAIL: no smc in the ARM32 stub as it stands in the memory")
    held = {}

    def at_smc(uc, address, size, data=None):
        held["regs"] = [uc.reg_read(UC_ARM_REG_R0 + k) for k in range(4)]
        uc.emu_stop()

    a.hook_add(UC_HOOK_CODE, at_smc, begin=smc, end=smc)
    try:
        a.emu_start(bs.STUB32, 0, timeout=30_000_000, count=3_000_000)
    except UcError as error:
        raise SystemExit(f"FAIL: the ARM32 stub on the emulated core stopped with {error!r} at pc {a.reg_read(UC_ARM_REG_PC):#010x}")
    pc = a.reg_read(UC_ARM_REG_PC)
    mode = a.reg_read(UC_ARM_REG_CPSR) & 0x1F
    print(f"   the secondary, AArch32: from {bs.STUB32:#010x} to pc {pc:#010x} "
          f"({'its smc' if pc == smc else 'NOT its smc'}); in SVC mode at the call: {'yes' if mode == 0x13 else f'NO ({mode:#x})'}; "
          f"the emulator's stand-ins: {', '.join(shown)}")
    if pc != smc or held.get("regs") != [0x82000400, bs.STUB64, 0x800, 1] or mode != 0x13:
        raise SystemExit(f"FAIL: the stub's call is {held.get('regs')} in mode {mode:#x}, not [0x82000400, the AArch64 stub "
                         f"{bs.STUB64:#010x}, 0x800, 1] in SVC mode")

    b = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for base, length in regions:
        b.mem_map(base, length)
        b.mem_write(base, bytes(a.mem_read(base, length)))
    md64 = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md64.skipdata = True
    NOP = 0xD503201F
    listing = list(md64.disasm(bytes(b.mem_read(bs.STUB64, bs.STUB_BYTES)), bs.STUB64))
    eret = next((i.address for i in listing if i.mnemonic == "eret"), None)
    stand_ins = []
    for i in listing:                                 # as for the entry: EL2 registers read stand-ins, writes are left out
        ops = i.op_str.split(", ")
        level = len(ops) > 1 and ops[1].lower() == "currentel" and eret and i.address < eret
        if i.mnemonic == "mrs" and len(ops) > 1 and (ops[1].endswith("_el2") or level):
            value = 8 if level else 0x8000 + len(stand_ins)      # EL2 is 0b1000 in CurrentEL
            b.mem_write(i.address, struct.pack("<I", 0xD2800000 | (value << 5) | int(ops[0][1:])))   # movz Xd
            stand_ins.append(f"{ops[1].upper()} -> {value:#x}")
        elif (i.mnemonic == "msr" and ops[0].endswith("_el2")) or i.mnemonic == "ic":
            b.mem_write(i.address, struct.pack("<I", NOP))
    print(f"   the secondary, AArch64 as at EL2: the emulator's stand-ins: {', '.join(stand_ins)}")
    stop_at = []

    def stop(uc, address, size, data=None):
        stop_at.append(address)
        uc.emu_stop()

    def skip_mpidr(uc, address, size, data=None):
        uc.reg_write(UC_ARM64_REG_X0 + data, 0x80000101)
        uc.reg_write(UC_ARM64_REG_PC, address + 4)

    for i in listing:
        if i.mnemonic == "mrs" and i.op_str.endswith(", mpidr_el1"):
            b.hook_add(UC_HOOK_CODE, skip_mpidr, begin=i.address, end=i.address, user_data=int(i.op_str.split(", ")[0][1:]))
    if eret is None:
        raise SystemExit("FAIL: no eret in the AArch64 stub as it stands in the memory")
    b.hook_add(UC_HOOK_CODE, stop, begin=eret, end=eret)
    try:
        b.emu_start(bs.STUB64, 0, timeout=30_000_000, count=3_000_000)
    except UcError as error:
        raise SystemExit(f"FAIL: the AArch64 stub on the emulated core stopped with {error!r} at pc {b.reg_read(UC_ARM64_REG_PC):#010x}")
    pc, x9, x10 = b.reg_read(UC_ARM64_REG_PC), b.reg_read(UC_ARM64_REG_X9), b.reg_read(UC_ARM64_REG_X10)
    stage = struct.unpack("<I", b.mem_read(bs.SCRATCH, 4))[0]
    el1_entry = struct.unpack("<Q", b.mem_read(bs.SCRATCH + 112, 8))[0]
    print(f"   the secondary, AArch64 as at EL2: stopped at pc {pc:#010x} ({'its eret' if pc == eret else 'NOT its eret'}), stage {stage}, "
          f"ELR {x9:#010x} ({'the EL1 entry it wrote' if x9 == el1_entry else 'WRONG'}), SPSR {x10:#010x} ({'EL1h, all masked' if x10 == 0x3C5 else 'WRONG'})")
    if pc != eret or stage != 4 or x9 != el1_entry or x10 != 0x3C5 or not bs.STUB64 <= el1_entry < bs.STUB64 + bs.STUB_BYTES:
        raise SystemExit("FAIL: the AArch64 stub does not reach its eret with the stage, the entry and the SPSR expected")
    park = next((int(i.op_str[1:], 0) for i, previous in zip(listing, [None] + listing)
                 if i.address > eret and i.mnemonic == "b" and previous and previous.mnemonic == "wfe" and int(i.op_str[1:], 0) == previous.address),
                None)                               # `park: wfe; b park`: the loop the core ends in
    if park is None:
        raise SystemExit("FAIL: no park loop after the eret in the AArch64 stub")
    b.hook_add(UC_HOOK_CODE, stop, begin=park, end=park)
    if b.reg_read(UC_ARM64_REG_X0 + 20) != bs.SCRATCH:     # the scratch page's register, as the stub set it before the eret
        raise SystemExit("FAIL: the AArch64 stub does not hold the scratch page's address in x20 at its eret")
    try:
        b.emu_start(el1_entry, 0, timeout=30_000_000, count=3_000_000)
    except UcError as error:
        raise SystemExit(f"FAIL: the AArch64 stub at EL1 on the emulated core stopped with {error!r} at pc {b.reg_read(UC_ARM64_REG_PC):#010x}")
    pc = b.reg_read(UC_ARM64_REG_PC)
    stage = struct.unpack("<I", b.mem_read(bs.SCRATCH, 4))[0]
    print(f"   the secondary, AArch64 at EL1 (the emulator's own level): from {el1_entry:#010x} to pc {pc:#010x} "
          f"({'its park loop' if pc == park else 'NOT its park loop'}), stage {stage}")
    for base, length in regions:
        main.mem_write(base, bytes(b.mem_read(base, length)))


def check_smp(u, trace: list, secondary: bytes | None, written: bytes) -> None:
    """The one-core experiment as the emulator saw it: the power sequence against the stock kernel's, register
    for register (platsmp.c of the release tree); the watchdog; the scratch page; the lines the secondary
    and the boot CPU must leave. `secondary` is what the core wrote in the ring (None: nothing came)."""
    import build_smp_stubs as bs
    core = 0x105C2000 + 0x80 * 5                  # PMU index 5: A53 core 1
    first = next((k for k, (address, value) in enumerate(trace) if address == core), None)
    if first is None:
        raise SystemExit("FAIL: the core is never powered on: no write to its CONFIGURATION")
    before, after = trace[:first], trace[first:]
    con, dat = struct.unpack("<II", u.mem_read(0x10020000, 8))
    held = struct.unpack("<8I", u.mem_read(core, 0x20))
    checks = [
        ("the watchdog is on with its reset let through, 12 s", con == 0xFF39 and dat == 12 * 2034
         and (0x105C0408, 0) in before and (0x105C040C, 0) in before),
        ("the boot address is the ARM32 stub, written before the core is powered",
         (0x0207B01C, bs.STUB32) in before),
        ("KFC NONCPU OPTION: no counter, a feedback (0x00020002)", (0x105C2428, 0x00020002) in before),
        ("the core's OPTION: counter, feedback, USE_SMPEN (0x10010103)", (core + 0x08, 0x10010103) in before),
        ("DURATION0: WAIT_RESET, SCALL 1 (0xffffff1f)", (core + 0x10, 0xFFFFFF1F) in before),
        ("UP_SCHEDULER: both clusters (3)", (0x105C0120, 3) in before),
        ("the power-up as the stock kernel does it: OPTION without feedback, DURATION0 to 3 at 0xfffff11f, CONFIGURATION last",
         before[-5:] == [(core + 0x08, 0x10010101)] + [(core + 0x10 + 4 * i, 0xFFFFF11F) for i in range(4)]),
        ("the core is powered on once, with 0x8000000f", [t for t in trace if t[0] == core] == [(core, 0x8000000F)]),
        ("after the power-on only the boot address is written again, until the reset",
         all(t == (0x0207B01C, bs.STUB32) for t in after[1:-1]) and after[-1] == (0x105C0400, 1)),
        ("the registers as they stand: CONFIGURATION 0x8000000f, OPTION 0x10010101, DURATION0 0xfffff11f",
         held[0] == 0x8000000F and held[2] == 0x10010101 and held[4] == 0xFFFFF11F),
    ]
    failed = [text for text, ok in checks if not ok]
    for text in failed:
        print(f"FAIL  {text}")
    print("   the power sequence as written: " + "; ".join(f"{address:#010x}={value:08x}" for address, value in trace[:first + 1])
          + f"; then {len(after) - 1} more writes" + (f" (last {after[-1][0]:#010x}={after[-1][1]:#x})" if len(after) > 1 else ""))
    print(f"   the power sequence: {len(checks) - len(failed)} of {len(checks)} checks pass"
          + ("" if not failed else ": FAILED " + "; ".join(failed)))
    stage = struct.unpack("<48I", u.mem_read(bs.SCRATCH, 192))
    print(f"   the scratch page: stage {stage[0]}; words 1 to 9 " + " ".join(f"{word:08x}" for word in stage[1:10])
          + "; words 8 to 38 (the 64-bit ones, low word first) " + " ".join(f"{word:08x}" for word in stage[8:39] if word))
    text = written.replace(bytes([13]), b"").decode("latin1")
    if secondary is None:
        want = "the ARM32 stub never ran; in 64 bits at EL2: not seen; at EL1 after the eret: not seen"
        ok = stage[0] == 0 and want in text
        print(f"   {'PASS' if ok else 'FAIL'}: nothing came from the core, and the boot CPU says so: {want!r}; the scratch page stays empty")
    else:
        lines = [line.decode("latin1") for line in secondary.split(bytes([0]))[0].replace(bytes([13]), b"").split(bytes([10])) if line.strip()]
        for line in lines:
            print("   the secondary logged: " + line)
        got = [line[line.index(" core 1"):] if " core 1" in line else line for line in lines]
        want = [("alive in 32 bits", "MPIDR=80000101 CPSR=000001d3"),
                ("in 64 bits at EL2", "CurrentEL=00000008 MPIDR=0000000080000101 HCR_EL2="),
                ("in 64 bits at EL1", "CurrentEL=00000004 MPIDR=0000000080000101")]
        ok = len(got) == 3 and stage[0] == 5 and all(any(w[0] in line and w[1] in line for line in got) for w in want) \
            and "the ARM32 stub ran; in 64 bits at EL2: yes; at EL1 after the eret: yes" in text
        print(f"   {'PASS' if ok else 'FAIL'}: three lines from the core (32 bits, 64 bits at EL2, 64 bits at EL1), its last stage 5, "
              f"and the boot CPU's result says yes three times")
    if failed or not ok:
        raise SystemExit("FAIL: the one-core experiment, as rehearsed")


def rehearse_el1(u, md, loaded: bytes | None, wanted_entry: int) -> None:
    """Run the AArch64 image for EL1 where S-Boot's reader puts it (0x40080000: its bytes are at PARAM
    offset 0xd1000 of the image being rehearsed), from the entry the eret names. The emulator stays
    at EL1 throughout: what it cannot show is the change of level itself."""
    from unicorn import UC_HOOK_CODE
    from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2
    if loaded is None:
        return
    header = struct.unpack_from("<4I", loaded, 0xD1000)
    print(f"   the image for EL1 at PARAM offset 0xd1000: magic {header[0]:#010x}, {header[1]:#x} bytes, entry {header[2]:#010x}"
          + (" as the eret names" if header[0] == 0x54314C45 and header[2] == wanted_entry else ": MISMATCH with the eret"))
    u.mem_write(0x40080000, loaded[0xD1000:0xD1000 + 0x8000])
    entry = wanted_entry
    from capstone import Cs as Cs2
    md.skipdata = True
    ins = [i for i in md.disasm(bytes(u.mem_read(0x40080000, 0x1800)), 0x40080000) if i.mnemonic != ".byte"]
    paint = next((i.address for i in ins if i.address >= entry and i.mnemonic == "str" and i.op_str == "w1, [x0], #4"), None)
    clean = next((i.address for i in ins if i.address >= entry and i.mnemonic == "dc" and i.op_str.endswith(", x0")), None)
    reset = [b.address for a, b in zip(ins, ins[1:]) if b.address >= entry and a.mnemonic == "mov" and a.op_str.replace("0x", "") == "w1, #1"
             and b.mnemonic == "str" and b.op_str == "w1, [x0]"]        # the software reset, on the main path and in the handler
    once = []

    def cut_paint(uc, address, size, data=None):
        if not once:
            uc.reg_write(UC_ARM64_REG_X0, uc.reg_read(UC_ARM64_REG_X2) - 4)
            once.append(1)

    def cut_clean(uc, address, size, data=None):
        uc.reg_write(UC_ARM64_REG_X0, uc.reg_read(UC_ARM64_REG_X2) - 64)
        uc.reg_write(UC_ARM64_REG_PC, address + 4)

    def stop(uc, address, size, data=None):
        uc.emu_stop()

    def on_write(uc, access, address, size, value, data=None):    # smp: the registers of the power sequence, in order
        if 0x105C0000 <= address < 0x105D0000 or 0x0207B000 <= address < 0x0207C000 or 0x10020000 <= address < 0x10020010 \
                or address == 0x10040900:
            trace.append((address, value & 0xFFFFFFFF))
            if address == 0x105C2280 and value & 0xF == 0xF and not powered:   # A53 core 1's CONFIGURATION: the core starts
                powered.append(value)
                trace.pop()                          # the write is recorded when it is made, after the core's turn
                uc.emu_stop()
            if address == 0x105C0400:                 # SWRESET: on the tablet the restart follows
                uc.emu_stop()

    if smp:
        u.hook_add(UC_HOOK_MEM_WRITE, on_write)
        u.mem_map(0x41000000, 0x4000)                 # the stubs and the scratch page: without cache on the tablet
        u.mem_map(0x0207B000, 0x1000)                 # the monitor's window: the boot address, then the boot flags
        u.mem_write(0x0207B028, struct.pack("<8I", 4, 4, 4, 4, 1, 4, 4, 4))   # what the 32-bit kernel read there
        for address, value in ((0x105C2280, 0x80000000), (0x105C2284, 0x10380000), (0x105C2288, 0x10010103),
                               (0x105C2290, 0xFFFFFFFF), (0x105C2294, 0xFFFFFFFF), (0x105C2298, 0xFFFFFFFF),
                               (0x105C229C, 0xFFFFFFFF), (0x105C2428, 0x00020001), (0x105C0120, 0x00000000)):
            u.mem_write(address, struct.pack("<I", value))

        def count_down(uc, address, size, data=None):  # "none": nothing will come from the core, so the watchdog counts
            passes["ticks"] = passes.get("ticks", 0) + 1
            if passes["ticks"] % 250 == 0:             # 250 instructions a tick: three seconds in 1.5 million
                now = struct.unpack("<I", uc.mem_read(0x10020008, 4))[0]
                uc.mem_write(0x10020008, struct.pack("<I", max(now, 1) - 1))
        if smp == "none":
            u.hook_add(UC_HOOK_CODE, count_down)
    if paint:
        u.hook_add(UC_HOOK_CODE, cut_paint, begin=paint, end=paint)
    if clean:
        u.hook_add(UC_HOOK_CODE, cut_clean, begin=clean, end=clean)
    for at in reset:
        u.hook_add(UC_HOOK_CODE, stop, begin=at, end=at)
    before = struct.unpack("<I", u.mem_read(COUNTER, 4))[0]
    try:
        u.emu_start(entry, 0, timeout=60_000_000, count=0)
    except UcError as error:
        print(f"   the EL1 image stopped with {error!r} at pc {u.reg_read(UC_ARM64_REG_PC):#010x}")
    pc = u.reg_read(UC_ARM64_REG_PC)
    after = struct.unpack("<I", u.mem_read(COUNTER, 4))[0]
    lines = [line.decode("latin1") for line in bytes(u.mem_read(RING + (before & RING_MASK), after - before)).replace(bytes([13]), b"").split(bytes([10])) if line.strip()]
    print(f"   the image for EL1, run from {entry:#010x}: stopped at pc {pc:#010x} "
          f"({'its software reset' if pc in reset else 'NOT its software reset'}); logged: {lines}")
    update, trigger = struct.unpack("<II", u.mem_read(0x13801410, 4) + u.mem_read(0x13802040, 4))
    last = bytes(u.mem_read(0x67BFFFFC, 4))                    # the band's last pixel: the only one the cut paint loop writes
    print(f"   the band's last pixel {last.hex(' ')} ({'green in XRGB8888' if last == bytes.fromhex('00 ff 00 00') else 'WRONG'}); "
          f"DECON_UPDATE {update:#010x} ({'ok' if update & 1 else 'WRONG'}), DECON_TRIGGER {trigger:#010x} ({'ok' if trigger == 0xE0000003 else 'WRONG'})")


def check_bundle(logo: bytes, param: bytes, bundle: bytes, reads: list) -> None:
    """The bundle is in the PARAM image, in the room S-Boot never reads, and the ARM32 code reads
    exactly it (KERNEL_LOAD in split_source.py): the calls it makes, as the emulator saw them."""
    import build_ffree as bf
    places = [m.start() for m in re.finditer(re.escape(bundle), param)]
    if len(places) != 1:
        raise SystemExit(f"the bundle is in the PARAM image {len(places)} time(s), not once")
    at = places[0]
    end = max(i for i in range(0, bf.SBOOT_DATA_AT, 512) if any(param[i:i + 512])) + 512   # the end of the archive, or of the bundle
    archive_end = max(i for i in range(0, at, 512) if any(param[i:i + 512])) + 512
    sector = bf.PARAM_SECTOR + at // 512
    tree = [i for i in range(0, len(bundle), 512) if bundle[i:i + 4] == b"\xd0\x0d\xfe\xed"][-1]   # the device tree: last, on a sector
    kernel = [(d, s, n) for d, s, n in reads if 0x40000000 < d < 0x5F000000]                 # the start of PARAM goes to 0x40000000
    device_tree = [(d, s, n) for d, s, n in reads if d == 0x5F000000]
    at_dest, at_sector, left = 0x42000000, sector, tree                                       # the kernel, piece after piece
    for dest, first, count in kernel:
        if (dest, first) != (at_dest, at_sector) or not 0 < count <= 0x400000 or count > left:
            break
        at_dest, at_sector, left = at_dest + count, at_sector + count // 512, left - count
    whole = left == 0
    checks = [
        ("the bundle is on a sector", at % 512 == 0),
        (f"the archive ends at {archive_end:#x}, then nothing until the bundle", archive_end + 0x8000 <= at),
        (f"the bundle ends at {at + len(bundle):#x}, clear of S-Boot's data at {bf.SBOOT_DATA_AT:#x}",
         at + len(bundle) + bf.SBOOT_DATA_MARGIN <= bf.SBOOT_DATA_AT),
        ("nothing after the bundle before S-Boot's data", at + len(bundle) == end),
        (f"the kernel: {tree:#x} bytes from sector {sector}, read whole in {len(kernel)} call(s)",
         whole and at_dest == 0x42000000 + tree),
        (f"the device tree: {len(bundle) - tree:#x} bytes from sector {sector + tree // 512}, in 1 call",
         device_tree == [(0x5F000000, sector + tree // 512, len(bundle) - tree)]),
    ]
    failed = [text for text, ok in checks if not ok]
    for text in failed:
        print(f"FAIL  {text}")
    if failed:
        raise SystemExit("the bundle is not where the ARM32 code will read it")
    print(f"the bundle ({len(bundle)} bytes: Image {tree:#x}, device tree {len(bundle) - tree:#x}) is in PARAM at {at:#x}: " + "; ".join(
        text for text, ok in checks))


def check_record(record: bytes | None, slot: bytes, letter: str) -> bytes:
    """What the ARM32 code left at 0x40003000 for stage 2 when it made the monitor call: the header of the slot
    whose kernel it read (its first 0x38 bytes, as written in CACHE), that slot's first sector, then "T7KR"."""
    import build_ffree as bf
    first = bf.CACHE_SECTOR + bf.SLOT_REL[letter]
    wanted = slot[:0x38] + struct.pack("<II", first, bf.KBOOT_RECORD_MAGIC)
    if record != wanted:
        got = struct.unpack("<16I", record) if record else ()
        raise SystemExit(f"FAIL: the record for EL2 at {bf.KBOOT_RECORD_AT:#010x} is not slot {letter}'s header, its sector and the "
                         f"magic: {' '.join(f'{w:08x}' for w in got)}")
    print(f"   the record for EL2 at {bf.KBOOT_RECORD_AT:#010x}: slot {letter}'s header as written (generation "
          f"{struct.unpack_from('<I', slot, 8)[0]}, image {struct.unpack_from('<I', slot, 0x10)[0]:#x} bytes, tree "
          f"{struct.unpack_from('<I', slot, 0x18)[0]:#x} bytes, hashes {struct.unpack_from('<Q', slot, 0x20)[0]:016x} "
          f"{struct.unpack_from('<Q', slot, 0x28)[0]:016x}), its first sector {first}, \"T7KR\"")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("logo", type=Path)
    parser.add_argument("--payload", choices=["smc", "sreset", "kboot"], default="smc")
    parser.add_argument("--node", type=lambda t: int(t, 0), default=0x24220000, help="F: the false free block in the file buffer")
    parser.add_argument("--ring", type=Path, help="a dump made with tools/seclog_dump: the guard rehearses against it")
    parser.add_argument("--needle", help="a text of the marker's length that the dump holds; it stands in for the image's marker")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--before", help="the write counter is set just before the N-th occurrence of this text")
    group.add_argument("--after", help="the write counter is set just after the N-th occurrence of this text")
    parser.add_argument("--nth", type=int, default=1)
    parser.add_argument("--then", default="",
                        help="after the moment, log what the boots that follow would (comma-separated): boot = the S-Boot log "
                             "of the next boot up to where its payload starts, skip = the line that says the test was skipped")
    parser.add_argument("--rotate", type=lambda t: int(t, 0), default=0, help="move the ring's content this many bytes forward")
    parser.add_argument("--counter", type=lambda t: int(t, 0), default=0xD0F02, help="AArch64 part: the log counter at entry")
    parser.add_argument("--param", type=Path, help="the PARAM image being rehearsed: its first bytes stand where S-Boot's reader loads")
    parser.add_argument("--kernel-bundle", type=Path, help="the kernel bundle (Image, then device tree): both stand where S-Boot's reader loads them")
    parser.add_argument("--slot-a", type=Path, help="kboot: slot A of CACHE as written (an empty file: the slot was never written)")
    parser.add_argument("--slot-b", type=Path, help="kboot: slot B of CACHE")
    parser.add_argument("--ledger", default="none",
                        help="kboot, with --ring: the boots logged after the real dump, oldest first, comma-separated (none, failed, up, "
                             "fallback, handback, failed-u; 'cold' first: an empty ring, as after a power-on), then this one's start")
    parser.add_argument("--ttbr", choices=["mapped", "zero"], default="mapped",
                        help="kboot: whether S-Boot's first-level table is made to map what the code needs")
    parser.add_argument("--expect", choices=["start", "handback", "reset"],
                        help="kboot: what the loader must do: start the kernel (the ARM32 code reaches the smc, stage 2 enters EL1), "
                             "hand S-Boot its own kernel, or reach the smc and have stage 2 refuse and reset the SoC (the next boot "
                             "falls back by the ledger)")
    parser.add_argument("--tamper", choices=["none", "record-missing", "record-corrupt", "kernel-changed"], default="none",
                        help="kboot: what changes between the ARM32 code and stage 2: nothing; the record at 0x40003000 missing "
                             "(zeros: as if the ARM32 code had written none); one byte of it changed (the generation, which only "
                             "the header's own hash covers); one byte of the kernel changed after the ARM32 code hashed it")
    parser.add_argument("--smp", choices=["secondary", "none"],
                        help="the one-core experiment: the PMU and the sysram window are as the tablet's kernel saw them; `secondary` plays "
                             "the two stubs on an emulated second core when stage 2 powers it on, `none` has nothing come")
    parser.add_argument("--stubs", type=Path, help="smp: smp-stubs.bin as scripts/build_smp_stubs.py built it")
    args = parser.parse_args()
    if args.smp and (args.payload != "sreset" or args.stubs is None):
        raise SystemExit("--smp goes with --payload sreset and --stubs (the stubs as built)")
    import build_ffree as bf
    a64_off = {"sreset": bf.SRESET_A64_OFF, "kboot": bf.KBOOT_A64_OFF}.get(args.payload, bf.A64_CODE_OFF)
    logo = bytearray(args.logo.read_bytes())
    ring, counter = None, None
    slots = None
    if args.payload == "kboot":
        if not (args.ring and args.slot_a is not None and args.slot_b is not None and args.expect):
            raise SystemExit("kboot needs --ring and --ledger (the boot before), --slot-a and --slot-b (what CACHE holds), and --expect")
        slots = {letter: (path.read_bytes() if path.stat().st_size else b"") for letter, path in (("A", args.slot_a), ("B", args.slot_b))}
    if args.ring and args.payload == "kboot" and not (args.before or args.after):
        raw = args.ring.read_bytes()
        ring, counter = ledger_ring(raw, args.ledger)
        print(f"the ledger, from {'an empty ring (a power-on)' if args.ledger.startswith('cold') else args.ring.name}, then the boots "
              f"{args.ledger!r}, then this boot's start: write counter {counter:#x}")
    elif args.ring:
        raw = args.ring.read_bytes()
        needle = args.needle.encode() if args.needle else None
        if needle and args.payload == "kboot":
            raise SystemExit("--needle is for the sreset guard: kboot's ledger is replayed with the dump as it is")
        if needle:
            at = logo.index(b"HIJACK3: ")
            marker = bytes(logo[at:at + 17])
            if len(needle) != len(marker):
                raise SystemExit(f"the needle must have the marker's length ({len(marker)})")
            logo = bytearray(bytes(logo).replace(marker, needle))
        ring = bytearray(RING_MASK + 1)
        ring[:len(raw) - 0x1000] = raw[0x1000:]          # the dump holds the first 0x1FF000 bytes of the ring
        ptr = struct.unpack_from("<I", raw, 0xFFC)[0] & RING_MASK   # the dump's write counter, as a ring offset
        counter = ptr
        if args.then and args.payload == "kboot":
            raise SystemExit("--then is for the sreset guard")
        if args.before or args.after or args.then:
            key = (args.before or args.after or "").encode()
            hits = [m.start() for m in re.finditer(re.escape(key), bytes(ring))]
            if args.nth > len(hits):
                raise SystemExit(f"{len(hits)} occurrence(s) of the text in the dump, not {args.nth}")
            index = hits[args.nth - 1] + (len(key) if args.after else 0) if key else ptr   # no text: the dump's own end
            counter = index                                # the ring's offsets and the counter agree below 2 MiB
            print(f"ring from {args.ring.name}: write pointer {ptr:#x}; " + (
                f"the counter is set {'after' if args.after else 'before'} occurrence {args.nth} of {key!r} (ring offset {index:#x}): "
                if key else "the counter is where the dump ends: ") + f"counter {counter:#x}")
            for step in filter(None, args.then.split(",")):
                if step == "boot":                       # the S-Boot log of a boot that ran the old payload, up to where
                    text = bytes(ring)                   # its payload started: the next boot would log the same lines
                    payload = max(m.start() for m in re.finditer(re.escape(needle), text) if m.start() < counter)
                    start = max(m.start() for m in re.finditer(b"PARAM ENV VERSION", text) if m.start() < payload)
                    chunk = text[start:payload]
                elif step == "skip":                     # what the payload logs instead of the test
                    chunk = needle + b" skipped: the previous boot already ran this image" + bytes([13, 10])
                else:
                    raise SystemExit(f"unknown step {step!r} in --then")
                at = counter & RING_MASK
                first = min(len(chunk), RING_MASK + 1 - at)
                ring[at:at + first] = chunk[:first]
                ring[:len(chunk) - first] = chunk[first:]
                counter += len(chunk)
            if args.then:
                print(f"   then logged after the moment ({args.then}): counter {counter:#x}, ring offset {counter & RING_MASK:#x}")
        shift = args.rotate & RING_MASK
        if shift:
            ring = ring[-shift:] + ring[:-shift]         # what was at position i is now at i + shift
            counter += shift
            print(f"   rotated by {shift:#x}: counter {counter:#x}, ring offset {counter & RING_MASK:#x}")
    if ring is None:                                   # no dump given: an empty ring, the counter where the last dump had it
        ring, counter = bytearray(RING_MASK + 1), 0x134509
    reads = rehearse_arm32(bytes(logo), args.node, a64_off, bytes(ring), counter, slots, args.ttbr == "mapped")
    if slots is not None:
        want = "hand" if args.expect == "handback" else "smc"
        if rehearse_arm32.outcome != want:
            raise SystemExit(f"FAIL: the loader {rehearse_arm32.outcome or 'stopped elsewhere'} where it must "
                             f"{'start the kernel' if want == 'smc' else 'hand back to S-Boot'}")
        print(f"PASS: the loader {'starts the kernel' if want == 'smc' else 'hands S-Boot its own kernel'}, as expected")
        chosen = None                                 # the slot the kernel was read from last: the one the loader kept, for stage 2's own checks
        for dest, sector, count in reversed(reads):
            chosen = next((letter for letter, rel in bf.SLOT_REL.items()
                           if dest == bf.KERNEL_AT and sector == bf.CACHE_SECTOR + rel + bf.SLOT_HEADER_BYTES // 512), None)
            if chosen:
                break
        if want == "smc" and chosen is None:
            raise SystemExit("FAIL: the ARM32 code reached the smc without reading a kernel from a slot")
        if want == "smc":
            record = check_record(rehearse_arm32.record, slots[chosen], chosen)
            data = bytearray(slots[chosen][bf.SLOT_HEADER_BYTES:])
            if args.tamper == "record-missing":       # as if the ARM32 code had written none: the zeros it starts the slots with
                record = bytes(len(record))
            elif args.tamper == "record-corrupt":     # the generation's low byte: only the header's own hash says it changed
                record = record[:8] + bytes([record[8] ^ 0x01]) + record[9:]
            elif args.tamper == "kernel-changed":     # a byte of the kernel, after the ARM32 code hashed it
                data[0x20000] ^= 0xFF
            if args.tamper != "none":
                print(f"   tampered on the way to EL2 ({args.tamper}): stage 2 must refuse and reset the SoC")
            bundle = Path(args.logo).parent / "bundle-of-the-slot.tmp"
            bundle.write_bytes(bytes(data))
            rehearse_a64(bytes(logo), args.node, args.payload, args.counter, None, bundle, record=record)
            why = {'reset': 'resets the SoC', 'eret': 'enters EL1', 'other': 'stops elsewhere', 'painted': 'touches the screen',
                   'wfe': 'resets the SoC (its own software reset)'}.get(rehearse_a64.outcome, rehearse_a64.outcome)
            if args.expect == "start":
                if rehearse_a64.outcome != "eret":
                    raise SystemExit('FAIL: at EL2 the loader ' + why + ' where it must enter EL1: the kernel would not start')
                said = struct.unpack_from("<QQ", slots[chosen], 0x20)
                line = next((l for l in rehearse_a64.lines if " kernel: magic=" in l), "")
                if f"hash={said[0]:016x}" not in line or f"tree={said[1]:016x}" not in line or "every byte as the slot's header says" not in line:
                    raise SystemExit(f"FAIL: stage 2 did not check the kernel of slot {chosen} against its header's hashes "
                                     f"({said[0]:016x}, {said[1]:016x}): {line[:200]!r}")
                print(f"PASS: at EL2 the loader enters EL1 as it must, the kernel and the tree of slot {chosen} checked against its "
                      f"header's hashes ({said[0]:016x}, {said[1]:016x}), handed over by the ARM32 code")
            else:
                if rehearse_a64.outcome not in ("reset", "wfe"):
                    raise SystemExit('FAIL: at EL2 the loader ' + why + ' where it must reset the SoC: the kernel would start')
                refused = next((l for l in rehearse_a64.lines if "REFUSED" in l or "NOT every byte" in l or "not as expected" in l), "")
                print(f"PASS: at EL2 the loader resets the SoC as it must (stage 2: {refused.split('KBOOT: EL2', 1)[-1].strip()[-90:]!r}); "
                      "the next boot finds the ledger's try without up and gives S-Boot its own kernel")
        return 0
    if args.param and args.kernel_bundle:
        check_bundle(bytes(logo), args.param.read_bytes(), args.kernel_bundle.read_bytes(), reads)
    rehearse_a64(bytes(logo), args.node, args.payload, args.counter, args.param.read_bytes() if args.param else None, args.kernel_bundle,
                 args.smp or "", args.stubs.read_bytes() if args.stubs else b"")
    return 0


if __name__ == "__main__":
    sys.exit(main())
