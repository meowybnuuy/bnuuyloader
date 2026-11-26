# Credits

## People and projects

| Who | What | Where |
|---|---|---|
| **meowybnuuy**, "bnuuy" | bnuuyloader: the idea of using the boot logo vulnerability to run ARM64 on an Exynos 5433, the loader for the Galaxy Note 4 (SM-N910C), and the monitor call that makes it possible. | https://github.com/meowybnuuy/bnuuyloader, MIT |
| **UnsignedChad** | The vulnerability: CVE-2026-21155 (SVE-2026-3546), its write-up and proof of concept. | https://github.com/UnsignedChad/CVE-2026-21155-SVE-2026-3546 |
| **elkir0** | The port to the Galaxy Tab S2 8.0 LTE (SM-T715), the picture of its boot screen (`t715/loader/art/`), and the tablet's 32-bit Linux port that it builds on. | https://github.com/elkir0/omarchy-tab-s2, GPL-2.0-or-later |
| **The Linux kernel developers** | The kernel code that the patches of `t715/kernel/` are made of. | Their SPDX headers: GPL-2.0-only |

The arm64 Omarchy image, built from [Omarchy](https://github.com/basecamp/omarchy) and
[omarchy-mobile](https://github.com/derekross/omarchy-mobile) (MIT and GPL-3.0-or-later parts,
Copyright (c) 2026 Derek Ross), with patches for Hyprgraphics (BSD-3-Clause), is in
[omarchy-tab-s2](https://github.com/elkir0/omarchy-tab-s2) under `arm64/` since 2026-11-25; the
fork's release 0.9.0 carried a first copy of it in `t715/rootfs/`.

The port is not affiliated with bnuuy, with Samsung, or with Omarchy.

## What the port takes from upstream

| Taken from upstream | Upstream has it in | The port has it in |
|---|---|---|
| The principle of the entry: a forged heap node, and the split of a heap block that writes over a saved return address. Upstream's comment: "The decoder's large-heap split follows this forged node. Its next pointer reaches the ARM32 entry through the saved return address." | `build.py`, `sboot_util.py` | `t715/loader/scripts/build_split.py`, `build_ffree.py` (docstrings) |
| The monitor call: `SMC 0x82000400`, with the entry in r1, r2 = 0x800, r3 = 1. The port's comment calls it "the Note 4 loader's call". | `src/a32_entry.S` | `t715/loader/scripts/split_source.py` |
| Cleaning the data cache and invalidating the instruction cache before the `smc`, so that code written as data can be fetched | `src/a32_entry.S` | `t715/loader/scripts/split_source.py` |
| The register sequence that enters EL1: HCR_EL2, CNTHCTL_EL2, CNTVOFF_EL2, CPTR_EL2, MDCR_EL2, SCTLR_EL1, SPSR 0x3C5, then `eret`. The port's header says it is "the way the Note 4 loader does it (bnuuyloader's boot_el1.S)". | `src/boot_el1.S` | `t715/loader/stage2/boot_el1.S` |
| The framebuffer at 0x67000000, the two display registers, and the trigger value | `src/fb.c` | `t715/loader/stage2/stage2.c`, `t715/loader/scripts/a64_marker.S` |
| The byte signature of S-Boot's allocator, looked for in another device's bootloader | `sboot_util.py` | `t715/loader/scripts/scan_sboot.py` |

Nothing else is copied. The port does not import or link upstream's `src/`: its console, its eMMC
driver and its boot image parser are not used. Each file of the port that derives from upstream
says so in its header.

## What is new in the port

- The entry rebuilt for this tablet's S-Boot: a forged heap head and a false free block.
- The forged block calibrated against S-Boot's own decoder, run in an emulator.
- A picture on the whole panel in the forged logo, drawn by S-Boot itself before any kernel, with
  Huffman tables built for the file to make room for it (`t715/docs/SPLASH.md`).
- A rescue in BOOT and RECOVERY that writes the loader known to work back when PARAM holds none
  (`t715/rescue/`, `t715/docs/RESCUE.md`).
- The hand-back to S-Boot, and a ledger in S-Boot's RAM log ring that gives the tablet back to its
  own kernel after a failed attempt.
- Stage 2 at EL2 in C, with exceptions caught, the MMU and the caches on.
- S-Boot's own eMMC reader in place of a driver; the kernel hashed before it is started; two slots
  in the CACHE partition.
- The watchdog as a way out of a hang.
- An enable-method that starts the eight cores without PSCI.
- The findings about arm64 Linux on this SoC: the stopped generic counter and the MCT patch, the
  clock units in power domains, the limit of `/dev/kmsg`, the regulator core.

## Licence

`LICENSE` is upstream's, unchanged: MIT, Copyright (c) 2026 meowybnuuy. The files of this
repository are under four licences; a file's SPDX line wins.

| Files | Licence |
|---|---|
| Upstream's: the root files, `src/`, `assets/` | MIT, Copyright (c) 2026 meowybnuuy |
| The port's own sources: `t715/loader/scripts/`, `t715/loader/stage2/`, `t715/loader/el1/`, `t715/loader/art/` (the picture of the boot screen and its preview), `t715/tools/t715-arm64-install`, and the documents `t715/README.md`, `t715/docs/FINDINGS.md`, `t715/docs/PRODUCTION-LOADER.md`, `t715/docs/SPLASH.md`, `t715/docs/RESCUE.md`, `t715/docs/GO-ARM64.md`, `CREDITS.md` | MIT, Copyright (c) 2026 elkir0; those derived from upstream carry their notice too |
| `t715/rescue/`: the patch to omarchy-tab-s2's `boot/`, and its page | GPL-2.0-or-later, as omarchy-tab-s2, the tree it is made for |
| `t715/kernel/patches/` and the kernel files under `t715/kernel/` | GPL-2.0-only, as the kernel: the SPDX headers of the files they change |
| `t715/loader/tools/seclog_dump/seclog_dump.c` | GPL-2.0 |
| Everything else under `t715/` in the fork: `t715/kernel/` build scripts and configuration, `t715/build-arm64.sh`, and the other documents of `t715/docs/` | GPL-2.0-or-later, as omarchy-tab-s2, unless a file says otherwise |

No Samsung firmware, blob or dump is in this repository.

## AI assistance

bnuuy discloses their use in the README. The port to the Tab S2 was made with AI coding agents as
well; its kernel patches carry their co-author lines.

The picture of the boot screen, `t715/loader/art/splash-bnuuy-and-me.png`, is the one the owner
gave for it. The file they provided carried Google's content credentials, which say it was created
with Google's generative AI and resized there. What is published here is its pixels alone, as a
plain PNG: the credentials, with their time stamps, were left out. The loader built from it is the
one on the owner's tablet, byte for byte.
