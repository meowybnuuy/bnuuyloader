# Findings: S-Boot on the Galaxy Tab S2 8.0 (SM-T715) and the path to AArch64

What was found while porting bnuuyloader to the Galaxy Tab S2 8.0 (SM-T715) and bringing arm64
Linux up on it: about this tablet's S-Boot, about the loader, and about what arm64 Linux meets on
this SoC when it is started this way. The loader is described in [../README.md](../README.md), and
the loader of the daily boot in [PRODUCTION-LOADER.md](PRODUCTION-LOADER.md). Two later additions,
the boot screen and the rescue, have their own pages: [SPLASH.md](SPLASH.md) and
[RESCUE.md](RESCUE.md).

All of it comes from one tablet, with one bootloader. Another Exynos 5433 device may differ: the
addresses and the calibrated block certainly, the decoder's rounding perhaps.

How sure each fact is:

| Tag | Meaning |
|---|---|
| **[hardware]** | Observed on the tablet: a line of the cycle log, a line the loader wrote in S-Boot's log ring, or a dated observation written in a comment of the loader's code. |
| **[static]** | Read in code: S-Boot's code through the disassembler and the call-path tools of `../loader/scripts/`, the secure monitor's code (section 23), the loader's source, or Linux. |
| **[emulator]** | Seen only in the Unicorn rehearsal. Not a measurement. |

Paths such as `drivers/regulator/core.c` are files of the kernel tree of omarchy-tab-s2 (v6.12.114
plus its patch series). Lines of the loader are under `../loader/`. Some paths quoted from the studies name files of
the fork that are not in this tree (`../kernel/test-kernel/`, `../kernel/smp/`,
`../kernel/config/`, and the logs under `../loader/out/`): they are in
[elkir0/bnuuyloader](https://github.com/elkir0/bnuuyloader). `../rootfs/` is the arm64 image's
build, in [omarchy-tab-s2](https://github.com/elkir0/omarchy-tab-s2) under `arm64/rootfs/`.
## 1. The device and its S-Boot

The SM-T715 has an Exynos 5433: four Cortex-A53 and four Cortex-A57. The one unit tested runs
bootloader `T715XXU2CRH1`, hardware revision 9.

S-Boot for this unit is version 4.0, built Aug 6 2018. It runs ARM32 at EL1 with the MMU and the
caches on. There is no Trusted Firmware-A, and so no PSCI: upstream's README says so for the Note 4,
and the owner's 32-bit port starts its other seven cores without it. The arm64 test kernel runs on
one core (section 17).

Upstream's README describes the Note 4 (N910C) differently: it says S-Boot "runs in EL2", and that
"the boot core is Cortex-A53". The two devices should not be assumed to match on either point.

| Item | Value | Tag | Source |
|---|---|---|---|
| SoC | Exynos 5433, 4 × Cortex-A53 + 4 × Cortex-A57 | [static] | omarchy-tab-s2, `docs/hardware/SMP_BRINGUP.md` §1.1 |
| Tested unit | SM-T715, bootloader `T715XXU2CRH1`, hardware revision 9 | [static] | omarchy-tab-s2, `README.md:51` |
| S-Boot version | 4.0 (Aug 6 2018) | [static] | |
| Exception level of S-Boot | ARM32 at EL1, MMU and caches on | [hardware] | the monitor call lands at EL2 and the kernel is entered at EL1 (section 6); upstream's README says EL2 for the Note 4 |
| RAM | 0x40000000..0xBEA00000 minus a hole; about 2.8 GB usable, 3 GiB fitted | [static] | omarchy-tab-s2 |
| eMMC as S-Boot uses it | 8-bit DDR at 52 MHz | [static] | omarchy-tab-s2 |

## 2. S-Boot's memory map and functions

All addresses are runtime addresses. S-Boot's code is loaded at 0x23DE2000; a file offset in the
bootloader image is the runtime address minus that base.

| What | Address | Tag | Source |
|---|---|---|---|
| Code, data, own stack and heaps | from 0x23DE2000 | [static] | `../loader/scripts/sbdis.py:12`, `sboot_jpeg_emu.py:33` |
| File buffer (where a file of PARAM is copied; 1 MiB) | 0x24200000..0x24300000 | [static] | `../loader/scripts/build_hijack.py:38-39` |
| JPEG decode buffer (12 MiB) | 0x24300000, ends at 0x24F00000 | [static] | `../loader/scripts/build_split.py:8`, `build_hijack.py:7` |
| DRAM heap | 0x24F00000..0x25100000; its first node B0 at 0x24F00000 | [static] | `../loader/scripts/build_calib.py:37-38`, `build_split.py:8-9` |
| DRAM heap list head | 0x23EC1048 | [static] | `../loader/scripts/build_split.py:39`, `sbdis.py:16` |
| Stack while `boot` calls its two helpers | sp 0x23EC0018; saved return address at 0x23EC0014 | [static] | `../loader/scripts/build_split.py:42-43` |
| Saved return address of the logo loader | 0x23EC00B4 | [static] | `../loader/scripts/build_hijack.py:41` |
| Kernel command line | 0x240C36E0 | [static] | `../loader/scripts/build_calib.py:41` |
| S-Boot's kernel entry cell | 0x23E56810 | [static] | `../loader/scripts/build_split.py:127,159` |
| RAM log ring | 0x26000000, 2 MiB; write counter 0x25FFFFFC; magic `LOGM` at 0x25FFFFF8 | [hardware] | `../loader/stage2/stage2.c:16-18`, `scripts/hijack_lines.py:9` |
| Framebuffer | 0x67000000, 1536 x 2048, XRGB8888, 6144 bytes a row | [hardware] | `../loader/stage2/stage2.c:19`, `scripts/build_hijack.py:366-367` |
| Display controller | DECON_UPDATE 0x13801410, DECON_TRIGGER 0x13802040 | [hardware] | `../loader/stage2/stage2.c:21-22`; `https://github.com/meowybnuuy/bnuuyloader/tree/main/src/fb.c:9-10` |
| Power management unit (PMU) | 0x105C0000 | [static] | omarchy-tab-s2, `docs/hardware/SMP_BRINGUP.md` §1.2 |
| Watchdog | 0x10020000 | [static] | omarchy-tab-s2, `docs/hardware/WATCHDOG.md` §1 |
| Clock units: A53 (APOLLO), A57 (ATLAS), memory (MIF) | 0x11900000, 0x11800000, 0x105B0000 | [static] | `../loader/stage2/stage2.c:219-221` |
| PERIS clock gates (0x800 ACLK, 0x900 PCLK) | 0x10040000 | [static] | `../loader/stage2/stage2.c:222` |
| eMMC controller (driven directly by upstream, not by this port) | 0x15540000 | [static] | `https://github.com/meowybnuuy/bnuuyloader/tree/main/src/emmc.c:4` |

Functions of S-Boot that the port uses or relies on. Names in italics are labels of this port.

| Address | Role | Source |
|---|---|---|
| 0x23E05820 | `printf`: writes a line into the RAM log ring | `../loader/scripts/sbdis.py:14-16`, `callpath.py:25-27` |
| 0x23E07080 | `malloc` | same |
| 0x23E071D8 | `malloc_large` | same |
| 0x23E071FC | `free` | same |
| 0x23E07B74 | `load_logo` | `../loader/scripts/sbdis.py:14-16` |
| 0x23E0A4BC | *`load_file`*: walks the archive of PARAM | `../loader/scripts/callpath.py:25-27, `build_ffree.py` (`SBOOT_DATA_AT`, its comment) |
| 0x23E14694 | `jpeg_wrapper`: decodes `logo.jpg` | `../loader/scripts/sboot_jpeg_emu.py:6-10,36` |
| 0x23E148D8 | `decode_and_draw` | `../loader/scripts/sbdis.py:14-16` |
| 0x23E17808 | the eMMC reader (section 9) | `../loader/scripts/split_source.py:326-330` |
| 0x23E17B20, 0x23E17B90 | the two helpers `boot` calls; each does `malloc_large(0x200)` | `../loader/scripts/build_split.py:10-12` |
| 0x23E17B68 | the `pop {r3,r4,r5,pc}` that lands in the forged code | `../loader/scripts/preflight.py` (`rehearse_arm32`: the `pop` at 0x23E17B68) |
| 0x23E069D8 / 0x23E069DC | `boot`'s call site / `boot` right after it (the hand-back) | `../loader/scripts/build_ffree.py:12`, `preflight.py` (`HAND_BACK`) |

## 3. S-Boot's RAM log ring

**Layout.** S-Boot keeps its log in a 2 MiB ring of ordinary RAM at 0x26000000. A 32-bit write
counter at 0x25FFFFFC counts every byte ever written; a byte goes to `ring + (counter & 0x1FFFFF)`.
The four bytes at 0x25FFFFF8 are the magic `LOGM`. The ring is cached, write-back memory for S-Boot.

**Content.** Each S-Boot log starts with the text `PARAM ENV VERSION`. The kernel's log starts with
`Booting Linux on physical CPU`. With the kernel option the owner's port adds
(`console=sec_log`), the kernel's console goes on writing in the same ring, after S-Boot's lines.

**What it survives.** It survives a software reset: every self-resetting test of 2026-11-24 read
the marker that the boot before had written, and skipped. A line is in RAM for the next boot only
if it has been written back: on 2026-11-24 the AArch64 code wrote its lines through the
data cache with the MMU on, "its counter never reached the memory and the next boot wrote over
every line after that". The loader now cleans each line and the counter before it goes on, and maps
the ring as normal memory that is not cached.

Not established: whether the ring survives a watchdog reset, a cold boot, or a power cut.

**How it is read.** From the owner's Linux, a small kernel module exposes the raw ring as a
read-only file in debugfs (`/sys/kernel/debug/seclog_dump`): it maps 0x25FFF000 for 2 MiB, which
is the 4 KiB header page and the first 0x1FF000 bytes of the ring. Two scripts then read the dump:
one splits it into boots and masks the identifiers; the other lists the lines the payloads wrote,
each with the context of its boot.

**Identifiers.** The ring holds the device's identifiers. The masking script names them: the eMMC
serial number, the `connie` and `cordon` tokens, serial numbers, the `ATAG_SERIAL` line, MAC
addresses, `{{...}}` tokens, and an RTC time stamp at the start of every boot. A raw dump must
never be published.

**The guard.** The ARM32 payload searches the ring before it runs a test. It finds the start of the
present boot's S-Boot log, then the start of the boot before, then looks for its own 17-character
marker between the two. If the marker is there, the boot before already ran this image: it logs
that it skips, and hands back to S-Boot. That is what stops a self-resetting test from running for
ever.

## 4. S-Boot's JPEG decoder, and why forged data must be calibrated against it

**The bug.** S-Boot decodes the boot logo (`logo.jpg` in PARAM) row by row into the 12 MiB decode
buffer at 0x24300000, with a stride of `(3 * width + 3) & ~3`. It does not stop the image at the
end of the buffer. An image tall enough writes its last rows past the end, over the DRAM heap that
follows. A JPEG carries no arbitrary bytes, so the forger has to find coefficients that decode to
the bytes he wants.

**The decoder is not libjpeg-turbo.** Only a quarter of all colours come out exactly through
libjpeg's integer YCbCr to RGB conversion, so a pixel of three wanted bytes may not exist at all.
Worse, S-Boot's decoder rounds differently from the libjpeg-turbo that Pillow and `djpeg` use. On
the tablet, bytes meant as `04 6a f5 fe 03 00 00 00 00 00 00 00 00 00 22 24` came out as
`0f 69 ef f9 05 05 06 00 00 00 00 01 01 00 21 23` (2026-11-24, in S-Boot's own exception
dump), where both other decoders said `00 00 22 24` for the last four. A block calibrated against
Pillow would have been wrong on the device.

**The answer.** The port runs S-Boot's own decoder, in a CPU emulator (Unicorn), on the forger's
output, and corrects the one block that matters in a closed loop until S-Boot's decoder gives the
wanted bytes. The rest of the image is black and written directly as coefficients, with no encoder
loss. The result is one calibrated block, kept as a small JSON file.

**The image.** 310 x 13501 pixels, stride 932. The heap head at 0x24F00000 is row 13500, byte 912:
pixel 304. One 8 x 8 block, band 1687, column 38, holds the head's 16 bytes and three spill bytes.
Pixels 310 and 311 of that row are beyond the width and are never decoded.

**The wide image.** 2048 x 2049 pixels, stride 6144: the whole panel, and one row more. The heap
head is row 2048, byte 0: block (256, 0), the first block of the last row. S-Boot draws a logo
from the top corner with nothing cut off (section 22), so the first 1536 columns of the first
2048 rows are the panel: a picture can live there. The JPEG must then end before the false free
block, at file offset 0x20000. **[emulator]** The decoder reads the code lengths of the Huffman
tables from the file (DHT) and takes the symbols in their standard order, whatever order the file
lists them in; so tables can be built for a file that is black almost everywhere. With libjpeg's
tables a black wide logo alone takes 116,288 of the 131,072 bytes; with tables built for it,
67,200. How S-Boot draws, the colours, the room in the file and the making of such a logo:
[SPLASH.md](SPLASH.md).

**Before any test.** `build_ffree.py --verify` decodes the whole logo with S-Boot's decoder in the
emulator (about 75 s; two minutes for the wide logo) and prints the bytes S-Boot will really leave
at 0x24F00000. It refuses the image unless they are the heap head's, and nothing was written past
the last row.

Upstream also relies on one calibrated block, `assets/jpeg_heap_header_block.npy`, and encodes the
rest of its image with Pillow. Its README does not say which decoder that block was calibrated
against. Whether the Note 4's S-Boot decoder rounds like this one is not known.

## 5. How code execution is obtained

**Lineage.** The principle is bnuuyloader's: a forged heap node, and the split of a heap block that
writes over a saved return address. Upstream states it in two lines of comment: "The decoder's
large-heap split follows this forged node. Its next pointer reaches the ARM32 entry through the
saved return address." It finds the place in S-Boot by a byte signature, and keeps a hit only with
the Note 4's literal values, among them a heap base of 0x24E00000. **This S-Boot holds that code
too**: `../loader/scripts/scan_sboot.py` finds the signature once, with the literals sentinel
0x23EC1048, heap base 0x24F00000, mode flag 0x240C0848 and small sentinel 0x23EC1058. Upstream's
own scan keeps a hit only with the Note 4's heap base, so on this image it keeps none of the one
it finds, and its `build.py` stops: "S-Boot allocator signature yielded 0 valid targets; expected
one".

Another trigger was tried first on this device, on 2026-11-23: `free()` writing over the logo
loader's saved return address while the JPEG decoder is destroyed. The cycle log shows five such
images that did not bring the tablet back by itself, and three more with no result logged.

The design that works was rebuilt for this S-Boot. It has two parts.

**Part 1: a forged heap head.** The calibrated block makes the decoder write, over the DRAM heap's
first node B0 at 0x24F00000, a node that says: size 0, not free, and `next` is F at 0x24220000.
F is in S-Boot's file buffer, where the logo file was copied: file offset 0x20000.

**Part 2: a false free block.** The bytes at F are a node: `{size 0xFFCA0208, free, prev 0, next
0x24220100}`, followed by padding and the ARM32 code at 0x24220100. The size is chosen so that
"the end of the block, less 0x200" is 0x23EC0008, on S-Boot's stack.

**The walk.** After the logo, S-Boot loads the kernel and calls `boot`. `boot` calls one of two
helpers (0x23E17B20 or 0x23E17B90), which asks the heap for 0x200 bytes with sp = 0x23EC0018.
`malloc_large` walks the list: the head, then B0 (not free: skipped), then B0's `next`, F (free,
and "big enough"). It takes F and carves the new node from F's end. The end is 0x23EC0008, so the
allocator writes `{0x200, 0, F, F.next}` onto the stack. The fourth word lands on the saved return
address at 0x23EC0014 and holds F's `next`: the code node.

**The landing.** The helper frees its buffer and returns with `pop {r3,r4,r5,pc}` at 0x23E17B68.
`pc` becomes 0x24220100. The code node's first word branches over its header; its free byte says
"busy", so a later walk skips it; its `next` is the list head, so a later walk ends there.

**What the code does.** It checks the ring (section 3). If the test is to run, it may call S-Boot's
reader (section 9), cleans the data cache from 0x24220000 to 0x26200000, invalidates the
instruction cache, and calls the monitor (section 6). If the monitor returns, or the test is
skipped, it puts the heap back and returns into `boot` at 0x23E069DC: S-Boot then boots the owner's
32-bit kernel as if nothing had happened. That hand-back is what makes every test recoverable.

**Putting the heap back.** A free block of 0x80000 bytes is declared at 0x67B00000, the bottom of
the screen. The heap head stays busy and points to it, so any later request of S-Boot is served
there and never on the stack again.

**Where the code is placed** (file offsets in the logo; the file buffer starts at 0x24200000):

| Offset | Address | What |
|---|---|---|
| 0..115873 | 0x24200000.. | the JPEG itself (115874 bytes) |
| 0x20000 | 0x24220000 | F, the false free block (16 bytes), then 0xF0 bytes of padding |
| 0x20100 | 0x24220100 | the code node (16 bytes) and the ARM32 payload |
| 0x20800 | 0x24220800 | the AArch64 entry, with its texts |
| 0x21000 | 0x24221000 | its vector table (2 KiB aligned) |
| 0x24000 | 0x24224000 | stage 2, the C code (section 7) |
| 0x38000 | 0x24238000 | in earlier tests only: an image for EL1 |

The logo file is padded to whole sectors (321 sectors, 164352 bytes, for the kernel test) and must
stay under the file buffer's 1 MiB.

## 6. The monitor call to EL2, and the state it leaves

**The call** comes from upstream and is unchanged. In ARM32, with r0 = 0x82000400, r1 = the AArch64
entry address, r2 = 0x800, r3 = 1, execute `smc #0`. The monitor enters the address in r1 as
AArch64 code at EL2.

**The state it leaves**, as the loader's own line in the ring gives it (`KBOOT: EL2 …`):

| Register at entry | Value | Tag |
|---|---|---|
| Exception level | EL2, AArch64 | [hardware] |
| MMU | off | [hardware] |
| Caches | off | [hardware] |
| `VBAR_EL2` | 0: an exception before the table is replaced is a jump to address 0 | [hardware] |
| `HCR_EL2` | 2: bit 1 (SWIO) only. RW, bit 31, is 0; the loader sets it before EL1 (section 8). Read here as RW until 2026-11-26 (section 23) | [hardware] |
| `MIDR_EL1` | 0x410fd031: a Cortex-A53 r0p1 | [hardware] |
| `MPIDR_EL1` | 0x80000100: the boot CPU, the first core of the A53 cluster | [hardware] |
| `DAIF` | masked by the loader's first instruction; its state at entry was not recorded | |

**It works on a secondary core too.** The one-core experiment of 2026-11-24 made the call from a
secondary A53, powered on by the PMU and released by the monitor in AArch32: the core landed in
AArch64 at EL2 ([SMP-EXPERIMENT.md](SMP-EXPERIMENT.md)). The kernel's method (section 17) relies on
it for all seven other cores, the four A57 included.

**Consequences for the loader.**
- Its first instructions mask every exception and install a vector table of its own.
- Nothing is cached. "Without it a loop runs about a hundred times slower than it should."
- Nothing the core wrote through S-Boot's cache is guaranteed to be in RAM. Hence the data-cache
  clean over the file buffer and the whole ring before the `smc`.
- The call does not come back when it works. The payload has a path for a return, which logs
  "the SMC returned to ARM32 (unexpected); handing back to S-Boot".

## 7. The stage-2 environment at EL2

Stage 1 (`scripts/a64_sreset.S`) runs with no runtime. It sets up what C needs, then calls stage 2.

**Vector table.** 16 slots of 0x80 bytes, 2 KiB aligned, at 0x24221000. Every slot branches to one
handler, which reads ESR, ELR, FAR and SPSR, logs them in the ring, and resets the SoC. Every
image with vectors raises an exception on purpose at its end (`svc #0`), to exercise the handler.

**MMU and caches.** An identity map, in tables written at 0x90000000 while nothing is cached:
a level-1 table of four entries (one gigabyte each), each pointing to a level-2 table of 512 blocks
of 2 MiB. TCR_EL2 = 0x80821720: a 32-bit address space, 4 KiB granule, inner shareable, 40-bit
outputs. MAIR_EL2 = 0x0044FF00.

| Region | Attribute |
|---|---|
| Everything | device |
| 0x20000000..0xDE800000 (the tablet's memory) | normal, write-back |
| 0x25C00000..0x26400000 (the ring and its header) | normal, **not cached** |

The ring is not cached because of the loss described in section 3. Then SCTLR_EL2 gets M, C and I,
followed by `ic iallu`.

**Stack.** 0x90020000, above the page tables.

**Stage 2** is C code linked at 0x24224000: compiled for a bare Cortex-A53 (`-O2 -ffreestanding
-mgeneral-regs-only -fno-pic`), linked with `ld.lld`, turned into a raw binary. Its entry clears
`.bss` itself, because nothing zeroed the memory behind the logo file. For the kernel test the
image is 16440 bytes, with 64 KiB of `.bss`.

**What stage 2 proves** once it runs: the stack by recursion, 64-bit division, `.data`, `.rodata`,
`.bss`, the screen (eight bands, read back), and the ring. The brief dates the whole chain as
proven on 2026-11-24; the first image that carried stage 2 is `sreset5`.

**Options** are chosen at build time: `EMMC_CHECK`, `EL1_TEST`, `HANDOFF`, `WATCHDOG_PROOF`,
`WATCHDOG_ARM`, `KERNEL`. Each one adds a block of code to the same file; a test image is a
combination of them.

**One rule of the loader.** It reads clocks and rails, and writes the watchdog and two PMU
markers. It changes no clock and no voltage: the first kernel runs on what S-Boot left.

## 8. Entering EL1

The last step is `stage2/boot_el1.S`. Its register sequence is upstream's `boot_el1.S` ("the way
the Note 4 loader does it"): mask DAIF; HCR_EL2 = 0x80000000 (RW only, so EL1 executes AArch64);
CNTHCTL_EL2 |= 3; CNTVOFF_EL2 = 0; CPTR_EL2 = 0; MDCR_EL2 = 0; clear M, C and I in SCTLR_EL1;
SPSR = 0x3C5 (EL1h, every exception masked); x0 = the device tree, x1 to x3 = 0; `eret`.

The port adds one thing: before the `eret`, it cleans and invalidates the whole data cache, level
by level and set by way, reading the geometry from CCSIDR_EL1. At EL1 the caches are off, and a
line left in the cache would be lost at the next reset, or would hide what EL1 writes to the same
place.

It was exercised without a kernel first, with a small test image for EL1: the image `sreset7`
(2026-11-24) carried it, and the tablet came back by itself.

## 9. S-Boot's own eMMC reader

Instead of driving the eMMC controller itself, as upstream does, the port calls S-Boot's reader
from ARM32: `0x23E17808(destination, first sector, bytes)`.

| Property | Value | Tag |
|---|---|---|
| Arguments | destination address, first sector (512 bytes), byte count | [static] |
| Return | the number of sectors read, or an error | [static] |
| Who uses it | `load_kernel` | [static] |
| Direct reads | "straight to the destination when that is at or above 0x25700000" | [static] |
| Below 0x25700000 | not established: a comment of the code implies a bounce buffer, and the loader never asks for a read there | |
| Largest read | not established; the loader keeps each piece at or under 4 MiB | |
| Bus | 8-bit DDR at 52 MHz | [static] |
| Proven on the tablet | By the three boots of section 18: the kernel arrived whole, and was started only because its hash was as built | [hardware] |
| First image with a read | `sreset6`, 2026-11-24 | [static] |

**Caches.** The reader is a DMA master. Before a read to 0x40000000, the payload looks up the page
table entry S-Boot holds for that address and, if it is mapped, cleans and invalidates those lines.
After the switch to EL2, stage 2 invalidates the cache over everything the reader wrote, and only
then reads it.

**How the kernel was read** (the three boots of 2026-11-24): the Image in two calls (4 MiB, then
the rest), the device tree in one. The payload compares the sector count of each piece with what it
asked for. Stage 2 then hashes both, with FNV-1a 64, and starts the kernel only if every byte is as
built.

**Sector numbers.** They are computed from PARAM's first sector (92160), not from the partition
table: another unit or another firmware must check them.

## 10. The PARAM partition

**Layout.** PARAM is 8 MiB. It is a tar archive from the first sector; `download.jpg` comes before
`logo.jpg`, whose header is at 0x98E00 and whose data starts at 0x99000. The stock archive is kept
byte for byte except for the replaced member. With the forged logo, the archive ends at 0x115C00.

| Range of PARAM | What | Who writes it |
|---|---|---|
| 0..end of archive | the tar archive: `download.jpg`, `logo.jpg`, others | the builder, around the stock bytes |
| end of archive..0x6FC000 | room: never read by S-Boot | the builder (the kernel bundle of the test boots, at 0x120000) |
| 0x700000..0x700000+0x1A28 | S-Boot's environment | S-Boot, at every boot |
| 0x700000..end | S-Boot's own data: the command line, records | S-Boot |

**How S-Boot reads it.** Its archive reader (0x23E0A4BC) walks the headers from the first sector
and stops at the first block without a name or without `ustar`. Nothing between the end of the
archive and 0x700000 is ever looked at (2026-11-24).

**How S-Boot rewrites it.** It rewrites 0x1A28 bytes of environment at 0x700000 at every boot, so
a forged image must carry the stock bytes there. The builder copies everything from 0x200000 on
from the stock image, and refuses an image whose last MiB differs from the stock's.

**It writes more when it boots a kernel itself [hardware]**, a fallback boot included
(2026-11-25): what differs in PARAM after such a boot starts at 0x700009, in that environment.
The first 0x700000 bytes, the archive the loader is, are not touched. So a loader is identified by
the SHA-256 of those bytes, never by the whole partition's: the rescue and
`t715-arm64-install` do so ([RESCUE.md](RESCUE.md), section 3).

**What the builder checks** before it writes an image: the archive ends at least 1 KiB below
0x200000; the image has the size of the partition; a bundle starts at least 0x8000 after the end of
the archive, on a whole sector; it ends at least 0x40000 below 0x700000; the stock image is empty
where the bundle goes; and the last MiB is the stock's.

**Rule of the owner's project.** Its README says "**Never write** BOOTLOADER, EFS, m9kefs1-3,
RADIO, CDMA-RADIO, PARAM or BOTA". The owner decided on 2026-11-24 that this exploit is the case
that rule did not cover, and that the forged logo may live in PARAM for good. The fork's README
must say so in those words: the loader writes PARAM, and nothing else.

## 11. The watchdog

| Register | Address | Role |
|---|---|---|
| WTCON | 0x10020000 | control: prescaler (bits 15:8), divider (bits 4:3), reset enable (bit 5), on (bit 0) |
| WTDAT | 0x10020004 | reload value |
| WTCNT | 0x10020008 | the counter |
| WTCLRINT | 0x1002000C | clear interrupt |
| PMU 0x105C0408 | AUTOMATIC_WDT_RESET_DISABLE | bits 24 (A53 cluster) and 23 (A57 cluster) |
| PMU 0x105C040C | MASK_WDT_RESET_REQUEST | bit 24 |
| PMU 0x105C0404 | RST_STAT | bit 24: the last reset was a watchdog reset (inferred in the public study) |
| PERIS 0x10040900 | PCLK gate | bit 17: the watchdog's clock |
| PMU 0x105C0400 | SWRESET | 1 = software reset |
| PMU 0x105C0808, 0x105C080C | INFORM2, INFORM3 | what S-Boot reads to choose the boot mode |

**Clock.** `pclk_wdt_apollo`, 66 666 667 Hz. With the widest prescaler (256) and divider (128) the
counter ticks 2034 times a second.

**Arming it from EL2** (`watchdog_arm`): open its clock gate; clear bits 24 and 23 in 0x105C0408
and bit 24 in 0x105C040C, so that the PMU lets a watchdog reset through; write the reload value and
the counter; then WTCON = 0xFF39 (prescaler 255, divided by 128, on, reset on, no interrupt).

**Proven on the tablet.** A watchdog armed at EL2 is proven on 2026-11-24,
and the three kernel tests armed it for 20 s before EL1: "if the kernel hangs before its own
watchdog takes over, the tablet restarts". A separate proof test arms it for 4 s and then does
nothing: if it did not count, the loader would reset by software instead, so the tablet never stays
frozen. Which image carried that proof, and whether the counter counted, is not recorded.

What is proven since: the ARM32 code arms the watchdog before it reads the slots, and a boot
that died there was reset, after which the 32-bit system came back by itself (2026-11-25).

**What a watchdog reset makes S-Boot boot.** On its own, a watchdog reset clears INFORM3 and
S-Boot then boots RECOVERY. A software reset keeps INFORM3, and S-Boot boots BOOT. The loader
writes the two values the owner's 32-bit kernel writes at its own start (INFORM2 = 0x12345678,
INFORM3 = 0x12345670) before it enters EL1. From then on, any reset (a panic, the watchdog, a
restart by software) goes back to BOOT, out of the charger mode, and the loader's guard skips the
test: the tablet returns to its own system.

**Relation to the owner's rules.** His rule is to leave Linux with `systemctl reboot`, "never the
watchdog": a watchdog reset is "a failure path, not a method". The loader's use is exactly a
failure path.

## 12. State measured at handoff

Three kinds of measurement exist. Only the second is quoted here: the other two are in dumps that
hold the tablet's identifiers.

**A. Registers read by the loader at EL2** (`HANDOFF`), written into the ring: the A53 and A57
clock units (PLL control, selectors, dividers, gates), the MIF clock unit, the PERIS clock gates,
three PMU registers, the four watchdog registers. The MIF divider register at +0x600 "aborted on the
bus (2026-11-24)" and was left out. **The values are in ring dumps, which hold the tablet's identifiers and are not published.**

**B. Rails as the study of the chip in omarchy-tab-s2 gives them.**

| Rail | At hand-over | Feeds | Source | Tag |
|---|---|---|---|---|
| vdd_kfc | 1.1625 V (1162 mV) | the A53 cluster | omarchy-tab-s2, `docs/hardware/CPUFREQ.md` §3.1 | measured by the owner under the stock kernel |
| vdd_eagle | 1.0625 V (1062 mV) | the A57 cluster | same | same |
| vdd_mif | 1.0125 V | the memory interface, at the top DRAM level (825 MHz) | same | same |
| vdd_int | 0.975 V | internal, at its top level | same | same |
| vdd_g3d | 0.9375 V | the GPU | same | same |

S-Boot leaves the A53 at 1200 MHz and the A57's PLL at 1200 MHz, both clusters being at
1200 MHz; and a kernel that scales nothing runs safely there. Whether the A57 cores themselves
run at 1200 MHz, or only their PLL, is a divider question that the handoff lines answer.

**C. What the arm64 test `init` read** (2026-11-24): the PMIC rails whose name holds `vdd_` or
`BUCK` (voltage, range, state), the clock rates of the two clusters and of five other clocks, four
thermal zones, the watchdog, memory, uptime, and one second of sleep measured against the
clocksource. **The values are in the pstore and ring records of the three boots, which are not published.**

**Two facts for any other unit.** These voltages are those of the owner's chip: ASV table version
8, group 1. Another SM-T715 may be in another group, and S-Boot will have left other voltages. And
the PMIC is an S2MPS13 at `pmic@66`, on HSI2C channel 0.

## 13. The ARM generic counter does not run, and the MCT patch

On 2026-11-24, a test read the generic counter at EL2: `CNTFRQ_EL0` was 0, and the
counter did not move. The loader relies on nothing of it.

arm64 Linux cannot start like that. Its `time_init()` panics with "Unable to initialise architected
timer", and its delay loops count the counter. The patch `0001-arm64-exynos5433-MCT-without-the-
architected-timer.patch` changes two things, for a machine compatible with `samsung,exynos5433`
only:

- `arch/arm64/kernel/time.c`: no panic and no calibration of the delay loop from the counter when
  the rate is 0; a line is logged instead.
- `arch/arm64/lib/delay.c`: `__delay()` counts loop iterations when there is no counter rate. That
  is what `loops_per_jiffy` was calibrated on.

The Exynos MCT then keeps time, as it does for the owner's 32-bit kernel: `ARCH_EXYNOS` selects
`CLKSRC_EXYNOS_MCT`.

This may matter to other Exynos 5433 devices. Upstream's repository does not say whether the
counter runs on the Note 4; its kernel is not published.

Whether the counter could be started instead (a register in the PMU or the sysreg block) was not
investigated.

## 14. The clock units that sit in a power domain

The board's device tree has 23 clock units. Eleven of them carry a `power-domains` property: G2D,
DISP, AUD, G3D, GSCL, MSCL, MFC, HEVC, ISP, CAM0 and CAM1. So does the AUD pin controller.

A kernel built without `EXYNOS_PM_DOMAINS` has no driver for those domains. The driver core gives
up waiting for the domain and lets the clock unit probe with the domain off. The first register
read then aborts on the bus. It was seen on the tablet on 2026-11-24: "G2D, panic".

The fix for a kernel without power domains is in the tree, not in the code: a boot-time overlay
disables those eleven units and the AUD pin controller. With them disabled their clocks do not
exist, and nothing of the test needs them. The build checks that every clock unit in a power
domain is disabled, and fails otherwise.

Why the domain driver is absent in the test kernel: it disables `PM`, and `ARCH_EXYNOS` selects
the power domains only `if PM_GENERIC_DOMAINS`, which comes only `if PM`.

## 15. The rate limit of `/dev/kmsg`

The kernel keeps what user space writes to `/dev/kmsg` to 10 lines in 5 seconds. A line over the
limit is dropped without an error: the write returns its length. A test `init` that reports by
`/dev/kmsg`, as this one does, goes silent after ten lines.

`printk.devkmsg=on` on the command line lifts the limit and locks the setting against the sysctl.
The option is spelled `printk.devkmsg=` in the kernel, with `on`, `off` or `ratelimit`.

## 16. The regulator core

**What the kernel does.** With a device tree, the regulator core assumes it has the full picture.
At the end of its initcalls it queues a job for 30 seconds later. That job disables every
regulator that is enabled, has no user, is not `always_on`, and whose status it may change. It logs
each one as "disabling", "since this may kill the system if it goes wrong".

**Why it matters here.** The test kernel builds almost no driver. Nothing holds the rails S-Boot
left on. In a system that stays up, that job runs.

**A defect in the test kernel's command line.** The overlay passes `regulator.ignore_unused=1`.
The kernel's option is the bare word `regulator_ignore_unused`. The two do not match: the kernel
compares the option's name with the argument's, taking `-` and `_` as equal and nothing else. An
argument with a dot that matches nothing is accepted in silence as an "unused module parameter".
So the option as written does nothing. The 32-bit release kernel shows the right spelling by
analogy: it passes `clk_ignore_unused pd_ignore_unused`, with underscores, and no regulator option.

**Why the three test boots held anyway** (read in code, not on their records):
- BUCK2 (vdd_eagle), BUCK3 (vdd_kfc) and BUCK4 are `regulator-always-on` in the board file. The
  job skips those, whatever the command line says. The board file has 31 regulators, 11 of them
  `always_on` and 14 `boot_on`.
- The test `init` restarts the tablet by itself after about 16 s. That may be before the job runs.

**How to tell on a record.** When the option is honoured, the kernel logs "regulator: Not
disabling unused regulators". If that line is absent from the three boots, the argument was
ignored, as the code says.

**What the test kernel does about voltages.** It enables the PMIC driver only to read the rails.
It disables `EXYNOS_REGULATOR_COUPLER` and `REGULATOR_FIXED`. Its configuration check refuses
`CPU_FREQ`, `PM_DEVFREQ`, `EXYNOS5433_ATLAS_ASV`, `EXYNOS5433_G3D_ABB`, `EXYNOS_ASV_ARM`, among
others: nothing that may set a frequency, a voltage or a bias is built in.

## 17. The eight cores

`SMP` cannot be switched off on arm64: in this tree it is `def_bool y`. The first test kernel was
kept to one core by its command line (`nosmp`) and by its device tree, which carries no `psci` node
and no `enable-method`. Upstream's README says of the other cores that they need "legacy SMC calls",
that they "will startup in ARM32 and you'll have to switch them to ARM64", and calls this "very
hacky, but it works".

**How the cores are started on this board.** The firmware gives a kernel no PSCI. The PMU powers a
core on and the monitor releases it in **AArch32** at the address the kernel leaves in one register
of sysram-ns (+0x1c, one for all cores). That is how the vendor kernel and the 32-bit kernel start
their cores. A 64-bit kernel cannot run that way. (Strictly, the monitor releases the core at
sysram-ns + 0x0, where a stub that BL2 copied there waits for that register and jumps to it:
section 23.)

**The method.** An enable-method of the kernel's own, `samsung,exynos5433-el2`
(`CONFIG_ARM64_EXYNOS5433_SMP`, patches 0002 to 0004 of `../kernel/patches/`):

```
 AArch32, from the monitor              AArch64, EL2, from the monitor      AArch64, EL1
 exynos5433_smp_entry                   exynos5433_smp_entry_el2           exynos5433_smp_pen
   mask interrupts           SMC           mask interrupts        eret         wait for this CPU's
   SMC 0x82000400  -------------------->  EL2 as the loader     ------>       MPIDR in the pen
   (entry 2 KiB away, 0x800, 1)           SCTLR_EL1: MMU off                   |
                                                                          v
                                                                     secondary_entry
```

- The entry the kernel puts in the register is a twelve-word AArch32 stub (eleven instructions and a
  constant), hand-assembled as words because no AArch32 assembler builds an arm64 kernel. Its only
  job is the monitor call the loader makes for the boot CPU, `SMC 0x82000400`, which switches the
  core to AArch64 at EL2 with the MMU and the caches off.
- An AArch64 stub puts EL2 in the state the loader gives the boot CPU and `eret`s to EL1, so that
  every CPU starts at the same level.
- A holding pen waits for the CPU's own MPIDR before it joins `secondary_entry`. The monitor has
  one boot register for all the cores: a core that an event meant for another one releases must not
  run on with a `secondary_data` that is not its own.
- The CPU side (PMU, boot register, release with `dsb; sev`) is the 32-bit kernel's sequence,
  register for register. Nothing in it touches a clock, a voltage or a power domain.

**What the tablet said** (2026-11-24; each cycle came back by itself).

| Image | What it ran | Result |
|---|---|---|
| `smp2` | from the loader: a secondary A53 powered on and released, then the monitor's call | the core landed in AArch64 at EL2: the call works on a secondary core |
| `smpk2` | the kernel's method, `maxcpus=2` | CPU4, an A57, booted; the three other A53 were refused |
| `smpk3` | `maxcpus=4`, 20 s of load | the four A53 online, each busy 19.3 s of 20 s |
| `smpk4` | `maxcpus=8`, 30 s of load | "smp: Brought up 1 node, 8 CPUs" |

**A wrong shift.** `exynos5433_cpu_init()` refused any MPIDR with `mpidr >> (MPIDR_LEVEL_BITS_SHIFT
* 2)` non-zero. `MPIDR_LEVEL_BITS_SHIFT` is 3, the log2 of the 8 bits of a level, so the check
shifted by 6 where it meant level 2: `0x101 >> 6 = 4`. Every A53 secondary (Aff1 = 1) failed it and
every A57 (Aff1 = 0) passed. Fixed in patch 0005: the check reads affinity levels 2 and 3. The
same slip made `exynos5433_show_core()` print a wrong MPIDR.

**Two more consequences of a kernel without the architected timer.** The frequency invariance code
warns when the timer's rate reads 0: these cores have no AMU, so nothing is lost, and patch 0006
returns quietly in that case.

**Not done then.** Hot-unplug: without a `cpu_die` the kernel refused to take a CPU offline, and the
monitor's shutdown call had not been tried from AArch64. Suspend to RAM. Both work since
2026-11-26, with patch 0010: section 23.

## 18. The three arm64 boots of 2026-11-24

In each of the three, the loader's chain ran to its end: forged logo, ARM32 in S-Boot, AArch64 at
EL2, the kernel read through S-Boot's reader and hashed, EL1 by `eret`. Each cycle then ended by
itself, with no forced restart.

| | Boot 1 | Boot 2 | Boot 3 |
|---|---|---|---|
| Image (marker) | sreset10 (`HIJACK3: 7e5e7010`) | sreset11 (`7e5e7011`) | sreset12 (`7e5e7012`) |
| Back under the 32-bit system, by itself, after | 52 s | 62 s | 62 s |
| Kernel | Linux 6.12.114 arm64, 5 545 992 bytes | same Image | same size, rebuilt |
| Device tree | 79 117 bytes | 79 405 bytes | 79 425 bytes |
| Bundle in PARAM | 0x120000..0x67D800 | 0x120000..0x67DA00 | 0x120000..0x67DA00 |
| pstore records read afterwards | 2 | 2 | 2 |

**Kernel**: `allnoconfig` plus a short list, `-Os`, a static test `init` in the initramfs, 39-bit
VA, 4 KiB pages, 250 Hz, `NR_CPUS` 8. It is built from the owner's release tree, mounted
read-only; the patch of section 13 is applied as two files of `overlay/` mounted over the tree's
own.

**Device tree**: the release tree's board file for the 32-bit port, compiled by the tree's `dtc`,
plus `bootargs.overlay.dts`.

**What differs between the three.** Boot 2's device tree is 288 bytes longer than boot 1's, about
the size of eleven `status = "disabled"` properties: the clock units of section 14 were disabled
for boot 2. The overlay's comment dates the G2D panic to boot 1. The cycle lengths
fit that reading: 52 s for boot 1 against 62 s for the other two, while an ordinary boot of the
owner's system took 43 s in two cycles the day before. That leaves about 9 s for the first attempt
(about the 5 s of `panic=5`) and about 19 s for the others. The three boots are summed up as
"userland reached, state read, restart by software". Whether boot 1 reached its `init`
at all was not read from its pstore record. Boot 3's device tree is 20 bytes longer than boot 2's, and its
`init` was rebuilt; what changed was not recorded: the overlay and `init.c` were both saved again before it.

**What `init` reads**, in order, each line tagged `T715-ARM64` in the kernel log:

| Step | Files |
|---|---|
| Identity | `uname`: release, machine, version; `/proc/sys/kernel/tainted`; cpus online and present |
| The core | `/proc/cpuinfo`: processor, BogoMIPS, implementer, architecture, variant, part, revision |
| Arguments | `/proc/cmdline` |
| Rails | `/sys/class/regulator/*/`: name, `microvolts`, `min_microvolts`, `max_microvolts`, `state` |
| Clocks | `/sys/kernel/debug/clk/clk_summary`: apollo, atlas, the memory and bus PLLs, `sclk_mif`, the GPU PLL, `cntclk`, `oscclk` |
| Temperatures | `thermal_zone0` to `3`: type and temp |
| Watchdog | `/sys/class/watchdog/watchdog0/`: identity, state, timeout, bootstatus, status |
| Memory, uptime | `MemTotal`, `MemFree`; `/proc/uptime` |
| Time | the current and the available clocksources; one second of `nanosleep`, measured |

It then sleeps 15 s more, takes the watchdog with a 12 s timeout without feeding it, and calls
`reboot`. If that call returns it tries SysRq `b`. Either way the tablet restarts.

**The arguments the kernel was given**:

`console=sec_log sec_log=0x200000@0x26000000 loglevel=8 printk.devkmsg=on initcall_debug nosmp
clk_ignore_unused pd_ignore_unused regulator.ignore_unused=1 panic=5 oops=panic
s3c2410_wdt.tmr_atboot=1 watchdog.handle_boot_enabled=0`

Two of them are traps of their own. `watchdog.handle_boot_enabled=0`: the kernel must not feed the
watchdog the loader armed. `s3c2410_wdt.tmr_atboot=1`: without it the driver stops a running
watchdog at probe, as the owner's watchdog study explains.

## 19. Other traps met

| Trap | What was found | Source |
|---|---|---|
| `image_size` | The field in the Image header is the kernel's footprint in memory, `.bss` included: 0x5A0000 for a file of 5 545 992 bytes. More than the file. | `../kernel/test-kernel/out/build.log` ("header of the Image"); `../loader/stage2/stage2.c:149-150` |
| Size | `-Os`, because the kernel was stored inside PARAM in the test. The room there was 6 160 384 bytes for the kernel and its device tree. | `../kernel/test-kernel/build-inner.sh:45-46,83` |
| PMIC | An S2MPS13 at `pmic@66`, on HSI2C channel 0 (`I2C_EXYNOS5`). | `../kernel/test-kernel/build-inner.sh:36-38`; `.../exynos5433-gts28ltexx.dts:401-402` |
| Randomisation | `RANDOMIZE_BASE` and 52-bit VA are refused by the build's checks; the loader starts a fixed address. | `../kernel/test-kernel/build-inner.sh:47,65-67` |
| Watchdog at probe | The driver stops a running watchdog unless `s3c2410_wdt.tmr_atboot=1`. | omarchy-tab-s2, `docs/hardware/WATCHDOG.md` §3 |
| The log ring is shared | The kernel console writes into the same 2 MiB as S-Boot. A boot that logs more than the ring holds hides the marks the guard reads; the daily tree logs at console level 4 for that reason. | `../kernel/test-kernel/bootargs.overlay.dts:20`; `../loader/scripts/split_source.py:216-218` |
| System MMUs | On arm64 the kernel selects `IOMMU_DMA`, and with it `OF_IOMMU`, which the 32-bit kernel lacks. The System MMU driver is not built, so `of_iommu_xlate()` waited for a driver that never binds, and DECON, the scalers, JPEG and MFC probed only at the deferred-probe timeout, 16.9 s into the boot: a black screen behind the bootloader's logo until then. The twelve System MMUs are disabled in the board tree; DECON binds at 0.5 s. | patch 0008 of `../kernel/patches/` |
| Frequency invariance | `freq_inv_set_max_ratio()` takes the architected timer's frequency as its reference and warns when it reads 0. These cores have no AMU, so nothing is lost: it returns quietly in that case. | patch 0006 of `../kernel/patches/` |
| The modem driver | `SEC_MODEM_V1` was kept to ARM by a Kconfig dependency and a `sizeof(size_t) == 4` assertion. The driver has no 32-bit-only code: both guards go, and its host test vectors pass on a 64-bit host (76 of 76). | patch 0009 of `../kernel/patches/` |

## 20. What upstream does differently

| Aspect | Upstream, Note 4 (N910C) | This port, SM-T715 |
|---|---|---|
| Trigger | a forged heap node; S-Boot's large-heap split writes over a saved return address; the place is found by a byte signature | the same principle, rebuilt for this S-Boot: a forged heap head and a false free block (section 5) |
| Finding S-Boot's allocator | a byte signature, kept only with the Note 4's literals | static reading of this S-Boot; the scan tool reports every device |
| Calibration | one block, against libjpeg through Pillow | one block, against S-Boot's own decoder in an emulator |
| After the monitor call | never returns to S-Boot | hands back to S-Boot whenever it can |
| At EL2 | a stack, then C | vectors, MMU and caches, the ring, C |
| Storage | its own eMMC driver, the partition table, an Android boot image | S-Boot's reader; a raw Image and device tree |
| Screen | 1440 x 2560 | 1536 x 2048; same framebuffer base, same display registers |
| Where S-Boot runs | "EL2", by its README | ARM32 at EL1 here |
| The other cores | "legacy SMC calls", which make them "startup in ARM32"; "very hacky" | an enable-method of the kernel's own: each secondary makes the loader's monitor call itself (section 17) |
| The scan of S-Boot | a byte signature, kept only with the Note 4's literals | the same signature, looked for with every literal pool reported: this S-Boot has it once, with another heap base (section 5) |

The credits are in [../CREDITS.md](../../CREDITS.md).

## 21. What the production loader taught

Four traps met while turning the chain into a loader for every boot. Each is told with its evidence
in [PRODUCTION-LOADER.md](PRODUCTION-LOADER.md).

| Trap | What happened | The fix |
|---|---|---|
| **r12 across a call to S-Boot.** S-Boot's functions are C: under the ARM procedure call standard r0 to r3 and r12 are the callee's to clobber. The slot loop kept a slot's sector in r12 across the eMMC reader. | the loader logged "sector 0" and refused every slot; the emulator had not seen it, because its stand-ins left the registers alone | `push {r3, r12}` around each call; the emulator's stand-ins now clobber as the tablet's do, and the old image fails 9 of 12 cases exactly as the tablet did |
| **The carry of the ARM32 hash.** The 64-bit FNV-1a written in ARM32 added the carry of an intermediate sum back into the high half. FNV drops it. | about one byte in 10 to 20 million meets it: kernels of 5.6 MB passed by luck, the full kernel of 17 MB did not | `add` without flags, in all five places; a rehearsal case looks for the three bytes that meet it |
| **A ledger of one boot is not enough.** A failed try ended in a watchdog reset, which makes S-Boot boot RECOVERY; there the loader fell back, and the boot after tried again: a loop that never reached the 32-bit system. | the first boot of the full kernel never came back by itself | the ledger looks at the two boots before (section 2.3 of [../README.md](../README.md)); 27 situations rehearsed |
| **A search that could run away.** The ring search lowered a position and then compared it with the lowest one; with the lowest one at 0 it wrapped round and went on for ever, before the watchdog is armed. | seen in the rehearsal of an empty ring, never on the tablet | the bound is tested before the step down |
| **A loader is not the whole of PARAM.** The first rescue compared the partition whole, and S-Boot changes its last MiB at each boot where it starts a kernel itself. | it took its own good loader for a lost one, twice, and restarted after about 7 s each time | the first 0x700000 bytes name the loader ([RESCUE.md](RESCUE.md), section 3) |

## 22. How S-Boot draws its logo

Read on 2026-11-25, when a picture was put in the forged logo. Told in full in
[SPLASH.md](SPLASH.md).

| Fact | Tag |
|---|---|
| `decode_and_draw` (0x23E148D8) decodes the JPEG and draws it row by row from the top left corner; the pixel writer (0x23E14088) stores a 32-bit word at `fb + (1536 * y + x) * 4`. Nothing is cut off, nothing is scaled | [static] |
| In its 24 bits per pixel path the writer stores `b0 \| b2 << 8 \| b1 << 16`: the decoded pixel's bytes, first, third, second | [static] |
| The panel shows the decoded pixel as it is: a file that carries the picture's channels in the order B, R, G shows them permuted (the picture's pink came out green) | [hardware] |
| The decoder calls no allocator during a decode, uses about 2 KiB of stack, and its working memory grows downwards by 24 bytes per pixel column, from about 0x240BD3AC | [emulator] |
| A logo of 2049 rows whose trapped block is black draws 16 zero bytes over the heap head, and `malloc_large` never returns | [emulator] |
| The loader's ARM32 code writes 16 bytes at 0x67B00000 for S-Boot's later requests: row 1877 of the screen, pixel 512 | [static], [emulator] |

## 23. The monitor's calls from AArch64: hot-unplug and suspend to RAM

The 32-bit kernel takes a core down, and puts the SoC to sleep, through two calls of the secure
monitor made from AArch32: SHUTDOWN (-7) and SLEEP (-3). Whether a 64-bit kernel at EL1 could make
them, and how a core, or the whole SoC, would come back to it, was open (section 17). Patch 0010 of
`../kernel/patches/` is the answer, in omarchy-tab-s2 2.1.0 (2026-11-26).

**How it was established.** First a static reading of the monitor: its code in the boot partition
(boot0, AArch64 at EL3, loaded at 0x02024000), with BL1 before it and the ARM32 code after it
(BL2, S-Boot), read with a disassembler; nothing was run for it. It is told in full in
[SMP-MONITOR.md](SMP-MONITOR.md), sections 2 to 9, with the monitor's addresses. Then the kernel
code, and tests on the tablet on 2026-11-26, in this order: one core unplugged, then a cluster,
then all seven secondaries; a secondary's power-down and return through the resume path while the
system runs (`c2test`); three dry runs; real sleeps.

**What the monitor does, read in its code.**

| Fact | Tag |
|---|---|
| One dispatcher for every caller. The vectors for a lower exception level in AArch64 and in AArch32 run the same code; the function id is compared as w0, the upper half of x0 ignored, so a negative id (-3, -7) from AArch64 works as from AArch32. The caller's exception level is not examined | [static] |
| A negative id is turned into `0x82000000 \| -id`: SLEEP is 0x82000003, SHUTDOWN 0x82000007. The calls of the 32-bit kernel that the monitor lacks (INIT, INFO, CPU1BOOT and others) return without writing anything | [static] |
| No PSCI and no SMCCC service is registered. An id of an unregistered service (0x84000000, PSCI's version, or 0x80000000) is a harmless probe: it returns 0xFFFFFFFF in x0 with the upper half zero, not sign-extended, and runs nothing. 0x820000EE returns 0 | [static] |
| For an AArch64 caller x0 to x17 come back clobbered: x8 to x17 are saved for an AArch32 caller only, and x0 to x3 hold what the handler wrote, or nothing fresh. x18 to x30, SP_EL0, the EL1 system registers and the FP/SIMD registers are kept. Linux's out-of-line SMCCC call allows for that | [static] |
| SHUTDOWN: x1 = 0 for this core, non-zero for the whole cluster (for its last core); x2 is not read; x3 = 1 would select a path for the last core of the system, so x3 = 0. It cleans and invalidates L1 by set/way, takes the core out of coherency, and waits in WFI, where the PMU powers the core down. For a cluster it goes on only if the PMU shows the core alone in it: then L1 and L2, and the cluster's snoops off at the CCI-400. Otherwise it returns to the caller, x0 to x3 not written | [static] |
| SLEEP: copies sysram-ns + 0x8 (the resume address) and + 0xc (the flag) to the PMU's INFORM0 and INFORM1, unchecked; saves the secure iRAM to DRAM; cleans every cache level by set/way; leaves coherency; waits in WFI. If the WFI returns (a wake-up source pending), the caller gets x0 = -1 in its own state | [static] |
| The word 0x2bedf00d before the resume address is checked by nothing in the boot partition: not BL1, the monitor, BL2, its stub or S-Boot. The 64-bit resume stub goes without it | [static] |
| No core keeps AArch64 across a power-down. Each core's init at EL3 clears SCR_EL3.RW, and every way out of the monitor after a power-on is AArch32 SVC, a constant | [static] |
| A secondary powered on goes to sysram-ns + 0x0, a stub that BL2 copied there, which jumps to the address in + 0x1c: but only if its boot flag (sysram-ns + 0x28 + 4 × index, index = Aff0 + 4 × Aff1) has bit 2, HOTPLUG; without it the monitor parks the core in WFI at EL3 | [static] |
| The boot CPU (MPIDR 0x100) on a wake-up: the monitor reruns its cold init; BL2 at 0x0203B000, in AArch32 SVC, finds 0xbad in INFORM1, restores what it must, and through its stub jumps to the address in INFORM0, in AArch32 SVC with the MMU off | [static] |
| `0x82000400` rewrites the calling core's secure context and leaves through it: the entry in x1, AArch64 EL2 with D, I and F masked when x3 = 1, SCR with NS and RW. It sets nothing in HCR_EL2 or SCTLR_EL2. It is the launcher of Samsung's EL2 hypervisor; it refuses only once a global word is set, and only `0x82000401`, the hypervisor's "done" call, sets it. So it can be called again and again, by every secondary, after a hot-plug, after a sleep, as long as `0x82000401` is never called | [static] |
| What the loader reads in HCR_EL2 at the EL2 entry, 2, is bit 1 (SWIO), not RW: the monitor writes 0 there at each core's init, and that bit reads as one on these cores. CPTR_EL2 0x33FF is its RES1 bits: no trap. Section 6 and [SMP-EXPERIMENT.md](SMP-EXPERIMENT.md), section 7.2, read them otherwise until this reading | [static] |

**The dangers it shows.**

- Treat x0 to x17 as clobbered by every call: an inline `smc` with a short clobber list is wrong here.
- Never unplug the boot CPU, MPIDR 0x100. Its next power-on would rerun the monitor's cold init
  while the other cores run (every core's context zeroed), and send it to BL2's cold path.
- Never call `0x82000401`: after it every `0x82000400` fails until the next cold boot, so no
  secondary, and no boot CPU waking up, could reach AArch64 again.
- SHUTDOWN compares x1 and x3 as 64-bit values: x1 in {0, 1}, x3 = 0.
- After the switch, SCR_EL3.FIQ and SCR_EL3.HCE are 0: a secure interrupt would reach EL1 as an
  FIQ (none was seen), and HVC is undefined. No Trustonic call may be made from a switched core.
  An exception the monitor does not handle hangs the core at EL3, with no reset.

**Hot-unplug from AArch64 EL1.** The 32-bit kernel's sequence, register for register:

1. the core's HOTPLUG boot flag, at sysram-ns + 0x28 + 4 × index;
2. the PMU core's CONFIGURATION &= ~0xF;
3. `SMC` SHUTDOWN (-7), x1 = 0 (this core) or non-zero (the whole cluster, for its last core), x2
   ignored, x3 = 0.

A core powered back on starts again in AArch32 at the address in sysram-ns + 0x1c, through the
secondaries' stub of section 17, as at boot. `cpu_kill`, on another core, polls the PMU status;
arm64's convention is 0 = dead, the opposite of ARM32's. By hand it stays refused until
`/sys/module/smp_exynos5433/parameters/hotplug` is 1; a system sleep may.

**Suspend to RAM from AArch64.** The 32-bit kernel's PMU and clock programming, unchanged; the
secondaries go down through the hot-unplug above, and the boot CPU sleeps alone. The kernel leaves
the resume address and 0xbad in sysram-ns, then makes the monitor's SLEEP call from AArch64 inside
`cpu_suspend()`; Linux cleans no cache, the monitor cleans every level. The way back:

```
 wake-up: the monitor's cold init, then BL2, which finds 0xbad at sysram-ns + 0xc
    |
    v
 AArch32 SVC, MMU off                 AArch64, EL2                       AArch64, EL1
 exynos5433_resume_entry     SMC      EL2 set up as for       eret       cpu_resume: back
 (the address at             ------>  a secondary core      -------->    from cpu_suspend()
  sysram-ns + 0x8)
   SMC 0x82000400
```

`exynos5433_resume_entry` is a second twelve-word AArch32 stub, built as the secondaries' one. With
`exynos5433_sleep=on` the kernel always sleeps; with `exynos5433_sleep=dryrun` it sleeps for real
only once armed, for one sleep (`/sys/module/exynos5433_sleep/parameters/arm`), as on 32 bits.
`c2test` (`/sys/module/smp_exynos5433/parameters/c2test`) powers one secondary down and back
through `exynos5433_resume_entry` while the system runs: the way back of a sleep, without one.

**What the tablet showed**, on 2026-11-26.

| Test | Result | Tag |
|---|---|---|
| Hot-unplug: CPU7, then the whole A57 cluster, then all seven secondaries down to CPU0 alone and back | four rounds, no error | [hardware] |
| `c2test` on CPU1 | `cpu_suspend()` returned 0: down in 73 us, back 81 us after power-on | [hardware] |
| Three dry runs | the suspend path ran, and no sleep, as meant | [hardware] |
| A first real sleep, the Wi-Fi chip left up | never resumed: the board reset, and S-Boot booted BOOT | [hardware] |
| Real sleeps with the modem's CP and the Wi-Fi/Bluetooth chip powered down first | five of five woke, with the eight cores, Wi-Fi, Bluetooth and the modem back: four on the PMIC's RTC alarm (WAKEUP_STAT 0x80000001, CENTRAL_SEQ 0x00010000 afterwards), one on the power key after 165 s on battery, through the root's `t715-sleep` | [hardware] |

What the tablet confirmed of the reading: SHUTDOWN from AArch64 powers a core and a cluster down;
a core powered on comes back in AArch32 through the boot register; `0x82000400` accepts a second
call from every core, and from the boot CPU after a sleep; SLEEP from AArch64 puts the SoC to
sleep, and the wake-up goes through BL2 to the resume address in AArch32.

## State on 2026-11-26

**Proven on the tablet**, by the cycle log and by the loader's own lines in S-Boot's log ring.

- ARM32 code runs inside S-Boot from the forged logo, logs through S-Boot's own `printf`, and
  hands back: 2026-11-24.
- AArch64 code runs at EL2 after the monitor call, on the boot core and on a secondary A53: the
  same day.
- The state that call leaves (MMU off, caches off, `VBAR_EL2` = 0, `HCR_EL2` = 2): the same day.
- The MMU and the caches at EL2; the ring lost when written through the cache, kept once mapped
  uncached.
- The generic counter reads 0.
- A software reset from EL2, and the guard that reads the previous boot's marker: every
  self-resetting image of 2026-11-24 came back by itself.
- S-Boot's eMMC reader, and a kernel read through it, hashed and started at EL1: three times on
  2026-11-24 with the kernel inside PARAM, then from a slot of CACHE (`kboot3`, the same day, and
  at every boot of the tablet since 2026-11-25).
- A watchdog armed at EL2, and a watchdog reset after which the 32-bit system came back by itself.
- The kernel options of sections 14 and 15 were needed: the G2D panic is in a comment.
- The eight cores (section 17): 2026-11-24.
- Earlier, on 2026-11-23: the first image of the split design after which the log says "LINUX IS
  BACK", and a control image that "BOOTED, the hijack did not fire".
- Later on 2026-11-25: the logo covers the whole panel with the colours of the picture (section
  22), and the loader under it fires at every boot; S-Boot writes its own data at the end of
  PARAM when it boots a kernel itself (section 10); the rescue in BOOT puts a lost loader back,
  and the ledger hands two boots to it, then tries arm64 again ([RESCUE.md](RESCUE.md)).
- On 2026-11-26 (section 23): hot-unplug from AArch64, seven secondaries down and back, four
  rounds; a secondary's power-down and return through the resume stub; five real sleeps out of
  five, with the modem's CP and the Wi-Fi/Bluetooth chip down first.

**Built and rehearsed only, or read in code.** The rehearsals in the emulator (the allocator's
walk, the payload up to its `smc`, the page tables, the vector table, the `eret`, the 27 situations
of the production loader, the ledger against real dumps) narrow the risk before each test; none of
them is a measurement. The parameter matcher of section 16, the kmsg limit and the Kconfig entries
of sections 14 and 17 were read in code. So was the monitor (section 23); the tablet confirmed what
patch 0010 relies on, not every path of the reading.

**Open.** Another unit and another bootloader. The eMMC reader's limits. What died in the first
boot of the full 17 MB kernel (`kboot5`). Whether the A57 cores themselves run at 1200 MHz or only
their PLL. A sleep with the Wi-Fi chip left up, which reset the board. The A57 above 1.2 GHz on arm64.
RECOVERY with the rescue's image, written and never booted.
