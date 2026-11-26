# The SM-T715 loader: how it works and how to work with it

The loader is a chain that starts an AArch64 Linux kernel on a Galaxy Tab S2 8.0 (SM-T715), whose
signed bootloader, S-Boot, only starts AArch32 kernels. It enters through the boot logo of the
PARAM partition, by CVE-2026-21155. It then runs ARM32 code inside S-Boot, asks S-Boot's monitor for
AArch64 at EL2, and enters the kernel at EL1.

It is a port of the idea of [bnuuyloader](https://github.com/meowybnuuy/bnuuyloader), by meowybnuuy
(MIT): the same vulnerability and the same monitor call. The loader itself was written again for
this tablet's S-Boot. What it takes from upstream is listed in [CREDITS.md](../CREDITS.md).

Three things make it usable as a daily loader rather than a one-off exploit:

- **It hands back.** At every point where it can stop, it puts S-Boot's heap in order and returns
  into S-Boot, which then boots BOOT's kernel: the rescue, or the 32-bit system where it is
  kept. A failed attempt costs one boot.
- **It checks what it starts.** The kernel and its device tree are read through S-Boot's own eMMC
  reader and hashed. Nothing is started unless every byte is as the slot's header says.
- **It leaves the hardware alone.** The loader changes no clock and no voltage.

The details, with addresses and register values, are in [docs/FINDINGS.md](docs/FINDINGS.md). The
loader of the daily boot is told cycle by cycle in [docs/PRODUCTION-LOADER.md](docs/PRODUCTION-LOADER.md).
To pass a tablet from the 32-bit system to arm64, in order: [docs/GO-ARM64.md](docs/GO-ARM64.md).

## 1. State on 2026-11-26

For developers. Tested on one tablet: bootloader `T715XXU2CRH1`, hardware revision 9.

| What | State |
|---|---|
| ARM32 code inside S-Boot, from a forged boot logo | works, and hands control back to S-Boot |
| AArch64 at EL2, through upstream's monitor call | works, on the boot core and on a secondary core |
| The production loader, in PARAM for good | `kboot7`: `kboot6`'s code with a picture in the logo; in the tablet since 2026-11-25, at every boot |
| A picture on the whole panel as the boot screen, drawn by S-Boot itself | works ([docs/SPLASH.md](docs/SPLASH.md)) |
| An arm64 kernel read from a slot of CACHE, hashed, started at EL1 | works: Linux 6.12.114 with its eight cores |
| The way back after a failed attempt | seen on the tablet twice over: with the 32-bit system in BOOT (it came back by itself, with nobody at the tablet), then with the rescue in BOOT ([docs/RESCUE.md](docs/RESCUE.md)): two boots handed to it, then arm64 tried again |
| A loader lost in PARAM, put back by the rescue | seen once: back under arm64 35 s after the restart |
| A boot by the power key with the loader in PARAM | seen once: arm64, marked up |
| A turnkey install (download, flash, it installs) | omarchy-tab-s2 2.1.0's installer (since 2.0.0): [docs/GO-ARM64.md](docs/GO-ARM64.md), section 1 |
| Another unit, another firmware | not tried |

That tablet runs Omarchy 4.5 on arm64 as its daily system: user space in about 13 s, a soak of
three hours with eight busy cores, the LTE modem's processor online. The rest of that port is in two
places: the kernel configuration in the fork
[elkir0/bnuuyloader](https://github.com/elkir0/bnuuyloader), under the same `t715/`; the root
image and the tools of the daily system in
[omarchy-tab-s2](https://github.com/elkir0/omarchy-tab-s2), under `arm64/`. The 32-bit
system of [omarchy-tab-s2](https://github.com/elkir0/omarchy-tab-s2) was in the BOOT partition as
the way back until 2026-11-25; its root was removed that day, and the rescue is in BOOT and
RECOVERY since.

## 2. How it works

### 2.1 The chain, step by step

| Step | Where | What happens |
|---|---|---|
| 1 | S-Boot, PARAM | S-Boot decodes `logo.jpg`. A calibrated block overflows onto the DRAM heap's head and forges it. |
| 2 | S-Boot, `boot` | `boot` asks the heap for 0x200 bytes. The allocator follows the forged head to a false free block in the file buffer, and carves a node over its own stack. |
| 3 | ARM32, 0x24220100 | The helper returns into the forged code. It reads S-Boot's RAM log ring: the ledger of the boots before decides whether this boot tries (2.3). |
| 4 | ARM32 | For the production loader: it calls S-Boot's reader to load the headers of the two slots of CACHE, then the kernel of the best valid one and its device tree, and hashes them. It cleans the data cache, invalidates the instruction cache, and calls the monitor. |
| 5 | AArch64, EL2, 0x24222000 | Stage 1 masks exceptions, installs vectors, maps the MMU and turns the caches on, with the ring uncached. |
| 6 | AArch64, EL2, 0x24224000 | Stage 2, in C, invalidates the cache over what the reader wrote, checks the record of the chosen slot, then the hashes, arms the watchdog, and writes two PMU markers. |
| 7 | AArch64, EL1 | An `eret` with the device tree in x0. The kernel starts. |

If stage 2 finds nothing to start, it resets the SoC by software. The loader then hands the next
boots to S-Boot's own kernel.

### 2.2 The production loader

| Decision | In the code |
|---|---|
| **PARAM carries the loader only.** It is small, rarely changed, and the one partition whose loss costs the exploit. The kernel does not live in PARAM. | `scripts/build_ffree.py --payload kboot`; the AArch64 entry is at 0x24222000 |
| **The kernel lives in CACHE** (`/dev/mmcblk0p20`, 200 MiB, first sector 6553600, unused by the 32-bit system). Its ext4 is shrunk to its first 64 MiB (Android keeps a `/cache`); the rest is raw. | `CACHE_SECTOR`, `CACHE_FS_SECTORS`, `SLOT_SECTORS`, `SLOT_REL` in `scripts/build_ffree.py`; `scripts/slot.py shrink` |
| **Two slots.** A at the partition's relative sector 131072 (absolute 6684672), B at 262144 (absolute 6815744): 64 MiB each, then 8 MiB spare. | same |
| **A slot**: a 4 KiB header, then the uncompressed arm64 `Image`, then the device tree. The header holds a magic (`T7K1`), a version, the slot's generation, the lengths, the load addresses, the FNV-1a 64 of the `Image`, of the tree and of the header's own first 0x30 bytes. No compression, no decompressor in the loader. | `scripts/build_slot.py` |
| **The ARM32 part reads both headers**, keeps the valid one with the highest generation, reads `Image` and tree through S-Boot's reader in pieces of at most 4 MiB, hashes them, and copies the chosen header to a record for EL2 (`T7KR`, at 0x40003000). | `KBOOT_SOURCE` in `scripts/split_source.py` |
| **Stage 2 checks the record, not the build.** It refuses the record, then re-hashes the kernel and the tree against it, with 64-bit arithmetic. So one PARAM image starts whatever valid kernel a slot holds: a slot is updated without a new PARAM. | `stage2/stage2.c`, `KERNEL` and `SLOT_RECORD` |
| **A bad slot is skipped.** If no slot is valid, the loader hands back: S-Boot boots BOOT, where the rescue is ([docs/RESCUE.md](docs/RESCUE.md)), or the 32-bit system where it is still kept. | `KBOOT: no valid kernel in CACHE: S-Boot's kernel boots` |
| **Updates never touch the newer slot.** The other one is written, read back and hashed; it wins by its generation. | `scripts/slot.py write`, `../tools/t715-arm64-install kernel` |
| **The ledger** (2.3) gives the tablet back to BOOT's system after an attempt that never came up. | `KBOOT: try`, looked for before anything is read |
| **The watchdog.** Armed by the ARM32 code before the slots are read, and masked again on every way back to S-Boot. Armed again before EL1. In the daily kernel the kernel's own watchdog core keeps it alive for 120 s at most (`watchdog.handle_boot_enabled=1`, `watchdog.open_timeout=120`), and the system's `t715-watchdog-keeper` feeds it from then on; in a test image the kernel never feeds it (`watchdog.handle_boot_enabled=0`). A kernel that hangs is reset. | `stage2/stage2.c` (`watchdog_arm`); [../kernel/README.md](kernel/README.md) |

### 2.3 The ledger

The loader writes `KBOOT: try` into S-Boot's RAM log ring before it touches anything risky. Once the
arm64 system runs, its `t715-kboot-mark` service writes `KBOOT: up` there.

A boot tries the arm64 kernel only if **neither of the two boots before it** holds a `KBOOT: try`
that, later in that same boot, has neither a `KBOOT: up` nor one of the loader's own hand-back
lines. So:

- a boot that came up makes the next boot try again;
- a try that handed back (no valid slot) costs nothing: that boot went on to S-Boot's kernel;
- a try that failed costs the next two boots. A failure usually ends in a watchdog reset, and S-Boot
  then boots RECOVERY; the loader hands back there too, and again in the boot after, and the boot
  after that tries again.

Why two boots and not one: the first boot of a full kernel, with the ledger of one boot, never found
its way back (a detour BOOT, RECOVERY, BOOT that repeated). The rule of two boots was rehearsed in
27 situations and has been seen working on the tablet. The story is in
[docs/PRODUCTION-LOADER.md](docs/PRODUCTION-LOADER.md), sections 6 and 7.

## 3. What you need

| Need | What |
|---|---|
| Host | macOS on Apple silicon, as for omarchy-tab-s2. The paths of LLVM below are Homebrew's. |
| C compiler | Apple's `clang`, for `--target=arm-none-eabi` and `--target=aarch64-none-elf` |
| Linker and binutils | LLVM 22 and `lld` 22 from Homebrew: `/opt/homebrew/opt/llvm@22/bin` (`llvm-objcopy`, `llvm-nm`, `llvm-objdump`) and `/opt/homebrew/opt/lld@22/bin/ld.lld` |
| Python **3.12 or later** | one script has an f-string that nests quotes of the same kind. Tested with 3.15.0, `unicorn` 2.1.4, `capstone` 5.0.9, `Pillow` 13.0.0 and `numpy` 2.5.5 (`requirements.txt`) |
| Your own dumps | the S-Boot of your tablet and its stock PARAM (below) |
| On the tablet | a running Linux you can reach over ssh: the 32-bit system of omarchy-tab-s2 (`device/tssh`) to start with, then the arm64 system. The tools work with the tablet under either |
| The ring reader | the kernel module `tools/seclog_dump/`, built against the kernel that runs on the tablet (`make -C <that kernel's build directory> M=$PWD/tools/seclog_dump`), to read S-Boot's log after a test |
| An arm64 kernel | built from the kernel tree of omarchy-tab-s2 with `../kernel/patches/` ([../kernel/README.md](kernel/README.md)) |

**The two dumps.** Put them in `dumps/`, which no script writes and which must never be committed or
shared: they are Samsung's firmware, and the PARAM dump also holds what S-Boot writes there.

| File | What it is | Size |
|---|---|---|
| `dumps/mmcblk0boot0.bin` | the bootloader of your own tablet: S-Boot, loaded at 0x23DE2000 | 4 MiB |
| `dumps/PARAM-mmcblk0p8.bin` | the stock PARAM partition of your own tablet (`/dev/mmcblk0p8`) | 8 MiB |

Read them from your own tablet's Linux, before anything else, and keep the PARAM copy safe: it is
the way back. No script of this directory makes them.

**Versions.** The addresses and the calibrated block depend on one bootloader, `T715XXU2CRH1`.
Another firmware needs the whole method again, not just other numbers: every address that is
specific to it is listed in [docs/FINDINGS.md](docs/FINDINGS.md), section 2.

## 4. Building

All commands run from this directory (`t715/loader/`). The two dumps go in `dumps/` first.

```
mkdir -p dumps out
python3 -m venv venv
venv/bin/pip install -r requirements.txt
venv/bin/python -I scripts/sboot_calib.py calibrate
```

The last command corrects the one forged block against S-Boot's own decoder, run in the emulator
with your S-Boot dump, and writes `out/calibrated_block.json`. Every builder reads it.

### 4.1 The production loader

```
venv/bin/python -I scripts/build_kboot.py --prod --name kbootN
```

It builds stage 2, then the PARAM image: `out/kbootN.param` and `out/kbootN-logo.jpg`. The log is
`out/kbootN-build.log`. The image holds nothing of a kernel.

That is `kboot6`: a black logo, 310 pixels wide. The panel shows nothing until the kernel's
splash. The loader of the daily boot adds a picture: the same code, byte for byte, in a logo as
wide as the panel ([docs/SPLASH.md](docs/SPLASH.md)). The owner's boot screen:

```
venv/bin/python -I scripts/build_kboot.py --prod --geometry wide --art art/splash-bnuuy-and-me.png --luma-floor 4 --chroma-floor 3 --name kbootN --verify
```

`--verify` decodes the logo with S-Boot's own decoder and refuses the image unless it leaves the
heap exactly as the exploit needs (section 4.4). Build a wide logo with it, always.

To also make what goes into a slot of CACHE, give the kernel and its device tree:

```
venv/bin/python -I scripts/build_kboot.py --prod --name kbootN --image Image --dtb DTB --gen N
```

which writes `out/slot-kbootN-genN.img`. `--gen` is one more than the generation of the slot in use.

### 4.2 A test image

The kernel inside PARAM, for one self-resetting boot, with nothing written to CACHE:

```
venv/bin/python -I scripts/build_kboot.py --test --image Image --dtb DTB --id 0xNNNNNNNN --name sresetN
```

Give `--id` by hand. Without it the marker is the clock of the build, and every line the image logs
would carry a time stamp.

### 4.3 The pieces, one by one

| Command | What it does | Needs |
|---|---|---|
| `scripts/sboot_calib.py calibrate` | corrects the one calibrated block against S-Boot's decoder in the emulator | your S-Boot dump |
| `scripts/build_stage2.py OUT.bin --marker "HIJACK3: xxxxxxxx" [--emmc] [--handoff] [--watchdog-arm] [--kernel AT BYTES DTB_AT DTB_BYTES] [--prod] [--define NAME=VALUE]...` | compiles stage 2 and links it at 0x24224000 | `clang`, `ld.lld`, `llvm-objcopy` |
| `scripts/build_ffree.py STOCK_PARAM OUT_PARAM --payload sreset --id 0xNNNNNNNN --vectors --mmu --stage2 STAGE2 --emmc --kernel Image --dtb DTB --bundle BUNDLE --kernel-in-param 0x120000 [--out-jpeg FILE] [--verify]` | builds the forged logo and writes the PARAM image around the stock archive | the stock PARAM, the calibrated block, `scripts/jpegforge.py` |
| `scripts/build_ffree.py STOCK_PARAM OUT_PARAM --payload kboot --marker "KBOOT: EL2" ... [--geometry wide --art PICTURE --luma-floor N --chroma-floor N --no-trap]` | the same, with the production loader's ARM32 code; the options of the wide logo and its picture ([docs/SPLASH.md](docs/SPLASH.md)) | same |
| `scripts/logo_art.py PICTURE --trap out/calibrated_block.json --out out/logo.jpg [--luma-floor N] [--chroma-floor N] [--black N] [--scale F] [--order R,G,B] [--tables PLAN] [--measure]` | a picture in the wide logo, with Huffman tables built for the file | the calibrated block, `scripts/jpegforge.py`, Pillow, numpy |
| `scripts/preview_logo.py LOGO.jpg OUT.png [--decoder pillow\|sboot] [--assume stored\|xrgb\|xbgr] [--crop X0,Y0,X1,Y1 OUT.png]` | the panel as the logo leaves it, a PNG | Pillow, numpy; `sboot_jpeg_emu.py` for `sboot` |
| `scripts/build_slot.py --image Image --dtb DTB --gen N --out out/slot-NAME-genN.img [--corrupt]` | makes what goes into a slot of CACHE; `--corrupt` changes one byte after the hash, for tests | nothing private |
| `scripts/build_el1.py OUT.bin --marker "HIJACK3: xxxxxxxx"` | the small test image for EL1 | `clang`, `ld.lld`, `llvm-objcopy` |

`build_kboot.py` runs the right ones in the right order, and passes what one needs from the other
from one to the next.

### 4.4 What the builders refuse

Each builder stops, and leaves no output of its own. Most say why. `build_stage2.py` ends in a
Python traceback when the compiler fails: the reason is the compiler's line just above it.

| Builder | Refuses when |
|---|---|
| `build_ffree.py` | the JPEG reaches the forged node; the AArch64 code does not start with `msr`; the vector table is not 2 KiB aligned or not 16 branches; the code node is not `{branch, 0, 0, head}`; stage 2 or the EL1 image does not fit the file buffer; the archive ends within 1 KiB of 0x200000; a bundle is off a sector, or starts within 0x8000 of the archive, or ends within 0x40000 of 0x700000; the stock image is not empty where the bundle goes; the image is not the partition's size; anything past 0x200000 differs from the stock |
| `build_stage2.py` | a warning (`-Wall -Wextra -Werror`), an unused function included; a kernel block without its two hashes (`#error`); the image is over 0xC000 bytes; it does not start with an `adr`; a production stage 2 built with the hash of one kernel |
| `build_kboot.py` | the Image has no arm64 header, or a text offset other than 0; the device tree has no magic; stage 2 holds both hashes (test) or either of them (production) |
| `build_slot.py` | no arm64 header, no device-tree magic; the kernel and its tree do not fit a slot |

`build_ffree.py --verify` goes one step further: it decodes the whole logo with S-Boot's own
decoder in the emulator (about 75 s for the narrow logo, two minutes for the wide one) and
**refuses** the image unless the bytes S-Boot will leave at 0x24F00000 are the heap head the
loader is forged for, and nothing was written past the last row; a refused image is removed.
Use it after any change to the image's geometry, and for every wide logo.

## 5. Rehearsing before anything reaches the tablet

### 5.1 The production loader, case by case

```
venv/bin/python -I scripts/kboot_cases.py out/kbootN-logo.jpg --slot-good out/slot-kbootN-genN.img [--ring RAW]
```

27 situations. Each says what the log of the two boots before holds, what the two slots of CACHE
hold, and whether S-Boot maps the memory the loader needs. The loader must then start the kernel
from the expected slot, or hand S-Boot its own kernel. The slots are rebuilt for each case from a
good one: other generations, another kernel, a byte changed after hashing, the record missing or
corrupt, a kernel changed in memory, a hash that meets an old bug of the ARM32 routine, a slot never
written. `kboot6` passes 27 of 27 with a kernel of 5.6 MB and with one of 17 MB. `kboot7`, the
picture's loader: 27 of 27, twice. Exit status 1 if a case fails.

### 5.2 In the emulator

```
venv/bin/python -I scripts/preflight.py LOGO_FILE --payload sreset|kboot [--param PARAM_IMAGE] [--kernel-bundle BUNDLE] [--smp secondary|none --stubs ...]
```

`preflight.py` loads your S-Boot dump into Unicorn and plays the real code:

- **ARM32.** The logo goes into S-Boot's file buffer, the heap head is what S-Boot's decoder leaves.
  Then `boot`'s call is played: `malloc_large(0x200)`, `free()`, the `pop`, and so into the forged
  code. The run stops at the `smc`, and prints the registers. It then plays on from there to the
  hand-back, and checks that `boot` gets its registers back.
- **AArch64.** The entry runs in a 64-bit emulator with the ring, the framebuffer, the display
  registers and the PMU mapped. The page tables and the vector table are decoded independently. For
  a kernel image, the rehearsal stops before the `eret`, after checking where it goes and that the
  PMU markers and the watchdog are as they must be.
- **The stand-ins follow the ARM procedure call standard.** S-Boot's `printf` and its eMMC reader
  return r0 and clobber r1 to r3 and r12, as the tablet's do. That is how a bug was found: the
  loader kept a slot's sector in r12 across a call, and the tablet refused every slot.

What it prints for the handoff registers is all zeros: the emulator maps empty pages there. It is
not a measurement.

### 5.3 Against a real ring dump

```
venv/bin/python -I scripts/guard_cases.py LOGO_FILE RING_DUMP
```

The ledger decides by reading S-Boot's log of the boots before. The only honest test is a real
dump. `guard_cases.py` takes one, finds in it the decisions loaders took on the tablet, and replays
the payload just before each: it must decide what the tablet decided. It also replays the lines
wrapped across the start of the ring. One line per case, `PASS` or `FAIL`; exit status 1 on any
failure. `kboot6`: 6 of 6. `kboot7`, the picture's loader: 6 of 6.

The dump holds identifiers. `sbootlog.py --mask` and `hijack_lines.py` mask them when they print.
The dump itself stays private.

### 5.4 What a rehearsal cannot show

- What the monitor does. The emulator does not change exception level: it cannot take the `svc`,
  nor the `eret`.
- The real state of EL2: its reads of EL2 registers get stand-in values.
- The eMMC: S-Boot's reader is not emulated. Its calls are printed, and it is "said to have read
  them all".
- The cache: maintenance instructions are skipped, not emulated.
- Timing, the watchdog's clock, and anything a real controller does.

That is why the tests on the tablet reset by themselves and put the stock PARAM back: the rehearsal
narrows the risk; it does not remove it.

## 6. Installing for the daily boot

`../tools/t715-arm64-install` works from the computer, over `device/tssh` of omarchy-tab-s2 (set
`T715_TSSH` if it is not where section 3 says), with the tablet running either system. The whole
order, from the 32-bit system to arm64, is in [docs/GO-ARM64.md](docs/GO-ARM64.md), section 2.

```
export ORIG_SHA=$(shasum -a 256 dumps/PARAM-mmcblk0p8.bin | cut -c1-64)
T=../tools/t715-arm64-install

venv/bin/python -I scripts/slot.py backup CACHE-before.bin   # the whole partition, read back and verified
venv/bin/python -I scripts/slot.py shrink                     # its ext4 to 64 MiB; the rest is raw
$T kernel Image DTB                                          # builds a slot and writes the one that is not the newest
$T loader out/kboot7.param                                   # the loader into PARAM, for good (verified)
$T status
$T unloader                                                  # the stock PARAM back: BOOT's system only
```

**A loader is the first 7,340,032 bytes of PARAM.** They are the archive S-Boot reads its logo
from, and all the builder writes. S-Boot writes data of its own after them whenever it boots a
kernel itself (a fallback boot included: 2026-11-25), so PARAM is named by the SHA-256 of those
bytes, never by the whole partition's. A write is still verified by the whole partition's. The
rescue goes by the same bytes ([docs/RESCUE.md](docs/RESCUE.md)).

| Command | What it does |
|---|---|
| `slot.py backup FILE` | reads the whole CACHE partition and checks it was read whole. Do it first: it is the way back for the partition |
| `slot.py shrink` | shrinks CACHE's ext4 to 64 MiB, with `e2fsck` and `resize2fs`. Android keeps a `/cache`; nothing else of it is used |
| `slot.py show` | what the two slots hold |
| `t715-arm64-install kernel IMAGE DTB` | builds a slot from the kernel and its tree, and writes the slot that is not the newest (slot B when both are empty), with a generation one more; read back and hashed |
| `slot.py write A GEN IMAGE DTB` | the same, to the slot you name |
| `slot.py erase A` | a slot's header zeroed: the slot counts as never written |
| `t715-arm64-install loader PARAM_IMAGE` | writes the loader to PARAM, read-write for the time of the write, then read-only again, and checks its SHA-256. Nothing is written unless PARAM holds the stock image or a loader built in `out/`, known by its first 7,340,032 bytes. From the next boot on, every boot runs the loader |
| `t715-arm64-install unloader [--no-32bit-root-ok]` | the stock PARAM back, verified. The next boot is BOOT's. Refused while BOOT's 32-bit kernel would have no root behind it, unless the flag is given: give it when the rescue is in BOOT |
| `t715-arm64-install status` | which system runs, what USERDATA holds, what PARAM holds (by its loader's part), what the slots hold |

The order that keeps a way back at every step: back up CACHE; shrink it; write a slot; put the stock
PARAM image aside; write the loader. From then on a bad kernel costs two boots, and `unloader` is
the way out for good. Then, with arm64 up, the rescue into BOOT and RECOVERY
([docs/RESCUE.md](docs/RESCUE.md)): from then on a loader that does not fire costs one restart.

**There is no on-tablet switch to boot BOOT's system once.** To go back for good: `unloader`.

## 7. The test cycle job

```
ORIG_SHA=$(shasum -a 256 dumps/PARAM-mmcblk0p8.bin | cut -c1-64) T715_TSSH=/path/to/device/tssh \
    bash scripts/cycle.sh PARAM_IMAGE LABEL
```

### 7.1 What it does, in order

1. Checks that the image, the stock PARAM and the ring-reader module exist.
2. Waits up to 30 s for the tablet to answer.
3. Reads PARAM's SHA-256 on the tablet.
4. Writes the image, read-write for the time of the write, then sets the partition read-only again,
   and reads PARAM's SHA-256 again.
5. Stops the two modem services and waits two seconds (section 11).
6. Reboots the tablet with `systemctl reboot`.
7. Waits 150 s for the tablet to be back. If it is not, it says so, and waits up to 35 minutes.
8. **Puts the stock PARAM back first**, and verifies its SHA-256.
9. Reads what the kernel left of its last moments (pstore). Read only.
10. Loads the ring-reader module, copies the ring, unloads the module.
11. Logs each step under `[LABEL]` in `out/cycles.log`.

### 7.2 Safety rules

| Rule | Where |
|---|---|
| PARAM only. RECOVERY, BOOT and every other partition are never touched. | header |
| Nothing is written unless the tablet answers, and PARAM holds the stock image or this very image. | before the write |
| The image is verified after the write. If it is not, there is no reboot. | after the write |
| The modem's services are stopped first, and their state is logged. | before the reboot |
| The reboot is a `systemctl reboot`, never a key combination. | |
| The stock image goes back first, "so that an unexpected restart cannot run the image a second time". | after the wait |
| The partition is left read-only, as the 32-bit system keeps it. | after each write |
| Nothing identifying is logged. | |
| The ring dump and the pstore records go under `dumps/`, never in `out/`. | |

The job relies on the image's own guard for the rest: a test image that resets by itself runs once.
The stock PARAM is back before anything else can happen.

### 7.3 Exit codes, and what to do

| Code | Meaning | What to do |
|---|---|---|
| 0 | cycle complete | read `out/cycles.log` and the ring |
| 1 | nothing written: the tablet does not answer, or PARAM holds neither the stock image nor this image, or the write was not verified | look at PARAM's hash before anything else |
| 2 | a file is missing | check the three paths |
| 4 | the tablet is not back within 35 minutes: **PARAM still holds the image** | recover the tablet by hand, then put the stock PARAM back |
| 6 | the stock image is not back in PARAM | put it back before any other cycle |

**Recovery.** For exit 4 the job's own message says: "a forced restart is needed (Power + Volume
Down about 10 s)". Four images needed it on 2026-11-24, before the self-resetting design: `ffree`,
`smc1`, `smc1b` and `a64paint`. Each time the tablet came back under Linux. To put the stock PARAM
back outside a complete cycle: boot the 32-bit system, then `t715-arm64-install unloader`. With
the rescue in BOOT ([docs/RESCUE.md](docs/RESCUE.md)), a loader that does not fire is put back by
the tablet itself. If the tablet will not boot: flash your stock PARAM in download mode, with
Heimdall (`heimdall flash --PARAM PARAM-mmcblk0p8.bin`).

## 8. Reading the results

| Tool | Use |
|---|---|
| `scripts/sbootlog.py RAW [--full N] [--mask]` | splits the ring into boots; shows where each S-Boot log stops, and whether the kernel's log follows |
| `scripts/hijack_lines.py RAW [PATTERN]` | lists every line holding `PATTERN` (default `HIJACK`) with the context of its boot: the power-on source, the reboot mode, whether a kernel log follows |
| `dumps/pstore/LABEL/` | the kernel's console and panic records of the cycle, if pstore kept them |
| `scripts/sbdis.py FROM..TO [ADDR:NAME ...]` | disassembles a range of S-Boot, with literal values and known names |
| `scripts/callpath.py ROOT... [--to TARGET] [--sp SP]` | every static call path to a function, with the stack pointer at its entry |

A cycle is a success when the log says `LINUX IS BACK by itself`, the stock image is back and
verified, and the ring holds the lines the image was built to write.

## 9. What is proven on hardware

**2026-11-23: the search.**

| Image | Outcome |
|---|---|
| probe-01 | back after 43 s: "BOOTED, no marker" |
| hijack-w16090-a1, hijack2 to hijack6 | five times "NOT BACK after 135 s": the first trigger, `free()` writing over the logo loader's return address, does not bring the tablet back by itself |
| split-mark | **"LINUX IS BACK after 656 s"**: the first image of the split design |
| plain-248 | "BOOTED, the hijack did not fire": a control |
| b0-exact, split-1521 | "NOT BACK after 135 s" |

**2026-11-24: the chain, piece by piece.** Every cycle of this day ends with "ORIGINAL RESTORED AND
VERIFIED".

| Image | Options | Outcome | What it established |
|---|---|---|---|
| kentry | | back after 131 s | S-Boot's exception dump showed how its decoder really rounds |
| ffree | | not back by itself | a forced restart was needed |
| ffree2 | | back after 49 s | |
| ffree3 | | back after 51 s; ring fetched | the payload's line through S-Boot's `printf` |
| smc1, smc1b | | not back by itself; restarted by hand | the AArch64 code stops after its line, by design |
| a64paint | | not back by itself; restarted by hand | AArch64 code at EL2 painted the screen |
| sreset1 | | **back by itself after 126 s** | EL2 at entry: MMU off, caches off, `VBAR_EL2` = 0 |
| sreset2, sreset2b | vectors, mmu | by itself, 53 s and 45 s | lines written through the cache were lost |
| sreset3 | counter, vectors, mmu | by itself, 52 s | the generic counter reads 0 |
| sreset5 | vectors, mmu, stage2 | by itself, 53 s | stage 2 in C at EL2 |
| sreset6 | + emmc | by itself, 45 s | S-Boot's reader, called from ARM32 |
| sreset7 | + el1 | by itself, 46 s | the EL1 test image |
| sreset8, sreset9 | vectors, mmu, stage2, emmc | by themselves, 53 s and 55 s | a register read of the MIF clock unit aborted on the bus: left out of the handoff report |
| sreset10 | + kernel | by itself, 52 s; 2 pstore records | the first arm64 kernel; the G2D panic (FINDINGS, section 14) |
| sreset11, sreset12 | + kernel | by themselves, 62 s each; 2 pstore records each | the kernel with the clock units of power domains disabled |
| smp2 | the one-core experiment | back by itself after 46 s | **the monitor's call works on a secondary core**: an A53 |
| smpk2 | the kernel's own method, `maxcpus=2` | back after 66 s | CPU4, an A57, runs the 64-bit kernel; a wrong MPIDR check left the three other A53 out |
| smpk3 | the kernel's own method, `maxcpus=4`, 20 s of load | back after 72 s | the four A53 online, each busy 19.3 s of 20 s |
| smpk4 | the kernel's own method, `maxcpus=8`, 30 s of load | back by itself after 73 s | **the eight cores online under load** |
| cpuf1, cpuf2, cpuf3 | cpufreq on this chip's tables, cooling | back by themselves, after 141 s, 52 s and 147 s | under an eight-core load the clusters step down to 0.9 and 1.0 GHz and the temperature levels off |
| kboot1 to kboot6 | the production loader | see [docs/PRODUCTION-LOADER.md](docs/PRODUCTION-LOADER.md) | the kernel from CACHE, the record for EL2, the ledger of two boots |

"By itself" means without a forced restart: the AArch64 code reset the SoC, the next boot skipped
the test, and the 32-bit system came back.

**2026-11-25: the daily system.** With `kboot6` in PARAM for good: the first boot of the full kernel
with a root image (brought up in two goes, then Omarchy 4.5 on arm64), two reboots by software with
the arm64 system back in 32 and 33 s and marked up each time, a failed bring-up boot after which the
32-bit system came back by itself after 661 s, a cold boot by the power key, and a soak of three
hours.

**2026-11-25, later: the boot screen and the rescue.** The 32-bit root was gone by then, and the
rescue was in BOOT ([docs/RESCUE.md](docs/RESCUE.md)); every write was rehearsed first.

| Image | What it is | Outcome |
|---|---|---|
| `kboot7-probe` | the wide logo with the owner's picture, no trapped block, no loader | the picture on the panel; the rescue put `kboot6` back and restarted; arm64 again 35 s after the restart |
| `kboot7-cas1` | the picture's loader, the file's channels ordered `2,0,1` | the loader fired, Omarchy came up; the colours permuted |
| `kboot7-cas3` | the same, ordered `0,1,2` | the loader fired, Omarchy came up; the colours of the picture: **the loader in PARAM since** |
| one boot not marked up | the mark service disabled for one boot | the loader handed the next two boots to the rescue, which found the loader known to work and had nothing to do; arm64 again at the third |

The story of the logo is in [docs/SPLASH.md](docs/SPLASH.md).

## 10. What is not proven

- **Another unit, another bootloader.** One tablet, one firmware.
- **The eMMC reader's limits.** The largest read it accepts; what it does below 0x25700000.
- **The ring after a power cut.** It survives a software reset and a watchdog reset. A boot by the
  power key was seen once, with the ring empty.
- **What died in the first boot of the full 17 MB kernel** (`kboot5`): something between the ARM32
  code's first reads and stage 2. `kboot6` makes the tablet come back after it; it does not explain
  it.
- **The A57 above 1.2 GHz on arm64.** Open in the fork's roadmap. Suspend to RAM, listed here until
  2026-11-26, works on arm64 since then ([kernel/README.md](kernel/README.md)).
- **RECOVERY with the rescue's image.** Written and read back, never booted: it cannot be tried by
  keys while a loader is in PARAM ([docs/RESCUE.md](docs/RESCUE.md), section 8).

## 11. The hardware rules

The 32-bit port of omarchy-tab-s2 has rules for this tablet. They are quoted here as they stand.

| Rule | How this loader follows it |
|---|---|
| Nothing may scale a frequency or a voltage outside the rules for this chip: its own tables, 1.2 GHz on the A53 and 1.5 GHz on the A57, cooling before any cap above 1.2 GHz, never mainline's generic tables. | The loader changes no clock and no voltage. A kernel that scales nothing runs safely on what S-Boot left: A53 at 1200 MHz, A57 at 1200 MHz. |
| "Leave Linux with `systemctl reboot`, never the watchdog. A watchdog reset is a failure path, not a method." | The cycle job reboots that way. The loader's watchdog is armed so that a hang ends: it is a failure path, and nothing else. |
| "Never touch the RTC." | Nothing in the loader writes it. |
| "Never write RADIO, CDMA-RADIO, EFS, m9kefs1-3, BOOTLOADER, PARAM or BOTA." | This port writes PARAM, where the loader's image lives, and CACHE, where the slots live. It writes no other partition, and never BOOTLOADER. |
| "BOOT and RECOVERY only through `device/write-part.sh`." | The loader's tools write neither. The rescue's images go there through that script ([docs/RESCUE.md](docs/RESCUE.md)). |
| "CP off before rebooting into any test": the modem's boot programs eFuses. | The cycle job stops the two modem services before the reboot and logs that they are inactive. |
| "Do not hold hardware keys down to force a restart." | From `sreset1` on, no test needed it. |
| The voltages are one chip's: an image must not go to another unit unchanged. | The loader reads; it sets nothing. The calibrated block and the addresses are one bootloader's. |
| Every test must leave a way back. | The hand-back, the ledger, the stock PARAM put back after each cycle. |

The study of this chip's tables is `docs/hardware/CPUFREQ.md` in omarchy-tab-s2.

## 12. Known problems and open points

| Point | Where |
|---|---|
| **The ledger lives in the ring**, the same 2 MiB that the kernel's console fills. A boot that logs more than the ring holds pushes `KBOOT: try` out of it; the next boot then tries again instead of handing back. The daily tree logs at console level 4 for that reason. | `scripts/split_source.py` (`KBOOT_SOURCE`) |
| **CACHE is a filesystem's partition.** The slots sit behind an ext4 of 64 MiB. Anything that resizes, checks or uses that filesystem beyond its end overwrites a slot. | `scripts/slot.py shrink` |
| **`header_ok` adds the image and tree lengths in 32 bits.** A header crafted with a length near 4 GiB, and a matching hash of its own, would pass the size check and make the reader run over S-Boot's memory; the watchdog then resets, and the ledger falls back. Only someone writing the slot could do it. Stage 2 sums in 64 bits. | `scripts/split_source.py` |
| `push {r4}` before the `printf` at `mapped:` leaves the stack 4-byte aligned at a C call. It has worked on the tablet; it should be `push {r4, r5}`. | `scripts/split_source.py` |
| The test kernel's command line passes `regulator.ignore_unused=1`. The kernel's option is `regulator_ignore_unused`; as written it does nothing. The test boots held because the CPU rails are `regulator-always-on` in the board file and because the test restarts early. | `../kernel/test-kernel/bootargs.overlay.dts` (in the fork); [docs/FINDINGS.md](docs/FINDINGS.md), section 16 |
| `build_sreset`'s message "AArch64 entry at 0x24220800" is wrong for `kboot` (node + 0x2000). | `scripts/build_ffree.py` |
| `sbdis.py`'s usage calls it `scripts/dis.py`; the file is `sbdis.py`. | `scripts/sbdis.py` |
| The port needs Python 3.12 or later. | `scripts/sboot_calib.py` |
| The rehearsal of the production loader prints two `WRONG` flags for the display registers. They are right for a loader that leaves the screen alone. The verdict is `PASS`. | `scripts/preflight.py` |
| `build_ffree.py --id` defaults to the clock. | `scripts/build_ffree.py` |
| The rehearsal takes the newest ring dump that is not empty, and refuses an empty one given with `--ring`. | `scripts/kboot_cases.py` |
| Two paths of the research tools do not run: `preflight.py` in `rehearse_el1` (an EL1 test image given with `--param`) uses a name of another function, and the `diag` mode of `sboot_calib.py` calls a function that no longer exists. The production loader's build and rehearsals go through neither. | `scripts/preflight.py`, `scripts/sboot_calib.py` |
| The tools that talk to the tablet look for omarchy-tab-s2's `device/tssh` next to the fork. Set `T715_TSSH` if it is elsewhere. | `scripts/cycle.sh`, `scripts/slot.py`, `../tools/t715-arm64-install` |
| The scan of upstream's signature in this S-Boot: the signature is there once, with a heap base of 0x24F00000 where the Note 4's is 0x24E00000. Upstream's `build.py` keeps only the Note 4's. | `scripts/scan_sboot.py`; [docs/FINDINGS.md](docs/FINDINGS.md), section 5 |
| No script makes the two dumps. | section 3 |
| **One red pixel on the boot screen.** The loader's ARM32 code writes 16 bytes at 0x67B00000 for S-Boot's later requests: row 1877 of the screen, pixel 512. The owner accepted it; it could be moved past the panel's last row (never built). | `scripts/split_source.py` (`go:`); [docs/SPLASH.md](docs/SPLASH.md), section 6 |
| **S-Boot rewrites the end of PARAM** whenever it boots a kernel itself, a fallback boot included: what differs starts at 0x700009. A loader is named by PARAM's first 7,340,032 bytes; the whole partition's hash changes at each fallback boot. | `../tools/t715-arm64-install`; [docs/RESCUE.md](docs/RESCUE.md), section 3 |
| **RECOVERY cannot be tried by keys while a loader is in PARAM**: the loader runs in every S-Boot boot, a recovery one included, and hands back only as the ledger says. The rescue's RECOVERY image is therefore unproven. | `scripts/split_source.py`; [docs/RESCUE.md](docs/RESCUE.md), section 8 |
| **The rescue knows only the loaders it was built with.** One it has not been told of is replaced at the next boot that reaches BOOT: a probe does not stay, and a new loader must be added to the image. | [docs/RESCUE.md](docs/RESCUE.md) |
| There is no on-tablet switch to boot BOOT's system once. | section 6 |
