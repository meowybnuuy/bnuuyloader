# Passing a Galaxy Tab S2 (SM-T715) to arm64 Omarchy: the two routes

The Samsung Galaxy Tab S2 8.0 LTE (SM-T715) has an Exynos 5433, a 64-bit SoC that Samsung's
signed bootloader only starts in 32 bits. Two repositories let it run a 64-bit system:

| Brick | Where | What it holds |
|---|---|---|
| **The boot** | `t715/` here, kept in [elkir0/bnuuyloader](https://github.com/elkir0/bnuuyloader) | the loader that makes the tablet start an arm64 kernel at every boot, with the boot screen; the kernel patches; the rescue; the tools |
| **The system** | [omarchy-tab-s2](https://github.com/elkir0/omarchy-tab-s2) (its page on the 64-bit port: [docs/ARM64.md](https://github.com/elkir0/omarchy-tab-s2/blob/main/docs/ARM64.md)) | Omarchy for the tablet: its 32-bit release today; the arm64 image, its build, its packages and its tools ([arm64/](https://github.com/elkir0/omarchy-tab-s2/tree/main/arm64), [ROOTFS.md](https://github.com/elkir0/omarchy-tab-s2/blob/main/arm64/docs/ROOTFS.md)) |

There are two ways to use them, and this page is the door to both.

- **Route 1, "I download, I flash, it installs."** For whoever wants arm64 and nothing else.
  **Open since omarchy-tab-s2 2.0.0**; its current release is 2.1.0: section 1.
- **Route 2, the long one.** For whoever wants every step by hand, and to understand. Section 2 is
  the map; each step links to the page that tells it.

Two pages this one points to, and what builds the kernel (`t715/kernel/config/`,
`t715/build-arm64.sh`), are in the fork's `main` only: their links go there. The image is built
in omarchy-tab-s2, under `arm64/`.

All of it was made and tried on **one tablet**: bootloader `T715XXU2CRH1`, hardware revision 9.
Since 2026-11-25 that tablet boots Omarchy 4.5 on arm64 by itself at every power-on, with the
owner's picture as its boot screen.

## Before either route

- **Own device only.** This is a bootloader exploit. It writes the PARAM partition, which the
  32-bit port's rules tell never to write: the owner made that exception for the loader, on
  2026-11-24 ([../README.md](../README.md), section 11).
- **The Knox warranty bit is blown for good**, by anything that runs here: as with the 32-bit
  port. There is no way back from that.
- **Read "Read this first" of the 32-bit port's guide** (`docs/INSTALL.md` in omarchy-tab-s2):
  its warnings hold here too. Do not rely on this tablet for an emergency call.
- **Back up EFS before anything else**, as that guide says. No tool can rebuild it.
- **Know how to get out.** With a loader in PARAM, the way back is the rescue
  ([RESCUE.md](RESCUE.md)) and, past it, download mode with your own stock PARAM image. Section 2
  keeps a way back at every step: follow its order.

## 1. Route 1: "I download, I flash, it installs"

**Open since omarchy-tab-s2 2.0.0; its current release is 2.1.0 (2026-11-26).** The guide:
[docs/INSTALL-ARM64.md](https://github.com/elkir0/omarchy-tab-s2/blob/main/docs/INSTALL-ARM64.md)
in omarchy-tab-s2.

| Step | What you do |
|---|---|
| 1 | Download the image and the installer from [omarchy-tab-s2's release](https://github.com/elkir0/omarchy-tab-s2/releases); check the checksums |
| 2 | Copy `omarchy-arm64.img` and its `.sha256` into a folder `linux` on a microSD card, or on the internal storage while Android still runs |
| 3 | Flash the installer (`boot.img` and `recovery.img`, one Odin package) in download mode. The tablet installs itself and restarts into Omarchy's first-run setup |

No command to type, nothing to build. It needs the firmware `T715XXU2CRH1`: the installer checks
it, and PARAM, before it writes anything.

### 1.1 Why there has to be an installer

The loader cannot be shipped as a file. It lives in PARAM, and a PARAM image is Samsung's
firmware holding data of one tablet: no PARAM image can be distributed, and the forged logo must
be built from each tablet's **own** stock PARAM. The addresses it depends on are one
bootloader's, `T715XXU2CRH1`. So the installer runs on the tablet, builds the loader there from
that tablet's own PARAM, and writes it.

### 1.2 How it builds the loader

PARAM's first 7340032 bytes are a tar archive of the pictures S-Boot shows. The installer copies
the tablet's PARAM, replaces the archive's `logo.jpg` by this loader's (the forged logo of
`kboot7-cas3`, [SPLASH.md](SPLASH.md): the loader's code and its boot screen, no byte of
Samsung's), moves the members after it, pads with zeros, and writes the result only if its
sha256 is the one it was built for: the same bytes `scripts/build_kboot.py` writes from the same
stock image. Before that it checks that the stock part is that firmware's, and saves the whole
PARAM and EFS to the tablet's storage. The code is omarchy-tab-s2's `boot/initramfs/init`
(`t715.golden`), its files are `boot/golden/`, and `boot/golden/check-param.py` does the same on a
computer from a PARAM dump.

### 1.3 What is ready, what is missing

| Piece | State |
|---|---|
| The loader, with the boot screen | **done**, on the owner's tablet at every boot since 2026-11-25 ([SPLASH.md](SPLASH.md)) |
| The installer, which is the rescue afterwards | **done**, since omarchy-tab-s2 2.0.0; 2.1.0 today |
| The arm64 kernel and its patches | **done**: Linux 6.12.114, eight cores, suspend to RAM and hot-unplug since 2.1.0 ([KERNEL-CONFIG.md](https://github.com/elkir0/bnuuyloader/blob/main/t715/docs/KERNEL-CONFIG.md)); the release's kernel is the source tree of omarchy-tab-s2 1.0.5 with `../kernel/patches/` |
| The arm64 Omarchy image | **released** with omarchy-tab-s2 2.1.0 (first with 2.0.0) |
| Another tablet, another firmware | **not tried**: the installer refuses another bootloader, and a PARAM it does not know |

## 2. Route 2: the long one, for power users

Every step by hand, from a computer: how the reference tablet got there first. What it takes: the tablet running the 32-bit Omarchy, a computer with
Docker (everything here was done on macOS on Apple silicon, and the scripts assume it: about
20 GB free), the USB cable, and the readiness to recover a tablet from download mode if the
worst happens. A build takes from a few minutes to three quarters of an hour; the first arm64
boot is the moment to stay at the tablet.

The order below keeps a way back at every step. Do not skip ahead to the loader.

### 2.1 The map

| # | Step | Told in |
|---|---|---|
| 1 | Install the 32-bit Omarchy 1.0.5; reach the tablet over the USB link | omarchy-tab-s2: [its install guide](https://github.com/elkir0/omarchy-tab-s2/blob/main/docs/INSTALL.md) |
| 2 | Read the two dumps of **your** tablet; keep the PARAM copy safe | [../README.md](../README.md), section 3 |
| 3 | Build the loader's tools; calibrate; build the loader | [../README.md](../README.md), section 4; [SPLASH.md](SPLASH.md), section 9 |
| 4 | Build the arm64 kernel and the Omarchy image | [KERNEL-CONFIG.md](https://github.com/elkir0/bnuuyloader/blob/main/t715/docs/KERNEL-CONFIG.md); omarchy-tab-s2's [arm64/README.md](https://github.com/elkir0/omarchy-tab-s2/blob/main/arm64/README.md), "Building the image" |
| 5 | CACHE: back it up, shrink it, write a kernel to a slot | [../README.md](../README.md), section 6 |
| 6 | USERDATA: the arm64 root image and its modules | omarchy-tab-s2's [ROOTFS.md](https://github.com/elkir0/omarchy-tab-s2/blob/main/arm64/docs/ROOTFS.md), section 9 |
| 7 | The loader into PARAM: the tablet boots arm64 | [../README.md](../README.md), section 6 |
| 8 | The rescue into BOOT, then RECOVERY | [RESCUE.md](RESCUE.md), sections 4 and 5 |
| 9 | Only now, if room is wanted: the 32-bit root may go | [RESCUE.md](RESCUE.md) |

### 2.2 The steps, in a few words each

**1. The 32-bit system.** It is what you read the dumps from, and what BOOT boots whenever the
loader does not start arm64: the way back of every step until the rescue is in place. The port's
`device/tssh` is ssh, as root, to the tablet over the USB cable (172.16.42.1).

**2. The two dumps.** As root on the tablet's Linux, before anything else:

```bash
dd if=/dev/mmcblk0boot0 of=/run/t715/userdata/media/0/mmcblk0boot0.bin bs=1M count=4
dd if=/dev/mmcblk0p8     of=/run/t715/userdata/media/0/PARAM-mmcblk0p8.bin bs=1M count=8
```

Copy both to the computer into `t715/loader/dumps/`, and keep the PARAM copy somewhere safe as
well: it is the stock image you would flash in download mode. They are Samsung's firmware and
yours alone: never commit them, never share them.

**3. The loader.** The Python environment, the calibration of the forged block against S-Boot's
own decoder, then the loader itself, with `--verify`: one command decodes the logo with that
decoder and refuses the image unless it leaves exactly the bytes the exploit needs. With the
owner's boot screen:

```
venv/bin/python -I scripts/build_kboot.py --prod --geometry wide --art art/splash-bnuuy-and-me.png --luma-floor 4 --chroma-floor 3 --name kboot7 --verify
```

Without it, the black logo: `--prod --name kboot6`. Or with your own picture
([SPLASH.md](SPLASH.md), section 9).

**4. The kernel and the image.** `t715/build-arm64.sh` builds the kernel in a container; the
image with `bash build.sh` in omarchy-tab-s2's `arm64/rootfs/` ([its README](https://github.com/elkir0/omarchy-tab-s2/blob/main/arm64/README.md)). Build the image with your ssh key, or nobody can
log in to the arm64 system. **Mind the kernel's boot arguments.** They live in its device tree.
Those of daily use (`t715/kernel/config/bootargs-daily.dts`) name the root
`USERDATA/omarchy-arm64`. The others are for tests: they make the kernel go back to BOOT after a
while, skip the mark, and open a root shell over the USB cable, and the build applies one of
them by default. Read "The build" in [KERNEL-CONFIG.md](https://github.com/elkir0/bnuuyloader/blob/main/t715/docs/KERNEL-CONFIG.md), section 4, and
[../kernel/README.md](../kernel/README.md), before the first boot.

**5 and 6, then 7.** The installer does the writing, from the computer, with the tablet up under
either system:

```bash
cd t715/loader
export ORIG_SHA=$(shasum -a 256 dumps/PARAM-mmcblk0p8.bin | cut -c1-64)
T=../tools/t715-arm64-install
# The tools reach the tablet through omarchy-tab-s2's device/tssh, looked for next to the fork.
# If it is elsewhere: export T715_TSSH=/path/to/omarchy-tab-s2/device/tssh

venv/bin/python -I scripts/slot.py backup CACHE-before.bin   # the whole partition, the way back for it
venv/bin/python -I scripts/slot.py shrink
$T kernel Image DTB                                         # the kernel, and its device tree with the daily boot arguments
$T rootfs omarchy-arm64 ../../../omarchy-tab-s2/arm64/rootfs/out/rootfs-aarch64-omarchy45.img   # the root, built in omarchy-tab-s2: USERDATA/omarchy-arm64
$T modules omarchy-arm64 modules.tar.xz
$T loader out/kboot7.param                                  # from here, every boot runs the loader
$T status
```

`Image`, `DTB` and `modules.tar.xz` are what `build-arm64.sh` wrote (its `kernel-out/`).

Before the first arm64 boot, read the check list "Before the first boot on the tablet" in
omarchy-tab-s2's [ROOTFS.md](https://github.com/elkir0/omarchy-tab-s2/blob/main/arm64/docs/ROOTFS.md), section 9.

**8. The rescue.** It is in omarchy-tab-s2's tree since 2026-11-25. Built from it with the
loader you installed, written to BOOT while the loader works, then to RECOVERY. From this point a loader that fails to fire costs one
restart, not the tablet ([RESCUE.md](RESCUE.md)). The rescue replaces the 32-bit system's own
boot image in BOOT and RECOVERY: keep the release's `boot.img` and `recovery.img` at hand, to put
them back if ever wanted.

**9. The 32-bit root.** `USERDATA/omarchy` can then be deleted, if you want its room. The
installer's `unloader` refuses to put the stock PARAM back while it is gone, unless you insist
(`--no-32bit-root-ok`): with the stock image in PARAM, BOOT is what boots.

### 2.3 What you get, and what you do not

**What works**, on the one tablet tried: Omarchy 4.5 on arm64 as a daily system, user space in
about 13 s, a soak of three hours with eight busy cores; the boot screen of your choice; display,
touch, GPU, Wi-Fi, Bluetooth, sound, sensors, battery, the microSD card and the LTE modem's
processor as far as the health check sees. Since omarchy-tab-s2 2.1.0: suspend to RAM (the root
powers the modem's processor and the Wi-Fi/Bluetooth chip down before each sleep), and Android
apps through Waydroid, which the kernel's `COMPAT` makes possible. The details:
[../README.md](../README.md), section 1,
and [ROADMAP.md](https://github.com/elkir0/bnuuyloader/blob/main/t715/docs/ROADMAP.md).

**What does not yet**: the A57 cores above 1.2 GHz
([ROADMAP.md](https://github.com/elkir0/bnuuyloader/blob/main/t715/docs/ROADMAP.md), Milestone 4); the modem with a SIM; the camera's user space. One red
pixel on the boot screen, below the picture ([SPLASH.md](SPLASH.md), section 6). And everything
is one tablet's: another unit, another firmware, and the whole method has to be made again.

### 2.4 When it does not come up

| What you see | What it means | What to do |
|---|---|---|
| The arm64 desktop comes up, but the next boot shows the boot screen, then the rescue's message, twice, then arm64 again | the arm64 system did not mark itself up: the loader's ledger hands two boots to BOOT, then tries again | the arm64 system is up, so `$T status` works over ssh: look at what failed to start (`systemctl --failed`) and fix it. A boot that comes up and marks itself makes the next one try as usual |
| The boot screen, then the rescue's message, twice, then the boot screen again, and never arm64 | the kernel or the root does not start | the loader keeps trying, every third boot. To get in: the rescue's root shell over the USB cable, at each rescue boot ([RESCUE.md](RESCUE.md), section 7). While a system answers ssh, `$T` can write a kernel and a tree known to work (`$T kernel Image DTB`, `$T rootfs omarchy-arm64 IMAGE --replace`), or `$T unloader`. To start over cleanly: download mode, your stock PARAM back with Heimdall or Odin, then the 32-bit port's release as its guide says. To know why it fails: the ring and pstore ([../README.md](../README.md), section 8) |
| The rescue says PARAM does not hold the loader known to work, writes it back, restarts | a loader the rescue was not told of is in PARAM | nothing to do: it is the rescue working. Tell it about the new loader at the next build (`--paramrescue-also`) |
| The stock system boots at every start | PARAM holds the stock image | `$T status` to confirm; `$T loader out/kboot7.param` to start arm64 again |
| You want BOOT's system back for good | | `$T unloader` (it needs the 32-bit root, or `--no-32bit-root-ok` when the rescue is in BOOT) |
| Nothing answers, and the screen never shows the boot screen | the loader hangs before it can hand back: not the one for this bootloader, or a wrong logo | download mode, and flash your stock PARAM back with Heimdall or Odin |

The last line is the one the rescue exists to make rare.
