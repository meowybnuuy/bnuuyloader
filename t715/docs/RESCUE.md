# The rescue: a minimal system in BOOT and RECOVERY

A loader in PARAM starts the arm64 system at every boot. It is also the only way that tablet has
left to start anything: if the loader stops firing, nothing of it can run again, and what S-Boot
boots instead is the BOOT partition. The rescue is what must be in BOOT, and in RECOVERY, before
that can happen: a small 32-bit system whose one job is to look at PARAM and, when the loader it
finds there is not one known to work, write the one that is.

On the owner's tablet, since 2026-11-25, it replaced the 32-bit Omarchy that used to be BOOT's
content and the way back. It was tried the same day: with a PARAM image that holds no loader at
all, the tablet came back to arm64 by itself.

How sure each fact is, as in [FINDINGS.md](FINDINGS.md): **[hardware]** seen on the tablet,
**[static]** read in code.

## 1. Why there must be something behind the loader

S-Boot boots BOOT in three situations:

| When | Why |
|---|---|
| PARAM holds the stock image | there is no loader: the tablet's normal boot |
| The loader hands back | no valid kernel in CACHE, or the ledger says this boot must not try ([../README.md](../README.md), section 2.3) |
| The loader never fires | a failed attempt at a new logo: its code is what would hand back, and it never ran |

The first two cost one or two boots, and that is all, **if BOOT holds a system that works**. The
third is different: with nothing usable in BOOT the tablet restarts in a loop, nothing answers on
the USB link, and the only way in is download mode with a stock image for every partition
concerned.

Until 2026-11-25 the 32-bit system of [omarchy-tab-s2](https://github.com/elkir0/omarchy-tab-s2)
was in BOOT and was that fallback. Its root was removed that day, to give its room to the arm64
system: BOOT then held a 32-bit kernel with nothing behind it, and no loader could be tried
safely. Hence the rescue.

## 2. What it is

The initramfs of omarchy-tab-s2 (`boot/initramfs/init`: busybox, PID 1) with one more knob, packed
with the port's 32-bit kernel into a boot image by the port's own tools. Nothing was written from
scratch. The image must fit its partition: 14 MiB in BOOT, 16 MiB in RECOVERY.

With `t715.paramrescue=1`, `/init` looks at PARAM once the USB debug link is up:

| The loader's part of PARAM holds | What happens |
|---|---|
| the loader known to work | nothing: the boot goes on |
| the stock image (no loader) | nothing: the boot goes on |
| another loader the image was told about (`also.sha256`) | nothing: the boot goes on |
| anything else | the known loader is written over that part, read back, and the board restarts: the arm64 system comes back by itself |

The image's files, under `/lib/t715-paramrescue/`:

| File | What |
|---|---|
| `param.img.gz` | the PARAM image whose loader is written back |
| `loader.sha256` | the SHA-256 of that image's first `extent` bytes |
| `stock.sha256` | the SHA-256 of the stock PARAM's first `extent` bytes |
| `extent` | how many bytes of PARAM are the loader's (below) |
| `also.sha256` | one line per other loader the rescue must leave alone |

Nothing is written, and the boot goes on as without the knob, when: the knob is off; a file is
missing; the image is not the one its SHA-256 announces; there is no single partition named
PARAM; the write does not read back. A partition flagged read-only is made writable first (the
arm64 system leaves PARAM read-only by a rule of its own).

The boot then goes on to the root image, and as the 32-bit system is gone, to the failure path
the port already has: the reason on the panel, the USB debug link and, with `t715.telnet=1`, a
root shell on it, for `t715.failwait` seconds, then a restart.

**The loader's part.** PARAM is 8 MiB. Its first 7,340,032 bytes (0x700000) are the tar archive
S-Boot reads its logo from: that is the loader, and all the builder writes. What follows is
S-Boot's own data. So the rescue compares, and writes, only those first bytes (`--paramrescue-extent`).

## 3. What the tablet taught (2026-11-25)

- **S-Boot rewrites the end of PARAM whenever it boots a kernel itself** [hardware]. A fallback
  boot included. That it rewrites its environment at 0x700000 was known
  ([FINDINGS.md](FINDINGS.md), section 10); what differs after such a boot starts at 0x700009, in
  that environment. The first rescue compared the whole partition: at each fallback boot it found
  a hash it did not know, took its own good loader for none, wrote it again and restarted after
  about 7 s. It looked like a loader that never works. Hence the extent: a loader is identified by
  the SHA-256 of PARAM's first 7,340,032 bytes, never by the whole partition's.
  `t715-arm64-install` names and checks PARAM the same way since.
- **The loader's ledger works for real** [hardware]. One boot not marked `KBOOT: up` made the
  loader hand the next two boots to BOOT, where the rescue found the loader known to work and had
  nothing to do; the boot after tried arm64 again.
- **The rescue heals by itself** [hardware]. With a probe in PARAM (a logo with no loader:
  [SPLASH.md](SPLASH.md), section 7), S-Boot booted BOOT, the rescue saw a loader's part that was
  neither the stock image nor a known loader, wrote its loader and restarted. The tablet was back
  under arm64 35 s after the restart.
- What the rescue boot showed on the panel and the link: the port's kernel (6.12.114, 32 bits),
  the initramfs and the USB gadget all work; the shell answered on port 23.

## 4. Building it

The rescue is in omarchy-tab-s2's tree since 2026-11-25, after its 1.0.5 release: a clone of
its `main` has it. For a clone at `v1.0.5`, the same change is a patch in [../rescue/](../rescue/),
with its instructions. In short: omarchy-tab-s2 with the rescue, its 32-bit kernel built (its
developer guide is `docs/DEPLOY.md`, and `kernel/README.md`), and from the loader's `dumps/` the
stock PARAM and the loader images.

```bash
LOADER=/path/to/kboot7.param                   # the loader the rescue writes back
LOADER_BYTES=7340032                           # the loader's part of PARAM
STOCK=$(head -c $LOADER_BYTES /path/to/dumps/PARAM-mmcblk0p8.bin | sha256sum | cut -d' ' -f1)
KNOBS="t715.usbfn=ecm t715.telnet=1 t715.failwait=120 t715.quiet=1"
BUILD_DIR=out/mainline                         # the port's 32-bit kernel, built

# for BOOT
bash boot/build-initramfs.sh --out out/initramfs-rescue-boot --knobs "$KNOBS" \
     --paramrescue $LOADER --paramrescue-extent $LOADER_BYTES --paramrescue-stock $STOCK \
     --paramrescue-also /path/to/kboot6.param
bash boot/pack-test-recovery.sh --boot --initramfs out/initramfs-rescue-boot/initramfs.cpio.gz \
     --out out/rescue/boot $BUILD_DIR

# for RECOVERY: the same, and the watchdog guard off, since S-Boot boots RECOVERY after one
bash boot/build-initramfs.sh --out out/initramfs-rescue-recovery --knobs "$KNOBS t715.wdtguard=0" \
     --paramrescue $LOADER --paramrescue-extent $LOADER_BYTES --paramrescue-stock $STOCK \
     --paramrescue-also /path/to/kboot6.param
bash boot/pack-test-recovery.sh --initramfs out/initramfs-rescue-recovery/initramfs.cpio.gz \
     --out out/rescue/recovery $BUILD_DIR

bash boot/tests/test_initramfs.sh               # the whole suite, in Docker; never touches a tablet
```

Both SHA-256 are of the first `LOADER_BYTES` bytes (`head -c LOADER_BYTES IMAGE | sha256sum`).
`--paramrescue` turns the knob on by default; `--paramrescue-also` can be given more than once.

The result: `out/rescue/boot/boot.img` and `out/rescue/recovery/recovery.img`.

## 5. Installing it, and the order

```bash
bash device/write-part.sh BOOT out/rescue/boot/boot.img              # while the loader works
bash device/write-part.sh RECOVERY out/rescue/recovery/recovery.img  # after a ledger cycle, below
```

**BOOT first, while the loader works.** With a working loader in PARAM, S-Boot never boots BOOT:
a broken image in it costs nothing. `device/write-part.sh` writes over ssh, which needs the tablet
up and answering.

**RECOVERY after**, once the rescue in BOOT has been seen to work. It cannot be tried by keys
while a loader is in PARAM: the loader runs in every S-Boot boot, a recovery one included, and
hands back only as the ledger says.

**To see the rescue for real**, make one boot that the ledger will not count as up, and let the
loader do the rest:

```
systemctl disable t715-kboot-mark.service     # on the arm64 system
systemctl reboot
```

The loader hands the next two boots to BOOT: the rescue runs twice (its log must say that PARAM
holds the loader known to work, nothing to do), and the third boot tries arm64 again. Then:

```
systemctl enable t715-kboot-mark.service
```

(`systemctl mask` does not work there: the unit's file is in `/etc/systemd/system`.) With
`t715.failwait=120` the two rescue boots take four to five minutes.

## 6. Rules

- **Such an image is one tablet's own PARAM with a loader in it: never publish it.** Neither
  image built with `--paramrescue` leaves the computer it was built on.
- **The stock PARAM's SHA-256 is required.** Without it the rescue would take the stock image for
  a loader that did not run, and write a loader over the stock PARAM.
- **The known loaders must follow the loaders in use.** BOOT is booted also when a working loader
  hands back, and the rescue then replaces any loader it knows of neither way: a newer one, tried
  behind a failure of the arm64 system, would be undone. With each new loader, rebuild both
  images: the last proven one as `--paramrescue`, the others as `--paramrescue-also`.
- **A loader is its first 7,340,032 bytes.** Every tool that names PARAM goes by them:
  `t715-arm64-install status`, `t715-arm64-install loader` (which writes only if PARAM holds the
  stock image or a loader built in `out/`), the rescue.
- **BOOT and RECOVERY only through `device/write-part.sh`**, as the 32-bit port's rules say.

## 7. Finding out what a rescue boot did

| Want | How |
|---|---|
| To get in | `telnet 172.16.42.1` over the USB cable while the rescue is up: a root shell, with `wget`, `tftp`, `httpd` and `nc`. From there a loader can be fetched from the computer and written by hand. It was never needed on the owner's tablet |
| The rescue's own log | the lines on the panel (`say`), and the kernel's log. With `t715.quiet=1` only its first lines are kept; build an image without that knob, and the whole log of the boot lands in `/sys/fs/pstore/console-ramoops-0`, readable at the next arm64 boot. The record before is overwritten each time |
| What the loader decided | S-Boot's log ring: [../README.md](../README.md), sections 5.3 and 8 |
| What PARAM holds | `t715-arm64-install status` |

Those records hold the device's identifiers: print them through `scripts/sbootlog.py --mask`,
and keep them out of any repository.

## 8. Limits

- **A restart loop cannot be reached.** If a loader stops firing before the rescue is in BOOT,
  or with an image that does not boot, only download mode is left: a stock PARAM image flashed
  with Heimdall or Odin. The rescue narrows the risk of every loader change after the first one;
  it does not remove the first one.
- **The rescue knows only what it was built with.** A loader it has not been told of is replaced.
- **RECOVERY is not proven on the tablet.** Its image is the BOOT one's twin, with the watchdog
  guard off; it was written and read back, never booted.
- **One tablet, one firmware**, as everything in this port.
