# The kernel side of the arm64 port

What a Linux kernel needs to boot on the Galaxy Tab S2 8.0 (SM-T715) in 64 bits, started by the
loader of [../](../README.md).

The tree is the kernel tree of [omarchy-tab-s2](https://github.com/elkir0/omarchy-tab-s2): Linux
v6.12.114 plus its patch series, on the branch of its 1.0.5 release. The ten patches of `patches/`
go on top of it, in their order, with `git am`. The kernel that runs on the tablet is
`6.12.114-00106-gd30e37ad41ab`: that tree with the ten patches, built with the configuration of
`config/` (in the fork). It is the kernel of omarchy-tab-s2 2.1.0 (2026-11-26).

## The patches

| Patch | What it does |
|---|---|
| `0001` | **arm64: exynos5433: MCT without the architected timer.** The ARM generic counter does not run on this boot path: `CNTFRQ_EL0` reads 0. arm64 Linux panics on that, and its delays count the counter. For a machine compatible with `samsung,exynos5433` there is no panic, and no calibration from the counter, when the rate is 0; `__delay()` counts loop iterations. The Exynos MCT keeps time. |
| `0002` | **arm64: exynos5433: start the secondary CPUs without PSCI.** The enable-method `samsung,exynos5433-el2`, under `CONFIG_ARM64_EXYNOS5433_SMP`. The entry is a twelve-word AArch32 stub whose only job is the monitor call the loader makes for the boot CPU, `SMC 0x82000400`, which switches the core to AArch64 at EL2. An AArch64 stub `eret`s to EL1, and a holding pen hands the core to `secondary_entry()` once its own MPIDR is there. The CPU side is the 32-bit kernel's sequence, register for register. |
| `0003` | **dt-bindings: arm: cpus: the enable-method `samsung,exynos5433-el2`.** |
| `0004` | **arm64: dts: exynos: gts28ltexx: the board for a 64-bit kernel.** The 64-bit board file includes the 32-bit one and gives the eight CPU nodes the enable-method. |
| `0005` | **arm64: exynos5433: fix the MPIDR check of the secondary CPUs.** A shift of 6 bits where the code meant affinity level 2 refused every A53 secondary. |
| `0006` | **arm64: topology: no warning without an architected timer.** These cores have no AMU, so nothing is lost when the timer's rate reads 0. |
| `0007` | **arm64: dts: exynos: gts28ltexx: the A57 at 1.2 GHz at most (stage 1).** The A57 levels above 1.2 GHz are left out of the board's table until stage 2 of the frequency plan has run on arm64. BUCK2 is capped at 1.0625 V, the A57 cooling states are renumbered. |
| `0008` | **arm64: dts: exynos: gts28ltexx: no System MMU for a 64-bit kernel.** On arm64 the kernel selects `OF_IOMMU`. With no System MMU driver built, DECON and three other masters waited for the deferred-probe timeout, 16.9 s into the boot: a black screen behind the bootloader's logo. The twelve System MMUs are disabled; DECON binds at 0.5 s. |
| `0009` | **misc: modem_v1: build on arm64.** The driver has no 32-bit-only code; a Kconfig dependency and a `sizeof(size_t) == 4` assertion kept it to ARM. |
| `0010` | **arm64: exynos5433: CPU hot-unplug and suspend to RAM without PSCI.** Hot-unplug is the 32-bit kernel's `exynos5433_cpu_die()`, from AArch64 EL1: the HOTPLUG boot flag, the core's power off in the PMU, then the monitor's SHUTDOWN call; a core powered back on comes in again through the AArch32 stub of `0002`, and `cpu_kill` polls the PMU status. By hand it stays refused until `/sys/module/smp_exynos5433/parameters/hotplug` is 1; a system sleep may. Suspend to RAM (`CONFIG_ARM64_EXYNOS5433_SUSPEND`): the 32-bit kernel's PMU and clock programming, unchanged; the monitor's SLEEP call, from AArch64, inside `cpu_suspend()`; and the way back through a second twelve-word AArch32 stub, `exynos5433_resume_entry`, which the firmware jumps to on a wake-up: `SMC 0x82000400` again, EL2 set up as for a secondary, `eret` to `cpu_resume` at EL1. `exynos5433_sleep=on` or `=dryrun` and the one-shot arm switch work as on 32 bits. `c2test` powers one secondary down and back through the resume stub while the system runs. |

Patches `0001` to `0003`, `0005`, `0006` and `0010` are for any Exynos 5433 started this way.
`0010` touches only `arch/arm64/kernel/`, with its entry in `arch/arm64/Kconfig` and its line in the
Makefile: no board file, no driver. Like `0002`, it relies on this tablet's secure monitor: another
device's monitor should be read first ([../docs/SMP-MONITOR.md](../docs/SMP-MONITOR.md)). Patches
`0004`, `0007`, `0008` and `0009` change files that exist only in the tree of omarchy-tab-s2: the
board file of this tablet and the modem driver it imports.

The findings behind them are in [../docs/FINDINGS.md](../docs/FINDINGS.md), sections 13, 14, 17, 19
and 23. The comments of `0010` cite the monitor's reading as `docs/arm64-monitor-smc.md` of the
port: it is [../docs/SMP-MONITOR.md](../docs/SMP-MONITOR.md) here.

## What the kernel must be

| Need | Why |
|---|---|
| `CONFIG_CLKSRC_EXYNOS_MCT=y` | the time base: the architected timer does not run |
| `CONFIG_ARM64_EXYNOS5433_SMP=y` | the seven other cores |
| `CONFIG_ARM64_EXYNOS5433_SUSPEND=y` | suspend to RAM without PSCI (`0010`). It needs `ARM64_EXYNOS5433_SMP`, `SUSPEND`, `HOTPLUG_CPU` and `CPU_PM`, and registers nothing unless the command line has `exynos5433_sleep=on` or `=dryrun` |
| `CONFIG_COMPAT=y` | 32-bit user space. Waydroid's arm64 Android image runs 32-bit services (`boringssl_self_test32`, `zygote64_32`) and 32-bit apps. Off until 2.1.0; the build's check no longer requires it off |
| `CONFIG_SAMSUNG_SEC_LOG_CONSOLE=y` | `console=sec_log`: the kernel's log goes on in S-Boot's RAM log ring, where the loader's ledger reads `KBOOT: up`. Without that mark the ledger counts every boot as a failed try, and the tablet never boots arm64 twice in a row |
| `CONFIG_S3C2410_WATCHDOG=y` | the loader arms the watchdog; the kernel must neither stop it nor let it fire |
| The initramfs built in | the loader passes no initrd: the kernel's own initramfs mounts the root |
| `CONFIG_RANDOMIZE_BASE` not set | the kernel of this port is built without it: the loader starts the `Image` at a fixed address, 0x42000000. A kernel with it has not been tried |
| An uncompressed `Image`, with a text offset of 0 | a slot of CACHE holds it as it is: no compression, no decompressor in the loader |

## The boot arguments the loader depends on

The daily arguments of the tablet are in `config/bootargs-daily.dts` (in the fork). Four of them
matter to the loader:

| Argument | Why |
|---|---|
| `console=sec_log sec_log=0x200000@0x26000000` | the kernel's log goes on in the ring, so that `KBOOT: up` reaches the ledger |
| `s3c2410_wdt.tmr_atboot=1` | without it the driver stops, at probe, the watchdog the loader armed |
| `watchdog.handle_boot_enabled=1 watchdog.open_timeout=120` | the kernel's watchdog core feeds the watchdog the loader armed, for 120 s at most after boot, until a service of the system opens it |
| `quiet` | console loglevel 4: the boot mark, at level 3, still reaches the ring |

A test image, which resets by itself, uses `watchdog.handle_boot_enabled=0` instead: there the
kernel must not feed the watchdog at all.

Since 2.1.0 the daily arguments also carry `exynos5433_sleep=dryrun`, for the kernel rather than
the loader: the system sleep is registered, and a sleep is real only once armed
(`/sys/module/exynos5433_sleep/parameters/arm`, for one sleep). The root's `t715-sleep` arms it
after it has powered the modem's CP and the Wi-Fi/Bluetooth chip down; a suspend that nothing
prepared stays a dry run. With the Wi-Fi chip left up, the first real sleep never resumed: the
board reset.

## Building

In the fork: `../build-arm64.sh` builds the kernel in a container from a clone of that tree, with
`config/` and the boot argument overlays, and writes the `Image`, the modules and the device trees.
The test kernel of the first boots, with a static init that reads the tablet's state and restarts
it, is in `test-kernel/` (in the fork).

The loader checks what it is given: the arm64 magic of the `Image`, a text offset of 0, the
`image_size` of its header (the kernel's footprint in memory, `.bss` included), and the magic and
the `totalsize` of the device tree.

## State on 2026-11-26

**Proven on the tablet.** The ten patches, on Linux 6.12.114: one core first, then the eight cores
under load (2026-11-24), then the full kernel of the daily system, at every boot since 2026-11-25.
`0010` on 2026-11-26: CPU7, then the whole A57 cluster, then all seven secondaries down to CPU0
alone and back, four rounds, no error; `c2test` on CPU1 (down in 73 us, back 81 us after
power-on); five real sleeps out of five woke, with the modem's CP and the Wi-Fi/Bluetooth chip
powered down first: four on the PMIC's RTC alarm, one on the power key after 165 s on battery,
through the root's `t715-sleep` ([../docs/FINDINGS.md](../docs/FINDINGS.md), section 23).

**Built or rehearsed only.** Nothing: every patch has run.

**Open.** A sleep with the Wi-Fi chip left powered (the first try reset the board). The power the
tablet draws asleep. A secondary's power-down as an idle state: `c2test` shows the way back, no
cpuidle driver uses it. The A57 above 1.2 GHz. Another kernel version.
