# The one-core experiment: is the monitor's switch to AArch64 accepted on a secondary core?

Run on the tablet on 2026-11-24: **the switch works on a secondary core** (section 7.2). The first image faulted before the experiment (7.1).
The question is the owner's priority #1 of that day: all 8 cores of the SM-T715 in 64 bits. A secondary
core starts in AArch32 (as the 32-bit port brings it up: `arch/arm/mach-exynos/platsmp.c` of the release
tree, `omarchy-tab-s2/docs/hardware/SMP_BRINGUP.md`). On the boot CPU, the monitor's call `r0 = 0x82000400, r1 = entry,
r2 = 0x800, r3 = 1, smc #0` switches to AArch64 at EL2 (proven). Whether it is accepted on a secondary
core is what nobody knew. No decision on the rest of the port before the answer.

`../kernel/smp/`, `../kernel/test-kernel/` and the logs under `../loader/out/` are in the fork
([elkir0/bnuuyloader](https://github.com/elkir0/bnuuyloader)), not in this tree.

## 1. What the image does

Image `smp1`: PARAM = the original with the forged `logo.jpg` (`../loader/out/smp1.param`,
sha256 `f15cc0d3…`), marker `HIJACK3: 7e5e7021`. Built from `../loader/`, with
`venv/bin/python -I scripts/build_smp.py --id 0x7e5e7021 --name smp1`. Nothing else is written on the
tablet: no kernel, no slot, the loader stays a test image that resets the SoC by itself.

On the boot CPU, as every test image: S-Boot decodes the logo, the forged heap runs ARM32 code, the
monitor switches to AArch64 at EL2, stage 1 puts its vectors and an identity map (MMU and caches on),
stage 2 runs in C. Then `smp_experiment()` (`../loader/stage2/stage2.c`, `SMP_EXP`):

1. It logs what S-Boot left: the PMU registers of A53 core 1 (MPIDR 0x80000101, PMU index 5: base
   0x105C0000 + 0x2000 + 0x80 x 5 = 0x105C2280), KFC NONCPU OPTION (0x105C2428), UP_SCHEDULER
   (0x105C0120), the monitor's boot-address register (sysram-ns 0x0207B000 + 0x1C) and its boot flags
   (+0x28 + 4 x index).
2. It puts the two stubs in DRAM at 0x41000000 (ARM32, 0x800 bytes) and 0x41000800 (AArch64, 0x800
   bytes) and empties a scratch page at 0x41001000. For this image the 2 MiB at 0x41000000 are mapped
   Normal, not cached (`a64_sreset.S`, `SMPX`): what this core writes there is in the memory at once,
   and what the secondary writes there is read from it. The stubs are read back and summed (the sum
   is checked against the build's).
3. It arms the watchdog for 12 s.
4. It writes the ARM32 stub's address into the boot-address register.
5. The options, as the stock kernel's `exynos5433_pmu_cpu_init()`: KFC NONCPU OPTION without
   USE_SC_COUNTER, with USE_SC_FEEDBACK; the core's OPTION with USE_SC_COUNTER, USE_SC_FEEDBACK and
   USE_SMPEN; DURATION0 with WAIT_RESET and SCALL = 1; UP_SCHEDULER with both clusters' bits.
6. The power-up, as `exynos5433_core_power_up()`: OPTION without USE_SC_FEEDBACK, DURATION0 to 3
   with the feedback field at 0x11, then CONFIGURATION |= 0xF. It waits up to 10 ms for STATUS's low
   nibble to read 0xF.
7. It waits for the secondary's last stage: at most 3 s on the watchdog's counter (the generic
   counter does not run on this tablet) and at most 4,000,000 passes. Each pass writes the boot
   address again and sends an event (`dsb sy`, `sev`), as the stock release loop does.
8. It logs the registers, the scratch page and a result line, then writes 1 to PMU SWRESET.

The secondary runs `../loader/stage2/smp_stub32.S` at 0x41000000: it writes its MPIDR, CPSR,
SCTLR, CPACR, NSACR, VBAR, TTBR0 into the scratch page, the stage 1, then a line in S-Boot's log
ring; then the monitor's call (same registers as on the boot CPU, r1 = 0x41000800). If the
monitor returns to AArch32, it writes stage 0x80, what the monitor answered, and a line; it then
parks. If the monitor switches it, `../loader/stage2/smp_stub64.S` runs at EL2 with the MMU and
the caches off: it writes MPIDR, CurrentEL, HCR_EL2, SCTLR_EL2, ELR_EL2, SPSR_EL2, SP,
CNTHCTL_EL2, CNTVOFF_EL2, CPTR_EL2, stage 3, then a line; then it
enters EL1 by an `eret` exactly as the loader's `boot_el1.S` does (HCR_EL2 = RW only, EL1 with the MMU
and caches off, SPSR 0x3C5), stage 4; at EL1 it writes MPIDR, CurrentEL, SCTLR_EL1, DAIF, a line, then
stage 5, and parks. Other levels are recorded (stages 0x81, 0x82, 0x83) and nothing else is attempted.
If the core comes up unprivileged, the stub does not call the monitor (stage 0x81, a line).

The stubs use no stack: the monitor may leave any SP. Register rules: on the 32-bit side r7 holds the
scratch page and the writing routines use r0 to r6, r8 and r9; on the 64-bit side x20 holds the scratch
page and x19 the level, the routines use x0 to x4 and x7 to x10.

Nothing in the image changes a clock or a voltage: the core is powered on in the state S-Boot left the
cluster (A53 at 1.2 GHz, 1.1625 V as measured by the first arm64 kernel).

## 2. The way back

Two, both independent of what the secondary does. The normal one: the boot CPU writes SWRESET within
3 s of the power-on (a software reset keeps INFORM3 normal: S-Boot boots BOOT). If the boot CPU were to
hang before that, the watchdog fires at 12 s; a watchdog reset makes S-Boot boot RECOVERY, and the
owner's initramfs guard turns that into a software reset, so BOOT follows (`omarchy-tab-s2/docs/hardware/CPUFREQ.md`
8.2; exercised by `sreset9` on 2026-11-24). In both cases the next boot's ARM32 code sees the marker in
the previous boot's S-Boot log and skips the test, S-Boot's 32-bit kernel boots, and `../loader/scripts/cycle.sh`
puts the original PARAM back.

## 3. How to read the ring

Three lines come from the secondary, one from each state. With the emulator's stand-ins they are:

```
HIJACK3: 7e5e7021 core 1 alive in 32 bits: MPIDR=80000101 CPSR=000001d3 SCTLR=30c50830 CPACR=00000000 VBAR=00000000
HIJACK3: 7e5e7021 core 1 in 64 bits at EL2: CurrentEL=00000008 MPIDR=80000101 HCR_EL2=... SCTLR_EL2=... SPSR_EL2=... SP=...
HIJACK3: 7e5e7021 core 1 in 64 bits at EL1: CurrentEL=00000004 MPIDR=80000101 SCTLR_EL1=... DAIF=...
```

On the tablet CurrentEL is 0x8 at EL2 and 0x4 at EL1; MPIDR's bit 31 is set in the non-secure world.
The boot CPU's last line, `smp: result: ...`, says what it saw, from the stage word alone.

The owner's rule: the three lines mean the switch works on a secondary core (go to step 2); only the
first means the monitor refuses there (read its code, find another call); no line means the power-on
from EL2 is not right (compare with `platsmp.c`).

The stage word: 1 alive in AArch32, 2 calling the monitor, 3 in AArch64 at EL2, 4 the eret is tried,
5 at EL1; 0x80 the monitor came back to AArch32 (scratch word 9 is what it answered in r0); 0x81 to
0x83 another level or an unprivileged mode.

## 4. The rehearsal (`../loader/scripts/preflight.py --smp secondary|none --stubs ...`)

The emulator has one core; this adds a second one, on demand. The ARM32 part is the usual one (the
forged heap up to the monitor's call; the guard against a real dump of the ring: `guard_cases.py`,
0 failure). The AArch64 part runs stage 1 and stage 2 with the PMU and the sysram window holding what
the 32-bit kernel read there, and traces every write to them. When stage 2 powers the core on, the
emulator stops before the write; the ARM32 stub runs from the boot address in an ARM32 emulator up to
its `smc` (its four arguments are checked); the AArch64 stub runs from the entry they name in an
AArch64 emulator, as at EL2 (stand-ins for the EL2 registers and for CurrentEL) up to its `eret` (the
stage, the entry and the SPSR are checked), then from that entry up to its park loop. The ring and the
scratch page are copied back; STATUS is set to 0x2004000F; the boot CPU resumes.

What is checked after the run: the power sequence, register for register against `platsmp.c` (10
checks: the watchdog on for 12 s with its reset let through; the boot address written first; KFC
NONCPU OPTION 0x00020002; OPTION 0x10010103; DURATION0 0xFFFFFF1F; UP_SCHEDULER 3; the power-up's
last five writes before CONFIGURATION; CONFIGURATION written once, 0x8000000F; only the boot address
written again until SWRESET; the registers as they stand); the page tables (0x41000000..0x41200000 not
cached); the three lines and the boot CPU's result; the exception handler. With `none`, nothing comes
from the core: the watchdog's counter is made to count, the wait ends by its 3 s bound, and the result
must say that nothing came.

What the emulator caught before anything reached the tablet (all in the stubs, none visible in a
reading): a text routine that returned after its first character (a tail call where a loop was
meant); the hex routine's return address and its value overwritten by `bl` and by the digit; the
scratch page's address lost after one printed line; a stand-in for CurrentEL that took the wrong
branch. Two builder checks were wrong too (a mask that took two bits of an `adr` immediate for the
opcode, and the rehearsal's own expected values for two bit fields).

The proven images still rehearse as before after these changes: the test image `sreset12`, and the
12 cases of the production loader (`kboot_cases.py`: 0 failure).

## 5. What this proves and what it does not

Proven if the three lines are there: on this tablet, a secondary core powered on as the 32-bit kernel
does it runs AArch32 at EL1 at the address of the boot register, the monitor's call switches that
core to AArch64 at EL2, and it can enter EL1 by an `eret`. Not proven by it: the three other A53 and
the four A57 (the A57 cluster needs more: see `SMP-DESIGN.md` 6.5), a kernel's secondary entry
on these cores, hot-unplug and resume, and long runs with the cores busy.

## 6. Files

| File | What |
|---|---|
| `../loader/stage2/smp_stub32.S`, `smp_stub64.S` | the two stubs |
| `../loader/stage2/stage2.c` (`SMP_EXP`) | the boot CPU's side |
| `../loader/scripts/a64_sreset.S` (`SMPX`) | the uncached block |
| `../loader/scripts/build_smp_stubs.py`, `build_smp.py` | the build |
| `../loader/scripts/preflight.py` | the rehearsal (`rehearse_secondary`, `check_smp`) |
| `../loader/out/smp1-build.log`, `preflight-smp1-*.log`, `guard-regress-smp1.log` | the logs |

The monitor's side is in `SMP-MONITOR.md` (static reading of the boot image); the kernel side
for step 2 in `SMP-DESIGN.md` and `../kernel/smp/`.

## 7. On the tablet

Both cycles wrote PARAM only; the tablet came back under its 32-bit Linux by itself and
`../loader/scripts/cycle.sh` put the original PARAM back (verified each time).

### 7.1 `smp1`: the experiment did not run

Ring: `EXCEPTION at EL2: ESR=96000061 ELR=24224010 FAR=242286a9 SPSR=800003c9`, then the reset by the
exception handler, Linux back after 52 s. `0x24224010` is stage 2's fifth instruction, the store that
clears `.bss`; the exception is an alignment fault (DFSC 0x21): `.bss` began at `0x242286a9`. The array
of the stubs, 4 KiB, had pushed it onto an odd address, and on the tablet `SCTLR_EL2.A` is 1. The
emulator does not check alignment, so the rehearsal was green. No secondary core was powered on.
Fixed in `../loader/stage2/stage2.ld` (`.bss` aligned to 8 at both ends), in the generated array
(aligned to 8), and by a check in `build_stage2.py` that refuses a `.bss` not on a multiple of 8.
In every image that had run before (the test kernels, the production loader) `.bss` began on a
multiple of 8.

### 7.2 `smp2`: the switch works on a secondary core

Image `smp2.param`, sha256 `99123466…`; marker `HIJACK3: 7e5e7022`. Boot 39 of 40 in the ring;
"no exception"; Linux back after 46 s. The lines of the image, as read with
`../loader/scripts/hijack_lines.py` (identifiers masked; none in these lines):

```
HIJACK3: 7e5e7022 smp: as S-Boot left it: PMU core 5 CONF STATUS OPTION 0x0c DURATION0-3 80000000 10380000 10010103 00000000 ffffffff ffffffff ffffffff ffffffff KFC_NONCPU_OPTION=00020001 UP_SCHEDULER=00000000 boot_addr=00000000 boot_flags(index 0 to 7): 00000004 00000004 00000004 00000004 00000001 00000004 00000004 00000004
HIJACK3: 7e5e7022 smp: the stubs are at 41000000: 00001000 bytes, the sum of their words as read back 6a6ef725
HIJACK3: 7e5e7022 smp: this core's SP_EL0 at EL2 (the monitor's, from S-Boot's sp_usr; the secondary takes it as its own before the call): 0
HIJACK3: 7e5e7022 smp: options set: PMU core 5 CONF STATUS OPTION 0x0c DURATION0-3 80000000 10380000 10010103 00000000 ffffff1f ffffffff ffffffff ffffffff KFC_NONCPU_OPTION=00020002 UP_SCHEDULER=00000003 boot_addr=41000000 boot_flags(index 0 to 7): 00000004 00000004 00000004 00000004 00000001 00000004 00000004 00000004
HIJACK3: 7e5e7022 core 1 alive in 32 bits: MPIDR=80000101 CPSR=200001d3 SCTLR=00c5083a CPACR=00300000 VBAR=00000000
HIJACK3: 7e5e7022 core 1 in 64 bits at EL2: CurrentEL=00000008 MPIDR=80000101 HCR_EL2=2 SCTLR_EL2=0000000030c5083a SPSR_EL2=00000000060081ab SP=3f7cb3ecffcbf2b4
HIJACK3: 7e5e7022 core 1 in 64 bits at EL1: CurrentEL=00000004 MPIDR=80000101 SCTLR_EL1=0000000000c5083a DAIF=000003c0
HIJACK3: 7e5e7022 smp: after the wait: PMU core 5 CONF STATUS OPTION 0x0c DURATION0-3 8000000f 2004000f 10010101 00000000 fffff11f ffffffff ffffffff ffffffff KFC_NONCPU_OPTION=00020002 UP_SCHEDULER=00000003 boot_addr=41000000 boot_flags(index 0 to 7): 00000004 00000004 00000004 00000004 00000001 00000004 00000004 00000004
HIJACK3: 7e5e7022 smp: the watchdog was armed for 12 s (WTCNT 00005f58); the core's STATUS after the power-on 2004000f (01 milliseconds waited); then 00000000 passes and 00000000 watchdog ticks (2034 a second); the secondary's last stage 05
HIJACK3: 7e5e7022 smp: the scratch page, words 0x00 to 0x09 (the ARM32 stub: the stage, MPIDR CPSR SCTLR CPACR NSACR VBAR TTBR0, what the monitor answered): 00000005 80000101 200001d3 00c5083a 00300000 00000c00 00000000 26252480 80000101 00000000
HIJACK3: 7e5e7022 smp: the scratch page, words 0x08 to 0x1b (the AArch64 stub at EL2: MPIDR CurrentEL HCR_EL2 SCTLR_EL2 ELR_EL2 SPSR_EL2 SP CNTHCTL CNTVOFF CPTR): 80000101 00000000 00000008 00000000 00000002 00000000 30c5083a 00000000 8c9bdedc d0640bb9 060081ab 00000000 ffcbf2b4 3f7cb3ec 00000003 00000000 afdffffc f9fb1fff 000033ff 00000000
HIJACK3: 7e5e7022 smp: result: the ARM32 stub ran; in 64 bits at EL2: yes; at EL1 after the eret: yes; the SoC is reset
```

The next boot (40 of 40) skipped the image and started the 32-bit kernel.

What it shows, fact by fact:

| Fact | Where |
|---|---|
| The power-on from EL2 works: STATUS `0x10380000` then `0x2004000F`, CONFIGURATION `0x8000000F`, after one millisecond waited | the two `smp:` PMU lines |
| The core is A53 core 1: MPIDR `0x80000101`, in AArch32 and in AArch64 | the three lines of the core |
| It starts in AArch32, SVC mode, A, I and F masked, MMU and caches off, VBAR 0, CPACR with FP/NEON allowed, NSACR `0xC00`: CPSR `200001d3`, SCTLR `00c5083a` | line 1 and the scratch page |
| The monitor's call switches it: CurrentEL 8, with HCR_EL2 already 2 and SCTLR_EL2 `30c5083a` (MMU and caches off), as the boot CPU at its own entry. That 2 is bit 1, SWIO, not RW: RW, bit 31, is 0 (read as RW here until 2026-11-26; `SMP-MONITOR.md`, section 9) | line 2 |
| At EL2 the rest is not usable as it stands: CPTR_EL2 `0x33FF` (its RES1 bits: no trap, despite what this page said until 2026-11-26), CNTHCTL_EL2 3, CNTVOFF_EL2 `0xF9FB1FFFAFDFFFFC`, SP `0x3F7CB3ECFFCBF2B4`, SP_EL0 0, ELR_EL2 and SPSR_EL2 old state: the 64-bit stub sets CNTVOFF, CPTR_EL2, MDCR_EL2, CNTHCTL_EL2 and HCR_EL2 itself before its eret, as the loader's `boot_el1.S` does | line 2, the scratch page |
| It enters EL1 by the eret: CurrentEL 4, SCTLR_EL1 `00c5083a`, DAIF `0x3C0` | line 3 |
| The core had finished (stage 5) before the boot CPU's first look, less than a millisecond after STATUS turned `0xF` | the watchdog line: 0 passes |
| SP_EL0 was 0 on the boot CPU too, so the stub did not set sp_usr, and the call worked without | the SP_EL0 line |
| DURATION1 to 3 read back `0xFFFFFFFF` although all four were written `0xFFFFF11F`; DURATION0 kept it | the last PMU line |

So, for one A53 core of this tablet: powered on from EL2 by the stock sequence, started in AArch32 at
EL1 at the address of the boot register, switched to AArch64 at EL2 by `smc #0` with r0 = 0x82000400
and r3 = 1, and brought to EL1 by an eret. Not shown by it: the three other A53, the four A57, what a
kernel's secondary entry does on such a core, hot-unplug, long runs.

## 8. Step 2: the kernel's own method on the tablet

Each cycle below wrote PARAM only, came back under the 32-bit Linux by itself, and
`../loader/scripts/cycle.sh` put the original PARAM back (verified); the tablet's pstore was copied
first.

The kernel is `../kernel/smp/build-kernel/Image-boot`: the test kernel's configuration plus
`HOTPLUG_CPU` and `ARM64_EXYNOS5433_SMP` (the method of the kernel tree, branch `t715-arm64-smp`), no
cpufreq, no cpuidle, no PM. The device tree is the board's with the method on the eight CPU nodes,
plus the boot arguments of `../kernel/test-kernel/bootargs.overlay.dts` with `nosmp` replaced
(below). Nothing changes a clock or a voltage: the cores run where S-Boot left them (A53 1.2 GHz
at 1.1625 V, A57 PLL 1.2 GHz at 1.0625 V, as the kernel reads the rails).

### 8.1 `smpk2`: two CPUs, and the second one is an A57

`maxcpus=2`, marker `7e5e7023`, PARAM sha256 `74ba3e27…`. Back after 66 s. From the kernel's log (pstore):

```
EXYNOS5433: SMP: boot CPU MPIDR 0x100
EXYNOS5433: SMP: entry 0x4201d800 at sysram-ns + 0x1c, AArch64 entry 0x4201e000, PMU core options set
EXYNOS5433: CPU1: unexpected MPIDR 0x101
EXYNOS5433: CPU2: unexpected MPIDR 0x102
EXYNOS5433: CPU3: unexpected MPIDR 0x103
CPU4: Booted secondary processor 0x0000000000 [0x411fd070]
EXYNOS5433: CPU4: MPIDR 0x000, PMU core 0 powered (STATUS 0x10380000 -> 0x1004000f, 1 ms)
smp: Brought up 1 node, 2 CPUs
T715-ARM64: cpus online: 0,4
T715-ARM64: cpus present: 0,4-7
```

CPU4 is A57 core 0 (MIDR `0x411fd070`, Cortex-A57 r1p0): the first A57 to run a 64-bit kernel on this
tablet, at 1.2 GHz and S-Boot's 1.0625 V. The three other A53 were left out by a bug of the method:
`exynos5433_cpu_init()` refused any MPIDR with `mpidr >> (MPIDR_LEVEL_BITS_SHIFT * 2)` non-zero.
`MPIDR_LEVEL_BITS_SHIFT` is 3 (the log2 of the 8 bits of a level), so that shifted by 6, not 16:
`0x101 >> 6 = 4`, and every A53 but the boot CPU (Aff1 = 1) failed the check, while the A57
(Aff1 = 0) passed. `maxcpus=2` then took the first CPU that was present, CPU4. Fixed (commit d24f74a08 on
`t715-arm64-smp`, patch 0004 in `../kernel/smp/`): the check reads `MPIDR_AFFINITY_LEVEL(mpidr, 2)` and `(mpidr, 3)`; the same slip
made `exynos5433_show_core()` print a wrong MPIDR (`<< MPIDR_LEVEL_BITS_SHIFT` for
`<< MPIDR_LEVEL_BITS`), fixed too.

### 8.2 The test init's load phase

`../kernel/test-kernel/init.c` gained a load test, run only when the boot arguments carry
`t715.load=N` (N seconds, at most 60; without it the init does what it did before). Init takes the
watchdog (30 s) and feeds it during the load; one process pinned to each online CPU spins; every
second the thermal zones are logged, and the load stops early if one reaches 75 °C; at the end the
busy and idle jiffies each CPU accumulated (`/proc/stat`) are logged, which shows that each core ran
code. Then, as before, init holds the watchdog (12 s) without feeding it and restarts by software.

### 8.3 `smpk3`: the four A53

`maxcpus=4 t715.load=20`, marker `7e5e7024`, PARAM sha256 `8abcbdde…`, kernel `Image-boot`
sha256 `49d4eba5…` (5 611 536 bytes, the fix and the new init), device tree
`../loader/out/smpk3/gts28ltexx-arm64-smpk3.dtb`. Rehearsal: the eret reached, guard
0 failures. Back after 72 s.

```
CPU1: Booted secondary processor 0x0000000101 [0x410fd031]
EXYNOS5433: CPU1: MPIDR 0x101, PMU core 5 powered (STATUS 0x10380000 -> 0x1004000f, 1 ms)
CPU2: Booted secondary processor 0x0000000102 [0x410fd031]
EXYNOS5433: CPU2: MPIDR 0x102, PMU core 6 powered (STATUS 0x10380000 -> 0x1004000f, 1 ms)
CPU3: Booted secondary processor 0x0000000103 [0x410fd031]
EXYNOS5433: CPU3: MPIDR 0x103, PMU core 7 powered (STATUS 0x10380000 -> 0x1004000f, 1 ms)
smp: Brought up 1 node, 4 CPUs
T715-ARM64: cpus online: 0-3
T715-ARM64: load: 4 spinning processes, one per online CPU, for 20 s (stop at 75000 mC)
T715-ARM64: load t= 1 s: mC 42000 43000 43000        (zones: atlas0, atlas1, apollo)
T715-ARM64: load t=19 s: mC 44000 45000 45000
T715-ARM64: load: cpu0 busy 1930 idle 78 jiffies during the load      (cpu1, cpu2, cpu3: the same, ±1)
T715-ARM64: load: over; hottest zone 45000 mC
```

The four A53 (Cortex-A53 r0p1) run the 64-bit kernel and each spent 19.3 s of the 20 s busy;
the A53 cluster's zone went from 43 to 45 °C.

### 8.4 `smpk4`: the eight cores

`maxcpus=8 t715.load=30`, marker `7e5e7025`, PARAM sha256 `ac62c115…`, the same kernel as `smpk3`,
device tree `../loader/out/smpk4/gts28ltexx-arm64-smpk4.dtb`. Rehearsal: the eret reached,
guard 0 failures. Back by itself, original PARAM restored.

```
CPU1..CPU3: Booted secondary processor 0x0000000101..0x0000000103 [0x410fd031]   (PMU cores 5 to 7)
CPU4: Booted secondary processor 0x0000000000 [0x411fd070]
EXYNOS5433: CPU4: MPIDR 0x000, PMU core 0 powered (STATUS 0x10380000 -> 0x1004000f, 1 ms)
CPU5: Booted secondary processor 0x0000000001 [0x411fd070]
EXYNOS5433: CPU5: MPIDR 0x001, PMU core 1 powered (STATUS 0x10380000 -> 0x1004000f, 1 ms)
CPU6: Booted secondary processor 0x0000000002 [0x411fd070]
EXYNOS5433: CPU6: MPIDR 0x002, PMU core 2 powered (STATUS 0x10380000 -> 0x1004000f, 1 ms)
CPU7: Booted secondary processor 0x0000000003 [0x411fd070]
EXYNOS5433: CPU7: MPIDR 0x003, PMU core 3 powered (STATUS 0x10380000 -> 0x1004000f, 1 ms)
smp: Brought up 1 node, 8 CPUs
T715-ARM64: cpus online: 0-7
T715-ARM64: rail vdd_kfc: 1162500 uV ...; rail vdd_eagle: 1062500 uV ...
T715-ARM64: load: 8 spinning processes, one per online CPU, for 30 s (stop at 75000 mC)
T715-ARM64: load t= 1 s: mC 61000 65000 54000        (zones: atlas0, atlas1, apollo)
T715-ARM64: load t= 5 s: mC 67000 71000 59000
T715-ARM64: load t=10 s: mC 69000 74000 62000
T715-ARM64: load t=13 s: mC 70000 75000 63000
T715-ARM64: load: a zone reached 75000 mC: the load stops at 13 s
T715-ARM64: load: cpu0..cpu7 busy 1304-1305 idle 0 jiffies during the load
```

**All eight cores run the 64-bit kernel**: the four A53 (r0p1) and the four A57 (r1p0), started by
the method with the stock PMU sequence, each one 100 % busy for the 13 s of the load. No cluster or
L2 write was needed for the A57 (§6.5 of `SMP-DESIGN.md` feared one).

**What it says about heat**, plainly: with the four A57 busy at 1.2 GHz and S-Boot's 1.0625 V, the A57
zone `atlas1` read 65 °C after one second and climbed about 0.8 °C a second; the load's own limit
(75 °C) stopped it at 13 s. Nothing in this kernel can slow a core down (no cpufreq, no cooling
device), so a long full load of the A57 at 1.2 GHz would keep heating until the TMU's hardware trip.
The 32-bit daily system keeps the A57 offline (`/sys/devices/system/cpu/online` = 0-3 on it). For the
daily arm64 system: no sustained A57 load before a cooling path works (cpufreq with the board's own
tables and the cooling maps, or at least taking the A57 offline on a trip), as the owner's
`CPUFREQ.md` asks. The A53 cluster alone stayed at 45 °C over 20 s (`smpk3`).

The answer, cpufreq and the cooling maps on the arm64 kernel, is `CPUFREQ-THERMAL.md`
(`cpuf1`, `cpuf3`: the clusters step down under load and the temperature levels off).

Not shown: hot-unplug and re-plug, a kernel with PM domains and cpuidle, suspend, long runs.
The temperature line printed before the load is empty in these two cycles (a line written in five
pieces to `/dev/kmsg`, each its own record); fixed in `init.c` for the next build.

## State on 2026-11-26

**Proven on the tablet.** On 2026-11-24: the switch works on a secondary core (`smp2`, §7.2);
the kernel's own method starts an A57 (`smpk2`), the four A53 (`smpk3`) and all eight cores, each
busy under load (`smpk4`). Since 2026-11-24 the tablet boots the arm64 system by itself at every
boot, and a soak of several hours on 2026-11-25 ran twelve phases of 3 min with eight busy cores,
without a reboot (`ROADMAP.md`). With cpufreq and the cooling maps, the clusters step down under
load (`CPUFREQ-THERMAL.md`).

**Built or rehearsed only.** Nothing: every image this document describes ran on the tablet,
`smp1` included.

**Open.** A kernel with PM domains and cpuidle (§8.4). Hot-unplug and re-plug, and suspend, work
since 2026-11-26 (patch 0010; `FINDINGS.md`, section 23); the monitor's static reading, begun on
2026-11-24, was finished that day (`SMP-MONITOR.md`).
