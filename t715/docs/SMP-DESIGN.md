# Bringing up the eight cores in 64 bits: the design (SM-T715, Exynos 5433)

Written 2026-11-24 for step 2 of the port, after the re-scoping of that day: step 1 (one core,
without Linux, from the loader's EL2 stage) is in `../loader/`; `SMP-EXPERIMENT.md` covers it.
This document is the kernel that follows: all eight cores, through an enable-method of Linux
6.12.114.

The method is written and compiles (three commits on `t715-arm64-smp` of the kernel tree, exported
as patches in `../kernel/smp/`). It had not run on a device when this was written. The state is at
the end.

Paths: `platsmp.c`, `firmware.c`, `headsmp.S` are files of the kernel tree of omarchy-tab-s2
(commit 1595b1660, the base of the clone), under
`arch/arm/mach-exynos/`. `smp.c`, `head.S`, `cpu_ops.c`, `smp_spin_table.c`, `vmlinux.lds.S` are
files of that tree under `arch/arm64/kernel/`. `SMP_BRINGUP.md` is the owner's
`omarchy-tab-s2/docs/hardware/SMP_BRINGUP.md`. "The loader" is `../loader/`. Line numbers of files
the patch does not touch are those of the release tree; for the files it adds, see the patch
itself.

`../kernel/smp/`, `../kernel/test-kernel/` and the logs under `../loader/out/` are in the fork
([elkir0/bnuuyloader](https://github.com/elkir0/bnuuyloader)), not in this tree.

## 0. Summary

The firmware gives a kernel no PSCI. The PMU powers a core on and the monitor releases it in
**AArch32** at the address the kernel leaves in one register of sysram-ns (+0x1c, one for all
cores). That is how the vendor kernel and the owner's 32-bit kernel start their cores. A 64-bit
kernel cannot run that way, so the entry it puts there is a twelve-word AArch32 stub (eleven
instructions and a constant) whose only job is the monitor call the loader makes for the boot
CPU, `SMC 0x82000400`, which switches the core to AArch64 at EL2 with the MMU and the caches
off. From there:

```
 AArch32, from the monitor              AArch64, EL2, from the monitor      AArch64, EL1
 exynos5433_smp_entry                   exynos5433_smp_entry_el2           exynos5433_smp_pen
   mask interrupts           SMC           mask interrupts        eret         wait for this CPU's
   SMC 0x82000400  -------------------->  EL2 as the loader     ------>       MPIDR in the pen
   (entry 2 KiB away, 0x800, 1)           leaves the boot CPU                  |
                                         SCTLR_EL1: MMU off                   v
                                                                          secondary_entry (kernel)
```

The CPU side (PMU, boot register, release with `dsb; sev`) is the 32-bit kernel's sequence,
register for register. One file of assembly, one of C, a line in the enable-method table, a
Kconfig option, a dtsi.

What is not known and only the device can tell, in the order in which it could stop the first
boot: does the monitor's call work on a secondary (step 1); is a secondary in the
kernel's coherency domain; does the A57 cluster come up without an explicit cluster power-up;
does a secondary arrive with an empty data cache. Sections 3 and 12 say what the design does
about each.

## 1. The facts everything rests on

| Fact | Source | Weight |
|---|---|---|
| S-Boot runs ARM32 at EL1, MMU and caches on | the design decided on 2026-11-24, §6 | measured |
| ARM32 code at NS EL1 doing `r0 = 0x82000400, r1 = entry, r2 = 0x800, r3 = 1; smc #0` lands at `entry` in AArch64 at EL2, MMU and caches off, `HCR_EL2 = 2` | `../loader/scripts/split_source.py:263-267`; the design decided on 2026-11-24, §3, §6 | measured, three times, on the boot CPU only |
| A secondary powered on by the PMU executes AArch32 code at the address in sysram-ns + 0x1c | the 32-bit kernel does exactly that on this board: `firmware.c:82-101`, `platsmp.c:581-603`; board dts `:11-14` ("8 cores (SMP)") | by the 32-bit kernel running |
| PMU state as S-Boot leaves it (below, §6) | the 32-bit kernel's journal, 2026-11-24 | measured |

The second fact is the one that is being extended: it was measured on the boot CPU, and whether
the monitor's handler does the same for a core it has just released is unknown (§3).

## 2. What is known

### 2.1 About the monitor and the release of a core

- **One boot register for all the cores**: sysram-ns + 0x1c (`firmware.c:89`); sysram-ns is
  4 KiB at 0x0207B000 (board dts `:272-275` as `samsung,secure-firmware`, `:340-343` as
  `samsung,exynos4210-sysram-ns`). The 32-bit kernel writes one address there for every core.
- **A core is released with `dsb; sev`, no SMC, no IPI**: `platsmp.c:671-688`; the vendor kernel
  uses neither `SMC_CMD_CPU1BOOT` nor a wake-up IPI on this SoC (SMP_BRINGUP.md §2.3 step 4).
- **The monitor takes SMCs from secondary cores in AArch32**: the stock kernel's idle and
  hot-unplug paths call it from every core (`exynos_smc()`, `exynos-smc.S:15-20`; the 32-bit
  kernel's `exynos5433_cpu_die()`, `platsmp.c:835-875`). Whether the monitor takes *this* call
  (`0x82000400`) from a secondary is not known.
- **Meaning of `0x800` and `1`**: unknown. The loader passes them and so does bnuuyloader for the
  Note 4 (`src/a32_entry.S:23-31`, "the arguments used by the working handoff"); we pass them
  unchanged.
- **bnuuyloader's README** says of the Note 4 (the same SoC): "you will have to use legacy SMC
  calls to bring up the other cores, which means they will startup in ARM32 and you'll have to
  switch them to ARM64. This is very hacky, but it works" (`README.md:21`). Its repository holds
  no code for it, so this is a pointer, not a proof; and on the Note 4 that README says S-Boot
  runs at EL2 (`README.md:18`), where EL1 was measured here.
- **What the monitor's release stub does** (whether it waits in WFE for an event) is unknown
  (SMP_BRINGUP.md §7, OQ-6). The `dsb; sev` is what works.
- **The monitor itself** is being read in `SMP-MONITOR.md` (a first version in progress).
  Its finding so far, with high confidence from three agreeing constants: the monitor is AArch64
  code at EL3, loaded at 0x02024000 in iRAM, and carries a `tbase_cpu_on_finish_handler` among
  its strings. What the handler of `0x82000400` does, and whether it does it on a core other than
  the boot CPU, was not written there yet: U1 below was still open.

### 2.2 In which state a secondary starts

Established, by the 32-bit kernel running on this board: **AArch32, ARM state, in a privileged
mode, MMU off**. The evidence is that `exynos4_secondary_startup` (`headsmp.S:18-35`) is ARM-state
code that reads MPIDR, and that `secondary_startup` (`arch/arm/kernel/head.S:388`) then masks
interrupts and sets up page tables of its own before it turns the MMU on, as a core with its
MMU already on would not let it.

That the mode is **EL1** (SVC) and not EL2 in AArch32 (HYP) is at this point only stated, and
what S-Boot itself runs at on this board (the design decided on 2026-11-24, §6) makes it the only
one to expect; we found no line in our sources that tells the two apart (the owner's document
allows both in its expected output: SMP_BRINGUP.md §8.3). The stubs work from either, and step
1's `CPSR` settles it: mode bits 0x13 are SVC.

Not established: the SCTLR bits at entry (data cache, instruction cache), the security state
read from the core itself, and whether a core that the bootloader left powered arrives the same
way. Step 1 logs them. The stubs do not depend on the answer: they write what they
need (§4) and touch no data of their own.

### 2.3 What the arm64 kernel provides (Linux 6.12.114)

- **No `CPU_METHOD_OF_DECLARE` on arm64.** The enable-method is matched by name in a static
  table, `dt_supported_cpu_ops[]` (`cpu_ops.c:25-29`), through `cpu_get_ops()` (`:39-53`). A
  new method needs an `extern` and a table entry there.
- **The callbacks** (`struct cpu_operations`, `arch/arm64/include/asm/cpu_ops.h:35-47`):
  `cpu_init`, `cpu_prepare`, `cpu_boot`, `cpu_postboot`, and with `CONFIG_HOTPLUG_CPU`
  `cpu_can_disable`, `cpu_disable`, `cpu_die`, `cpu_kill`.
- **When they run**: `cpu_init` for each CPU of the tree from `smp_init_cpus()` (`smp.c:762-767`),
  during `setup_arch()`; `cpu_prepare` for each secondary from `smp_prepare_cpus()`
  (`smp.c:796-811`), which returns at once with `nosmp` (`:788-789`); `cpu_boot` from
  `__cpu_up()` (`smp.c:119-182`), after it has set `secondary_data.task` (`:128`);
  `cpu_postboot` on the new CPU, before it is online (`smp.c:236-238`).
- **`smp_prepare_cpus()` is called before any driver is probed** (`init/main.c:1533`, against
  `do_basic_setup()` at `init/main.c:1551`): no syscon yet for the PMU, the method maps it itself.
- **A section for data read with the MMU off**: `.mmuoff.data.read`, set apart by 2 KiB so that
  the cache maintenance of one does not touch its neighbours (`vmlinux.lds.S:298-314`). The
  spin-table's pen lives there (`smp_spin_table.c:22-23`) and its writer cleans it to the point
  of coherency (`smp_spin_table.c:33-40`).
- **`SYM_FUNC_START` puts a `bti c` first, always** (`arch/arm64/include/asm/linkage.h:18-20`).
  A NOP for AArch64; a floating-point instruction for a core in AArch32. It was in our first
  build, at the AArch32 entry, and only the inspection of the linked image showed it. The
  entries use `SYM_START`.
- **A method without `cpu_die` cannot be unplugged**: `op_cpu_disable()` answers `-EOPNOTSUPP`
  (`smp.c:291-292`), and `cpu_die()` would call a null pointer (`:391`).

## 3. What is unknown, and what the design does about it

| # | Unknown | If it goes against us | What the design does |
|---|---|---|---|
| U1 | Does `SMC 0x82000400` switch a *secondary*? | The stub returns in AArch32 or the core is lost; no secondary ever runs | The stub parks on return (`wfe` loop); the boot CPU gives up after its bounded wait (§10). Answered by step 1. |
| U2 | SCTLR state at entry (D-cache, I-cache on?) | None expected | The EL2 stub masks DAIF first, sets `SCTLR_EL1 = INIT_SCTLR_EL1_MMU_OFF`, `ic iallu`. Logged by step 1. |
| U3 | Must the AArch64 entry be aligned? | The monitor could refuse an unaligned entry | Unknown; the entry is put on a 2 KiB boundary like the one proven for the boot CPU (`build_ffree.py:51`, `:132`: 0x24220800), so that the question stays out of the way |
| U4 | Is a secondary in the kernel's coherency domain? (`booting.rst:197-202` requires it of every CPU) | The secondary reads stale lines once its caches are on: crash or corruption | Nothing in the kernel: the 32-bit kernel leaves it to the monitor too (SMP_BRINGUP.md §7, OQ-7). First sign: CPU1 "failed to come online" or an oops on CPU1 right after "Booted secondary processor" |
| U5 | Does the A57 cluster come up from the core's power-up alone? | CPU4 never powers, or hangs | §6.5. The kernel logs the cluster blocks before anything is written and after a failure |
| U6 | Is a secondary's L1 data cache empty when it arrives? | Stale lines for addresses the kernel now uses | Nothing in the first patch (§12, R4): the 32-bit kernel invalidates it on every core, arm64 does not |
| U7 | Meaning of the boot flags, of `UP_SCHEDULER`, of `OPTION` bit 28 | None as long as the registers are written as the 32-bit kernel writes them | Written exactly so; nothing more |

## 4. The chain, stage by stage

All of it is in `arch/arm64/kernel/smp_exynos5433_head.S`. Everything there runs with the MMU
and the caches off at its **physical** address: position independent, no stack, no absolute
address, nothing written.

### 4.1 `exynos5433_smp_entry`: AArch32, the address that goes into sysram-ns + 0x1c

```
	cpsid	aif			// nothing may interrupt this
	ldr	r1, 3f			// 2048 - 16: the AArch64 entry is 2 KiB after this one
	add	r1, r1, pc
	movw	r0, #0x400
	movt	r0, #0x8200		// 0x82000400: enter AArch64 at EL2
	mov	r2, #0x800
	mov	r3, #1
	dsb	sy
	smc	#0
1:	wfe				// the monitor came back: this core is not switched
	b	1b
3:	.word	exynos5433_smp_entry_el2 - exynos5433_smp_entry - 16
```

- **Why words**: no AArch32 assembler builds an arm64 kernel, so the source is in a comment and
  the twelve words follow, as `clang --target=arm-none-eabi -mcpu=cortex-a53` emits them, with no
  relocation. `../kernel/smp/build-kernel.sh` compares the words in the linked image with that list after
  every build.
- **Why the entry address is PC-relative**: the kernel is relocatable (`CONFIG_RANDOMIZE_BASE`
  off in the test kernel's configuration, on in general), so an absolute literal would be wrong.
  The two entries are exactly 2 KiB apart, which makes the distance a constant; an `.if` in the
  file stops the build if the stub outgrows its 2 KiB.
- **Why 32-bit is enough**: the monitor takes a 32-bit address in `r1` and a 32-bit one in its
  boot register. `cpu_prepare` refuses to start anything if either entry is above 4 GiB. All the
  board's memory is (the design decided on 2026-11-24, §6: 0x40000000 to 0xBEA00000).
- **Why in the kernel image and not in sysram-ns**: the 32-bit kernel points the boot register at
  its own code in DRAM (`platsmp.c:533`), and that is proven; code *inside* sysram-ns is not, and
  the rest of that page belongs to the monitor (flags at +0x28, resume and idle addresses at
  +0x08 to +0x24; SMP_BRINGUP.md §1.3). The kernel image is in memory before any core is
  started, like `secondary_entry` itself, and nothing writes to it.
- **On return**: a core that comes back in AArch32 spins there with interrupts masked, touching
  nothing. The boot CPU's wait expires by itself (§10).

### 4.2 `exynos5433_smp_entry_el2`: AArch64 at EL2, where the monitor lands the core

```
	msr	daifset, #0xf
	mov_q	x0, HCR_RW			// bit 31: EL1 executes AArch64
	msr	hcr_el2, x0
	mrs	x0, cnthctl_el2
	orr	x0, x0, #3			// EL1PCTEN, EL1PCEN
	msr	cnthctl_el2, x0
	msr	cntvoff_el2, xzr
	msr	cptr_el2, xzr			// no trap on FP/SIMD
	msr	mdcr_el2, xzr			// no trap on debug
	mov_q	x0, INIT_SCTLR_EL1_MMU_OFF	// MMU, data cache, instruction cache off
	msr	sctlr_el1, x0
	ic	iallu
	dsb	sy
	isb
	adr_l	x0, exynos5433_smp_pen		// its physical address: the MMU is off
	msr	elr_el2, x0
	mov_q	x0, INIT_PSTATE_EL1		// 0x3c5: EL1h, every exception masked
	msr	spsr_el2, x0
	eret
```

- **The same EL2 as the boot CPU.** The loader's `../loader/stage2/boot_el1.S:43-67` does exactly this
  before it erets the boot CPU into the kernel: `HCR_EL2 = 0x80000000`, `CNTHCTL_EL2 |= 3`,
  `CNTVOFF_EL2 = 0`, `CPTR_EL2 = 0`, `MDCR_EL2 = 0`, `SCTLR_EL1` without M, C, I, `ic iallu`,
  `SPSR = 0x3c5`. The kernel then runs at EL1 on the boot CPU, so it must on the others
  (`hyp_mode_check()`, `smp.c:431-444`: "All CPU(s) started at EL1"; a mix gives
  "CPUs started in inconsistent modes" and `TAINT_CPU_OUT_OF_SPEC`).
- **Why not simply jump to `secondary_entry` from EL2**: `secondary_entry` does accept EL2
  (`init_kernel_el`, `head.S:267-328`) and would record "started at EL2" for that CPU against
  "EL1" for the boot CPU. If the loader ever hands the kernel over at EL2 instead, the eret
  goes out of this stub and all the CPUs take `secondary_entry` at EL2: one line to remove.
- **DAIF first**: the kernel has no vector table for this core yet (`VBAR_EL2 = 0` when the
  monitor lands the boot CPU: `../loader/scripts/a64_sreset.S:3-5`), and the boot protocol wants every
  exception masked (`Documentation/arch/arm64/booting.rst:169-170`).
- **What is not set, on purpose**: `SCTLR_EL2`, `VBAR_EL2`, `HCR_EL2`'s trap bits. The loader
  sets none of them for the boot CPU either. The kernel's own `HCR_HOST_NVHE_FLAGS`
  (`kvm_arm.h:101`) is RW plus three bits of later revisions of the architecture (API, APK,
  ATA), which it gives itself when it is entered at EL2; set on the secondaries alone, they
  would make the cores differ.
- **`ic iallu`**: as the loader does before its eret (`boot_el1.S:56`). The kernel does it again
  when it turns the MMU on (`set_sctlr`, `assembler.h:727-738`, from `__enable_mmu`,
  `head.S:467`), because alternatives have patched the text since.

### 4.3 `exynos5433_smp_pen`: AArch64 at EL1, the holding pen

```
	mrs	x1, mpidr_el1
	mov_q	x2, MPIDR_HWID_BITMASK		// 0xff00ffffff
	and	x1, x1, x2
	adr_l	x3, exynos5433_smp_pen_release
1:	ldr	x4, [x3]
	cmp	x4, x1
	b.eq	2f
	wfe
	b	1b
2:	b	secondary_entry
```

- **Why a pen at all**: the monitor has one boot register for eight cores, and an event releases
  whatever is waiting. The kernel gives `secondary_data` to one CPU at a time (`smp.c:128`), and
  `__secondary_switched` runs on it blindly (`head.S:391-401`). A core that an event meant for
  another one releases must not go on. So the pen holds the MPIDR of the CPU being started, and
  only while `__cpu_up()` has set its `secondary_data`; a core with another MPIDR waits, and goes
  on only when it is its turn.
- **Keyed on the full MPIDR**, where the 32-bit kernel's pen keeps MPIDR[3:0] only
  (`headsmp.S:21`) and needs its "twin" guard (`platsmp.c:547-571`) because of it: an A53 and an
  A57 with the same Aff0 do not collide here.
- **Where the pen is**: `exynos5433_smp_pen_release`, in `.mmuoff.data.read`. Its writer cleans
  it to the point of coherency (`write_pen_release()`, as `smp_spin_table.c:33-40`), because a
  core waiting in the pen reads the memory itself. Only the boot CPU writes it.
- **The kernel's own `secondary_holding_pen`** (`head.S:334-346`) is the same loop. It is not
  used because it calls `init_kernel_el` itself, which takes EL2 as it finds it (previous point).

## 5. Kernel integration

| File | What |
|---|---|
| `arch/arm64/kernel/smp_exynos5433_head.S` | the three entries and the pen loop (§4) |
| `arch/arm64/kernel/smp_exynos5433.c` | the PMU sequence, the boot register, the pen, the logs; `exynos5433_smp_ops` |
| `arch/arm64/kernel/cpu_ops.c` | `extern const struct cpu_operations exynos5433_smp_ops;` and its line in `dt_supported_cpu_ops[]`, under `#ifdef CONFIG_ARM64_EXYNOS5433_SMP` |
| `arch/arm64/kernel/Makefile` | `obj-$(CONFIG_ARM64_EXYNOS5433_SMP) += smp_exynos5433.o smp_exynos5433_head.o` |
| `arch/arm64/Kconfig` | `ARM64_EXYNOS5433_SMP`, `depends on ARCH_EXYNOS`, default n, in "Boot options" next to the ACPI parking protocol |
| `arch/arm64/boot/dts/exynos/exynos5433-gts28ltexx.dts` | the board for a 64-bit kernel: the 32-bit board file, plus the dtsi below |
| `arch/arm64/boot/dts/exynos/exynos5433-gts28ltexx-smp.dtsi` | `enable-method = "samsung,exynos5433-el2"` on the eight CPU nodes |
| `Documentation/devicetree/bindings/arm/cpu-enable-method/samsung,exynos5433-el2`, `.../arm/cpus.yaml` | the binding |

It lives in `arch/arm64/kernel/` and not in `drivers/soc/samsung/` because the pen branches to
`secondary_entry` and the method is an entry of an arch-private table; the other three methods
(`smp_spin_table.c`, `psci.c`, `acpi_parking_protocol.c`) are there too.

**The enable-method name**, `samsung,exynos5433-el2`: the SoC, and the level the monitor hands
the core over at. It describes the firmware's interface, which does not change if §4.2's eret
ever goes.

**The callbacks**

```c
const struct cpu_operations exynos5433_smp_ops = {
	.name		= "samsung,exynos5433-el2",
	.cpu_init	= exynos5433_cpu_init,		/* MPIDR of this SoC's shape, or the CPU is left out */
	.cpu_prepare	= exynos5433_cpu_prepare,	/* once: map, record, entry point, PMU */
	.cpu_boot	= exynos5433_cpu_boot,		/* one core: pen, power, release, wait */
	.cpu_postboot	= exynos5433_cpu_postboot,	/* on the new CPU: the signal cpu_boot waits for */
};
```

- `cpu_prepare`: the 32-bit kernel's `exynos5433_smp_prepare_cpus()` (`platsmp.c:502-545`).
  It maps the PMU and sysram-ns with `of_iomap()`, logs what the firmware left ("before SMP
  setup", §6.6), refuses if an entry is above 4 GiB, writes the entry point into the boot
  register, and prepares the PMU (§6.2). A failure is logged once and every secondary then stays
  out: `smp_prepare_cpus()` drops a CPU whose `cpu_prepare` fails without a word (`smp.c:805-807`).
- `cpu_boot` (`exynos5433_cpu_boot()`), under a mutex, one core at a time:
  1. entry point into the boot register;
  2. pen := this CPU's MPIDR (cleaned to memory);
  3. if `STATUS & 0xf != 0xf`: power the core up (§6.3), then poll up to 10 times `mdelay(1)`;
  4. release loop, at most 100000 times: entry point again, `dsb sy; sev`, until `cpu_postboot`
     has run on the new CPU, `udelay(10)` between tries (about a second, the 32-bit kernel's
     limit);
  5. drop the core's HOTPLUG boot flag, pen := "nobody", return 0. `__cpu_up()` then waits up to
     5 s for the CPU to be online (`smp.c:143-144`).
  On any failure at 3 or 4: pen := "nobody", no other core is started, the PMU registers of the
     failed core are logged (§10).
- The loops count their tries rather than the clock: they end even if the timer tick stands
  still. On this kernel `udelay()` is a calibrated loop (the MCT patch), so "about a
  second".

## 6. The PMU sequence

PMU at 0x105C0000 (`exynos5433.dtsi:915-917`, node `samsung,exynos5433-pmu`, 0x5008 bytes).
Core block *n*: CONFIGURATION at 0x2000 + 0x80·n, STATUS +0x4, OPTION +0x8
(`include/linux/soc/samsung/exynos-regs-pmu.h:134-140`), DURATION0 to 3 at +0x10 to +0x1c
(`platsmp.c:55-57`). The index is *core + 4 × cluster* (`platsmp.c:89-93`), so the four A57 are
0 to 3 and the four A53 are 4 to 7. Every value below is `platsmp.c`'s, which cites the vendor
files; the vendor tree itself is not on the machine where this was written, we could not read
it.

### 6.1 As S-Boot leaves it (measured on 2026-11-24)

| PMU core | CPU | CONFIGURATION | STATUS | OPTION | DURATION0-3 | boot flag |
|---|---|---|---|---|---|---|
| 4 | 0, MPIDR 0x100, the boot CPU | 0x8000000F | 0x0004000F | 0x01010101 | not given | 0x00000001 |
| 5 | 1, MPIDR 0x101 | 0x80000000 | 0x10380000 | 0x10010103 | 0xFFFFFFFF | 0x00000004 |
| 6, 7 | 2 and 3, MPIDR 0x102 and 0x103 | not given | not given | not given | not given | 0x00000004 |
| 0 to 3 | 4 to 7, MPIDR 0x000 to 0x003 | not given | not given | not given | not given | 0x00000004 |

`UP_SCHEDULER` (0x0120) reads 0. Powering core 5 up gives `STATUS` 0x2004000F in 1 ms.
A core is "powered" when `STATUS & 0xf == 0xf` (`platsmp.c:390-395`).

Two things to read in that table. The low nibble is what the code tests: 0xF on, 0 off.
Every core but the boot CPU carries the HOTPLUG flag (bit 2) and the boot CPU the RESET flag
(bit 0) (SMP_BRINGUP.md §1.3): the vendor kernel and the 32-bit kernel drop the HOTPLUG flag
once a core is up (`platsmp.c:323-331`), and this method does the same.

### 6.2 Before any core is started: `exynos5433_pmu_cpu_init()` (`platsmp.c:455-500`)

The CPU part of the vendor's `exynos5433_pmu_init()`, in its order. These are the writes the
32-bit kernel makes on every boot of this board.

| Order | Register | Write | 32-bit kernel |
|---|---|---|---|
| 1 | EAGLE (A57) NONCPU OPTION, 0x2408; KFC (A53) NONCPU OPTION, 0x2428 | `&= ~bit 0` (`USE_SC_COUNTER`), `\|= bit 1` (`USE_SC_FEEDBACK`) | `:472-480` |
| 2 | OPTION of the eight cores | `\|= bit 0 \| bit 1 \| bit 28` (`USE_SMPEN`) | `:482-487` |
| 3 | DURATION0 of the eight cores | `\|= 0xF << 20`, `&= ~(0xF << 4)`, `\|= 0x1 << 4` | `:489-495` |
| 4 | UP_SCHEDULER, 0x0120 | `\|= bit 0 \| bit 1` (ENABLE_EAGLE_CPU, ENABLE_KFC_CPU) | `:497-499` |

On the measured cores: the A53's OPTION (0x10010103) already has those three bits, so line 2
changes the boot CPU's (0x01010101 to 0x11010103) and whatever the A57's are; DURATION0 goes
from 0xFFFFFFFF to 0xFFFFFF1F; UP_SCHEDULER from 0 to 3.

### 6.3 Powering one core up: `exynos5433_core_power_up()` (`platsmp.c:581-603`)

The vendor's `exynos5433_cpu_up()` with the block its defconfig enables. For PMU core *n*:

| Order | Register | Write |
|---|---|---|
| 1 | OPTION (0x2008 + 0x80·n) | `&= ~bit 1` |
| 2 | DURATION0 to 3 (0x2010 to 0x201c + 0x80·n) | bits [11:4] := 0x11 |
| 3 | | `wmb()`: the pen and the entry point are on their way to memory |
| 4 | CONFIGURATION (0x2000 + 0x80·n) | `\|= 0xF` |

Then `STATUS & 0xf == 0xf` within 10 ms. Measured on core 5: 1 ms, and `STATUS` 0x2004000F.
By the writes, on that core, the registers then read CONFIGURATION 0x8000000F (the boot CPU's
value), OPTION 0x10010101, DURATION0 to 3 0xFFFFF11F: computed, not read back.

### 6.4 Releasing it

The entry point is written again, then `dsb sy; sev()`, up to the limit of §5. No SMC
(`SMC_CMD_CPU1BOOT`), no IPI: `platsmp.c:671-688`.

### 6.5 The A57 cluster (CPU 4 to 7, PMU cores 0 to 3)

**What the sequence does for it**: lines 1 and 2 of §6.2 write the A57 cluster's NONCPU OPTION,
the four A57 OPTIONs and DURATION0s, and ENABLE_EAGLE_CPU; then each A57 goes through §6.3 like
an A53. That is all the vendor kernel and the 32-bit kernel do, and the 32-bit kernel runs the
four A57 this way (board dts `:11-14`). **There is no explicit cluster or L2 power-up in either**:
the vendor's `exynos5433_l2_up()` (0x7 << 8 | 0x7 into L2 CONFIGURATION, then a busy-wait on L2
STATUS) has no caller on this SoC (SMP_BRINGUP.md §2.4 and §7, OQ-3). By what mechanism the
cluster's power and its L2 follow the first core is not known; the owner's document supposes the
PMU sequencer armed by UP_SCHEDULER.

So the first patch does not write a cluster register that the 32-bit kernel does not write. The
kernel brings CPU 4 up right after CPU 3 (the generic code goes through the CPU numbers in
order), which is where a cluster problem would show, as "CPU4: core power-up timed out" or a
hang after "PMU core 0 powered".

**Unknown, and what would settle it**: the values as S-Boot leaves them for PMU cores 0 to 3 and
for the EAGLE NONCPU, L2 and CPUSEQ blocks. The measured figures cover the A53; the 32-bit kernel
logs the others as "before SMP setup: EAGLE NONCPU .../.../... L2 ... CPUSEQ ..." and "CPU4:
MPIDR 0x000, PMU core 0 powered (STATUS ... -> ..., N ms)" (`platsmp.c:420-438`, `:667-669`), and
this kernel prints the same lines at its first boot.

If CPU 4 fails, in that order: (1) read those two lines and the "failed" one; (2) port what the
32-bit kernel left out of the vendor's `exynos5433_pmu_init()`: the L2 OPTION writes (the
vendor's `pmu-exynos5433.c:480-498`, as SMP_BRINGUP.md §1.5 lists them: clear
`USE_AUTOMATIC_L2FLUSHREQ`, the retention and standby options); (3) the vendor's
`exynos5433_l2_up()` (`pmu-exynos5433.c:228-240`). Each needs the vendor header for the meaning
of the bits, and each is a write no kernel of this board has made yet.

### 6.6 What the kernel logs

"EXYNOS5433: before SMP setup: ..." is the 32-bit kernel's dump (`platsmp.c:412-453`): the eight
core blocks, both clusters' NONCPU, L2 and CPUSEQ, UP_SCHEDULER, the boot address and the eight
boot flags. Read only, and before any write. The owner's document asks for that record at every
first boot (SMP_BRINGUP.md §8.3); it is what tells U5 and U7 apart.

## 7. Device tree

What the method needs, all of it already in the 32-bit board file:

| Node | Property | Used for |
|---|---|---|
| `pmu_system_controller`, `system-controller@105c0000` | `compatible = "samsung,exynos5433-pmu"` (`exynos5433.dtsi:915-917`) | the PMU, mapped by `of_iomap()` |
| `smp-sram@207b000` under `soc@0` | `compatible = "samsung,exynos4210-sysram-ns"`, `reg = <0x0207b000 0x1000>` (board dts `:340-343`) | the monitor's boot register at +0x1c and the boot flags at +0x28 |
| the eight `cpu@...` nodes | `enable-method = "samsung,exynos5433-el2"` | selects the method |

- **No `cpu-release-addr`**: that is the spin-table's, one address per CPU in the tree. Here
  there is one monitor register and the kernel's own pen.
- **No new node, no new address.** The dtsi only puts the enable-method back on the eight nodes
  the board file took it from (board dts `:294-325`). The `psci` node stays deleted
  (`:261-262`).
- **One board file for both kernels**: `arch/arm64/boot/dts/exynos/exynos5433-gts28ltexx.dts`
  includes the 32-bit board file and the dtsi. The same pattern as
  `socionext/uniphier-pxs3-ref-gadget1.dts:8-9`. The boot-arguments overlay still applies on
  top of its dtb.
- The 32-bit `-smp.dts` first mentioned no longer exists in the release tree: its content is
  in the board file.

## 8. What `secondary_entry()` needs on entry

From `head.S:352-376` and `booting.rst`:

| | Requirement | The stub gives |
|---|---|---|
| State | AArch64, at EL1 or at EL2 (`init_kernel_el` takes both, `head.S:267-328`); EL1 here (§4.2) | EL1h by the eret |
| Address | At its **physical** address: `secondary_startup` turns the MMU on with the identity map in TTBR0 (`head.S:371-373`) | `adr_l` in the pen, with the MMU still off |
| MMU, caches | MMU off (`booting.rst:176`); instruction cache either, without stale lines for the kernel image (`:178-179`) | `SCTLR_EL1 = INIT_SCTLR_EL1_MMU_OFF` (`sysreg.h:889-891`): MMU, data cache and instruction cache off; `ic iallu` |
| Exceptions | every one masked (`booting.rst:169-170`) | `daifset #0xf`, then `SPSR = INIT_PSTATE_EL1` = 0x3c5 (`ptrace.h:19-20`) |
| EL2 | `HCR_EL2.RW = 1` or the eret to EL1 is illegal; `CNTHCTL_EL2.EL1PCTEN` (`booting.rst:192-195`); `CPTR_EL2.TFP = 0` (`booting.rst:306-308`) | set (§4.2) |
| `x0` | **nothing**: `secondary_entry` does `mov x0, xzr` and sets it itself (`head.S:353`) | holds the pen's address, ignored |
| `x1` to `x30`, `sp` | nothing | ignored; the kernel takes its stack from `secondary_data` once the MMU is on (`head.S:391-395`) |
| Memory | `secondary_data` set for this CPU by `__cpu_up()` before `cpu_boot` (`smp.c:128`); the kernel's page tables and text in memory | `cpu_boot` runs after that; the pen keeps every other core out until then |

Then the kernel does the rest itself: `__cpu_setup`, MMU on, `secondary_start_kernel()`.

## 9. Memory visibility

| What | Who reads it with the MMU off | What makes it visible |
|---|---|---|
| the boot address (sysram-ns + 0x1c) | the monitor | a device mapping: the write reaches the SRAM at once |
| the entry stubs, `secondary_entry`, the kernel's text | the new core | nothing to do: part of the loaded image, never written by the kernel. The instructions the kernel patches at boot (alternatives) are written through the linear map and cleaned and invalidated to the point of coherency by the kernel (`alternative.c:166`, `:177-178`) |
| the pen | a core waiting in the pen | `dcache_clean_inval_poc()` by the writer, in `.mmuoff.data.read` |
| `secondary_data`, the page tables | the new core, after its MMU and caches are on | coherency: see U4 |

Nothing else is cleaned for the arriving core, and nothing is invalidated: no `dc isw`, no
`tlbi`. See R4.

## 10. When a core does not come up

A single state, written under the mutex: new, ready, failed.

| Failure | Where it is seen | What happens |
|---|---|---|
| the tree lacks the PMU or the sysram-ns node; an entry above 4 GiB | `cpu_prepare` | one error line, every secondary stays out, the kernel runs with one CPU |
| `STATUS` never reaches 0xF | after 10 ms | "CPU%u: core power-up timed out", "failed" dump, state failed, `-ETIMEDOUT` |
| the core never runs `cpu_postboot` | after about 1 s | "CPU%u: did not reach the kernel within ... tries", "failed" dump, state failed, `-ETIMEDOUT` |
| a later CPU | at once | "CPU%u: not started: no secondary CPU is started after a failure", `-EIO` |
| the core is in the kernel but not online 5 s later | `__cpu_up()` | the kernel's own "CPU%u: failed to come online" and its decoding (`smp.c:148-181`) |

In the first three cases the pen is left at "nobody": a core that the monitor releases later
waits there and never reaches `secondary_data`. The failed core stays powered, idle in `wfe` or
in the monitor; nothing turns it off (§11). Worst case for the boot: about 1.1 s, then the rest
of the system.

`__cpu_up()` prints "CPU%u: failed to boot: %d" for the two `-ETIMEDOUT`s (`smp.c:135`). The
boot goes on ("smp: Brought up 1 node, N CPUs").

## 11. Hot-unplug: what `cpu_die` does without PSCI

On arm64 the method's `cpu_die(cpu)` is what takes a CPU out (`smp.c:374-394`), and a CPU can
only be taken out if the method has one (`:291-292`). This method has none, so
`/sys/devices/system/cpu/cpuN/online` refuses with "Operation not supported". That is correct for
now, and it costs what the 32-bit kernel has: it takes its four A57 offline when the display
sleeps, through `exynos5433_cpu_die()` (`platsmp.c:822-875`).

To get that back, three things the 32-bit kernel does from AArch32 have to be tried from AArch64
EL1, and none has:

1. the HOTPLUG boot flag, `CONFIGURATION &= ~0xF`, then `SMC_CMD_SHUTDOWN` (-7) with
   OP_TYPE_CORE or OP_TYPE_CLUSTER and SMC_POWERSTATE_IDLE (`platsmp.c:856-865`;
   `smc.h:14-18`, `:42-46`) — a different monitor call, from a different execution state;
2. `cpu_kill`: `STATUS & 0xf` back to 0 within 100 ms (`platsmp.c:882-900`);
3. the core's return: powered on again, it must arrive in AArch32 at the boot address as it does
   the first time, which the 32-bit kernel's hot-plug path shows and this one does not yet.

The monitor being AArch64 at EL3 (`SMP-MONITOR.md`, §1), an SMC from AArch64 EL1 is
no change of execution state for it: that makes the first of the three plausible, and it is
still untried.

An experiment of its own, from the kernel or from the loader, after the eight cores are up.

**Done on 2026-11-26**, with patch 0010 of `../kernel/patches/`: the three steps above from AArch64
EL1, with x3 = 0 and x2 ignored by the monitor; `cpu_kill` returns 0 for a dead core, arm64's
convention. The monitor takes the call as from AArch32, and a core powered on again comes back
through the boot register in AArch32. CPU7, the A57 cluster, then all seven secondaries went down and
back, four rounds, with no error ([FINDINGS.md](FINDINGS.md), section 23;
[SMP-MONITOR.md](SMP-MONITOR.md), section 6.1). The boot CPU must never go down this way.

## 12. Risks

For the hardware: the method writes the registers of §6 with the bits the 32-bit kernel writes
on every boot of this board. No clock, no voltage, no power domain, no regulator (the design decided on 2026-11-24, §2.8).
With `nosmp` it writes nothing at all.

| # | Risk | Why it is taken | If it shows |
|---|---|---|---|
| R1 | The monitor's call does not work on a secondary (U1) | Nothing else is available without PSCI | step 1 tells before any kernel is tried |
| R2 | A secondary is not coherent with the boot CPU (U4) | The 32-bit kernel relies on the monitor for the same thing | CPU1 dies just after it enters the kernel; stop at `maxcpus=1` until understood |
| R3 | The A57 cluster does not come up (U5) | The 32-bit kernel brings it up the same way | `maxcpus=4`; §6.5 |
| R4 | A secondary keeps stale data-cache or TLB content | The arm64 kernel assumes a core that starts cold; the 32-bit kernel invalidates the L1 data cache of every core at start (`arch/arm/mm/cache-v7.S:30-41`, `proc-v7.S:488-489`), arm64 does not. It matters only if the PMU's power-up is not a power-on of the core. Unknown | Corruption on secondaries only. Then: in the EL2 stub, invalidate the L1 data cache by set and way for **level 0 only** (the core's own; level 1 is the cluster's L2, shared with running cores) and `tlbi`, on the model of the loader's loop (`boot_el1.S:17-41`, which does clean *and* invalidate on the boot CPU when no other core runs) |
| R5 | The wrong core is released | One boot register for all | the pen (§4.3); no core runs without its own MPIDR in it |
| R6 | A core arrives after the boot CPU gave up | The monitor's release is not under the kernel's control | the pen is shut on every failure; such a core waits there |
| R7 | A hand edit puts `bti c` back at the AArch32 entry | It is what `SYM_FUNC_START` does | the build script compares the words in the linked image |
| R8 | The kernel image above 4 GiB | The monitor takes 32-bit addresses | `cpu_prepare` refuses; cannot happen with this board's memory |
| R9 | The loader changes to hand the kernel over at EL2 | The stub erets to EL1 | one line out of §4.2; otherwise "inconsistent modes" and a taint |
| R10 | Hot-unplug is lost (§11) | The monitor's shutdown call is untried from AArch64 | an experiment of its own: done on 2026-11-26, it works (§11) |
| R11 | A hang on a PMU write | None known: the 32-bit kernel writes the same registers | the watchdog policy: the kernel never feeds it, so the tablet resets and falls back |

Not a risk: interrupts on the arriving core (masked first thing, on both sides of the SMC); a
wrong MPIDR shape (`cpu_init` leaves such a CPU out); two starts at once (the mutex; arm64 has
no parallel bring-up in 6.12, `HOTPLUG_PARALLEL` is not selected).

## 13. On the device, in order

Each step is one boot; the boot arguments are the boot-arguments overlay with `nosmp` replaced.

| Step | Boot arguments | Look for |
|---|---|---|
| 1 | `nosmp` (unchanged) | nothing of the method runs: same kernel as today, one CPU |
| 2 | `maxcpus=1` | "EXYNOS5433: SMP: boot CPU MPIDR 0x100", the "before SMP setup" lines, "entry ... at sysram-ns + 0x1c, AArch64 entry ...": the PMU is prepared, no core is started |
| 3 | `maxcpus=2` | "EXYNOS5433: CPU1: MPIDR 0x101, PMU core 5 powered (STATUS 0x10380000 -> 0x2004000f, 1 ms)", "CPU1: Booted secondary processor 0x0080000101 [...]" (`smp.c:260-262`), "smp: Brought up 1 node, 2 CPUs", "CPU: All CPU(s) started at EL1" |
| 4 | `maxcpus=4` | the same for PMU cores 6 and 7 |
| 5 | no limit | PMU cores 0 to 3 (§6.5), "SMP: Total of 8 processors activated." |

Step 3 is the one that answers U1 and U4 for the kernel. If it fails, the line before the
failure says which half: "core power-up timed out" is the PMU, "did not reach the kernel" is the
monitor, the stubs or the pen, and "failed to come online" is the kernel's own start on that
core. The "failed" dump goes with it.

`../kernel/smp/bootargs-smp-test.overlay.dts` is the boot-arguments overlay with `nosmp` replaced
by `maxcpus=2` (the original is the reference); applied to the dtb built here it gives
`../kernel/smp/build-kernel/exynos5433-gts28ltexx-arm64-maxcpus2.dtb`. `../kernel/smp/build-kernel.sh --archive`
builds the kernel: the test kernel's configuration and test init, plus `HOTPLUG_CPU` and the method.
Step 2 comes before step 3 for a reason: with `maxcpus=1` the PMU is prepared and logged and no
core is started.

## 14. What we are not sure about

1. **The EL2 state of the stub is the loader's, not the kernel's.** It is what the boot CPU of
   this kernel runs with, which is why we copied it. The kernel's own `init_el2_state` does more
   (among others `HCR_HOST_NVHE_FLAGS`, a vector table at EL2); using it on the secondaries only
   would make the cores disagree, using it nowhere is what the three boots did.
2. **The 2 KiB between the entries.** We have no evidence that the monitor cares about the
   alignment of `r1`. We copied the proven one rather than find out with a failing test. The
   experiment of `SMP-EXPERIMENT.md` does not settle it either: its entry, 0x41000800, is on a
   2 KiB boundary too (`../loader/scripts/build_smp_stubs.py:27`).
3. **R4.** We looked for a way to read the state of a core's cache from the loader and found
   none that proves it empty; we did not add the invalidation, because a wrong level there would
   destroy the running cores' data and because arm64 works without it everywhere the firmware
   starts cores cold.
4. **`USE_SMPEN`, bit 28 of OPTION.** S-Boot leaves it set on the cores that are off and clear on
   the one that runs; the 32-bit kernel sets it on all eight. What the hardware does with it is
   not in any source we could read; U4 may well hang on it.
5. **The vendor files.** Every register of §6 is cited through the 32-bit kernel's comments; the
   vendor tree they cite is not on the machine where this was written.
6. **The binding** is written in the form of the three older ones of its directory, and
   `cpus.yaml` has the new string; `dtbs_check` was not run (no `dtschema` in the build image).
7. **The patches are authored under a neutral name** ("T715 arm64 port (SMP work stream)"), so
   that the owner's name is not on commits they have not read, and they are not signed off:
   re-author and sign them when adopting them.
8. **Step 1 is written apart from this document.** Everything §3 and §12 say about the experiment
   is read from its sources; its result was not known when this was written.

## 15. Where things are

From this document:

| Path | What |
|---|---|
| the kernel tree, branch `t715-arm64-smp` | the clone, three commits on the release commit 1595b1660 |
| `../kernel/smp/0000-cover-letter.patch`, `../kernel/smp/0001-*.patch`, `../kernel/smp/0002-*.patch`, `../kernel/smp/0003-*.patch` | the series, `git am` them |
| `../kernel/smp/build-kernel.sh`, `../kernel/smp/build-kernel-inner.sh` | the compile test; `--archive` builds the committed tree, `--requested` adds `PM` |
| `../kernel/smp/build-kernel/Image-boot`, `../kernel/smp/build-kernel/System.map-boot` | the kernel of the boot configuration: 5,546,000 bytes, sha256 7c729c88…, and its symbols |
| `../kernel/smp/build-kernel/exynos5433-gts28ltexx-arm64-boot.dtb` | the board with the enable-method, without boot arguments |
| `../kernel/smp/bootargs-smp-test.overlay.dts`, `../kernel/smp/build-kernel/exynos5433-gts28ltexx-arm64-maxcpus2.dtb` | the boot arguments of the first test with a secondary (§13) |
| `../kernel/smp/build-kernel/Image-requested`, `config-boot`, `config-requested`, `build-*.log` | the compile test with `PM` (to compile only), the two configurations, the logs |
| `SMP-DESIGN.md`, `SMP-EXPERIMENT.md` | this, and the experiment |

Docker: the volume `t715-kbuild-arm64-port-smp` only, 1.8 GB, to delete: `src/` the
tree of the last commit (1.6 GB), `out-archive/` its build in the boot configuration, `out/` an
earlier build made from the clone on disk.

## 16. Checks and first runs (2026-11-24)

**Verified on paper.** Every line number cited above was read again from the release tree at
1595b1660, from the loader's files and from the design decided on 2026-11-24. The three measured
rows of §6.1 and the power-up time come from measurements made apart from this document;
nothing in it was measured for it.

**Compile-tested.** Linux 6.12.114 arm64 in the container `t715-kbuild`, from the committed
tree (`git archive` into the volume, so a case-correct tree):

- the test kernel's configuration plus `HOTPLUG_CPU` and `ARM64_EXYNOS5433_SMP`: `Image` and the
  board's dtb build, with no compiler warning at all; built twice, the same `Image` both times;
- the same with `PM` on, as first asked for the compile test: builds (it brings the
  Exynos power domains in, which that small kernel must not probe: for compiling only).

In the linked image, after each build: the twelve words of the AArch32 entry are the assembled
ones, both entries are on 2 KiB boundaries 2 KiB apart, the constant is the distance, the pen
is in `.mmuoff.data.read`, both entries are below 4 GiB. The dtb decompiled: eight CPU nodes
with the method, no `psci`.

**The patches.** They apply with `git am` to a fresh checkout of 1595b1660 and give the same
tree as the branch; `git apply --check` passes on the clone used for the kernel configuration
(the kernel tree, branch `t715-arm64`, at 512804d49). `scripts/checkpatch.pl`: no error besides
the missing `Signed-off-by` (deliberate, §14.7); warnings for new files (MAINTAINERS) and one
`extern` for an assembly symbol, as `smp_spin_table.c:21`.

**Not done.** `dtbs_check` (no `dtschema` in the image): the binding is written but not
validated. A build with `CONFIG_RANDOMIZE_BASE`, with big-endian, or with any configuration but
the two above.

**Not run, before the runs below.** Nothing of this had run on the tablet; no secondary CPU had
entered this kernel. The experiment that tells whether it can is `SMP-EXPERIMENT.md`.

**Run on the tablet (2026-11-24, `SMP-EXPERIMENT.md` §8).** `smpk2` started CPU4 only,
because `exynos5433_cpu_init()` shifted the MPIDR by `MPIDR_LEVEL_BITS_SHIFT * 2` (6) instead of
16 and refused every A53 secondary; fixed (commit d24f74a08 on `t715-arm64-smp`,
`../kernel/smp/0004-arm64-exynos5433-fix-the-MPIDR-check-of-the-secondar.patch`). With the fix:
`smpk3` four A53 online, `smpk4` **all eight CPUs online and busy under load**. The A57 at 1.2 GHz
heat fast under full load (75 °C in 13 s): see §8.4 there.

## State on 2026-11-26

**Proven on the tablet.** On 2026-11-24 the method, `samsung,exynos5433-el2`, brought up the
eight cores of the 64-bit kernel (`SMP-EXPERIMENT.md` §8): CPU4, an A57, with `smpk2`; the four
A53 with `smpk3`; all eight, busy under load, with `smpk4`. That answers U1 (the monitor's call
switches a secondary) and U5 (the A57 cluster comes up with no cluster or L2 write); no failure
of U4 or R4 is recorded. The method is in the full kernel, and the tablet boots the arm64 system
by itself at every boot since 2026-11-25. A soak of several hours on 2026-11-25 ran twelve phases
of 3 min with eight busy cores, without a reboot (`ROADMAP.md`). On 2026-11-26 the method gained
its `cpu_die` and `cpu_kill` (patch 0010, §11): the seven secondaries go down and come back.

**Built or rehearsed only.** Nothing of the method: all that was built for it ran on the tablet.
Not built: the stub without its `eret` (§4.2) and the invalidation of R4. The binding is written
and `dtbs_check` was not run (§16).

**Open.** A kernel with PM domains and cpuidle (`SMP-EXPERIMENT.md` §8.4). Hot-unplug and re-plug,
and suspend, work since 2026-11-26 (§11; `FINDINGS.md`, section 23). The meaning of `UP_SCHEDULER`
(U7), and the alignment of the entry (U3, §14.2). The meaning of `0x800` and `1` and of the boot
flags was read in the monitor's code on 2026-11-26 (`SMP-MONITOR.md`, sections 3.1 and 5.3). On the
daily system, `schedutil` under real use and idle power (`ROADMAP.md`).
