# The secure monitor of the SM-T715 (Exynos 5433): its calls seen from AArch64

First version of 2026-11-24 (section 1). Sections 2 to 9 were written on 2026-11-26, for the
hot-unplug and the suspend to RAM of a 64-bit kernel (patch 0010 of `../kernel/patches/`): how the
monitor dispatches a call, its `0x82000400`, SHUTDOWN and SLEEP handlers, how a core comes back after
a power-down, and what can go wrong for an AArch64 caller. The comments of patch 0010 cite this
reading under its working name, `docs/arm64-monitor-smc.md` of the port.

Method: static disassembly of the boot partition image only (`../loader/dumps/mmcblk0boot0.bin`), plus S-Boot's own code:
the monitor, BL1 before it, and the ARM32 code after it (BL2 and S-Boot), read with GNU objdump.
Nothing was run on the tablet for the reading; what the tablet showed afterwards is in
[FINDINGS.md](FINDINGS.md), section 23, and at the end of this page. No firmware bytes are reproduced:
only addresses, register values and logic (section 1 quotes a few instructions, to show how the load
address was found).

Confidence: what is not marked otherwise is **high**, read directly in the code and consistent with
a measurement or a second path. **Medium**: read in the code, one step of inference. **Low**:
inference only.

Address conventions used below:

* **file offset**: offset inside `mmcblk0boot0.bin`.
* **monitor address**: where the code runs. The monitor image (file offsets `0x2000`..`0xd000`) is loaded at
  `0x02024000`, so `monitor address = 0x02022000 + file offset`. Its zero-filled data area runs on behind it.
* **S-Boot address**: `0x23DE2000 + file offset` (S-Boot is the `0x18000`..`0x9d000` region).
* **BL1 and BL2**: the same offset as the monitor. BL1 (file `0x0`) runs at `0x02022000`; the ARM32 code at file
  `0x19000`, BL2, runs at `0x0203B000` (section 5.2).
* **sysram-ns**: `0x0207B000`, 4 KiB, non-secure: the page of the boot register and the boot flags.
* **core index**: `Aff0 + 4 x Aff1` of the MPIDR. The boot CPU, MPIDR `0x100`, is index 4. The monitor and BL2's
  stub both use it.

---

## 1. Where the monitor is

| Item | Value | How identified |
|---|---|---|
| Image | `mmcblk0boot0.bin`, file offsets `0x2000`..`0xd000` (44 KiB: 16-byte header, ~24 KiB code, data, strings) | strings at file `0xa6b0`..`0xaba0`: `Built : Jan 23 2017`, `UBL31 %s`, `mon_smc`, `tbase_smc`, `tbase_fastcall`, `tbase_oem_fastcall`, `tbase_cpu_on_finish_handler %d`, `PANIC in PC location 0x%016X`, and the names of every `_el3`/`_el1` register it dumps; build string `aarch64-linux-gnu-gcc (crosstool-NG linaro-1.13.1-4.8-2013.09)` |
| Architecture | **AArch64, EL3** (reads `mpidr_el1`, `scr_el3`, `cptr_el3`, sets `vbar_el3`) | disassembly is clean AArch64 (more than 99 % of the words decode, with `mrs/msr` of EL3 registers) and meaningless as ARM32 |
| Load address | `0x02024000` (iRAM) | BL1 (file `0x0`..`0x1c00`, AArch64) ends its warm path with `ldr w4, =0x02024010 ; br x4` (file `0x158`); the monitor stores `0x0202D000` in `VBAR_EL3` and that is exactly where its vector table sits in the image (file `0xb000`); its own function-pointer table holds `0x0202A9F0`, which is the start of the `0x82xx` SMC group handler (file `0x89f0`). All three agree on one base. |
| Entry | `0x02024010` | first instruction `mrs x1, cptr_el3` (file `0x2010`) |
| Vector table | `0x0202D000` (file `0xb000`), 16 vectors of 0x80 bytes, handlers at `0x0202D400+` | `msr vbar_el3, x0` at file `0x8974` |
| Reset entry of BL1 | file `0x10` | `b 0x18`, then checks, then either `br x5` (x5 = `*0x02020024`) or `br 0x02024010` |
| Data (zero-initialised) | `0x0202F000`.. about `0x02036600` | `adrp` targets up to file `0x15000` (= `0x02037000`) |

Confidence: **high** for image, architecture, entry and load address (three independent constants agree). The image is
not present in `mmcblk0boot1.bin`, `BOTA0`, `BOTA1` or `md5hdr.bin`.

Other contents of the boot partition, for orientation (all from strings):

* `0x00000`..`0x01c00`: BL1, AArch64, signed block `20140623 / SLSI / Exynos BL1` at `0x1bf8`.
* `0x02000`..`0x0d000`: the monitor (this document).
* `0x18000`..`0x09d000`: S-Boot, ARM32.
* `0x0ee000`..`0x0fd000`, `0x137000`..`0x14c000`: the Trustonic secure OS (`t-base-EXYNOS64-Android-302A-V015-681_681`).
* `0x16e000`..`0x175000`: the modem bootloader (`CL5311075`).
* `0x181000`..`0x199000`: an ARM32 component with the strings `Kernel Data Double Mapping`, `prevent_double_mapping`
  (Samsung's loadable firmware); it contains one `smc #0` (file `0x181028`) and the literal `0x82000401` (file `0x181034`).

**Runtime evidence missing:** the dump `iram-0x02020000-runtime.bin` does **not** contain the monitor (nor BL1) at the
addresses they are linked for: the 384 KiB are a dense ARM32 code blob with no strings except `ARMv7 Processor`, and
none of the monitor's bytes are found in it. It cannot be used to confirm the monitor's run-time state. See section 8.

## 2. How an SMC is dispatched

### 2.1 The vectors

`VBAR_EL3` is `0x0202D000`.

| Entry | Role |
|---|---|
| +0x400, `0x0202D400` (lower EL, AArch64, synchronous) | reads the exception class in `ESR_EL3`: an SMC from AArch32 (class `0x13`) goes to `0x0202C514`, one from AArch64 (class `0x17`) to `0x0202C528`; any other class ends in the panic path (section 7.6) |
| +0x600, `0x0202D600` (lower EL, AArch32, synchronous) | the same code, instruction for instruction |
| +0x480, +0x500, +0x680, +0x700 (IRQ, FIQ from a lower EL) | save every general register (`0x0202D8B0`), look up the handler registered for the interrupt (`0x02027A80`), call it or panic. Reached only if `SCR_EL3` routes the interrupt to EL3 |
| the four groups for the current EL, +0x000 to +0x380 | the panic path |

The class is not checked against the vector, and the SMC's immediate is not read: any `smc` number works.

### 2.2 The common entry (`0x0202C514`, `0x0202C528`)

`SP_EL3` points at the calling core's current context (section 4.2). Then:

* `0x0202C514`, for an AArch32 caller only, stores **x8 to x17**, then runs on into `0x0202C528`.
* `0x0202C528`, for both, stores x4 to x7, x18 to x29 and `SP_EL0` (the vector stored x30). **x0 to x3 are not
  saved.**
* **A negative id** (`0x0202C558`..`0x0202C57C`): when the upper half of w0 is all ones, w0 becomes
  `0x82000000 | -w0`. -3 becomes `0x82000003`, -7 `0x82000007`, -101 `0x82000065`. Writing w0 also clears the
  upper half of x0.
* **The service** (`0x0202C580`): the owning entity number (bits 24 to 29 of the id) and the fast-call bit (bit 31)
  make an index into a byte table at `0x020322E0`, filled at init by the runtime services' setup (`0x02027818`).
  No service registered: w0 = -1 and return (`0x0202C638`; section 6.4).
* Otherwise `SPSR_EL3`, `ELR_EL3` and `SCR_EL3` go into the context (+0x110, +0x118, +0x120), bit 0 of x7 gets
  `SCR_EL3.NS`, the stack becomes the core's runtime stack, and the handler is called with the id in x0, the
  arguments in x1 to x4 and the context in x6.
* If the word at `0x02036000` is non-zero, the id is first stored at that word + 8 x core (`0x0202C5C8`): a debug
  buffer that call -120 registers (section 7.9).
* The return (`0x0202C5F0`) reloads `SCR_EL3`, `SPSR_EL3` and `ELR_EL3` from the context; `0x0202D8F8` then reloads
  **x0 to x30 and `SP_EL0`** from it, and leaves by `eret`.

### 2.3 The registered services

`rt_svc_descs` at `0x0202CBB8`, 32 bytes each. The names are the firmware's own strings.

| Name | Owning entity | Type | Handler |
|---|---|---|---|
| `mon_smc` | 2 (SiP) | fast | `0x0202A9F0` |
| `tbase_dummy_sip_fastcall` | 1 | fast | `0x02027D0C` |
| `tbase_oem_fastcall` | 3 | fast | `0x02027D0C` |
| `tbase_smc` | 0 to 2 | yielding | `0x02027ED4` |
| `tbase_fastcall` | 50 to 63 | fast | `0x02027D0C` (its init at `0x02028634`) |

Nothing else is registered: not the fast calls of entity 0 (the Arm architecture calls of SMCCC), not entity 4
(PSCI).

### 2.4 `mon_smc`, the SiP service (`0x0202A9F0`)

A chain of comparisons of **w0**, 32 bits, with each id it knows:

| Id | Name in the 32-bit kernel | Handler |
|---|---|---|
| `0x82000003` | SLEEP (-3) | `0x0202B4B0` (section 6.2) |
| `0x82000006` | SAVE (-6) | `0x0202B4A0`: computes a per-core pointer and returns; nothing else |
| `0x82000007` | SHUTDOWN (-7) | `0x0202B82C` (section 6.1) |
| `0x82000065` | REG (-101) | `0x0202AB44`, register access (section 6.4) |
| `0x82000078` | (-120) | `0x020254E8`, registers a debug buffer |
| `0x820000E6`..`0x820000EC`, `0x820000F0`..`0x820000F2`, `0x8200012C`, `0x8200012D` | the services of BL2 and S-Boot (an image load, the cold hand-over `0xE7`, the sleep wake `0xE8`, ...) | various |
| `0x820000EE` | (-238) | `0x0202C000`: returns 0 |
| `0x82000400`, `0x82000401` | the hypervisor's launch and "done" | `0x02025858`, `0x02025950` (section 3) |
| `0x82000600` | | `0x02025B00`, not read |

INIT (-1), INFO (-2), CPU1BOOT (-4), CPU0AFTR (-5), C15RESUME (-11) and L2X0 (-21 to -25) are **absent**: they fall
to the common return (`0x0202AAEC`), which writes nothing, so x0 to x3 come back with whatever the context held. An
id of the SMC64 convention (`0xC2000003`) reaches `mon_smc` (entity 2, fast) and matches nothing.

### 2.5 What it means for an AArch64 caller

* **AArch64 or AArch32**: the same dispatcher. The one difference is that x8 to x17 are saved for an AArch32 caller
  and not for an AArch64 one (section 7.1).
* **w0, not x0**, in the dispatcher and in `mon_smc`. x0 = `0x00000000FFFFFFFD` and x0 = `0xFFFFFFFFFFFFFFFD` behave
  alike: the handler sees `0x82000003`. Passing `0x82000003` itself works as well.
* **Normal-world EL2 or EL1**: both are "a lower EL in AArch64" and enter at +0x400. The monitor saves and restores
  `SPSR_EL3` and `ELR_EL3` without looking at the mode. Each core's init clears `SCR_EL3.SMD` (`0x0202A190`), so SMC
  is enabled at EL1 and EL2; an SMC from EL1 reaches EL3 as long as `HCR_EL2.TSC` is 0, and the loader's `HCR_EL2`
  has only RW.

## 3. The `0x82000400` handler

### 3.1 What it does (`0x02025858`)

Arguments: x1 = the entry, x2 = a per-core stride (the loader passes `0x800`), x3 = the mode, x4 and x5 = values
for the target.

1. Takes this core's normal-world and secure contexts (`0x020274CC`; the table of context pointers is at
   `0x02036300`).
2. **Fails** if the global word `0x02036008` is non-zero, if x1 is not 4-byte aligned, or if x3 is neither 0 nor 1
   (compared as 64-bit values). A failure writes -1 into the normal-world context's x0 and returns through the
   current context.
3. Keeps x1, x2 and x3 in globals: `0x02036010`, `0x02036018`, `0x0203600C` (32 bits).
4. Copies the secure context's `SPSR`, `ELR` and `SCR` to `0x02036020`..`0x02036030`: global, the last caller wins.
5. Sets the secure context's way out (`0x02027624`), as below. That function clears `SCR` bits 1 and 2 and puts in
   the interrupt routing of the security state it is given: here the secure one (section 7.7).
6. The secure context's x0 and x1 become the caller's x4 and x5 (`0x02025914`..`0x02025920`).
7. Makes the secure context the next one: **`SP_EL3` now points at this core's secure context**, and the common
   return leaves through it.

| Field | x3 = 1 | x3 = 0 |
|---|---|---|
| `ELR_EL3` | x1 | x1 |
| `SPSR_EL3` | `0x2C9`: AArch64 EL2h, D, I and F masked, **A unmasked** | `0x1DA`: AArch32 Hyp, A, I and F masked |
| `SCR_EL3` | the live `SCR` with NS, bits 4 and 5, and **RW**; IRQ = FIQ = 0; HCE as before (0 unless a hypervisor was installed) | the same without RW |
| x0, x1 at the target | the caller's x4, x5 | the same |
| x2 to x30, `SP_EL0` at the target | the secure context's slots: stale (the secure OS's last registers, or zero) | the same |
| `HCR_EL2`, `SCTLR_EL2`, `VBAR_EL2`, `CPTR_EL2` | **untouched**: as the core's last init at EL3 left them (`0x0202A1D4`..`0x0202A238`): `HCR_EL2` written 0, `SCTLR_EL2` with the MMU and the caches off and A and SA set, `CPTR_EL2` = `0x33FF`, `HSTR_EL2` = 0, `VBAR_EL2` = 0, `VPIDR` and `VMPIDR` from `MIDR` and `MPIDR` | the same |

That is what the one-core experiment measured on a secondary ([SMP-EXPERIMENT.md](SMP-EXPERIMENT.md), section
7.2): `SCTLR_EL2` `0x30C5083A` is exactly its RES1 bits plus A and SA; `CPTR_EL2` `0x33FF` is its RES1 bits with
TFP, TTA and TCPAC clear, so **no trap**; `HCR_EL2`, written 0, reads `0x2`: bit 1, SWIO, reads as one on these
cores (**medium**: RES1 is the consistent explanation). `HCR_EL2.RW`, bit 31, is **0** at the entry: the loader
sets it before EL1.

### 3.2 What it is for

The pair is the launcher of Samsung's EL2 hypervisor (RKP, whose ARM32 loader sits at boot0 file `0x181000` and
holds the literal `0x82000401`, section 1). `0x82000401` (`0x02025950`) is called from EL2 by the hypervisor, with
x1 = 0 for success. It sets `0x02036008` to 1, saves about twenty EL2 registers (`HCR`, `SCTLR`, `VBAR`, `TTBR0`,
`TCR`, `MAIR`, `VTTBR`, `VTCR`, `CPTR`, `TPIDR`, `SP_EL2`, ...) to `0x02036038`..`0x020360D8`, restores the secure
context's way out from step 4, writes x1 into the normal-world caller's x0, sets `SCR_EL3.HCE` in the normal-world
context, and returns to the **normal-world caller of `0x82000400`**: an AArch32 kernel then runs at EL1 under the
AArch64 hypervisor. With x1 non-zero it sets `0x02036008` to -1.

On every later warm entry of a core, and on the sleep wake, `0x02025690` puts the saved EL2 registers back, gives
the core its EL2 stack (base + index x stride, the two clusters' indexes swapped) and sets `SCR_EL3.HCE`: **only if
`0x02036008` is 1**. The cold init clears that word (`0x02025680`); the sleep wake does not, and restores the secure
iRAM anyway. **Medium** for the purpose, high for the mechanics.

### 3.3 It may be called again

Per core, the call records only the secure context (its way out, x0 and x1) and which context `SP_EL3` points at.
Globally it records x1, x2, x3 and the calling core's previous secure way out; only `0x82000401` reads them, and
`0x02025690` when `0x02036008` is 1. The loader never calls `0x82000401`, so `0x02036008` stays 0 and **`0x82000400`
may be called again**: on every secondary, after a hot-plug, after a secondary's power-down, after SLEEP, as long as
`0x82000401` is never called (section 7.5).

A second call from a core already in AArch64 works too (no check of the state or the level), but its target then
gets x0 and x1 from the stale x4 and x5 slots of the normal-world context; x4 to x7 and x18 to x30 keep the
caller's values.

## 4. Core dependence

### 4.1 The boot CPU and the others

The monitor tells the boot CPU by `(MPIDR & 0xFFFF) == 0x100` (`0x0202C690`). Only the boot CPU runs the cold init,
and its power-on is a warm entry only in one case (section 5.1): that is why it must never be unplugged (section
7.4). A secondary comes back only through its boot flag, at sysram-ns + 0x28 + 4 x index.

Cortex-A57 only (`MIDR` part `0xD07`): SHUTDOWN turns the L2 prefetch off and sets bit 32 of `CPUACTLR` before the
power-down, and on its abort path sets both controls to fixed values (section 6.1).

### 4.2 The contexts

Each core has a normal-world context (`0x270` bytes at `0x02030D60 + 0x270 x core`) and a secure one, inside the
secure OS's per-core data (`0x02036550 + 0x2D0 x core`). Both have the AArch64 layout of ARM Trusted Firmware: x0 to
x30 and `SP_EL0` in 64-bit slots, the runtime stack pointer at +0x108, `SPSR_EL3`, `ELR_EL3` and `SCR_EL3` at
+0x110, +0x118 and +0x120, the EL3 registers after them, the EL1 registers from +0x170 (the AArch64 ones and the
AArch32 banked SPSRs, `DACR32`, `IFSR32`, `FPEXC32`). The FP registers are saved apart. The SMC path touches only
the general registers and `SPSR`, `ELR` and `SCR`; the EL1 save serves the secure OS's world switches only. No
layout is sized for AArch32: the one asymmetry is the save of x8 to x17 (section 2.2).

### 4.3 What is global

Not per core: the arguments of `0x82000400` and the last caller's secure way out (section 3); the hypervisor word
`0x02036008` and the saved EL2 registers; SHUTDOWN's save slot for `HCR_EL2` (section 7.10); the debug-buffer
pointer at `0x02036000`.

## 5. Secondary core power-on path

### 5.1 The monitor's entry (`0x02024010`)

BL1 comes first. Its reset code (`0x02022018`) reads the PMU's reset status; on a warm reset it jumps to the address
at `0x02020024` when `0x02020020` holds `0xFCBA0D10`, or to `0x02024010` directly. The monitor writes `0x02024010`
into `0x02020000`..`0x0202001C` and `0x02020024`, and `0xFCBA0D10` into `0x02020020`, at every init (`0x0202A08C`).
(**Medium** for the PMU tests, high for the targets.)

The monitor's entry, in outline:

```
every core       CPTR_EL3 traps off, SCTLR_EL3.I on
                 boot CPU = (MPIDR & 0xFFFF) == 0x100
a secondary      INFORM5 low half = 0x3300 (a marker), SCTLR_EL3 A and SA
(0x0202A8F8)     flag = the word at sysram-ns + 0x28 + 4 x index
                   bit 3 (C2):           the core's init (0x0202A188), coherency on, VBAR_EL3, EL3 MMU on
                   else bit 2 (HOTPLUG): the same, and the GIC CPU interface (0x0202A31C)
                   else:                 WFI at EL3, for ever
the boot CPU     INFORM1 == 0xBAD: its flag word (sysram-ns + 0x38) is cleared
                 PMU 0x105C0908 == 0 (the first boot), or its flag word != 8: the whole cold init
                 its flag word == 8: the secondary's path above
then             after a cold init: the normal world at 0x0203B000 (BL2), SPSR 0x1D3, SCR | NS
(0x02024144)     otherwise: the normal world at 0x0207B000 (sysram-ns + 0x0), SPSR 0x1D3, SCR | 0x31
                 (0x02024164), after the secure OS's "cpu on finish" hook (the first time on each core it
                 sets up the core's secure context) and, only if installed, the hypervisor's EL2 state
```

The core's init, `0x0202A188`, runs at every power-on: `SCR_EL3` loses NS, IRQ, FIQ, EA, SMD, HCE, SIF and RW;
`HCR_EL2` = 0; `SCTLR_EL2` and `SCTLR_EL1` get known values with the MMU and the caches off; `CPTR_EL2` = `0x33FF`;
`HSTR_EL2` = 0; `VBAR_EL2` = `VBAR_EL1` = 0.

### 5.2 BL2 (`0x0203B000`)

The ARM32 code at boot0 file `0x19000` runs at `0x0203B000`: the monitor's EL3 map has one region
`0x0203B000`..`0x0207C000`, and BL2's first act sets its stack at `0x0207C000`. It is entered in SVC with A, I and
F masked and dispatches on INFORM1: `0xBAD00000` (deep idle), `0xABAD0000` (LPA), `0xBAD` (a sleep), anything else a
cold boot. It installs the sysram-ns stub on a cold boot and on a sleep wake, and hands over through
`SMC 0x820000E7` (cold: to S-Boot) or `SMC 0x820000E8` (wake: to the stub).

### 5.3 The sysram-ns stub

Its code runs at `0x0207B000`; BL2 copies it from `0x0203B250` (`0x160` bytes).

| sysram-ns offset | After BL2's copy | Use |
|---|---|---|
| +0x00 | a branch to +0x50 | where the monitor releases every core |
| +0x08 | 0 | the resume address; SLEEP copies it to INFORM0 |
| +0x0C | 0 | the sleep flag; SLEEP copies it to INFORM1 |
| +0x18 | 0 | the boot address for flag bit 4 |
| +0x1C | 0 | the boot address of the secondaries, one for all |
| +0x24 | 0 | the resume address of C2 and AFTR (flag bit 3) |
| +0x28..+0x44 | 4 for every core; BL2 then sets the boot CPU's word (index 4) to 1 | the cores' flags: bit 0 the boot CPU, bit 2 HOTPLUG, bit 3 C2, bit 4 |
| +0x48, +0x4C | 0 | per cluster, bit 0 "power-down in progress", set and cleared by SHUTDOWN's cluster path, with an event |
| +0x50..+0x15F | the stub's code and constants | |
| +0x800.. | a parameter block from BL2 (+0x848: the word the DRAM carveout comes from) | read by the monitor |
| +0x900 | SLEEP's progress markers, `0x30` to `0x34` | written by the monitor |

The stub reads the core's flag. Bit 4: it waits for +0x18 to be non-zero and jumps there. Bit 3: the same with
+0x24. Otherwise, if INFORM1 is non-zero, it clears INFORM1 and jumps to the address in INFORM0: a resume. Otherwise,
bit 0, the boot CPU: it jumps to S-Boot at `0x23E00000`. Otherwise it waits for events until +0x1C is non-zero, and
jumps there. So the monitor does not jump to the address in sysram-ns + 0x1C itself, as the earlier pages assumed:
it releases the core at sysram-ns + 0x0, and the stub reads +0x1C. The CPSR `0x200001D3` measured on a fresh
secondary is the monitor's SPSR `0x1D3`.

### 5.4 What a 64-bit kernel takes from it

* **Every way in after a power-on is a constant**: sysram-ns + 0x0 with SPSR `0x1D3` for a secondary and for a C2
  wake; `0x0203B000` with `0x1D3` for the boot CPU's cold or sleep entry. `SCR_EL3.RW` is 0 on all of them.
* **Nothing persists.** After a power cycle every core starts again in AArch32 SVC, and a 64-bit kernel must
  repeat its AArch32 stub and `0x82000400` as at the first bring-up: through +0x1C for a hot-plug, +0x24 for C2,
  INFORM0 for a sleep. Without a power cycle (SLEEP or SHUTDOWN coming back) the caller gets its own AArch64 state
  back, from the `SPSR`, `ELR` and `SCR` saved at its call.
* **After a sleep wake** BL2's copy has reset sysram-ns +0x08..+0x24, the flags (4 for the secondaries, 1 for the
  boot CPU) and +0x48, +0x4C: the kernel must write +0x1C again before it starts a secondary.

## 6. Other calls

### 6.1 SHUTDOWN (-7, `0x82000007`, handler `0x0202B82C`)

| Register | Use |
|---|---|
| x1 | 0: this core only; non-zero: the cluster. The abort path re-enables the cluster only if x1 is 1. Compared as 64-bit values |
| x2 | **not read** (the 32-bit kernel passes `SMC_POWERSTATE_IDLE`, 1) |
| x3 | 1 (a 64-bit compare) selects an extra path (`0x0202B7E4`): if exactly one core is on in both clusters, it turns a system-level control off (`0x105C2B00` bit 0, `0x105B0900` bits 0 and 3). The 32-bit kernel passes 0 |

The HOTPLUG flag is **not read** here: it matters at the next power-on (section 5.1).

The sequence:

1. the secure OS's "cpu off" hook (`0x02027180`; empty for this one);
2. `SCR_EL3`: NS = 0, IRQ = 1; `SCTLR_EL3.C` = 0; `HCR_EL2` saved in **one global word** (`0x0202BA38`), then
   `HCR_EL2.VM` = 0;
3. on a Cortex-A57 only: the L2 prefetch off in `CPUECTLR`, bit 32 of `CPUACTLR` set;
4. L1 cleaned and invalidated by set/way; `CPUECTLR.SMPEN` = 0: the core leaves coherency;
5. x3 = 1: the path of the table above;
6. x1 non-zero (`0x0202B6F8`): it sets the cluster's busy bit (sysram-ns + 0x48 + 4 x cluster) and counts the
   cluster's cores whose PMU STATUS (`0x105C2004 + 0x80 x core`, cluster 1 at +0x200) is on. Exactly one: L1 and L2
   cleaned and invalidated, snoops and DVM off for the cluster at the CCI-400 (`0x10704000` or `0x10705000`, then a
   poll of the change-pending bit at `0x1070000C`), and for cluster 0 (the A57) bit 22 of CMU_ATLAS `0x11800104`;
   the busy bit cleared. More than one: the busy bit cleared, and **back to the caller** with no power-down;
7. the instruction cache invalidated, `SCTLR_EL3.M` = 0, a short countdown with one WFI. The kernel cleared the
   core's CONFIGURATION power bits before the call, so the PMU powers the core down here.

**If the WFI returns**: the EL3 MMU back on; the cluster's snoops back if x1 is 1; the system control of step 5 back;
SMPEN on; the EL3 TLBs invalidated; `SCR_EL3` NS = 1, IRQ = 0; on an A57, `CPUACTLR` and `CPUECTLR` set to fixed
values (prefetch distances 3, not the saved ones); `HCR_EL2` from the global word; `SCTLR_EL3.C` on; the "cpu off
abort" hook; back through the context. **x0 to x3 are not written**: an AArch64 caller gets whatever the context's
slots held. The 32-bit kernel ignores the value and calls again until its pen releases the core.

### 6.2 SLEEP (-3, `0x82000003`, handler `0x0202B4B0`)

No argument is read. In order:

1. progress marker `0x30` at **sysram-ns + 0x900** (later `0x31` to `0x34`);
2. the secure OS's "suspend" hook (`0x020270FC`; this one returns 0); non-zero aborts;
3. SAVE (nothing), then `0x020261C4`: the memory-protection controller's settings saved in the monitor's iRAM;
4. **INFORM0 (`0x105C0800`) = the word at sysram-ns + 0x8, INFORM1 (`0x105C0804`) = the word at sysram-ns + 0xC**
   (`0x0202B4D8`..`0x0202B4F4`): 32-bit copies, no comparison with `0xBAD`, no magic checked;
5. bits set in three CMU_IMEM registers (`0x11060B04` |= `0x3000`, `0x11060B0C` |= 1, `0x11060B18` |= 3);
6. `SCR_EL3.NS` = 0, **every cache level cleaned by set/way** (to the level of coherence, L2 included), `SCR`
   restored;
7. the secure iRAM `0x02036000`..`0x0207B000` (`0x45000` bytes) saved to DRAM (`0x0202643C`, through the crypto
   block at `0x11100000`). The destination is the word at `0x0202C028` + `0x1300000`, where `0x0202C028` was set at
   boot by `SMC 0x820000E7` from the word BL2 leaves at **sysram-ns + 0x848**: that word + `0x20000000` -
   `0x1380000`. The EL3 map covers DRAM `0x20000000`..`0xE0000000`; if the word is the DRAM size (3 GiB), the
   secure carveout is `0xDEC80000`..`0xE0000000` and the save area `0xDFF80000`..`0xDFFC5000` (**low**: the word was
   never read on a running tablet). The device tree's memory ends at `0xDE980000`, below it. A failure aborts;
8. `CPUECTLR_EL1.SMPEN` (bit 6) = 0: the core leaves coherency;
9. `SCR_EL3.IRQ` = 1, barriers, WFI.

The caller's state is not saved: after a real sleep nothing comes back to the caller (section 6.3).

**If the WFI returns** (no power-down, for instance an interrupt pending): `SCR_EL3` restored, SMPEN set, the "post"
hook, INFORM0 and INFORM1 cleared, then x0 = -1 and x1 = x2 = x3 = 0 written into the current context
(`0x0202B5F0`..`0x0202B604`), and back. An AArch64 caller gets **x0 = `0xFFFFFFFFFFFFFFFF`**, x1 to x3 = 0, in its own
state. The abort paths of steps 2 and 7 end the same way.

### 6.3 The way back after a real sleep

1. **BL1 to the monitor**, as on any warm reset (section 5.1).
2. **The monitor, boot CPU.** INFORM1 is `0xBAD`, so it clears the boot CPU's flag word; PMU `0x105C0908` is
   non-zero (the monitor writes `0xFCBA0D10` there at its first init) and the flag word is not 8, so **the whole cold
   init runs again**: its zeroed data `0x02030B80`..`0x020323C0` (every core's normal-world context), each core's
   init (`0x0202A188`, which clears RW and HCE in `SCR_EL3`, and `HCR_EL2`), the runtime services and the secure
   OS's init; then the normal world is prepared at **`0x0203B000`, SPSR `0x1D3`, SCR | NS** (`0x020241D8`..
   `0x02024214`, `0x02029FD0`, `0x020273CC`). Because INFORM1 is `0xBAD`, the steps of `0x0202A0C8` kept for a cold
   boot are skipped, among them `0x02025680`, which would reset the hypervisor's state.
3. **BL2 at `0x0203B000`**, AArch32 SVC, finds `0xBAD` in INFORM1. It initialises some hardware again, **copies its
   sysram-ns stub again** (section 5.3), and calls `SMC 0x820000E8` (-232) with r3 = `0x0207B000` (`0x0203DD98`).
4. **`0x820000E8`** (`0x0202BD68`) checks the address, restores the secure iRAM from DRAM (on a failed check it clears
   INFORM1 and writes 1 to the PMU's SWRESET, `0x105C0400`: the SoC restarts), invalidates every cache by set/way,
   restores the controller's settings, the hypervisor's state if one was installed (`0x02025690`), calls the
   "resume" hook, then leaves to `0x0207B000` (`0x0202BE64`..`0x0202BE74`) with **BL2's own** `SPSR` and `SCR`, from
   its call: AArch32 SVC, RW = 0.
5. **The sysram-ns stub**: the boot CPU's flag has neither bit 4 nor bit 3; INFORM1 is non-zero, so it clears INFORM1
   and jumps to the address in INFORM0: the resume address, in AArch32 SVC, MMU off. That is what the 32-bit kernel
   met.

Nothing records that the core had been switched to AArch64. A 64-bit kernel needs an AArch32 stub at the resume
address that makes the call `0x82000400` again, with r1 = its AArch64 resume entry and r3 = 1; that second call is
accepted (section 3.3).

**The word `0x2bedf00d`**, before the resume address, is checked by nothing in the boot partition. The constant
appears in none of BL1, the monitor, BL2, the sysram-ns stub or S-Boot, neither as a literal nor built in a register
by two moves (ARM, Thumb-2 or AArch64). Only the iROM, which is not dumped, was not examined; it runs before BL1,
and the jump to the resume address comes later, from the stub. A 64-bit kernel's resume stub does not need the word.

### 6.4 Harmless probes

Calls that show the monitor answers an AArch64 caller, and change nothing:

| x0 from AArch64 | Path | Result |
|---|---|---|
| `0x0000000084000000` (PSCI's version) or `0x0000000080000000` (SMCCC's version): no service registered | the dispatcher, `0x0202C59C` then `0x0202C638` | **x0 = `0x00000000FFFFFFFF`**, not sign-extended; x1 to x3 untouched; x4 to x7 and x18 to x30 kept; x8 to x17 from the context. No handler runs |
| `0x00000000820000EE`, or -238 | `mon_smc`, then `0x0202C000` | **x0 = 0**; x1 to x3 stale. It shows the negative id's conversion and `mon_smc`'s dispatch |
| REG: x0 = -101, x1 = `0xC0000000` (a read of address 0) | `0x0202AB44`: a read, of an address outside `0x141E0000`..`0x141FFFFF`, refused (`0x0202BFF8`) | **x0 = `0xFFFFFFFFFFFFFFFF`**; nothing is read. An allowed read returns the value in x2; a block whose power domain is off could hang it, so no allowed address is suggested |
| INFO (-2), INIT (-1) | `mon_smc`, no match | nothing done; x0 to x3 stale: no usable answer |

A first test would be `0x84000000`, then `0x820000EE`, with x0 to x17 treated as clobbered.

## 7. What can go wrong for an AArch64 caller

### 7.1 Registers that come back clobbered

For an AArch64 caller, x8 to x17 are never saved and always reloaded from the context, and x0 to x3 come back with
what the handler wrote, or what nobody wrote. Treat **x0 to x17 as clobbered**, the AAPCS64 caller-saved set, as
Linux's out-of-line `__arm_smccc_smc` does: an inline `smc` with a short clobber list is wrong here. x18 to x30,
`SP_EL0`, every EL1 system register and the FP/SIMD registers are kept (no path of `mon_smc` uses SIMD). After
`0x82000400` the current context is the secure one, so the stale values may be the secure OS's registers.

### 7.2 Return values

An unknown id of `mon_smc` returns a stale x0, so "not implemented" cannot be told there. An unregistered service
returns `0x00000000FFFFFFFF`, which a 64-bit test against -1 misses. `mon_smc`'s failures and SLEEP's abort return
a 64-bit -1. Only the 32-bit convention's ids (`0x82...` or negative) work; `0xC2...` does nothing.

### 7.3 Argument widths

SHUTDOWN compares x1 and x3 as 64-bit values: pass x1 in {0, 1} and **x3 = 0** (x3 = 1 runs the system-level path).
`0x82000400`: x3 exactly 0 or 1. SLEEP reads +0x8 and +0xC as 32-bit words: the resume address must be below 4 GiB
(true for this DRAM) and must point at AArch32 code.

### 7.4 The boot CPU

* Never power MPIDR `0x100` down through SHUTDOWN (a hot-unplug). Its next entry would not be a warm one: the monitor
  would rerun its cold init while the other cores run (its zeroed data holds every core's normal-world context; the
  services and the secure OS set up again), and send the boot CPU to BL2's cold path.
* For C2 on the boot CPU the monitor compares its whole flag word with 8. BL2 sets bit 0 of that word at a cold boot,
  so OR-ing 8 into it gives 9, and the same cold init. Write exactly 8.
* SLEEP is meant for the boot CPU with every other core off: the wake path starts the boot CPU.

(High for the monitor, **medium** for what BL2 then does.)

### 7.5 Never call `0x82000401`

It sets `0x02036008` to 1 or -1, and from then on every `0x82000400` fails until the monitor's next cold boot: no
secondary, no hot-plugged core and no boot CPU waking up could reach AArch64 again. (Set to 1, it also restores EL2
registers at every warm entry.)

### 7.6 The panic path

The vectors for the current EL, a synchronous exception from a lower EL other than an SMC, an IRQ or FIQ from a lower
EL with no handler, and an SError from a lower EL all end in `0x020255D4` (which writes EL3 registers into the debug
buffer, if one is registered) and a branch to itself at `0x0202D888`: the core hangs, interrupts masked, with no
reset. The asserts of the runtime services' setup use `0x02028A88`, which prints "PANIC in PC location" to the
monitor's log, then hangs the same way. SLEEP and SHUTDOWN assert nothing, but their hardware polls (the CCI's change
pending at `0x0202B6A4`, `0x105C2B04` at `0x0202B7A0`) have no bound. The failed restore of a sleep wake is the only
path that resets the SoC (the PMU's SWRESET). `SCR_EL3.EA` is 0, so an SError stays in the normal world.

### 7.7 `SCR_EL3` after the switch

The secure OS registers its interrupt type with flags 2 (`0x02028604`): FIQ routed to EL3 while the normal world
runs, not while the secure world runs. `0x82000400` builds its `SCR` with the *secure* routing, so the 64-bit world
runs with **`SCR_EL3.FIQ` = 0** (the 32-bit kernel ran with 1): a Group-0 (secure) interrupt would reach EL1 of the
normal world as an FIQ, and arm64 Linux has no FIQ handler there. None has been seen. `SCR_EL3.IRQ` is 0 in both
worlds. **`SCR_EL3.HCE` = 0**, so HVC is undefined at EL1 and EL2: a kernel entered at EL2 that relies on an HVC to
its stub (KVM, a kexec back to EL2) cannot work; the loader enters Linux at EL1, which avoids it. (High for the
values, **medium** for the consequence.)

### 7.8 The secure OS, from a switched core

The switch writes over the core's secure context. A call that enters the secure OS (the fast calls of entities 1, 3
or 50 to 63, handler `0x02027D0C`; the yielding calls of entities 0 to 2) would save EL1 of the normal world and
leave through that context, that is, to the old EL2 entry. Keep every TEE driver off: an OP-TEE probe uses entity 63.
(**Medium**.)

### 7.9 Memory the monitor writes

* SLEEP's save (`0x45000` bytes) goes to the secure carveout derived from sysram-ns + 0x848 (section 6.2): the
  64-bit kernel must not own that memory.
* If a debug buffer was registered with call -120 (`0x82000078`) since the last cold init, the dispatcher writes
  every id to that buffer + 8 x core, and the panic path writes EL3 state there. S-Boot does not make that call;
  whether the vendor's Android kernel does, and whether the pointer at `0x02036000` survives a reset into the arm64
  chain (the monitor never zeroes it), is **not determined**.
* The monitor writes sysram-ns +0x48, +0x4C and +0x900; +0x00..+0x15F hold the stub. The kernel should write only
  +0x08, +0x0C, +0x1C, +0x20, +0x24 and the flag words.

(**Medium**.)

### 7.10 Smaller points

* SHUTDOWN's save slot for `HCR_EL2` is global: two cores in SHUTDOWN at once may restore each other's `HCR_EL2` on
  the abort path. Harmless while every core has the same `HCR_EL2`.
* The SPSR `0x2C9` of `0x82000400` leaves PSTATE.A unmasked at EL2 with `VBAR_EL2` = 0: the EL2 entry should set
  `VBAR_EL2` early.
* On SHUTDOWN's abort path the A57's prefetch controls are set to fixed values.

## 8. Not determined

* The exact PMU conditions by which BL1 chooses a warm or a cold entry (`0x02022018`..`0x0202210C`).
* The word at sysram-ns + 0x848, hence the exact DRAM address of SLEEP's save area.
* Whether the debug-buffer pointer at `0x02036000` can be non-zero in the arm64 boot chain.
* Whether any Group-0 interrupt is enabled while the 64-bit kernel runs (section 7.7).
* Whether the iROM checks anything on a sleep wake before BL1 runs: it is not dumped.
* What flag bit 4 and sysram-ns + 0x18 are for, what `0x82000600` does, and the services `0xE6` to `0xF2` of BL2.
* The monitor's run-time state: the iRAM dump does not hold it (section 1).

## 9. Corrections to earlier pages

* [SMP-EXPERIMENT.md](SMP-EXPERIMENT.md), section 7.2, and [FINDINGS.md](FINDINGS.md), section 6: `HCR_EL2` = 2 at
  the EL2 entry is bit 1, SWIO, not RW (RW is bit 31, and 0 at the entry); `CPTR_EL2` `0x33FF` means no trap.
* [SMP-DESIGN.md](SMP-DESIGN.md) and [FINDINGS.md](FINDINGS.md), section 17: the monitor releases a secondary at
  sysram-ns + 0x0, where BL2's stub reads +0x1C; and SHUTDOWN ignores x2 but reads x3.

## State on 2026-11-26

**Proven on the tablet.** Nothing was run for this reading. From the tablet, before it: the monitor's call
`SMC 0x82000400` switches a secondary core to AArch64 at EL2, and that core reaches EL1 by an `eret`
(`SMP-EXPERIMENT.md` §7.2); the eight cores run the 64-bit kernel through the enable-method built on that call
(`SMP-EXPERIMENT.md` §8.4). After it, on 2026-11-26, with patch 0010: SHUTDOWN from AArch64 EL1 takes a core, and a
cluster, down; a core powered on again comes back in AArch32 through the boot register; `0x82000400` accepts a second
call from every core, and from the boot CPU after a sleep; SLEEP from AArch64 puts the SoC to sleep, and the wake
goes through BL2 to the resume address in AArch32: five real sleeps out of five
([FINDINGS.md](FINDINGS.md), section 23). This page has no run-time confirmation of the load address of section 1:
the iRAM dump does not contain the monitor.

**Built or rehearsed only.** Nothing: the reading is static, and nothing was built or rehearsed for it.

**Open.** What section 8 lists.
