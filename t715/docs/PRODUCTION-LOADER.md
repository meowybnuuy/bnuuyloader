# The production loader: kboot1 to kboot7

Written 2026-11-24, completed 2026-11-25. The logs and the images named under `../loader/out/` are
the record of the tests on the computer that ran them; they are not in this repository.
The design is the one decided on 2026-11-24: PARAM holds the loader only; the kernel lives in a slot of CACHE
(`/dev/mmcblk0p20`; slot A at relative sector 131072, B at 262144, 64 MiB each, a 4 KiB header
`T7K1` then the Image then the device tree); the ARM32 part in S-Boot reads both headers, takes the
valid one with the highest generation, reads its Image and tree, hashes them, and only then makes
the monitor call; a ledger in S-Boot's RAM ring (`KBOOT: try` before anything risky, `KBOOT: up`
once the arm64 system runs) makes the boot after a failed attempt go to S-Boot's own kernel.

Code: `../loader/scripts/split_source.py` (`KBOOT_SOURCE`) and `../loader/stage2/stage2.c`
(`SLOT_RECORD`), built by `../loader/scripts/build_kboot.py --prod`; slots by
`../loader/scripts/build_slot.py`, written by `../loader/scripts/slot.py`; rehearsed by
`../loader/scripts/kboot_cases.py` (27 situations since `kboot6`, §6 and §7),
`../loader/scripts/guard_cases.py` (the ledger against the decisions the tablet logged, §6.4) and
`../loader/scripts/preflight.py --payload kboot`.

## 1. The cycles (2026-11-24)

| cycle | PARAM sha256 | what the ring says (masked lines, `../loader/scripts/hijack_lines.py RAW KBOOT`) | result |
|---|---|---|---|
| `kboot1` | `098e3c8f…` | `KBOOT: start: …`, then `KBOOT: no valid kernel in CACHE: S-Boot's kernel boots` | the way back works; slot A refused, cause unknown |
| `kboot2` | `49e9d327…` | `try`; first-level entry for 0x40000000 `4000000a`; slot A: the reader put 8 sectors, header words `314b3754 00000001 0054a200` (sound), no refusal; slot B: words `00003200 0000c800 00000000`, refused reason `0x101` (magic: never written); then `no valid kernel in CACHE`; **the sector printed was 0 for both slots** | the cause, below |
| `clear-ledger` | the original | a plain reboot, so that the boot before `kboot3` holds no `KBOOT: try` (a boot that tried and handed back makes the next one fall back once, by design) | — |
| `kboot3` | `15546aba…` | boot 1: `try`, both headers read (sectors 6684672 and 6815744), B generation 2 taken, image and tree hashed, EL2, eret; boot 2: `fallback for this boot: the previous attempt did not report that it was up` | **the kernel started from CACHE**, then the fallback; back in 75 s |

## 2. Why slot A was refused: r12 across S-Boot's reader

S-Boot's functions are C. Under the ARM procedure call standard (AAPCS) r0 to r3 and r12 (ip)
are the callee's to clobber; r4 to r11 are preserved. The slot loop kept the slot's first sector in
r12 across the call to S-Boot's eMMC reader (`0x23E17808`), which came back with r12 = 0 on the
tablet. So the log printed "sector 0", `accepted:` recorded the best slot as sector 0 (`mov r6,
r12`), and `chosen:` took r6 = 0 for "no slot": "no valid kernel in CACHE". The same trap sat in
`read_range` (its caller `try_slot` keeps the header's copy in r12 across the reader) and around the
two `printf` calls after `26:` (r12 is the chosen header there): with the first one fixed, the
second would have read garbage.

The emulator had not seen it: its stand-ins for S-Boot's `printf` and reader left r1 to r3 and r12
alone. **Fixed, both sides** (2026-11-24):
- `split_source.py`: `push {r3, r12}` / `pop {r3, r12}` around the reader in the slot loop, around the
  reader in `read_range`, and around the two `printf`s after `26:` (r3 goes with r12 to keep the stack
  8-byte aligned at the call). The other S-Boot calls were checked: r12 is restored by the code's own
  `pop` after them, or not live.
- `preflight.py`: `aapcs_return()`; both stand-ins now return r0 and clobber r1 to r3 (junk) and r12
  (0 after the reader, as on the tablet). With it, the unchanged `kboot2` fails 9 of the 12 cases
  exactly as the tablet did (`../loader/out/kboot-cases-strict-kboot2.log`): the bug is reproduced
  before it is fixed.

## 3. A test of nothing: the "corrupt" slots

`build_slot.make_slot(..., corrupt=True)` and `kboot_cases.variant(..., corrupt=True)` changed a
byte of the image **before** computing the header's hash, so the "corrupt" slot was a sound one
(`slot_is_sound()` said so). With the r12 fix the loader accepted them, as it must, and only stage 2's
own hash (baked in at build time) refused the kernel, by resetting the SoC. **Fixed**: `make_slot`
changes the byte after the hash, and `variant` passes `corrupt` to it. Why the same cases passed with
`kboot2` was not worked out (the r12 bug made the loader refuse everything, which looks like a pass
for the hand-back cases; not for the "start from the other slot" cases, which also passed).

With both fixes:
`../loader/scripts/kboot_cases.py ../loader/out/kboot3-logo.jpg --slot-good ../loader/out/slot-kboot3-gen2.img`:
**12 of 12 pass** (`../loader/out/kboot-cases-kboot3.log`), the corrupt slot is now refused in ARM32
and the other one is started, or S-Boot's kernel boots.

## 4. `kboot3`: the kernel from CACHE

- Kernel: `../kernel/smp/build-kernel/Image-boot` (sha256 `64a9eeee…`, 5 611 536 bytes): the
  test kernel with the eight-core method ([SMP-EXPERIMENT.md](SMP-EXPERIMENT.md) §8) and the test init.
- Device tree: `../loader/out/kboot3/gts28ltexx-arm64-kboot3.dtb`, boot arguments of
  `bootargs.overlay.dts` with `maxcpus=8` and no load test.
- Slot B, generation 2, written on the tablet with `../loader/scripts/slot.py write B 2 …` and read
  back (sha256 `442c08e7…`, the same as `../loader/out/slot-kboot3-gen2.img`); slot A still holds
  generation 1 (the first one-core test kernel), untouched.
- PARAM: `../loader/out/kboot3.param`. Rehearsal against the real ring after `clear-ledger`, with both
  slots as on the tablet: `KBOOT: try`, both headers read, B taken, image and tree hashed, stage 2
  enters EL1 (`../loader/out/preflight-kboot3.log`).

Result, 2026-11-24 (PARAM written, Linux back by itself after 75 s, original PARAM restored and
verified):

```
boot 34: KBOOT: try: the arm64 kernel of CACHE is tried this boot
         KBOOT: S-Boot's first-level entry for 0x40000000: 4000000a
         KBOOT: slot at sector 6684672: the reader put 8 sectors
         KBOOT: its header's words 0, 1 and 4: 314b3754 00000001 0054a200
         KBOOT: slot at sector 6815744: the reader put 8 sectors
         KBOOT: its header's words 0, 1 and 4: 314b3754 00000001 0055a200
         KBOOT: slot at sector 6815744, generation 2: the image is 5612032 bytes
         KBOOT: image at 42000000, device tree 79872 bytes at 5f000000: both read whole and hashed as the header says
         KBOOT: EL2 ... HCR_EL2=00000002 ... MIDR=410fd031 MPIDR=80000100
         KBOOT: EL2 kernel: ... every byte as built
         KBOOT: EL2 kernel: starting it at 42000000 with the device tree at 5f000000 ...
         (the kernel, pstore dumps/pstore/kboot3/: smp: Brought up 1 node, 8 CPUs; cpus online: 0-7;
          thermal zones 54/52/51 °C at rest; the test init restarts by software)
boot 35: KBOOT: fallback for this boot: the previous attempt did not report that it was up; S-Boot's kernel boots
```

**Proven on the tablet:** the production loader in PARAM reads both slots of CACHE through S-Boot's
reader, takes the newer valid one, hashes it in ARM32, starts the eight-core arm64 kernel from it,
and at the next boot, finding no `KBOOT: up`, gives the tablet back to its 32-bit system by itself.
Not yet proven: the arm64 system writing `KBOOT: up` (then the next boot tries again), a corrupt slot
on the device, a watchdog reset during an arm64 boot.

## 5. Open points of this loader

1. ~~**Stage 2 re-checks a hash baked in at build time** (`--define KERNEL_HASH=… DTB_HASH=…`). The
   ARM32 part checks the slot against its own header, but the EL2 part then refuses any kernel but the
   one the loader was built for. So an update of a slot also needs a new PARAM, which defeats the
   point of two slots.~~ **Fixed in `kboot4` (2026-11-24; §6):** the ARM32 part hands stage 2 a
   record of what it verified (the chosen header itself, at 0x40003000), and stage 2 checks
   the record, then the kernel and the tree against it. `kboot4.param` holds nothing of a kernel: built
   from either kernel it is the same image, byte for byte, and it starts whatever valid kernel a slot
   holds. A slot is updated without a new PARAM.
2. ~~A boot that tried and handed back (no valid slot) leaves `KBOOT: try` without `KBOOT: up`: the
   next boot falls back once before trying again.~~ **Fixed in `kboot6` (§7):** a try followed in the
   same boot by one of the loader's own hand-back lines does not count against the boots after it.
3. `push {r4}` before the `printf` at `mapped:` leaves the stack 4-byte aligned at a C call (AAPCS
   wants 8). It has worked on the tablet; it should be `push {r4, r5}`.
4. `build_sreset`'s message "AArch64 entry at 0x24220800" is wrong for kboot (node + 0x2000).
5. The arm64 system's side of the ledger (`t715-kboot-mark.service` writing `KBOOT: up`, and
   `t715-watchdog-keeper`) exists in the root image work stream (`../rootfs/`, in the fork). It had
   never run at the time of this list; it runs since 2026-11-25 (§8).
6. Seen while doing §6, not changed: `header_ok` adds the image and tree lengths in 32 bits, so a
   header crafted with a length near 4 GiB (and a matching own hash) would pass its size check and
   make the reader run over S-Boot's memory (the watchdog then resets; the ledger falls back). Stage 2
   sums in 64 bits. Only someone writing the slot could do it; worth a `cmp` per length one day.
7. ~~Seen too: the ledger looks for `KBOOT: up` with a length of 8 (`KBOOT: u`), not 9.~~ **Fixed in
   `kboot6`:** 9 characters (`t715-kboot-mark` writes `<3>KBOOT: up`, which the kernel logs as
   `KBOOT: up`).
8. Seen in §7, not changed: the test images' guard (`SRESET_SOURCE`) has the same `rfind` as the
   production loader had until `kboot6` (§7.3). A test image runs on a ring full of boots, for one
   boot, and we restore PARAM after it: left as proven.

## 6. `kboot4`: any valid kernel in a slot, and the ARM32 hash fixed

Built 2026-11-24 on the Mac only. The tablet never ran `kboot4`: it ran `kboot5`, then `kboot6`
(§7).

### 6.1 The record for EL2

- **ARM32** (`KBOOT_SOURCE`): before the slots are read, the 16 words at **0x40003000** are zeroed (so
  that stage 2 never takes what an earlier boot left in the memory). Once a slot's image and tree are
  read whole and hashed (`26:`), the chosen header's copy (r12: its first 0x38 bytes, its own FNV-1a 64
  at 0x30 included, then the slot's first sector at 0x38) is copied there, then `"T7KR"`
  (0x524B3754) as word 15, last; the 64-byte line is cleaned and invalidated (`clean_range`) before the
  monitor call. Constants: `build_ffree.KBOOT_RECORD_AT`, `KBOOT_RECORD_MAGIC`; `build_kboot.py` checks
  that the ARM32 code holds both.
- **Stage 2** (`stage2.c`, `KERNEL` + `SLOT_RECORD`, built by `build_stage2.py --slot`): invalidates the
  record's line, reads it once into its own copy, and refuses it (reason logged, `0x2xx`) unless: word
  15 is `T7KR` (`0x20a`: no record), the header's magic `T7K1` and version 1 (`0x201`, `0x202`), image
  and tree lengths non-zero whole sectors (`0x203`, `0x204`), header + image + tree within 64 MiB in
  64-bit arithmetic (`0x205`), image at 0x42000000 and tree at 0x5F000000 (`0x206`, `0x207`), a
  generation (`0x208`), the header's own FNV-1a 64 over its first 0x30 bytes (`0x209`), the image not
  running into the tree (`0x20b`). Then the same checks as before, with the record's lengths and
  hashes: arm64 Image magic, text offset 0, `image_size` as before, `KERNEL_AT + image_size <= DTB_AT`,
  the tree's magic and `totalsize` within its length, both FNV-1a 64 equal. A refusal returns; stage 1
  logs "stage 2 came back", resets the SoC, and the next boot, finding `KBOOT: try` without
  `KBOOT: up`, gives S-Boot its own kernel. The tree's address goes to the kernel in x0 as before.
- **No build-time hash on the production path:** `stage2.c` refuses to compile `PROD` with `KERNEL`
  without `SLOT_RECORD`, and `SLOT_RECORD` with any of `KERNEL_HASH`, `DTB_HASH`, `KERNEL_BYTES`,
  `DTB_BYTES`; `build_stage2.py` refuses `--prod --kernel`; `build_kboot.py --prod` checks that stage
  2 holds neither hash of the kernel it was given. `--image/--dtb/--gen` only build a slot image for
  convenience; without them `--prod` builds the loader alone.
- **The test chain is unchanged:** `build_kboot.py --test` (the kernel in PARAM, `--kernel` with the
  build's hashes) rebuilds `stage2-cpuf3.bin` and `cpuf3.param` byte for byte.

### 6.2 A bug in the ARM32 hash

`fnv64` (label 44) computes hi' = (lo << 8) + high32(lo × 0x1B3) + low32(hi × 0x1B3) mod 2^32, and
did `adds r10, r10, r11` then `adc r8, r8, #0`: the carry of that sum went back into hi'. That carry
is bit 64 of the product, which FNV-1a 64 drops. It shows when high32(lo × 0x1B3) (at most 0x1B2) +
low32(hi × 0x1B3) passes 2^32: about one byte in 10 to 20 million, so the 5.6 MB kernels passed by luck
and the full 17 MB kernel did not (the loader refused a sound slot). Fixed in all five places (four
unrolled bytes and the tail): `add r10, r10, r11`, no flags, no `adc`. The case "carry" (§6.3)
reproduces it: the good slot's kernel with three bytes chosen (a model of the old routine, searched
with numpy over the 2^24 choices) so that the old routine meets the carry; the pre-fix `kboot4` logo
fails exactly that case (it hands back: "not as its header says"), the fixed one starts the slot.

### 6.3 The cases (`kboot_cases.py`, 18 since `kboot4`)

The 12 situations of `kboot3` (§3), unchanged, then: (13) slot A holds another kernel than the one the loader was built
with → started; (14) slot B updated with another kernel, a generation higher, same PARAM → B
started; (15) the record missing (zeros, as if the ARM32 code had written none) → stage 2 refuses
(`0x20a`) and resets; (16) the record corrupt (its generation, which only the header's own hash
covers) → refused (`0x209`), reset; (17) the kernel changed in the memory after the ARM32 code hashed
it → "NOT every byte as the slot's header says", reset; (18) a kernel whose hash meets the carry of
§6.2 → started. "Another kernel" is `--slot-other`, or by default the good slot's kernel and tree with
a byte of each changed and hashed again (a kernel no build has seen). The emulator (`preflight.py`)
now carries the record from the ARM32 run into the AArch64 one, checks it is the chosen slot's header,
its sector and the magic, checks that stage 2 logged the slot's own hashes, and for kboot too checks
the page tables, the eret (ELR 0x42000000, the tree 0x5F000000 in x0, the PMU markers, the watchdog)
and the exception handler; `--tamper` and `--expect reset` make cases 15 to 17. The hand-back cases
allow 2 + 2 × (pieces + 1) reads (our bound, for kernels of several 4 MiB pieces).

Results (`../loader/out/`):
- `kboot-cases-kboot4.log`: the loader with the slot `slot-kboot4-gen3.img` (Image-thermal + the cpuf3
  tree): **18 of 18 pass**. In every "start" case the kernel is one the loader was not built from.
- `kboot-cases-kboot4-full.log`: the same with the full kernel (`../kernel/config/Image`, 17 424 400 bytes, 5
  pieces, with `gts28ltexx-bootargs.dtb`, `slot-kboot4-full-gen3.img`): **18 of 18 pass** (2 minutes;
  "both are corrupt" reads the storage 14 times, within the bound). The full kernel meets the carry
  of §6.2 by itself: the pre-fix `kboot4` logo refuses its sound slot ("not as its header says").
- `guard-cases-kboot4.log` (a local log): 5 of 5 pass.
- `../loader/scripts/preflight.py ../loader/out/cpuf3-logo.jpg --payload sreset --param
  ../loader/out/cpuf3.param --kernel-bundle ../loader/out/bundle-cpuf3.bin`: exit 0, its output
  unchanged; `guard_cases.py` on that logo: 0 failure.

### 6.4 The guard of a production logo: the ledger, against what the tablet decided

`guard_cases.py` rehearsed only the test images' guard and fails on any production logo (27 failures
on `kboot3` too). For a logo that holds `KBOOT: try` it now replays every decision the production
loader logged on the tablet that the dump holds (`KBOOT: try: …`, kboot1's `KBOOT: start: …`, and
`KBOOT: fallback for this boot`): the ring as dumped, the counter just before that line, CACHE empty;
the loader must decide what the tablet did. Then the fallback again with the ring turned so that the
boot before sits across the ring's start. Against `seclog-cpuf3.raw`: four decisions (kboot1, kboot2,
kboot3 boot 34: go on; kboot3 boot 35: fall back), all as on the tablet, and the turned one.

### 6.5 The images

- `../loader/out/kboot4.param` (sha256 `1f8711b8…`), `../loader/out/kboot4-logo.jpg`,
  `../loader/out/stage2-kboot4.bin` (14 024 bytes): the same bytes whether
  `build_kboot.py --prod --name kboot4 --gen 3` is given `../kernel/smp/build-kernel/Image-boot` with
  `../loader/out/kboot3/gts28ltexx-arm64-kboot3.dtb` or `Image-thermal` with
  `../loader/out/cpuf3/gts28ltexx-arm64-cpuf3.dtb`.
- `../loader/out/slot-kboot4-gen3.img`: Image-thermal + the cpuf3 tree, generation 3 (sha256 `b67b4937…`).
- `../loader/out/slot-kboot4-full-gen3.img`: the full kernel + `gts28ltexx-bootargs.dtb`, generation 3
  (sha256 `458e9796…`).
- `kboot1` to `kboot3` predate the record: under the new rehearsal their "start" cases fail (no record
  at 0x40003000), as they must; their logs stay as they were.

The plan at that point: slot B held generation 2 and slot A generation 1, so a slot written with
generation 3 would win, and the first cycle of `kboot4` could start a kernel the loader was not
built from (for instance the full kernel, written to slot A with `../loader/scripts/slot.py write A 3 …`).

## 7. `kboot6`: the ledger over the two boots before

Built 2026-11-24; on the tablet since 2026-11-25, in PARAM for good since that day (§8).

### 7.1 Why: the detour of `kboot5`

The first boot of the full 17 MB kernel from slot A (cycle `kboot5`; the loader of `kboot3` with the
two fixes of §6.2 and the r12 one) never came back: no fallback to the 32-bit system in 40 minutes,
no USB device. Our reading, which the ledger of `kboot1` to `kboot5` cannot survive:

1. B1 (BOOT): `KBOOT: try`, then something dies before stage 2 (perhaps S-Boot while the ARM32 code
   read the 17 MB kernel, up to 0x4309E200 where every proven kernel stopped at 0x4255A200). The ARM32
   code's watchdog resets the SoC, without the PMU's normal-boot markers (INFORM3).
2. B2: so S-Boot boots **RECOVERY**. The loader runs there too (S-Boot draws the logo in that mode as
   well, in this reading): the boot before tried and was never up, so it falls back, which in this boot
   means **S-Boot starts RECOVERY's kernel**, the owner's rescue image, not the 32-bit system in BOOT.
   The rescue's guard turns that boot into a software reset towards BOOT.
3. B3 (BOOT): the boot before (B2) logged only `KBOOT: fallback`, no `try`: the old ledger let it try
   again. B1 again: a loop that never reaches the 32-bit system.

### 7.2 The rule

A boot tries the arm64 kernel only if **neither of the two boots before it** holds a `KBOOT: try`
that, later in that same boot, has neither a `KBOOT: up` nor one of the loader's own hand-back lines
(they all end in `S-Boot's kernel boots`: that boot went on to S-Boot's kernel by itself, nothing hung).
So B3 falls back (B1 is two back); the 32-bit system comes up; B4 tries again (B2 and B3 fell back, no
`try`). With fewer than two boots before in the ring (a cold power-on), only those there are looked at;
none: it tries. The boots are the S-Boot logs, each from its `PARAM ENV VERSION` to the next one, looked
for no further back than 0x1F0000 bytes behind the write counter (2 MiB less 64 KiB: what is older is
written over), or from 0 when the counter is lower: the search never crosses into the ring's next turn.

**The hand-back clause** is a refinement of the rule as it was first worded, for two reasons. A loader
that handed back did not hang: S-Boot's own kernel booted in that very boot, so holding it against the
next two boots (§5.2) only delays the arm64 kernel. And the real ring disagrees with the literal rule:
`kboot3`'s first boot (34) had `kboot2`'s boot, which tried and found no valid kernel, two boots back;
the literal two-boot rule would have made it fall back, and the tablet's `clear-ledger` reboot would not
have been enough (it would take two). Stage 1's line when stage 2 refuses (`… the next boot goes to
S-Boot's kernel`) does not end so: that attempt counts as failed, as it must (its SoC reset is a failure).

### 7.3 Two more fixes in the same code

- **`rfind` could run away** (all loaders until `kboot5`): it lowered the position and then compared it
  with the lowest one. With the lowest position 0 (a search reaching the counter's start, which happens
  when the ring holds no boot before this one, after a power-on if S-Boot starts its counter low) it
  wrapped to 0xffffffff and went on round the ring, returning a position from the ring's other turn or
  never ending; the watchdog is not yet armed at the ledger. The rehearsal of a cold ring shows it on
  `kboot4` ("stopped: a loop taken for stuck"). Now the bound is tested before the step down.
- **`KBOOT: up`** is compared on its 9 characters (§5.7).

The ledger's code is a loop over the two boots (`69:`, labels 87 to 89), the try position kept on the
stack across the searches (`push {r0, r1}`, popped on every way out), r11 the lowest position.

### 7.4 The cases (`kboot_cases.py`, 27 since `kboot6`)

`preflight.py --ledger` now takes the boots after the real dump as a list, oldest first: `none`,
`failed`, `up`, `fallback`, `handback` (tried, no valid kernel), `failed-u` (failed, with a
`KBOOT: unready` line), and `cold` first for an empty ring with the counter at 0. The 18 of §6, then:
(19) the detour, `failed,fallback`: B3 falls back; (20) `failed,fallback,fallback`: B4 tries; (21)
`failed,none`: a failed try two back, falls back; (22) `up,none`: a try two back with its up, tries;
(23) `handback`: tries; (24) `failed-u`: falls back; (25) `cold`: tries; (26) `cold,failed`: falls
back; (27) `cold,up`: tries (one boot before only). The ledger's hand-backs read nothing from the
storage. Against `kboot4` (the ledger the tablet ran in `kboot5`), (19), (21) and (24) try where they
must fall back, and (25) runs away (stopped by the emulator's limit, §7.3).

Results (`../loader/out/`):
- `kboot-cases-kboot6.log` (slot `slot-kboot6-gen3.img`, Image-thermal + the cpuf3 tree): **27 of 27**.
- `kboot-cases-kboot6-full.log` (slot `slot-kboot6-full-gen3.img`, the full kernel `../kernel/config/Image`
  as of 2026-11-24, 17 424 400 bytes, with `gts28ltexx-bootargs.dtb`): **27 of 27** ("both are corrupt":
  14 reads, within the bound).
- `guard-cases-kboot6.log` (local): 6 of 6. The replays (§6.4) now compare with two models of the
  ledger written in Python on the same ring: the rule the tablet's loaders had must give what the tablet
  decided (it does, four times: the replay itself is sound), and `kboot6`'s rule must give what the
  loader decides (it does, four times, and twice with the ring turned so that the boots before sit
  across its start: the fallback of boot 35 and the try of boot 34, whose two-back boot is `kboot2`'s
  hand-back).
- The test images: `../loader/scripts/preflight.py ../loader/out/cpuf3-logo.jpg --payload sreset …` exit 0,
  output unchanged; `guard_cases.py` on that logo: 0 failure.

### 7.5 The images

- `../loader/out/kboot6.param` (sha256 `1a665678…`), `../loader/out/kboot6-logo.jpg`,
  `../loader/out/stage2-kboot6.bin` (14 024 bytes, the same as `kboot4`'s): the same bytes whether built
  with the full kernel and `gts28ltexx-bootargs.dtb` or with Image-thermal and the cpuf3 tree.
- Slots, generation 3: `../loader/out/slot-kboot6-gen3.img` (Image-thermal, sha256 `b67b4937…`, the same
  as `kboot4`'s) and `../loader/out/slot-kboot6-full-gen3.img` (the full kernel, sha256 `6a5173bf…`).

The question of §7.1 (what died in B1) is not answered here: `kboot6` only makes the tablet come back
to the 32-bit system after it, through RECOVERY at worst. A detour costs two boots (B2 in RECOVERY, B3
in BOOT), then B4 tries again if the loader is still in PARAM.

## 8. `kboot6` on the tablet (2026-11-25)

| cycle | what happened |
|---|---|
| `kboot6-bringup` | slot A generation 3 (the full kernel, bring-up tree): the kernel started, the initramfs found neither USB nor USERDATA (its archive had no `/sys`), the watchdog reset it after the bring-up limit; **the next boots went to the 32-bit system by themselves** (back at 661 s): the detour of §7.1 handled |
| `kboot6-bringup2` | slot A generation 5 (the same with `/sys`): **Omarchy 4.5 up on arm64**; no mark (`t715.kbootmark=0`), as the bring-up wants |
| daily | `t715-arm64-install loader kboot6.param` (PARAM verified, 1a665678…); slot B generation 6 = the same kernel with the daily tree; the running boot marked up by hand once its keeper, USB link and sshd were checked |
| daily reboots | two reboots: **slot B taken, arm64 back in 32 and 33 s**, each boot marked `KBOOT: up` by `t715-kboot-mark` |

What this proves: the ledger's two-boot rule in the field (a failed try is followed by the 32-bit
system without anyone's help, through a watchdog reset), the choice of the newest valid slot
(generation 6 over 5), and the mark carrying the arm64 system from one boot to the next. Not yet
seen: a cold boot by the power key with the loader in PARAM (S-Boot's counter low, the ring empty:
case 25 of the rehearsal, "cold": tries).

## 9. `kboot7`: the same loader, a picture in the logo (2026-11-25)

`kboot7` is `kboot6` with another `logo.jpg`: 2048 x 2049 pixels, black almost everywhere, and
carrying the owner's picture on the panel's 1536 x 2048. The ARM32 code after the JPEG and stage 2
are `kboot6`'s, byte for byte, and `kboot6` rebuilt with the default geometry is still the image of
§7.5, byte for byte. Only the logo changed; but the logo is where the exploit is, so everything was
measured again with S-Boot's own decoder in the emulator. The whole story is in
[SPLASH.md](SPLASH.md).

| What was checked | Result |
|---|---|
| The heap head after the decode | the 16 bytes the loader is forged for, and nothing after the last row: `build_ffree.py --verify` refuses any other image and removes it |
| What the decoder costs on a logo 2048 wide | no call to the allocator during the decode; the same number of instructions as on `kboot6`'s logo |
| The rehearsal | the 27 cases: 27 of 27, twice; the ledger against a real ring dump: 6 of 6 |

| Image | What | Outcome |
|---|---|---|
| `kboot7-probe` | the logo without its trapped block: 2048 rows, no loader | the picture on the panel; the rescue (below) took it for a lost loader, wrote `kboot6` back and restarted: arm64 again 35 s after the restart |
| `kboot7-cas1` | the loader, the file's channels ordered `2,0,1` | fired; Omarchy up; the colours permuted |
| `kboot7-cas2` | the same, ordered `0,2,1` | built, not tried |
| `kboot7-cas3` | the same, ordered `0,1,2` | fired; Omarchy up; the colours of the picture. **In PARAM since** (fe39aea0…) |

**The rescue behind it.** The 32-bit root had been removed from the tablet that day: a loader that
did not fire would have left it restarting for good. Before any `kboot7` was written, a rescue was
put in BOOT (RECOVERY followed): the 32-bit port's own initramfs with one more knob, which writes
the loader known to work back when PARAM holds neither the stock image nor a loader it knows
([RESCUE.md](RESCUE.md)). It was first built for `kboot6` alone, then for `kboot7-cas3`, with
`kboot6` as a loader to leave alone.

**The ledger, seen once more.** One boot not marked up (the mark service disabled for one boot):
the loader handed the next two boots to BOOT, where the rescue found the loader known to work and
had nothing to do; the boot after tried arm64 again.

**A trap met.** S-Boot rewrites the end of PARAM whenever it boots a kernel itself, a fallback
boot included. The first rescue compared the whole partition, so it took its own good loader for a
lost one at each fallback boot and restarted after about 7 s. Since, a loader is named by PARAM's
first 7,340,032 bytes, by the rescue and by `t715-arm64-install` alike ([RESCUE.md](RESCUE.md),
section 3).

## State on 2026-11-25

**Proven on the tablet.** `kboot6` was in PARAM for good, and the tablet booted Omarchy 4.5 on arm64 by
itself at every boot: `KBOOT: try`, user space in about 13 s, then the keeper, the USB network and
sshd (the side of §5.5, now running), then `KBOOT: up` from `t715-kboot-mark`, so the next boot tries
again. The ledger holds in the field: the bring-up boot without USB was reset by the watchdog and the
32-bit system came back by itself, and the two daily reboots came back in 32 s and 33 s. The cold boot
by the power key with the loader in PARAM, not yet seen in §8, is done (the owner, 2026-11-25): arm64,
user space in 12 s, marked up. Since 2026-11-25 CACHE holds slot B, generation 10 (the full kernel,
5ce33d24…, 6.12.114-00105-g96a2510ad486, `#2`, with the daily tree) and slot A, generation 9 (the
previous kernel, 481a247e…, 00103, with the same tree).

**Built or rehearsed only.** A corrupt slot on the device and the refusals of stage 2 (record missing
or corrupt, kernel changed in the memory) are cases of the emulator: not yet seen on the tablet. The
27 cases pass on two slots (27 of 27), and the ledger is replayed against the tablet's own decisions
(6 of 6). `kboot4` was built on the Mac only; the tablet runs `kboot7` (§9): `kboot6`'s code under
another logo.

**Open.** What died in B1 of `kboot5` (§7.1) is not answered. Points 3, 4, 6 and 8 of §5 are not
changed. There is no on-tablet way to boot BOOT's system once: today only
`t715-arm64-install unloader`, which puts the original PARAM back, for good. Since later that day,
BOOT and RECOVERY hold the rescue, and no 32-bit system (§9).
