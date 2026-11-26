/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 elkir0
 */
/* Stage 2: the first C code at EL2, called by scripts/a64_sreset.S once the MMU and the caches are
   on, the vector table is in place and a stack is set up. It proves what a loader needs from C —
   the stack by recursion, 64-bit arithmetic, .data, .rodata, .bss, the screen — and writes what it
   found into S-Boot's log ring, which stage 1 maps without cache: what is written is in the memory
   at once. MARKER ("HIJACK3: <id>") and the options come from build_stage2.py:

     EMMC_CHECK  check what S-Boot's reader (called from the ARM32 code) put at 0x40000000
     EL1_TEST    enter EL1 with the AArch64 image S-Boot's reader put at 0x40080000 (boot_el1.S)
     KERNEL      start an arm64 Linux image and its device tree, once both are hashed as built
     SLOT_RECORD with KERNEL: the production loader's kernel, hashed as the header of the slot the ARM32
                 code chose says (the record it hands over at RECORD_AT), not as built
     HANDOFF, WATCHDOG_PROOF, WATCHDOG_ARM: the registers as S-Boot left them; the watchdog
     PROD        the production loader: no self-test (the stack, .bss, the screen), only what is asked for
     SMP_EXP     the one-core experiment: a secondary core powered on from here, to learn whether the
                 monitor's call works on it too (smp_stub32.S, smp_stub64.S; build_stage2.py --smp-stubs) */
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define RING            ((volatile uint8_t *)0x26000000u)
#define RING_SIZE       0x200000u
#define COUNTER         (*(volatile uint32_t *)0x25FFFFFCu)
#define FRAMEBUFFER     ((volatile uint32_t *)0x67000000u)     /* 1536 x 2048, XRGB8888 */
#define FB_ROWS_SHOWN   1024u                                   /* what the tests paint: the top half */
#define DECON_UPDATE    (*(volatile uint32_t *)0x13801410u)
#define DECON_TRIGGER   (*(volatile uint32_t *)0x13802040u)

#ifndef PROD                                    /* the self-test's data: the production loader has none */
static uint64_t bss_table[8192];                                 /* 64 KiB that nothing has written yet */
static volatile uint64_t data_value = 0x0123456789abcdefULL;    /* in the image, and read from there */
static const char rodata_text[] = "the data came with the image";
#endif

static void barrier(void) {
    __asm__ volatile ("dsb sy" : : : "memory");
}

/* ---- the log: a line is a marker, fields, a new line; the counter moves with every byte ---- */

static void put_byte(uint8_t byte) {
    uint32_t position = COUNTER;
    RING[position & (RING_SIZE - 1)] = byte;
    COUNTER = position + 1;
}

static void put_text(const char *text) {
    while (*text) {
        put_byte((uint8_t)*text++);
    }
}

static void put_hex(uint64_t value, unsigned digits) {          /* digits: 2, 8 or 16 */
    for (unsigned shift = digits * 4; shift; shift -= 4) {
        put_byte((uint8_t)"0123456789abcdef"[(value >> (shift - 4)) & 15]);
    }
}

static void begin(void) {
    put_text(MARKER);
}

static void field(const char *name, uint64_t value, unsigned digits) {
    put_byte(' ');
    put_text(name);
    put_hex(value, digits);
}

static void end(void) {
    put_byte('\n');
    barrier();                                                   /* ordered before anything that follows */
}

/* ---- the screen, and memory a controller wrote ---- */

__attribute__((unused)) static void clean(const volatile void *address, size_t length) {   /* the framebuffer is cached: clean it to the memory */
    uintptr_t last = ((uintptr_t)address & ~(uintptr_t)63) + length;
    for (uintptr_t line = (uintptr_t)address & ~(uintptr_t)63; line < last; line += 64) {
        __asm__ volatile ("dc cvac, %0" : : "r"(line) : "memory");
    }
    barrier();
}

#if defined(EMMC_CHECK) || defined(KERNEL)
static uint64_t fnv1a(const volatile uint8_t *bytes, size_t length) {   /* what came from the storage against what was built */
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < length; i++) {
        hash = (hash ^ bytes[i]) * 0x100000001b3ULL;
    }
    return hash;
}
#endif

#if defined(EMMC_CHECK) || defined(EL1_TEST) || defined(KERNEL)
static void invalidate(const volatile void *address, size_t length) {   /* what a controller wrote: the cache may hold nothing of it */
    uintptr_t last = ((uintptr_t)address & ~(uintptr_t)63) + length;
    for (uintptr_t line = (uintptr_t)address & ~(uintptr_t)63; line < last; line += 64) {
        __asm__ volatile ("dc ivac, %0" : : "r"(line) : "memory");
    }
    barrier();
}
#endif

__attribute__((unused)) static void frame(void) {                /* the display controller's command mode: ask for the frame, start it */
    DECON_UPDATE |= 1;
    barrier();
    DECON_TRIGGER = 0xE0000003u;
    barrier();
    __asm__ volatile ("isb" : : : "memory");
}

/* ---- what the tests check ---- */

#ifndef PROD
static uint64_t fib(uint32_t n) {        /* the stack, by recursion: fib(30) needs about 30 frames deep */
    return n < 2 ? n : fib(n - 1) + fib(n - 2);
}
#endif

#ifdef EMMC_CHECK
#define LOADED          ((const volatile uint8_t *)0x40000000u)
#define LOADED_BYTES     0x100000u                     /* the first 1 MiB of PARAM, by S-Boot's reader, from ARM32 */
#endif

#ifdef EL1_TEST
#define EL1_HEADER      ((const volatile uint32_t *)0x40080000u)
#endif

#ifdef KERNEL
/* An arm64 Linux image and its device tree, read by S-Boot's reader from ARM32 to KERNEL_AT and
   DTB_AT. Both are hashed where they were read and start only if every byte is as expected, so a
   failed or short read starts nothing:
     - the test chain (KERNEL_LOAD in split_source.py, the kernel inside PARAM): as built, over
       KERNEL_BYTES and DTB_BYTES against KERNEL_HASH and DTB_HASH (scripts/build_kboot.py --test);
     - the production loader (SLOT_RECORD; KBOOT_SOURCE in split_source.py, the kernel in a slot of
       CACHE): as the header of the slot the ARM32 code chose says, lengths and hashes taken from the
       record it hands over at RECORD_AT. Nothing of a particular kernel is built into this image:
       a slot is updated without a new PARAM (t715/docs/PRODUCTION-LOADER.md, 5.1).
   Nothing here changes a clock or a voltage: the kernel runs on what S-Boot left, measured by the
   handoff report above. */
#define KERNEL_IMAGE    ((const volatile uint32_t *)KERNEL_AT)
#define KERNEL_HEADER(offset) KERNEL_IMAGE[(offset) / 4]
#define DTB_WORDS       ((const volatile uint32_t *)DTB_AT)
#ifdef SLOT_RECORD
#if defined(KERNEL_HASH) || defined(DTB_HASH) || defined(KERNEL_BYTES) || defined(DTB_BYTES)
#error "SLOT_RECORD takes the kernel's lengths and hashes from the slot the ARM32 code chose, never from the build"
#endif
#define AS_EXPECTED     " every byte as the slot's header says"
#define NOT_AS_EXPECTED " NOT every byte as the slot's header says: it will not be started"
#else
#ifdef PROD
#error "the production loader (PROD) takes the kernel from the slot the ARM32 code chose: build it with --slot (SLOT_RECORD)"
#endif
#ifndef KERNEL_HASH
#error "KERNEL_HASH is not defined: build stage 2 with scripts/build_kboot.py"
#endif
#ifndef DTB_HASH
#error "DTB_HASH is not defined: build stage 2 with scripts/build_kboot.py"
#endif
#define AS_EXPECTED     " every byte as built"
#define NOT_AS_EXPECTED " NOT every byte as built: it will not be started"
#endif

static uint32_t big_endian(uint32_t value) {   /* the device tree's header is big-endian */
    return __builtin_bswap32(value);
}

/* kernel_bytes and tree_bytes: what was read, in whole sectors; kernel_want and tree_want: their FNV-1a 64 */
static bool kernel_ready(uint32_t kernel_bytes, uint32_t tree_bytes, uint64_t kernel_want, uint64_t tree_want) {
    const uint32_t magic = KERNEL_HEADER(0x38), text_offset = KERNEL_HEADER(8), image_size = KERNEL_HEADER(0x10);
    const uint32_t fdt_magic = DTB_WORDS[0], fdt_size = big_endian(DTB_WORDS[1]);
    const uint64_t kernel_hash = fnv1a((const volatile uint8_t *)KERNEL_IMAGE, kernel_bytes);
    const uint64_t tree_hash = fnv1a((const volatile uint8_t *)DTB_WORDS, tree_bytes);
    /* image_size is what the kernel occupies once it runs (its .bss included): more than the bytes read */
    const bool fits = image_size >= kernel_bytes - 511u && image_size <= 0x8000000u && KERNEL_AT + image_size <= DTB_AT;
    const bool tree_ok = fdt_magic == 0xedfe0dd0u && fdt_size >= 0x1000u && fdt_size <= tree_bytes;   /* 0xd00dfeed read little-endian */
    const bool as_expected = kernel_hash == kernel_want && tree_hash == tree_want;
    const bool sane = magic == 0x644d5241u && text_offset == 0 && fits && tree_ok;
    begin();
    field("kernel: magic=", magic, 8);
    field("text_offset=", text_offset, 8);
    field("image_size=", image_size, 8);
    field("dtb: magic=", fdt_magic, 8);
    field("totalsize=", fdt_size, 8);
    field("hash=", kernel_hash, 16);
    field("tree=", tree_hash, 16);
    put_text(!sane ? " the headers are not as expected: it will not be started"
              : as_expected ? AS_EXPECTED : NOT_AS_EXPECTED);
    end();
    return sane && as_expected;
}

#ifdef SLOT_RECORD
/* The record the ARM32 code leaves for this stage (split_source.py KBOOT_SOURCE, after label 26): 16 words
   at RECORD_AT, zeroed before the slots are read, written once a slot's image and tree were read whole and
   hashed, cleaned to the memory before the monitor call:
     words 0 to 13  the chosen slot's header as the ARM32 code checked it (scripts/build_slot.py): 0 "T7K1",
                    1 version 1, 2 generation, 3 flags, 4 image bytes, 5 where it goes, 6 tree bytes, 7 where
                    it goes, 8-9 the image's FNV-1a 64 (low, high), 10-11 the tree's, 12-13 the FNV-1a 64 of
                    words 0 to 11;
     word 14        the slot's first sector (logged only);
     word 15        "T7KR", the record's own magic, written last.
   It is checked as the ARM32 code's header_ok checks a header (64-bit sums here), so that a record that
   is missing, left over or damaged on its way starts nothing: stage 2 then comes back, stage 1 resets
   the SoC, and the next boot, finding "KBOOT: try" without "KBOOT: up", gives S-Boot its own kernel. */
#define RECORD_AT       0x40003000u
#define RECORD          ((const volatile uint32_t *)RECORD_AT)
#define RECORD_WORDS    16u
#define RECORD_MAGIC    0x524b3754u             /* "T7KR" */
#define SLOT_MAGIC      0x314b3754u             /* "T7K1" */
#define SLOT_BYTES      0x4000000u              /* a slot: 64 MiB, its 4 KiB header included */

static uint32_t record[RECORD_WORDS];           /* the record as read once: everything below uses this copy */

static unsigned record_refused(void) {          /* 0 if the record is sound, else the reason (as header_ok's, + 0x200) */
    invalidate(RECORD, RECORD_WORDS * 4u);
    for (unsigned i = 0; i < RECORD_WORDS; i++) {
        record[i] = RECORD[i];
    }
    const uint64_t header_hash = fnv1a((const volatile uint8_t *)record, 0x30u);
    const uint64_t image = record[4], tree = record[6];
    if (record[15] != RECORD_MAGIC) return 0x20a;                           /* no record: the ARM32 code wrote none */
    if (record[0] != SLOT_MAGIC) return 0x201;
    if (record[1] != 1u) return 0x202;
    if (image == 0 || image % 512u) return 0x203;
    if (tree == 0 || tree % 512u) return 0x204;
    if (0x1000u + image + tree > SLOT_BYTES) return 0x205;
    if (record[5] != KERNEL_AT) return 0x206;
    if (record[7] != DTB_AT) return 0x207;
    if (record[2] == 0) return 0x208;
    if (header_hash != ((uint64_t)record[13] << 32 | record[12])) return 0x209;
    if (KERNEL_AT + image > DTB_AT) return 0x20b;                           /* the image read would run into the tree */
    return 0;
}

static bool slot_kernel_ready(void) {
    const unsigned refused = record_refused();
    begin();
    put_text(" kernel: the record of the ARM32 code at ");
    put_hex(RECORD_AT, 8);
    put_text(":");
    field("slot at sector ", record[14], 8);
    field("generation ", record[2], 8);
    field("image ", record[4], 8);
    field("at ", record[5], 8);
    field("tree ", record[6], 8);
    field("at ", record[7], 8);
    field("hashes ", (uint64_t)record[9] << 32 | record[8], 16);
    field("", (uint64_t)record[11] << 32 | record[10], 16);
    if (refused) {
        field("REFUSED, reason ", refused, 8);
        put_text(": nothing is started, the SoC is reset");
    } else {
        put_text(" sound: the kernel and its tree are checked against it");
    }
    end();
    if (refused) {
        return false;
    }
    invalidate(KERNEL_IMAGE, record[4]);
    invalidate(DTB_WORDS, record[6]);
    return kernel_ready(record[4], record[6], (uint64_t)record[9] << 32 | record[8], (uint64_t)record[11] << 32 | record[10]);
}
#endif

static void normal_boot_marker(void) {
    /* What the 32-bit kernel writes first thing (arch/arm/mach-exynos/exynos.c): with these in the
       PMU, any later reset (a panic, the watchdog, init's restart) goes back to BOOT and out of the
       charger mode, so the tablet returns to its own system and the loader's guard skips the test. */
    *(volatile uint32_t *)0x105C0808u = 0x12345678;   /* INFORM2 */
    *(volatile uint32_t *)0x105C080Cu = 0x12345670;   /* INFORM3 */
    barrier();
}
#endif

#if defined(EL1_TEST) || defined(KERNEL)
void boot_el1(uint64_t entry, uint64_t device_tree);   /* boot_el1.S: from here into EL1, as Linux is entered */
#endif

/* ---- what the loader finds when it arrives, and the watchdog ----
   These only read, except the watchdog (WATCHDOG_PROOF, WATCHDOG_ARM). Nothing here changes a
   clock or a voltage: the first kernel must run exactly on what S-Boot left (see HANDOFF). */

#define MMIO32(address)  (*(const volatile uint32_t *)(address))

__attribute__((unused)) static void reset(void) {   /* what Linux writes for `reboot` */
    *(volatile uint32_t *)0x105C0400u = 1;
    for (;;) {
        __asm__ volatile ("wfe");
    }
}

#ifdef HANDOFF
static void dump(const char *name, uintptr_t base, const unsigned *offsets, unsigned count) {
    begin();
    put_text(" handoff: ");
    put_text(name);
    put_text(" @");
    put_hex(base, 8);
    for (unsigned i = 0; i < count; i++) {
        put_byte(' ');
        put_hex(MMIO32(base + offsets[i]), 8);
    }
    end();
}

static void handoff_report(void) {
    /* Registers as mainline's clk-exynos5433.c names them: a clock unit of a CPU cluster has its PLL at
       0x100 (CON0: mdiv [26:16], pdiv [13:8], sdiv [2:0]; CON1 at 0x104), the selectors at 0x200 (the PLL
       or the 24 MHz crystal), 0x204 (the bus PLL), 0x208 (which of those feeds the cluster), the dividers
       at 0x600 and 0x604, the gates at 0x800 and 0x900. */
    static const unsigned cluster[] = {0x100, 0x104, 0x200, 0x204, 0x208, 0x600, 0x604, 0x800, 0x900};
    static const unsigned mif[] = {0x100, 0x120, 0x130, 0x200, 0x204, 0x208};   /* 0x600: its read aborted on the bus (2026-11-24) */
    static const unsigned peris[] = {0x800, 0x900};
    static const unsigned pmu[] = {0x404, 0x408, 0x40c};
    static const unsigned wdt[] = {0x00, 0x04, 0x08, 0x0c};
    dump("APOLLO (A53) clock unit: PLL CON0 CON1, selectors, dividers, gates", 0x11900000u, cluster, 9);
    dump("ATLAS (A57) clock unit: the same", 0x11800000u, cluster, 9);
    dump("MIF clock unit: memory PLL, bus PLL, media PLL CON0, selectors", 0x105b0000u, mif, 6);
    dump("PERIS clock gates (0x800 ACLK, 0x900 PCLK: bit 17 is the A53 watchdog's)", 0x10040000u, peris, 2);
    dump("PMU: 0x404 RST_STAT, 0x408 WDT reset disable, 0x40c WDT reset mask", 0x105c0000u, pmu, 3);
    dump("watchdog: WTCON WTDAT WTCNT WTCLRINT", 0x10020000u, wdt, 4);
}
#endif

#if defined(SMP_EXP) && !(defined(WATCHDOG_ARM) && defined(PROD))
#error "SMP_EXP needs --watchdog-arm (the watchdog is the clock and the way back) and --prod (nothing else runs)"
#endif

#if defined(WATCHDOG_PROOF) || defined(WATCHDOG_ARM)
#define WDT_CON          (*(volatile uint32_t *)0x10020000u)
#define WTDAT            (*(volatile uint32_t *)0x10020004u)
#define WTCNT            (*(volatile uint32_t *)0x10020008u)
#define WDT_PCLK         66666667u              /* pclk_wdt_apollo, as Linux reads it */
#define WDT_TICKS        (WDT_PCLK / 256 / 128) /* 2034 a second with the widest prescaler and divider */

static uint32_t watchdog_arm(unsigned seconds) { /* as the stock kernel and mainline's driver do it */
    *(volatile uint32_t *)0x10040900u |= 1u << 17;                 /* its clock, if S-Boot left it gated */
    *(volatile uint32_t *)0x105c0408u &= ~((1u << 24) | (1u << 23));   /* the PMU lets a watchdog reset through */
    *(volatile uint32_t *)0x105c040cu &= ~(1u << 24);
    const uint32_t ticks = seconds * WDT_TICKS;
    WTDAT = ticks;
    WTCNT = ticks;
    WDT_CON = (255u << 8) | (3u << 3) | (1u << 5) | 1u;   /* prescaler 255, divided by 128, on, reset on, no interrupt */
    barrier();
    return WTCNT;
}
#endif

#ifdef WATCHDOG_PROOF
static void watchdog_proof(void) {
    /* Armed for 4 seconds, then nothing is done until it fires. If it does not count, the software
       reset ends the test all the same: the tablet never stays frozen on this test. */
    const uint32_t start = watchdog_arm(4);
    for (volatile unsigned i = 0; i < 30000000u; i++) {
    }
    const uint32_t later = WTCNT;
    begin();
    field("watchdog: armed for 4 s, WTCON=", WDT_CON, 8);
    field("WTCNT at first=", start, 8);
    field("a moment later=", later, 8);
    end();
    if (later != 0 && later < start) {
        begin();
        put_text(" watchdog: it counts down: nothing more will be done, the reset should come from it");
        end();
        for (volatile unsigned long i = 0; i < 4000000000ul; i++) {
        }
    }
    begin();
    put_text(" watchdog: it does not count: software reset instead");
    end();
    reset();
}
#endif

#ifdef SMP_EXP
#include "smp_stubs.h"
/* The one-core experiment (2026-11-24): does the monitor's call work anywhere else than on the boot
   CPU? A53 core 1 (MPIDR 0x80000101, PMU index 5) is powered on as the stock 32-bit kernel does it
   (arch/arm/mach-exynos/platsmp.c of the release tree), and what it runs is smp_stub32.S, then, if the
   monitor switches it too, smp_stub64.S. Both write into S-Boot's log ring and into a scratch page.
   This core waits on the watchdog's counter (the generic one does not run), then resets the SoC: whatever
   the secondary did ends there. Nothing here changes a clock or a voltage.
   The 2 MiB at STUB32_AT are mapped without cache for this image (a64_sreset.S, SMPX): what this core
   writes there is in the memory at once, and what the secondary writes there is read from it. */
#define STUB32_AT           ((uintptr_t)0x41000000u)
#define STUB64_AT           ((uintptr_t)0x41000800u)
#define SCRATCH32           ((volatile uint32_t *)0x41001000u)
#define SCRATCH_WORDS       48u
#define PMU_BASE            0x105C0000u
#define CORE(n)             ((uintptr_t)PMU_BASE + 0x2000u + 0x80u * (n))    /* n = Aff0 + 4 * Aff1, as the stock kernel numbers it */
#define CORE_CONF(n)        (*(volatile uint32_t *)(CORE(n) + 0x00u))
#define CORE_STATUS(n)      (*(volatile uint32_t *)(CORE(n) + 0x04u))
#define CORE_OPTION(n)      (*(volatile uint32_t *)(CORE(n) + 0x08u))
#define CORE_DUR(n, i)      (*(volatile uint32_t *)(CORE(n) + 0x10u + 4u * (i)))
#define KFC_NONCPU_OPTION   (*(volatile uint32_t *)(PMU_BASE + 0x2428u))
#define UP_SCHEDULER        (*(volatile uint32_t *)(PMU_BASE + 0x0120u))
#define SYSRAM_NS           ((uintptr_t)0x0207B000u)                     /* the monitor's window: one boot address for every core */
#define BOOT_ADDRESS        (*(volatile uint32_t *)(SYSRAM_NS + 0x1Cu))
#define BOOT_FLAG(i)        (*(volatile uint32_t *)(SYSRAM_NS + 0x28u + 4u * (i)))
#define SECONDARY           5u                                /* A53 core 1 */
#ifndef SMP_STUBS_SUM
#error "SMP_STUBS_SUM is not defined: build stage 2 with scripts/build_smp.py"
#endif

static uint64_t this_core(void) {
    uint64_t value;
    __asm__ volatile ("mrs %0, mpidr_el1" : "=r"(value));
    return value;
}

static void smp_show(const char *when) {
    begin();
    put_text(" smp: ");
    put_text(when);
    put_text(": PMU core 5 CONF STATUS OPTION 0x0c DURATION0-3");
    for (unsigned offset = 0; offset <= 0x1Cu; offset += 4u) {
        put_byte(' ');
        put_hex(MMIO32(CORE(SECONDARY) + offset), 8);
    }
    field("KFC_NONCPU_OPTION=", KFC_NONCPU_OPTION, 8);
    field("UP_SCHEDULER=", UP_SCHEDULER, 8);
    field("boot_addr=", BOOT_ADDRESS, 8);
    put_text(" boot_flags(index 0 to 7):");
    for (unsigned i = 0; i < 8; i++) {
        put_byte(' ');
        put_hex(BOOT_FLAG(i), 8);
    }
    end();
}

static void smp_words(const char *what, unsigned first, unsigned count) {   /* words, 4 bytes each: the 64-bit ones come in pairs, low first */
    begin();
    put_text(" smp: the scratch page, words 0x");
    put_hex(first, 2);
    put_text(" to 0x");
    put_hex(first + count - 1u, 2);
    put_text(" (");
    put_text(what);
    put_text("):");
    for (unsigned i = first; i < first + count; i++) {
        put_byte(' ');
        put_hex(SCRATCH32[i], 8);
    }
    end();
}

static void smp_experiment(void) {
    uint32_t value;
    begin();
    put_text(" smp: one core, without Linux: this core MPIDR=");
    put_hex(this_core(), 16);
    put_text("; A53 core 1 (PMU index 5) is powered on as the stock 32-bit kernel does it, to run the ARM32 stub at ");
    put_hex(STUB32_AT, 8);
    put_text(" and call the monitor for the AArch64 stub at ");
    put_hex(STUB64_AT, 8);
    put_text("; nothing changes a clock or a voltage");
    end();
    smp_show("as S-Boot left it");

    /* The stubs where the secondary runs them, the scratch page empty. The block is not cached on this
       core; the clean is for the record. */
    uint8_t *stubs = (uint8_t *)STUB32_AT;
    for (unsigned i = 0; i < sizeof(smp_stubs); i++) {
        stubs[i] = smp_stubs[i];
    }
    for (unsigned i = 0; i < SCRATCH_WORDS; i++) {
        SCRATCH32[i] = 0;
    }
    clean(stubs, sizeof(smp_stubs) + SCRATCH_WORDS * 4u);
    uint32_t sum = 0;
    for (unsigned i = 0; i < sizeof(smp_stubs) / 4u; i++) {
        sum += *(volatile uint32_t *)(STUB32_AT + 4u * i);
    }
    begin();
    put_text(" smp: the stubs are at ");
    put_hex(STUB32_AT, 8);
    put_text(": ");
    put_hex(sizeof(smp_stubs), 8);
    put_text(" bytes, the sum of their words as read back ");
    put_hex(sum, 8);
    end();
    if (sum != SMP_STUBS_SUM) {
        begin();
        put_text(" smp: NOT the sum as built (");
        put_hex(SMP_STUBS_SUM, 8);
        put_text("): the core is not powered on; the SoC is reset");
        end();
        reset();
    }

    /* What the monitor restored for this core when it entered EL2: S-Boot's sp_usr. The monitor's SMC path
       runs on the caller's SP_EL0 (t715/docs/SMP-MONITOR.md), and a secondary that never ran has none
       of its own: the stub loads this one as its sp_usr before the call. */
    uint64_t sp_el0;
    __asm__ volatile ("mrs %0, sp_el0" : "=r"(sp_el0));
    SCRATCH32[40] = (uint32_t)sp_el0;
    SCRATCH32[41] = (uint32_t)(sp_el0 >> 32);
    begin();
    put_text(" smp: this core's SP_EL0 at EL2 (the monitor's, from S-Boot's sp_usr; the secondary takes it as its own before the call): ");
    put_hex(sp_el0, 16);
    end();
    barrier();

    /* the watchdog first: it is the clock of the waits below, and the way back */
    const uint32_t armed = watchdog_arm(12);

    /* 1. the entry point, before anything else, as the stock kernel writes it before powering any core */
    BOOT_ADDRESS = STUB32_AT;
    barrier();

    /* 2. the cluster and core options and the up scheduler: exynos5433_pmu_cpu_init(), register for register */
    value = KFC_NONCPU_OPTION;
    KFC_NONCPU_OPTION = (value & ~1u) | 2u;                   /* no counter, a feedback */
    value = CORE_OPTION(SECONDARY);
    CORE_OPTION(SECONDARY) = value | 1u | 2u | (1u << 28);    /* counter, feedback, USE_SMPEN */
    value = CORE_DUR(SECONDARY, 0);
    CORE_DUR(SECONDARY, 0) = ((value | (0xFu << 20)) & ~(0xFu << 4)) | (1u << 4);   /* WAIT_RESET, SCALL = 1 */
    UP_SCHEDULER |= 1u | 2u;                                   /* the EAGLE and the KFC CPU */
    barrier();
    smp_show("options set");

    /* 3. power on: exynos5433_core_power_up() */
    CORE_OPTION(SECONDARY) &= ~2u;                             /* no feedback: the stock kernel's CORE_FEEDBACK_CHECK_DISABLE */
    for (unsigned i = 0; i < 4u; i++) {
        value = CORE_DUR(SECONDARY, i);
        CORE_DUR(SECONDARY, i) = (value & ~(0xFFu << 4)) | (0x11u << 4);
    }
    barrier();                                                 /* the entry point and the stubs are in the memory first */
    CORE_CONF(SECONDARY) |= 0xFu;

    /* powered? The stock kernel waits 10 ms at most, a millisecond at a time. */
    unsigned waited = 0;
    while (waited < 10u && (CORE_STATUS(SECONDARY) & 0xFu) != 0xFu) {
        const uint32_t start = WTCNT;                        /* 2 ticks is a millisecond; a still counter ends it sooner */
        for (uint32_t spin = 0; spin < 20000u && (start - WTCNT) < 2u; spin++) {
        }
        waited++;
    }
    const uint32_t powered = CORE_STATUS(SECONDARY);

    /* 4. what the secondary does: up to 3 s on the watchdog's counter, less if its last stage comes.
       As in the stock release loop, the entry point is written again and an event is sent; here every pass. */
    uint32_t stage = SCRATCH32[0], passes = 0;
    const uint32_t wait_start = WTCNT;
    while (passes < 4000000u && (wait_start - WTCNT) < 3u * WDT_TICKS) {
        stage = SCRATCH32[0];
        if (stage == 5u || stage >= 0x80u) {
            break;
        }
        BOOT_ADDRESS = STUB32_AT;
        barrier();
        __asm__ volatile ("sev" : : : "memory");
        passes++;
    }
    barrier();
    stage = SCRATCH32[0];

    /* 5. what happened */
    smp_show("after the wait");
    begin();
    put_text(" smp: the watchdog was armed for 12 s (WTCNT ");
    put_hex(armed, 8);
    put_text("); the core's STATUS after the power-on ");
    put_hex(powered, 8);
    put_text(" (");
    put_hex(waited, 2);
    put_text(" milliseconds waited); then ");
    put_hex(passes, 8);
    put_text(" passes and ");
    put_hex(wait_start - WTCNT, 8);
    put_text(" watchdog ticks (2034 a second); the secondary's last stage ");
    put_hex(stage, 2);
    end();
    smp_words("the ARM32 stub: the stage, MPIDR CPSR SCTLR CPACR NSACR VBAR TTBR0, what the monitor answered", 0, 10);
    smp_words("the AArch64 stub at EL2: MPIDR CurrentEL HCR_EL2 SCTLR_EL2 ELR_EL2 SPSR_EL2 SP CNTHCTL CNTVOFF CPTR", 8, 20);
    smp_words("the EL1 entry, then at EL1: MPIDR CurrentEL SCTLR_EL1 DAIF, and the stage again", 28, 11);
    smp_words("the boot CPU's SP_EL0, then the secondary's SP_EL0 at EL2", 40, 4);
    begin();
    put_text(" smp: result: the ARM32 stub ");
    put_text(stage >= 1u ? "ran" : "never ran");
    put_text("; in 64 bits at EL2: ");
    put_text(stage == 3u || stage == 4u || stage == 5u ? "yes" : stage == 0x80u ? "no: the monitor came back to 32 bits" : "not seen");
    put_text("; at EL1 after the eret: ");
    put_text(stage == 5u ? "yes" : "not seen");
    put_text("; the SoC is reset");
    end();
    reset();
}
#endif

void stage2_main(void) {
#ifndef PROD
    const uint64_t stack = (uint64_t)(uintptr_t)&stack;
    const uint32_t colours[] = {0x00FF0000u, 0x0000FF00u, 0x000000FFu, 0x00FFFF00u,
                                0x00FF00FFu, 0x0000FFFFu, 0x00FFFFFFu, 0x00808080u};

    begin();
    put_text(" stage 2, C code at EL2: entry=");
    put_hex((uint64_t)(uintptr_t)stage2_main, 8);
    field("SP=", stack, 8);
    field("fib(30)=", fib(30), 8);
    field("div=", stack / 1000003u, 16);
    field("mod=", stack % 1000003u, 8);
    end();

    for (unsigned i = 0; i < 8192; i++) {                        /* .bss was cleared: then filled, then summed */
        bss_table[i] = data_value ^ (uint64_t)i * 0x9E3779B97F4A7C15ULL;
    }
    uint64_t sum = 0;
    for (unsigned i = 0; i < 8192; i++) {
        sum += bss_table[i];
    }
    begin();
    field("data=", data_value, 16);
    field("bss=", sum, 16);
    put_text(" rodata='");
    put_text(rodata_text);
    put_byte('\'');
    end();

    for (uint32_t row = 0; row < FB_ROWS_SHOWN; row++) {         /* eight bands of 128 rows over the top half */
        const uint32_t colour = colours[row >> 7];
        for (uint32_t column = 0; column < 1536u; column++) {
            FRAMEBUFFER[row * 1536u + column] = colour;
        }
    }
    clean(FRAMEBUFFER, FB_ROWS_SHOWN * 1536u * 4u);
    frame();
    uint64_t bands = 0;
    for (uint32_t band = 0; band < 8; band++) {                 /* read back: the pixel in the middle of each band */
        bands += FRAMEBUFFER[(band * 128u + 64u) * 1536u + 800u];
    }
    begin();
    put_text(" the screen: 8 bands of 128 rows, the pixel in the middle of each summed=");
    put_hex(bands, 16);
    end();
#endif

#ifdef EMMC_CHECK
    invalidate(LOADED, LOADED_BYTES);
    begin();
    put_text(" eMMC: what S-Boot's reader put at 0x40000000: fnv1a=");
    put_hex(fnv1a(LOADED, LOADED_BYTES), 16);
    put_text(" first=");
    for (unsigned i = 0; i < 8; i++) {
        put_hex(LOADED[i], 2);
    }
    put_text(" at 0x1000=");
    for (unsigned i = 0x1000; i < 0x1008; i++) {
        put_hex(LOADED[i], 2);
    }
    end();
#endif

#ifdef HANDOFF
    handoff_report();
#endif

#ifdef WATCHDOG_PROOF
    watchdog_proof();                            /* does not come back */
#endif

#ifdef SMP_EXP
    smp_experiment();                            /* does not come back */
#endif

#ifdef EL1_TEST
    /* The AArch64 image for EL1: S-Boot's reader put it at 0x40080000 (a header: "EL1T", its size, its entry). */
    invalidate(EL1_HEADER, 0x10000);
    begin();
    if (EL1_HEADER[0] != 0x54314c45u || EL1_HEADER[1] > 0x10000u || EL1_HEADER[1] < 0x10u
        || EL1_HEADER[2] < 0x400810u || EL1_HEADER[2] >= 0x40080000u + EL1_HEADER[1]) {
        put_text(" EL1: no image with a sane header at 0x40080000: ");
        put_hex(EL1_HEADER[0], 8);
        put_byte(' ');
        put_hex(EL1_HEADER[1], 8);
        put_byte(' ');
        put_hex(EL1_HEADER[2], 8);
        end();
    } else {
        invalidate(EL1_HEADER, EL1_HEADER[1]);
        put_text(" EL1: an image of ");
        put_hex(EL1_HEADER[1], 8);
        put_text(" bytes for EL1 at 0x40080000, entry ");
        put_hex(EL1_HEADER[2], 8);
        put_text(": the data cache is emptied, EL1 is entered by an eret");
        end();
#ifdef WATCHDOG_ARM
        (void)watchdog_arm(20);                   /* if the image hangs, the watchdog resets the tablet */
#endif
        boot_el1(EL1_HEADER[2], 0);
    }
#endif

#ifdef KERNEL
#ifdef SLOT_RECORD
    if (slot_kernel_ready()) {
#else
    invalidate(KERNEL_IMAGE, KERNEL_BYTES);
    invalidate(DTB_WORDS, DTB_BYTES);
    if (kernel_ready(KERNEL_BYTES, DTB_BYTES, KERNEL_HASH, DTB_HASH)) {
#endif
        normal_boot_marker();
        begin();
        put_text(" kernel: starting it at ");
        put_hex(KERNEL_AT, 8);
        put_text(" with the device tree at ");
        put_hex(DTB_AT, 8);
        put_text(": the PMU markers of a normal boot are written, the data cache is emptied, the watchdog is armed, EL1 is entered by an eret");
        end();
#ifdef WATCHDOG_ARM
        (void)watchdog_arm(20);                   /* if the kernel hangs before its own watchdog takes over, the tablet restarts */
#endif
        boot_el1(KERNEL_AT, DTB_AT);
    }
#endif
}
