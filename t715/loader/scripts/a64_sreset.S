/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 elkir0
 * Parts derived from bnuuyloader (https://github.com/meowybnuuy/bnuuyloader), MIT,
 * Copyright (c) 2026 meowybnuuy: see the comments that name "the Note 4 loader".
 */
/* The AArch64 entry (SMC 0x82000400, address in r1) of a test that ends by resetting the SoC, or of the
   production loader (KBOOT).
   Linked inside the file buffer that holds the forged logo, after the ARM32 code: nothing here
   depends on an address but its own. There is no runtime, only the register state the monitor
   left (2026-11-24: MMU off, caches off, VBAR_EL2 = 0). It writes into S-Boot's log ring
   (write counter at 0x025FFFFFC, 2 MiB at 0x26000000, read back from Linux by tools/seclog_dump),
   one line flushed at a time, paints the screen as on 2026-11-24, then does what Linux does
   for `reboot`: 1 into the power management unit's SWRESET. The ARM32 code skips the test at the
   next boot (scripts/split_source.py). @MARKER@ comes from build_ffree.py, and so do the options:

     VECTORS       a vector table of its own: an exception at EL2 is logged (ESR, ELR, FAR, SPSR)
                   and ends in the same software reset, instead of a jump to address 0
     MMU           the MMU on at EL2 with an identity map (tables at 0x90000000: the tablet's memory
                   write-back, everything else device) and both caches: without it a loop runs about
                   a hundred times slower than it should
     COUNTER_READS the generic counter (CNTFRQ_EL0, CNTPCT_EL0): on 2026-11-24 it read as 0
                   (the timer is off), so nothing relies on it
     STAGE2        call stage 2 at 0x24224000 (stage2/, scripts/build_stage2.py) on a stack at 0x90020000
     KBOOT         the production loader (scripts/split_source.py KBOOT_SOURCE): nothing is painted, and when
                   stage 2 comes back (it only does when the kernel was not started) or an exception is taken,
                   the SoC is reset at once: the ARM32 code logged its start, so the next boot hands S-Boot
                   its own kernel (KBOOT_SOURCE, the ledger)
     SMPX          the 2 MiB at 0x41000000 are mapped without cache too (stage2/stage2.c, SMP_EXP): the two
                   stubs a secondary core runs and the page it writes, nothing of them in this core's cache */

    .arch armv8-a
    .section .text,"ax",%progbits
    .global _start
_start:
    msr     daifset, #0xf              /* no interrupt, no FIQ: the vectors here are not ours */
    mrs     x19, CurrentEL
    mrs     x20, DAIF
#ifdef VECTORS
    adr     x0, vectors
    msr     vbar_el2, x0               /* from here on an exception is logged */
    isb
#endif

    /* The log. x9 = the counter's address, x12 = the ring; x25, x26, x27 = " ", line feed, the marker. */
    bl      ringregs

    bl      ringptr
    adr     x14, s_line1a
    bl      puts
    mov     x17, x19
    bl      hex8
    adr     x14, s_line1b
    bl      puts
    mov     x17, x20
    bl      hex8
    mov     x14, x26
    bl      puts
    bl      flush

#ifdef MMU
    bl      ringptr
    mov     x14, x27
    bl      puts
    adr     x14, s_mmuon
    bl      puts
    mov     x14, x26
    bl      puts
    bl      flush

    /* The tables, written while nothing is cached. A level-1 table of four entries (one gigabyte
       each), each to a level-2 table of 512 blocks of 2 MiB. Block: 0x701 = inner shareable,
       accessed, attribute 0 (device); | 4 for attribute 1 (the memory, write-back); | 8 for attribute 2
       (normal, not cached) around S-Boot's log: written through the cache on 2026-11-24, its
       counter never reached the memory and the next boot wrote over every line after that. */
    movz    x0, #0
    movk    x0, #0x9000, lsl #16      /* x0 = the level-1 table */
    mov     x4, #0                    /* the gigabyte */
3:  add     x5, x4, #1
    lsl     x5, x5, #12               /* its level-2 table: page 1 + the gigabyte */
    add     x5, x5, x0
    orr     x6, x5, #3                /* a table descriptor */
    str     x6, [x0, x4, sxtx #3]
    mov     x7, #0                    /* the block */
4:  lsl     x14, x4, #30             /* the gigabyte */
    lsl     x16, x7, #21
    add     x14, x14, x16             /* where the block is, and so where it stays */
    movz    x15, #0x0701
    movz    x16, #0x2000, lsl #16     /* 0x20000000: the memory starts */
    cmp     x14, x16
    b.lo    5f
    movz    x16, #0xde80, lsl #16     /* 0xde800000: ... and ends (the kernel's map says 0xde980000) */
    cmp     x14, x16
    b.hs    5f
    orr     x15, x15, #4
    movz    x16, #0x25c0, lsl #16     /* 0x25c00000..0x26400000: the log ring and its header */
    cmp     x14, x16
    b.lo    5f
    movz    x16, #0x2640, lsl #16
    cmp     x14, x16
    b.hs    5f
    add     x15, x15, #4
#ifdef SMPX
    b       6f
5:  movz    x16, #0x4100, lsl #16     /* SMPX: 0x41000000..0x41200000, not cached as the log is */
    cmp     x14, x16
    b.ne    7f
    add     x15, x15, #4              /* attribute 1 to attribute 2, as for the log */
6:
7:
#endif
5:  orr     x15, x15, x14
    str     x15, [x5, x7, sxtx #3]
    add     x7, x7, #1
    cmp     x7, #512
    b.lo    4b
    add     x4, x4, #1
    cmp     x4, #4
    b.lo    3b
    mov     x7, #4                    /* the rest of the level-1 table: nothing above 4 GiB */
    mov     x6, #0
6:  str     x6, [x0, x7, sxtx #3]
    add     x7, x7, #1
    cmp     x7, #512
    b.lo    6b
    dsb     sy

    movz    x0, #0xff00               /* MAIR: attribute 0 device, 1 normal write-back, 2 normal not cached */
    movk    x0, #0x44, lsl #16
    msr     mair_el2, x0
    movz    x0, #0x1720               /* TCR: 32-bit addresses, 4 KiB granule, inner shareable, write-back, 40-bit outputs */
    movk    x0, #0x8082, lsl #16
    msr     tcr_el2, x0
    movz    x0, #0
    movk    x0, #0x9000, lsl #16
    msr     ttbr0_el2, x0
    tlbi    alle2                      /* no translation has used these tables: only this core's */
    dsb     sy
    isb
    mrs     x0, sctlr_el2
    orr     x0, x0, #0x1000           /* the instruction cache */
    orr     x0, x0, #4                /* the data cache */
    orr     x0, x0, #1                /* the MMU: on tables where everything is where it was */
    msr     sctlr_el2, x0
    isb
    ic      iallu                     /* what was fetched before is not wanted (as Linux does) */
    dsb     sy
    isb

    bl      ringptr
    mov     x14, x27
    bl      puts
    adr     x14, s_mmudone
    bl      puts
    adr     x24, s_sctlr2
    mrs     x17, sctlr_el2
    bl      named
    adr     x24, s_tcr2
    mrs     x17, tcr_el2
    bl      named
    adr     x24, s_ttbr0
    mrs     x17, ttbr0_el2
    bl      named64
    adr     x24, s_mair2
    mrs     x17, mair_el2
    bl      named
    mov     x14, x26
    bl      puts
    bl      flush
#endif

#ifndef KBOOT
    /* The visible sign: rows 0..1023 of the screen in blue, shown the way the Note 4 loader does it. */
    movz    x0, #0
    movk    x0, #0x6700, lsl #16
    movz    x1, #0xff                  /* blue in XRGB8888 */
    movz    x2, #0
    movk    x2, #0x6700, lsl #16
    add     x2, x2, #0x600000          /* 1024 rows of 6144 bytes */
paint:
    str     w1, [x0], #4
    cmp     x0, x2
    b.lo    paint
    movz    x0, #0
    movk    x0, #0x6700, lsl #16
clean_fb:
    dc      cvac, x0                   /* lines of the framebuffer may sit in the cache (mine now, S-Boot's before) */
    add     x0, x0, #64
    cmp     x0, x2
    b.lo    clean_fb
    dsb     sy
    movz    x0, #0x1410
    movk    x0, #0x1380, lsl #16       /* DECON_UPDATE: ask for the whole frame */
    ldr     w1, [x0]
    orr     w1, w1, #1
    str     w1, [x0]
    dsb     sy
    movz    x0, #0x2040
    movk    x0, #0x1380, lsl #16       /* DECON_TRIGGER: the frame starts now */
    movz    w1, #3
    movk    w1, #0xe000, lsl #16
    str     w1, [x0]
    dsb     sy
    isb
#endif

    /* The state of the two exception levels: what any address means here depends on it. */
    bl      ringptr
    mov     x14, x27
    bl      puts
    adr     x24, s_hcr2
    mrs     x17, hcr_el2
    bl      named
    adr     x24, s_sctlr1
    mrs     x17, sctlr_el1
    bl      named
    adr     x24, s_cpacr
    mrs     x17, cpacr_el1
    bl      named
#ifdef VECTORS
    adr     x24, s_vbar2
    mrs     x17, vbar_el2
    bl      named
#endif
    mov     x14, x26
    bl      puts
    bl      flush

    /* A device address read from here: the power management unit's INFORM3, which S-Boot logged
       as 0x12345670 at the start of this boot. */
    bl      ringptr
    mov     x14, x27
    bl      puts
    movz    x0, #0x080c
    movk    x0, #0x105c, lsl #16
    ldr     w17, [x0]
    adr     x24, s_inform3
    bl      named
    adr     x24, s_midr
    mrs     x17, midr_el1
    bl      named
    adr     x24, s_mpidr
    mrs     x17, mpidr_el1
    bl      named
    mov     x14, x26
    bl      puts
    bl      flush

#ifdef COUNTER_READS
    /* Last, because the monitor may trap these: the counter, then the ticks a million-iteration loop takes. */
    bl      ringptr
    mov     x14, x27
    bl      puts
    adr     x24, s_cntfrq
    mrs     x17, cntfrq_el0
    bl      named
    adr     x24, s_cntpct0
    mrs     x17, cntpct_el0
    bl      named64
    mov     x23, x17
    movz    x0, #0x100, lsl #16        /* a million iterations */
7:  subs    x0, x0, #1
    b.ne    7b
    adr     x24, s_cntpct1
    mrs     x17, cntpct_el0
    bl      named64
    adr     x24, s_ticks
    sub     x17, x17, x23
    bl      named64
    mov     x14, x26
    bl      puts
    bl      flush
#endif

#ifdef STAGE2
    /* Stage 2: C code linked at 0x24224000 (scripts/build_stage2.py), on a stack above the page
       tables. It comes back here when it is done. */
    movz    x0, #0
    movk    x0, #0x9002, lsl #16
    mov     sp, x0
    movz    x0, #0x4000
    movk    x0, #0x2422, lsl #16
    blr     x0
    bl      ringregs                /* C keeps x19 to x28 and nothing else: the log's scratch registers are set again */
#endif

#ifndef KBOOT
    bl      ringptr
    mov     x14, x27
    bl      puts
    adr     x14, s_reset
    bl      puts
    mov     x14, x26
    bl      puts
    bl      flush

#ifdef VECTORS
    svc     #0                      /* the vector table, tried on purpose: the handler logs this and ends as below */
#endif

finish:                                 /* the end of the test, and of an exception: the reset */
#else
    bl      ringptr
    mov     x14, x27
    bl      puts
    adr     x14, s_cameback
    bl      puts
    mov     x14, x26
    bl      puts
    bl      flush

finish:                                 /* stage 2 came back, or an exception was taken: the reset, at once */
#endif
#ifndef KBOOT                        /* the test waits a moment, so that its paint can be seen; the loader resets at once */
#ifdef COUNTER_READS
    mrs     x0, cntpct_el0             /* two seconds of the counter */
    mrs     x1, cntfrq_el0
    add     x1, x0, x1, lsl #1
    mov     x3, #0xffffffff            /* or that many polls, should the counter stand still */
8:  mrs     x2, cntpct_el0
    cmp     x2, x1
    b.hs    9f
    subs    x3, x3, #1
    b.ne    8b
9:
#else
    movz    x0, #0
    movk    x0, #0x2000, lsl #16      /* about a minute without the caches */
wait:
    subs    x0, x0, #1
    b.ne    wait
#endif
#endif
    movz    x0, #0x0400
    movk    x0, #0x105c, lsl #16      /* PMU SWRESET: what Linux writes for `reboot` */
    mov     w1, #1
    str     w1, [x0]
halt:
    b       halt

exception:                              /* any exception at EL2 comes here (the table is below): it is logged,
                                           then the tablet is reset as at the end of the test */
    msr     daifset, #0xf
    bl      ringregs                 /* the registers may hold anything now */
    mrs     x19, esr_el2
    mrs     x20, elr_el2
    mrs     x21, far_el2
    mrs     x22, spsr_el2
    bl      ringptr
    mov     x14, x27
    bl      puts
    adr     x14, s_exception
    bl      puts
    adr     x24, s_esr
    mov     x17, x19
    bl      named
    adr     x24, s_elr
    mov     x17, x20
    bl      named
    adr     x24, s_far
    mov     x17, x21
    bl      named
    adr     x24, s_spsr
    mov     x17, x22
    bl      named
    mov     x14, x26
    bl      puts
    bl      flush
    b       finish

ringregs:                             /* x9 = the counter's address, x12 = the ring; x25, x26, x27 = " ", line feed, the marker */
    movz    x9, #0xfffc
    movk    x9, #0x25ff, lsl #16
    movz    x12, #0
    movk    x12, #0x2600, lsl #16
    adr     x25, s_space
    adr     x26, s_newline
    adr     x27, s_marker
    ret

ringptr:                             /* x10 = the counter, x13 = where the next byte goes; x28 counts the line */
    ldr     w10, [x9]
    and     x11, x10, #0x1fffff
    add     x13, x12, x11
    mov     x28, #0
    ret

puts:                                /* the NUL-ended text at x14 goes to [x13], which stays inside the ring */
1:  ldrb    w15, [x14], #1
    cbz     w15, 3f
    strb    w15, [x13], #1
    add     x28, x28, #1
    add     x16, x12, #0x200000
    cmp     x13, x16
    b.eq    2f
    b       1b
2:  mov     x13, x12
    b       1b
3:  ret

flush:                               /* the counter moves by the line, and its cache lines are cleaned: the
                                        line is in RAM even if the core never comes back this way */
    add     w11, w10, w28
    str     w11, [x9]
    dc      cvac, x9                  /* the counter is a line of the same memory: it must reach it too */
    and     x10, x10, #0x1fffff       /* where the line started in the ring */
    add     x17, x10, x28             /* one past its end; past the ring if the line wraps */
    bic     x15, x10, #63
    mov     x14, #0x200000
    cmp     x17, x14
    csel    x14, x17, x14, lo         /* up to the end of the line or of the ring, whichever comes first */
1:  add     x16, x12, x15
    dc      cvac, x16
    add     x15, x15, #64
    cmp     x15, x14
    b.lo    1b
    subs    x17, x17, #0x200000       /* what wrapped to the start of the ring */
    b.ls    3f
    add     x14, x17, #63
    bic     x14, x14, #63
    mov     x15, #0
2:  add     x16, x12, x15
    dc      cvac, x16
    add     x15, x15, #64
    cmp     x15, x14
    b.lo    2b
3:  dsb     sy
    ret

hex8:                                /* eight hex digits of x17 */
    mov     x16, #28
    b       hexdigits

hexdigits:                           /* from bit x16 down to bit 0 */
    lsr     x15, x17, x16
    and     x15, x15, #0xf
    cmp     x15, #10
    b.lo    1f
    add     x15, x15, #0x57           /* 10..15 -> 'a'..'f' */
    b       2f
1:  add     x15, x15, #0x30           /* 0..9 -> '0'..'9' */
2:  strb    w15, [x13], #1
    add     x28, x28, #1
    add     x11, x12, #0x200000
    cmp     x13, x11
    b.eq    3f
4:  subs    x16, x16, #4
    b.ge    hexdigits
    ret
3:  mov     x13, x12
    b       4b

named:                               /* x24 = a field's name, x17 = its 32-bit value: " " + name + 8 hex digits */
    mov     x29, x30                 /* puts is called with bl, and the return into hexdigits needs this one */
    mov     x14, x25
    bl      puts
    mov     x14, x24
    bl      puts
    mov     x16, #28
    mov     x30, x29
    b       hexdigits

named64:                             /* the same with 16 hex digits */
    mov     x29, x30
    mov     x14, x25
    bl      puts
    mov     x14, x24
    bl      puts
    mov     x16, #60
    mov     x30, x29
    b       hexdigits

s_marker:
    .asciz  "@MARKER@"
s_line1a:
    .asciz  "HIJACK2: AArch64 code is running: CurrentEL="
s_line1b:
    .asciz  " DAIF="
s_mmuon:
    .asciz  " turning on the MMU and the caches (identity map, tables at 0x90000000)"
s_mmudone:
    .asciz  " MMU and caches on:"
s_sctlr2:
    .asciz  "SCTLR_EL2="
s_hcr2:
    .asciz  "HCR_EL2="
s_sctlr1:
    .asciz  "SCTLR_EL1="
s_cpacr:
    .asciz  "CPACR_EL1="
s_mair2:
    .asciz  "MAIR_EL2="
s_tcr2:
    .asciz  "TCR_EL2="
s_ttbr0:
    .asciz  "TTBR0_EL2="
s_vbar2:
    .asciz  "VBAR_EL2="
s_inform3:
    .asciz  "INFORM3="
s_midr:
    .asciz  "MIDR="
s_mpidr:
    .asciz  "MPIDR="
s_cntfrq:
    .asciz  "CNTFRQ="
s_cntpct0:
    .asciz  "CNTPCT0="
s_cntpct1:
    .asciz  "CNTPCT1="
s_ticks:
    .asciz  "TICKS="
s_reset:
    .asciz  " resetting the SoC by software (PMU SWRESET)"
s_cameback:
    .asciz  " stage 2 came back: the kernel was not started; the SoC is reset, and the next boot goes to S-Boot's kernel\n"
s_exception:
    .asciz  " EXCEPTION at EL2:"
s_esr:
    .asciz  "ESR="
s_elr:
    .asciz  "ELR="
s_far:
    .asciz  "FAR="
s_spsr:
    .asciz  "SPSR="
s_space:
    .byte   32, 0
s_newline:
    .byte   10, 0

    .align  11                         /* the vector table: 16 slots of 0x80 bytes, 2 KiB aligned */
vectors:
    .rept   16
    b       exception
    .align  7
    .endr
