/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 elkir0
 */
/* A test image for EL1: AArch64 code entered from EL2 by an eret, with the MMU and the caches off
   at EL1, the way Linux is entered. It proves the last step of the loader without any kernel: it
   touches no clock and no voltage, logs into S-Boot's ring (nothing is cached: the stores reach the
   memory at once), paints a band of the screen, and resets the SoC. MARKER ("HIJACK3: <id>") comes
   from build_el1.py. */

    .arch armv8-a
    .section .text.header,"ax",%progbits
    .global el1_image
el1_image:
    .word   0x54314c45                  /* "EL1T" */
    .word   el1_end - el1_image         /* bytes, this header included */
    .word   el1_entry                   /* where the eret from EL2 goes */
    .word   0

    .section .text.entry,"ax",%progbits
    .global el1_entry
el1_entry:                              /* 0x40080010 */
    msr     daifset, #0xf
    adr     x0, vectors
    msr     vbar_el1, x0                /* S-Boot's table is for its own AArch32 exceptions: from here on, mine */
    isb
    mrs     x19, CurrentEL
    mrs     x20, MPIDR_EL1
    mrs     x21, SCTLR_EL1
    bl      ringregs
    bl      ringptr
    mov     x14, x27
    bl      puts
    adr     x14, s_line1
    bl      puts
    adr     x24, s_currentel
    mov     x17, x19
    bl      named
    adr     x24, s_mpidr
    mov     x17, x20
    bl      named
    adr     x24, s_sctlr1
    mov     x17, x21
    bl      named
    mov     x14, x26
    bl      puts
    bl      flush

    /* The visible sign: rows 1024..1535 in green, below the eight bands stage 2 painted. */
    movz    x0, #0
    movk    x0, #0x6700, lsl #16
    add     x0, x0, #0x600000
    movz    x1, #0xff00                 /* green in XRGB8888 */
    movz    x2, #0
    movk    x2, #0x6700, lsl #16
    add     x2, x2, #0xc00000
paint:
    str     w1, [x0], #4
    cmp     x0, x2
    b.lo    paint
    movz    x0, #0x1410
    movk    x0, #0x1380, lsl #16       /* DECON_UPDATE */
    ldr     w1, [x0]
    orr     w1, w1, #1
    str     w1, [x0]
    dsb     sy
    movz    x0, #0x2040
    movk    x0, #0x1380, lsl #16       /* DECON_TRIGGER */
    movz    w1, #3
    movk    w1, #0xe000, lsl #16
    str     w1, [x0]
    dsb     sy
    isb
    movz    x3, #0
    movk    x3, #0x6700, lsl #16
    add     x3, x3, #0xa00000
    movz    x0, #0
    movk    x0, #0x6700, lsl #16
clean:
    dc      cvac, x0
    add     x0, x0, #64
    cmp     x0, x3
    b.lo    clean
    dsb     sy

    bl      ringregs                    /* the loops used x9? no: they used x0 to x3 only */
    bl      ringptr
    mov     x14, x27
    bl      puts
    adr     x14, s_line2
    bl      puts
    adr     x24, s_readback
    movz    x1, #0x4c0                  /* row 1200: the middle of the band */
    movk    x1, #0x6700, lsl #16
    ldr     w17, [x1, #3200]            /* column 800 */
    bl      named
    mov     x14, x26
    bl      puts
    bl      flush

    movz    x0, #0x400
    movk    x0, #0x105c, lsl #16       /* PMU SWRESET: what Linux writes for `reboot` */
    mov     w1, #1
    str     w1, [x0]
halt:
    b       halt

exception:                              /* an exception at EL1: logged, then the reset */
    msr     daifset, #0xf
    bl      ringregs
    mrs     x19, esr_el1
    mrs     x20, elr_el1
    mrs     x21, far_el1
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
    mov     x14, x26
    bl      puts
    bl      flush
    movz    x0, #0x400
    movk    x0, #0x105c, lsl #16
    mov     w1, #1
    str     w1, [x0]
halt2:
    b       halt2

/* ---- the log, as in stage 1 (scripts/a64_sreset.S): x9 the counter's address, x12 the ring,
        x25 " ", x26 line feed, x27 the marker; a line is flushed by moving the counter ---- */

ringregs:
    movz    x9, #0xfffc
    movk    x9, #0x25ff, lsl #16
    movz    x12, #0
    movk    x12, #0x2600, lsl #16
    adr     x25, s_space
    adr     x26, s_newline
    adr     x27, s_marker
    ret

ringptr:
    ldr     w10, [x9]
    and     x11, x10, #0x1fffff
    add     x13, x12, x11
    mov     x28, #0
    ret

puts:
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

flush:
    add     w11, w10, w28
    str     w11, [x9]
    dsb     sy
    ret

hexdigits:                           /* from bit x16 down to bit 0 */
    lsr     x15, x17, x16
    and     x15, x15, #0xf
    cmp     x15, #10
    b.lo    1f
    add     x15, x15, #0x57
    b       2f
1:  add     x15, x15, #0x30
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

named:                               /* x24 = a name, x17 = a 32-bit value */
    mov     x29, x30
    mov     x14, x25
    bl      puts
    mov     x14, x24
    bl      puts
    mov     x16, #28
    mov     x30, x29
    b       hexdigits

s_marker:
    .asciz  "@MARKER@"
s_line1:
    .asciz  " EL1: AArch64 code is running at EL1 (entered from EL2 by an eret):"
s_line2:
    .asciz  " EL1: rows 1024..1535 painted green, the display controller triggered;"
s_exception:
    .asciz  " EL1: EXCEPTION:"
s_currentel:
    .asciz  "CurrentEL="
s_mpidr:
    .asciz  "MPIDR="
s_sctlr1:
    .asciz  "SCTLR_EL1="
s_readback:
    .asciz  "read-back="
s_esr:
    .asciz  "ESR="
s_elr:
    .asciz  "ELR="
s_far:
    .asciz  "FAR="
s_space:
    .byte   32, 0
s_newline:
    .byte   10, 0

    .align  11                         /* the vector table: 16 slots of 0x80 bytes */
vectors:
    .rept   16
    b       exception
    .align  7
    .endr
