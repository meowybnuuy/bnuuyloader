/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 elkir0
 * Parts derived from bnuuyloader (https://github.com/meowybnuuy/bnuuyloader), MIT,
 * Copyright (c) 2026 meowybnuuy: see the comments that name "the Note 4 loader".
 */
/* The AArch64 entry the monitor jumps to (SMC 0x82000400, address in r1). Linked at A64_CODE:
   inside the file buffer that holds the forged logo, after the three texts of the line it writes.
   There is no runtime, only the register state the monitor left. It writes one line straight into
   S-Boot's log ring (write counter at 0x025FFFFFC, 2 MiB at 0x26000000, which the kernel goes on
   filling and tools/seclog_dump reads back from Linux), with the exception level and the DAIF
   state it found; it cleans those cache lines and stops: nothing after that is known to be safe. */

    .arch armv8-a
    .section .text,"ax",%progbits
    .global _start
_start:
    msr     daifset, #0xf              /* no interrupt, no FIQ: the vectors here are not ours */
    mrs     x19, CurrentEL

    /* The visible half of the proof: rows 0..1023 of the screen in blue, then the two things the
       Note 4 loader does and S-Boot's own drawing does not need from me: clean the data cache lines
       of the framebuffer (it is mapped write-back; a paint left in the cache never reaches the
       panel), and trigger a frame in the display controller, whose addresses are the Note 4's. */
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
    dc      cvac, x0
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
    movk    x0, #0x1380, lsl #16       /* DECON_TRIGGER: start the frame now, with the buffer */
    movz    w1, #3
    movk    w1, #0xe000, lsl #16
    str     w1, [x0]
    dsb     sy
    isb
    mrs     x20, DAIF
    movz    x9, #0xfffc
    movk    x9, #0x25ff, lsl #16       /* x9 = 0x25FFFFFC: the ring's write counter */
    ldr     w10, [x9]
    and     x11, x10, #0x1fffff
    movz    x12, #0
    movk    x12, #0x2600, lsl #16      /* the ring */
    add     x13, x12, x11              /* where the next byte of log goes */

    movz    x14, #TEXT1_LO
    movk    x14, #TEXT1_HI, lsl #16
    movz    x16, #TEXT1_END_LO
    movk    x16, #TEXT1_END_HI, lsl #16
    bl      puts
    mov     x17, x19
    bl      hex8
    movz    x14, #TEXT2_LO
    movk    x14, #TEXT2_HI, lsl #16
    movz    x16, #TEXT2_END_LO
    movk    x16, #TEXT2_END_HI, lsl #16
    bl      puts
    mov     x17, x20
    bl      hex8
    movz    x14, #TEXT3_LO
    movk    x14, #TEXT3_HI, lsl #16
    movz    x16, #TEXT3_END_LO
    movk    x16, #TEXT3_END_HI, lsl #16
    bl      puts

    sub     x14, x13, x12              /* end of the line, as an offset in the ring */
    sub     x15, x14, x11              /* its length */
    add     w10, w10, w15
    str     w10, [x9]
    bic     x15, x11, #63              /* clean every cache line the line touched */
clean:
    add     x16, x12, x15
    dc      cvac, x16
    add     x15, x15, #64
    cmp     x15, x14
    b.lo    clean
    dsb     sy
halt:
    b       halt

puts:                                   /* copies [x14, x16) to [x13], advancing x13 */
    ldrb    w15, [x14], #1
    strb    w15, [x13], #1
    cmp     x14, x16
    b.lo    puts
    ret

hex8:                                   /* eight hex digits of x17's low 32 bits at [x13] */
    mov     w18, #28
hex_loop:
    lsr     w19, w17, w18
    and     w19, w19, #0xf
    cmp     w19, #10
    b.lo    hex_digit
    add     w19, w19, #0x57            /* 10..15 -> 'a'..'f' */
    b       hex_store
hex_digit:
    add     w19, w19, #0x30            /* 0..9 -> '0'..'9' */
hex_store:
    strb    w19, [x13], #1
    subs    w18, w18, #4
    b.ge    hex_loop
    ret
