/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 elkir0
 */
/* The entry of stage 2. Stage 1 (scripts/a64_sreset.S) calls it with the MMU and the caches on and
   a stack set up; nothing has zeroed the memory behind the logo file, so .bss is cleared here. */
    .arch armv8-a
    .section .text.entry,"ax",%progbits
    .global stage2_entry
stage2_entry:
    adr     x1, __bss_start
    adr     x2, __bss_end
1:  cmp     x1, x2
    b.hs    2f
    str     xzr, [x1], #8
    b       1b
2:  mov     x29, x30              /* the way back to stage 1: the call below would overwrite it */
    bl      stage2_main
    mov     x30, x29
    ret
