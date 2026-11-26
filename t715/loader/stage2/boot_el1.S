/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 elkir0
 * Parts derived from bnuuyloader (https://github.com/meowybnuuy/bnuuyloader), MIT,
 * Copyright (c) 2026 meowybnuuy: see the comments that name "the Note 4 loader".
 */
/* The last step of the loader: from EL2, where stage 2 runs, into EL1 in AArch64 — the way Linux is
   entered, and the way the Note 4 loader does it (bnuuyloader's boot_el1.S).
   x0 = the entry, x1 = the device tree's physical address.
   Before the eret, everything stage 2 wrote through the data cache is put in the memory and nothing
   is left in the cache: at EL1 the MMU and the caches are off, and a line still in the cache would
   be lost at the next reset, or would hide what EL1 writes to the same place. */

    .arch armv8-a
    .section .text,"ax",%progbits
    .global boot_el1
boot_el1:
    msr     daifset, #0xf
    mov     x9, x0                     /* the entry */
    mov     x14, x1                    /* the device tree's address: the kernel takes it in x0 */
    mov     x10, #0x3c5                /* EL1h, every exception masked */

    mov     x20, #0                    /* the data cache, level by level: every line cleaned and invalidated */
1:  msr     csselr_el1, x20
    isb
    mrs     x21, ccsidr_el1            /* [2:0] line size, [12:3] ways, [27:13] sets: one less each */
    and     x22, x21, #7
    ubfx    x23, x21, #13, #15
    ubfx    x24, x21, #3, #10
    clz     x25, x24                   /* the way sits this far down from bit 31 */
    mov     x27, x24
2:  mov     x28, x23
3:  add     x4, x22, #4
    lsl     x4, x28, x4                /* the set, above log2(line size) + 4 bits */
    lsl     x5, x27, x25
    orr     x4, x4, x5                 /* the way, in the top bits */
    add     x5, x20, x20
    orr     x4, x4, x5                 /* the level, bits [3:1] */
    dc      cisw, x4
    subs    x28, x28, #1
    b.pl    3b
    subs    x27, x27, #1
    b.pl    2b
    add     x20, x20, #1
    cmp     x20, #2                    /* levels 1 and 2 */
    b.lo    1b
    dsb     sy

    movz    x12, #0x8000, lsl #16
    msr     hcr_el2, x12               /* only RW: EL1 executes AArch64, and nothing is trapped */
    mrs     x12, cnthctl_el2
    orr     x12, x12, #3
    msr     cnthctl_el2, x12           /* EL1 may use the physical and the virtual counter */
    msr     cntvoff_el2, xzr
    msr     cptr_el2, xzr
    msr     mdcr_el2, xzr
    mrs     x12, sctlr_el1
    bic     x12, x12, #1               /* at EL1: the MMU off, */
    bic     x12, x12, #4               /* the data cache off, */
    bic     x12, x12, #0x1000          /* the instruction cache off */
    msr     sctlr_el1, x12
    ic      iallu
    dsb     sy
    isb
    msr     elr_el2, x9
    mov     x10, #0x3c5
    msr     spsr_el2, x10
    isb
    mov     x0, x14                    /* as Linux is entered: x0 the device tree, x1 to x3 zero */
    mov     x1, xzr
    mov     x2, xzr
    mov     x3, xzr
    eret
