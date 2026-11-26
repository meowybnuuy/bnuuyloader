/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 elkir0
 */
/* What a secondary core runs in AArch64 if the monitor accepts the loader's call there (smp_stub32.S
   calls it: function 0x82000400, this address as the entry, 0x800 and 1): as on the boot CPU after the
   switch, the MMU and the caches are off, HCR_EL2 is the monitor's, and this code is where it runs.
   It writes what it is into the scratch page and into S-Boot's log ring, then enters EL1 by an eret
   as the loader does for Linux (boot_el1.S) and writes again.

   Linked at STUB64 (0x41000800), where it runs: `bl` and `adr` are to its own labels and every other
   constant is built with movz/movk. No stack before EL1 (SP_EL1 is set just before the eret).
   x20 holds the scratch page's address and x19 the level: the three writing routines leave both alone.
   The scratch page (SCRATCH; byte offsets): 0 the stage (3 in 64 bits at EL2, 4 the eret is tried,
   5 at EL1; 0x81 and 0x82: another level, nothing else attempted); 32 MPIDR, 40 CurrentEL, 48 HCR_EL2,
   56 SCTLR_EL2, 64 ELR_EL2, 72 SPSR_EL2, 80 SP, 88 CNTHCTL_EL2, 96 CNTVOFF_EL2, 104 CPTR_EL2,
   112 the EL1 entry; 168 SP_EL0 at EL2; at EL1: 128 MPIDR, 136 CurrentEL, 144 SCTLR_EL1, 152 DAIF,
   and the stage again.
   The stage word is written last, after a dsb.

   MARKER, SCRATCH and STACK_TOP come from scripts/build_smp_stubs.py. */
    .arch armv8-a
    .section .text,"ax",%progbits
    .global smp_stub64
smp_stub64:
    msr     daifset, #0xf
    movz    x20, #(SCRATCH & 0xffff)
    movk    x20, #(SCRATCH >> 16) & 0xffff, lsl #16
    mrs     x19, CurrentEL             /* the level this core was given */
    mrs     x1, mpidr_el1
    str     x1, [x20, #32]
    str     x19, [x20, #40]
    ubfx    x1, x19, #2, #4            /* CurrentEL[3:2] */
    cmp     x1, #2
    b.ne    not_el2

    /* in 64 bits, at EL2: what the monitor left */
    mrs     x2, hcr_el2
    str     x2, [x20, #48]
    mrs     x2, sctlr_el2
    str     x2, [x20, #56]
    mrs     x2, elr_el2
    str     x2, [x20, #64]
    mrs     x2, spsr_el2
    str     x2, [x20, #72]
    mov     x2, sp
    str     x2, [x20, #80]
    mrs     x2, cnthctl_el2
    str     x2, [x20, #88]
    mrs     x2, cntvoff_el2
    str     x2, [x20, #96]
    mrs     x2, cptr_el2
    str     x2, [x20, #104]
    mrs     x2, sp_el0               /* what the monitor restored of the sp_usr the stub set */
    str     x2, [x20, #168]
    dsb     sy
    mov     w1, #3
    str     w1, [x20]

    /* the line in the ring */
    adr     x5, t_el2
    bl      put_text
    mov     x0, x19                    /* CurrentEL as it reads: 0x8 is EL2, 0x4 EL1 */
    mov     x6, #8
    bl      put_hex
    adr     x5, t_mpidr
    bl      put_text
    mrs     x0, mpidr_el1
    mov     x6, #16
    bl      put_hex
    adr     x5, t_hcr
    bl      put_text
    mrs     x0, hcr_el2
    mov     x6, #16
    bl      put_hex
    adr     x5, t_sctlr2
    bl      put_text
    mrs     x0, sctlr_el2
    mov     x6, #16
    bl      put_hex
    adr     x5, t_spsr2
    bl      put_text
    mrs     x0, spsr_el2
    mov     x6, #16
    bl      put_hex
    adr     x5, t_sp
    bl      put_text
    mov     x0, sp
    mov     x6, #16
    bl      put_hex
    mov     w0, #10
    bl      put_byte_ring
    dsb     sy
    b       to_el1

not_el2:
    mrs     x2, sctlr_el1
    str     x2, [x20, #144]
    dsb     sy
    mov     w1, #0x81
    cmp     x1, #1
    b.eq    1f
    mov     w1, #0x82
1:  str     w1, [x20]
    adr     x5, t_other
    bl      put_text
    mov     x0, x19
    mov     x6, #8
    bl      put_hex
    adr     x5, t_mpidr
    bl      put_text
    mrs     x0, mpidr_el1
    mov     x6, #16
    bl      put_hex
    mov     w0, #10
    bl      put_byte_ring
    dsb     sy
    b       park64

/* into EL1, as boot_el1.S does it: only RW in HCR_EL2, nothing trapped, EL1 with the MMU and the
   caches off, every exception masked */
to_el1:
    msr     daifset, #0xf
    movz    x12, #0x8000, lsl #16
    msr     hcr_el2, x12
    mrs     x12, cnthctl_el2
    orr     x12, x12, #3
    msr     cnthctl_el2, x12
    msr     cntvoff_el2, xzr
    msr     cptr_el2, xzr
    msr     mdcr_el2, xzr
    mrs     x12, sctlr_el1
    bic     x12, x12, #1
    bic     x12, x12, #4
    bic     x12, x12, #0x1000
    msr     sctlr_el1, x12
    ic      iallu
    dsb     sy
    isb
    msr     spsel, #1
    movz    x9, #(STACK_TOP & 0xffff)
    movk    x9, #(STACK_TOP >> 16) & 0xffff, lsl #16
    mov     sp, x9                      /* SP_EL1: above the scratch page; nothing is pushed anyway */
    adr     x9, el1_entry
    str     x9, [x20, #112]             /* the entry, for the record */
    dsb     sy
    mov     w1, #4
    str     w1, [x20]                   /* the eret is tried */
    msr     elr_el2, x9
    mov     x10, #0x3c5                 /* EL1h, every exception masked */
    msr     spsr_el2, x10
    isb
    eret

el1_entry:                              /* x19 and x20 came through the eret */
    msr     daifset, #0xf
    mrs     x19, CurrentEL
    mrs     x1, mpidr_el1
    str     x1, [x20, #128]
    str     x19, [x20, #136]
    mrs     x2, sctlr_el1
    str     x2, [x20, #144]
    mrs     x2, daif
    str     x2, [x20, #152]
    dsb     sy
    ubfx    x1, x19, #2, #4
    cmp     x1, #1
    b.ne    not_el1
    adr     x5, t_el1
    bl      put_text
    b       2f
not_el1:
    adr     x5, t_notel1
    bl      put_text
2:  mov     x0, x19
    mov     x6, #8
    bl      put_hex
    adr     x5, t_mpidr
    bl      put_text
    mrs     x0, mpidr_el1
    mov     x6, #16
    bl      put_hex
    adr     x5, t_sctlr1
    bl      put_text
    mrs     x0, sctlr_el1
    mov     x6, #16
    bl      put_hex
    adr     x5, t_daif
    bl      put_text
    mrs     x0, daif
    mov     x6, #8
    bl      put_hex
    mov     w0, #10
    bl      put_byte_ring
    dsb     sy
    ubfx    x1, x19, #2, #4
    cmp     x1, #1
    b.ne    3f
    mov     w1, #5
    b       4f
3:  mov     w1, #0x83
4:  str     w1, [x20]                   /* 5: at EL1, the last stage; 0x83: somewhere else */

park64:                                 /* nothing more to do: the boot CPU resets the SoC */
    wfe
    b       park64

/* The three routines take w0, or x5 and x6, and use x0 to x4 and x7 to x10: x19 and x20 stay. */

/* w0 = one byte, into S-Boot's log ring (2 MiB at 0x26000000, its write counter at 0x25FFFFFC), as
   stage 2 writes it. The boot CPU logs nothing while this core may write. */
put_byte_ring:
    movz    x1, #0xfffc
    movk    x1, #0x25ff, lsl #16
    ldr     w2, [x1]
    ubfx    x3, x2, #0, #21             /* position modulo the ring's size */
    movz    x4, #0x0000
    movk    x4, #0x2600, lsl #16
    strb    w0, [x4, x3]
    add     w2, w2, #1
    str     w2, [x1]
    ret

/* x5 = a text that ends with zero (x5 moves along it); x7 keeps the return, as bl moves x30 */
put_text:
    mov     x7, x30
1:  ldrb    w0, [x5], #1
    cbz     w0, 2f
    bl      put_byte_ring
    b       1b
2:  ret     x7

/* x0 = a value, x6 = digits (8 or 16): x8 the shift, x9 the return, x10 the value */
put_hex:
    mov     x9, x30
    mov     x10, x0
    lsl     x8, x6, #2
    sub     x8, x8, #4                  /* the shift of the first digit */
1:  lsr     x2, x10, x8
    and     x2, x2, #15
    adr     x3, digits
    ldrb    w0, [x3, x2]
    bl      put_byte_ring
    subs    x8, x8, #4
    b.ge    1b
    ret     x9

t_el2:
    .ascii  MARKER
    .asciz  " core 1 in 64 bits at EL2: CurrentEL="
t_el1:
    .ascii  MARKER
    .asciz  " core 1 in 64 bits at EL1: CurrentEL="
t_other:
    .ascii  MARKER
    .asciz  " core 1 in 64 bits, but not at EL2: CurrentEL="
t_notel1:
    .ascii  MARKER
    .asciz  " core 1 after the eret, but not at EL1: CurrentEL="
t_mpidr:
    .asciz  " MPIDR="
t_hcr:
    .asciz  " HCR_EL2="
t_sctlr2:
    .asciz  " SCTLR_EL2="
t_spsr2:
    .asciz  " SPSR_EL2="
t_sp:
    .asciz  " SP="
t_sctlr1:
    .asciz  " SCTLR_EL1="
t_daif:
    .asciz  " DAIF="
digits:
    .asciz  "0123456789abcdef"
