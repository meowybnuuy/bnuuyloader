/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 elkir0
 */
/* What a secondary core runs first, in AArch32 at EL1 with the MMU off: the entry the boot CPU writes
   into the monitor's boot-address register (sysram-ns + 0x1c) before the core is powered on
   (stage2/stage2.c, SMP_EXP). The core writes what it is into the scratch page and into S-Boot's log
   ring, then calls the monitor exactly as the loader does on the boot CPU (function 0x82000400 in r0,
   the AArch64 entry in r1, 0x800 and 1 in r2 and r3, `smc #0`): if the monitor switches this core too,
   the AArch64 stub (smp_stub64.S) takes over at STUB64.

   Linked at STUB32 (0x41000000), where it runs (scripts/build_smp_stubs.py links it there): `bl`
   reaches its own labels, the texts come through a literal pool, the other constants as movw/movt.
   No stack: the monitor leaves any SP.
   The scratch page (SCRATCH, which the boot CPU maps without cache): word 0 the stage (1 alive
   in 32 bits, 2 calling the monitor, 0x80 the monitor came back), words 1 to 7 MPIDR, CPSR, SCTLR,
   CPACR, NSACR, VBAR, TTBR0; words 40 and 41 the boot CPU's SP_EL0, loaded into sp_usr
   before the call; the 64-bit stub writes words 8 up. The stage word is written last, after
   a dsb: whoever reads 1 or 2 there finds the rest already in the memory.

   MARKER comes from scripts/build_smp_stubs.py. */
    .arch armv8-a
    .arm
    .syntax unified
    .section .text,"ax",%progbits
    .global smp_stub32
smp_stub32:
    movw    r7, #(SCRATCH & 0xffff)
    movt    r7, #(SCRATCH >> 16)       /* r7 = the scratch page: nothing below touches r7; r6 is the routines' */
    mrc     p15, 0, r1, c0, c0, 5       /* MPIDR */
    str     r1, [r7, #4]
    mrs     r2, cpsr
    str     r2, [r7, #8]
    cpsid   aif                         /* from here no interrupt takes this core elsewhere: the vectors are not ours */
    mrc     p15, 0, r3, c1, c0, 0       /* SCTLR */
    str     r3, [r7, #12]
    mrc     p15, 0, r3, c1, c0, 2       /* CPACR */
    str     r3, [r7, #16]
    mrc     p15, 0, r3, c1, c1, 2       /* NSACR */
    str     r3, [r7, #20]
    mrc     p15, 0, r3, c12, c0, 0      /* VBAR */
    str     r3, [r7, #24]
    mrc     p15, 0, r3, c2, c0, 0       /* TTBR0 */
    str     r3, [r7, #28]
    dsb     sy
    mov     r1, #1
    str     r1, [r7]                    /* alive in 32 bits */

    /* the line in the ring */
    ldr     r5, =t_alive
    bl      put_text
    ldr     r5, =t_mpidr
    bl      put_text
    mrc     p15, 0, r0, c0, c0, 5
    bl      put_hex
    ldr     r5, =t_cpsr
    bl      put_text
    ldr     r0, [r7, #8]               /* as the monitor left it, before the mask above */
    bl      put_hex
    ldr     r5, =t_sctlr
    bl      put_text
    mrc     p15, 0, r0, c1, c0, 0
    bl      put_hex
    ldr     r5, =t_cpacr
    bl      put_text
    mrc     p15, 0, r0, c1, c0, 2
    bl      put_hex
    ldr     r5, =t_vbar
    bl      put_text
    mrc     p15, 0, r0, c12, c0, 0
    bl      put_hex
    mov     r0, #10
    bl      put_byte_ring
    dsb     sy

    /* not a privileged mode: the call would only trap here */
    ldr     r0, [r7, #8]
    and     r0, r0, #0x1f
    cmp     r0, #0x10
    beq     no_call

    /* The monitor's SMC path runs on the caller's SP_EL0 (t715/docs/SMP-MONITOR.md): the boot CPU left
       here what the monitor had restored for it (S-Boot's sp_usr). It goes into sp_usr, in System mode. */
    ldr     r0, [r7, #160]
    cmp     r0, #0
    beq     2f
    cps     #0x1f                    /* System mode: its sp is sp_usr */
    mov     sp, r0
    cps     #0x13                    /* SVC again, the interrupts still masked */
2:
    mov     r1, #2
    str     r1, [r7]                    /* calling the monitor */
    dsb     sy
    movw    r0, #0x0400
    movt    r0, #0x8200                 /* the function, as the loader on the boot CPU passes it */
    movw    r1, #(STUB64 & 0xffff)
    movt    r1, #(STUB64 >> 16)
    movw    r2, #0x800
    mov     r3, #1
    smc     #0

back_in_32:                             /* only if the monitor returns to AArch32 */
    str     r0, [r7, #36]               /* what it answered: scratch word 9 */
    mov     r1, #0x80
    str     r1, [r7]
    ldr     r5, =t_back
    bl      put_text
    ldr     r0, [r7, #36]
    bl      put_hex
    ldr     r5, =t_cpsr
    bl      put_text
    mrs     r0, cpsr
    bl      put_hex
    mov     r0, #10
    bl      put_byte_ring
    dsb     sy
    b       park32

no_call:
    mov     r1, #0x81
    str     r1, [r7]
    ldr     r5, =t_nocall
    bl      put_text
    mov     r0, #10
    bl      put_byte_ring
    dsb     sy

park32:                                 /* nothing more to do: the boot CPU resets the SoC */
    wfe
    b       park32

/* The three routines take r0, or r5, and use r0 to r6, r8 and r9 only: r7 stays. */

/* r0 = one byte, into S-Boot's log ring (2 MiB at 0x26000000, its write counter at 0x25FFFFFC), as
   stage 2 writes it. The boot CPU logs nothing while this core may write. */
put_byte_ring:
    movw    r3, #0xfffc
    movt    r3, #0x25ff
    ldr     r1, [r3]
    ubfx    r2, r1, #0, #21             /* position modulo the ring's size */
    movw    r4, #0x0000
    movt    r4, #0x2600
    strb    r0, [r4, r2]
    add     r1, r1, #1
    str     r1, [r3]
    bx      lr

/* r5 = a text that ends with zero (r5 moves along it); r6 keeps the return, as bl moves lr */
put_text:
    mov     r6, lr
1:  ldrb    r0, [r5], #1
    cmp     r0, #0
    bxeq    r6
    bl      put_byte_ring
    b       1b

/* r0 = a word, 8 digits: r6 the shift, r8 the return, r9 the value, as the byte routine uses r1 to r4
   and bl moves lr */
put_hex:
    mov     r8, lr
    mov     r9, r0
    mov     r6, #28
1:  lsr     r2, r9, r6
    and     r2, r2, #15
    ldr     r3, =digits
    ldrb    r0, [r3, r2]
    bl      put_byte_ring
    subs    r6, r6, #4
    bge     1b
    bx      r8

t_alive:
    .ascii  MARKER
    .asciz  " core 1 alive in 32 bits"
t_mpidr:
    .asciz  ": MPIDR="
t_cpsr:
    .asciz  " CPSR="
t_sctlr:
    .asciz  " SCTLR="
t_cpacr:
    .asciz  " CPACR="
t_vbar:
    .asciz  " VBAR="
t_back:
    .ascii  MARKER
    .asciz  " core 1: the monitor came back to 32 bits, r0="
t_nocall:
    .ascii  MARKER
    .asciz  " core 1: alive in 32 bits but not in a privileged mode: the monitor is not called"
.ltorg
digits:
    .asciz  "0123456789abcdef"
