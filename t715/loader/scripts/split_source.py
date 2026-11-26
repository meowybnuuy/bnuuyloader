#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 elkir0
# Parts derived from bnuuyloader (https://github.com/meowybnuuy/bnuuyloader), MIT,
# Copyright (c) 2026 meowybnuuy: see the comments that name "the Note 4 loader".

"""The code S-Boot jumps to when the forged heap head splits onto the stack (see build_split.py).

Entered at F, the node in the file buffer, through `pop {.., pc}` of 0x23e17b20 or 0x23e17b90:
stack pointer 0x23EC0018 (boot's), r3, r4, r5 (and r6 for 0x23e17b90) garbage from the node header.
Marks the screen, waits, puts the heap and the registers back, and returns into `boot` right
after the call, so that the tablet still boots Linux.
"""

MARK_SOURCE = """    .syntax unified
    .arm
    .section .text,"ax",%progbits
    .global _start
_start:                         /* F: the node, and the entry */
    b       stub
    .word   0                   /* free byte: the walk must skip this node */
    .word   0                   /* the allocator writes the carved node here */
    .word   0x23EC1048          /* next: the list head, so that the walk ends */
stub:
    movw    r0, #0              /* the top quarter of the screen, solid green */
    movt    r0, #0x6700
    movw    r1, #0xFF00
    movt    r1, #0
    add     r2, r0, #0x300000
1:  str     r1, [r0], #4
    cmp     r0, r2
    blo     1b
    ldr     r0, =0xA0000000     /* let it be seen: five seconds at 1 GHz, more if S-Boot runs the core slower */
2:  subs    r0, r0, #1
    bne     2b
    ldr     r0, =0x24F00000     /* the heap head marked busy: later allocations from this heap fail cleanly,
                                   so none of them splits onto the stack a second time */
    ldr     r1, =0x23EC1048
    str     r1, [r0, #12]
    mov     r1, #0
    str     r1, [r0]
    str     r1, [r0, #4]
    ldr     r5, =0x23E8000C     /* what boot keeps in r5 and r6 */
    ldr     r6, [r5, #0x28]
    ldr     pc, =0x23E069DC     /* boot, right after its call */
"""


KENTRY_SOURCE = """    .syntax unified
    .arm
    .section .text,"ax",%progbits
    .global _start
_start:                         /* F: the node, and the entry: reached through boot's final blx */
    b       stub
    .word   0                   /* free byte: the walk must skip this node */
    .word   0                   /* the allocator writes the carved node here */
    .word   0x23EC1048          /* next: the list head, so that the walk ends */
stub:
    push    {r0, r1, r2, r3}    /* the kernel's arguments */
    movw    r0, #0              /* the top quarter of the screen, solid green */
    movt    r0, #0x6700
    movw    r1, #0xFF00
    movt    r1, #0
    add     r2, r0, #0x300000
1:  str     r1, [r0], #4
    cmp     r0, r2
    blo     1b
    ldr     r0, =0x20000000     /* let it be seen: four seconds at 1 GHz, more if the core runs slower */
2:  subs    r0, r0, #1
    bne     2b
    pop     {r0, r1, r2, r3}
    ldr     pc, =0x20008000     /* the kernel entry S-Boot's cell holds by default */
"""


FFREE_SOURCE = """    .syntax unified
    .arm
    .section .text,"ax",%progbits
    .global _start
_start:                         /* F2: the node the carved one points to, and the entry */
    b       stub
    .word   0                   /* free byte: the walk must skip this node */
    .word   0                   /* the allocator writes the carved node here */
    .word   0x23EC1048          /* next: the list head, so that the walk ends */
stub:
    movw    r0, #0              /* the top quarter of the screen, solid green */
    movt    r0, #0x6700
    movw    r1, #0xFF00
    movt    r1, #0
    add     r2, r0, #0x300000
1:  str     r1, [r0], #4
    cmp     r0, r2
    blo     1b
    ldr     r0, =0x30000000     /* let it be seen: six seconds at 1 GHz, more if the core runs slower */
2:  subs    r0, r0, #1
    bne     2b
    adr     r0, 9f              /* a line in S-Boot's own log, read back from Linux afterwards: the proof
                                   that this code ran, independent of what was on the screen */
    mov     r1, sp
    mov     r2, r4
    mov     r3, r5
    ldr     r4, =0x23E05820
    blx     r4
    b       8f
9:  .asciz  "HIJACK: the forged code ran: sp=%08lx r4=%08lx r5=%08lx\\n"
    .align  2
8:  ldr     r0, =0x67B00000     /* a free block for S-Boot's later requests: the bottom of the screen, which is
                                   memory nothing else uses and the cache does not hide from the storage controller */
    ldr     r1, =0x80000
    str     r1, [r0]
    mov     r1, #1
    strb    r1, [r0, #4]
    mov     r1, #0
    str     r1, [r0, #8]
    ldr     r1, =0x23EC1048
    str     r1, [r0, #12]
    ldr     r0, =0x24F00000     /* the heap head stays busy and now points there: nothing reaches the stack again */
    ldr     r1, =0x67B00000
    str     r1, [r0, #12]
    ldr     r5, =0x23E8000C     /* what boot keeps in r5 and r6 */
    ldr     r6, [r5, #0x28]
    ldr     pc, =0x23E069DC     /* boot, right after its call */
"""


# The monitor test: the same entry and hand-back as FFREE_SOURCE, but before handing back the ARM32
# code logs a line, cleans the data cache (so that the line reaches RAM), invalidates the
# instruction cache, and calls the monitor as the Note 4 loader does. A64_ENTRY comes from -D.
SMC_SOURCE = """    .syntax unified
    .arm
    .section .text,"ax",%progbits
    .global _start
_start:                         /* F2: the node the carved one points to, and the entry */
    b       stub
    .word   0                   /* free byte: the walk must skip this node */
    .word   0                   /* the allocator writes the carved node here */
    .word   0x23EC1048          /* next: the list head, so that the walk ends */
stub:
    movw    r0, #0              /* the top quarter of the screen, solid green */
    movt    r0, #0x6700
    movw    r1, #0xFF00
    movt    r1, #0
    add     r2, r0, #0x300000
1:  str     r1, [r0], #4
    cmp     r0, r2
    blo     1b
    adr     r0, 9f              /* a line in S-Boot's own log */
    ldr     r4, =0x23E05820
    blx     r4
    b       8f
9:  .asciz  "HIJACK2: ARM32 payload running: cleaning the caches, then SMC 0x82000400\\n"
    .align  2
8:  ldr     r4, =0x24220000     /* clean the data cache from my code to the end of S-Boot's log ring:
                                   what was written through the cache must reach RAM before the core changes state */
    ldr     r5, =0x26200000
2:  mcr     p15, 0, r4, c7, c10, 1
    add     r4, r4, #64
    cmp     r4, r5
    blo     2b
    dsb     sy
    mcr     p15, 0, r4, c7, c5, 0
    dsb     sy
    isb
    ldr     r0, =0x82000400     /* the Note 4 loader's call: function, AArch64 entry, 0x800, 1 */
    ldr     r1, =A64_ENTRY
    mov     r2, #0x800
    mov     r3, #1
    smc     #0
    adr     r0, 9f              /* back in ARM32: the monitor did not switch, say so and hand back */
    ldr     r4, =0x23E05820
    blx     r4
    b       8f
9:  .asciz  "HIJACK2: the SMC returned to ARM32 (unexpected); handing back to S-Boot\\n"
    .align  2
8:  ldr     r0, =0x67B00000     /* a free block for S-Boot's later requests: the bottom of the screen */
    ldr     r1, =0x80000
    str     r1, [r0]
    mov     r1, #1
    strb    r1, [r0, #4]
    mov     r1, #0
    str     r1, [r0, #8]
    ldr     r1, =0x23EC1048
    str     r1, [r0, #12]
    ldr     r0, =0x24F00000     /* the heap head stays busy and now points there */
    ldr     r1, =0x67B00000
    str     r1, [r0, #12]
    ldr     r5, =0x23E8000C     /* what boot keeps in r5 and r6 */
    ldr     r6, [r5, #0x28]
    ldr     pc, =0x23E069DC     /* boot, right after its call */
"""


# A test that ends by resetting the SoC from AArch64, so that nobody has to hold the power key:
# the tablet restarts by itself, draws this logo again, and the ARM32 code would run the test a
# second time. So the code first looks in S-Boot's log ring, which survives resets: if the S-Boot
# log of the *previous* boot already carries this image's marker, it logs that it skips and hands
# straight back to S-Boot. @MARKER@ (17 characters) and @MARKLEN@ come from build_ffree.py.
SRESET_SOURCE = """    .syntax unified
    .arm
    .section .text,"ax",%progbits
    .global _start
_start:                         /* F2: the node the carved one points to, and the entry */
    b       stub
    .word   0                   /* free byte: the walk must skip this node */
    .word   0                   /* the allocator writes the carved node here */
    .word   0x23EC1048          /* next: the list head, so that the walk ends */
stub:
    ldr     r8, =0x26000000     /* S-Boot's log ring, 2 MiB, addressed by (position & 0x1FFFFF) */
    ldr     r7, =0x000FFFFF
    orr     r7, r7, #0x100000
    ldr     r0, =0x25FFFFFC     /* its write counter: where this boot's log ends so far */
    ldr     r0, [r0]
    adr     r2, 7f              /* the start of this boot's S-Boot log */
    mov     r3, #17
    mov     r1, #0x20000
    mov     lr, pc             /* a call: pc reads as this instruction + 8, so lr = the instruction after the branch
                                   (a `bl` would leave a relocation in the object) */
    b       4f
    cmp     r0, #0
    beq     run                 /* not seen: nothing says the test must not run */
    mov     r5, r0
    mov     r0, r5              /* the start of the previous boot's S-Boot log */
    ldr     r1, =0x180000
    adr     r2, 7f
    mov     r3, #17
    mov     lr, pc             /* a call: pc reads as this instruction + 8, so lr = the instruction after the branch
                                   (a `bl` would leave a relocation in the object) */
    b       4f
    cmp     r0, #0
    beq     run
    rsb     r1, r0, r5          /* did that boot already log this image's marker? */
    mov     r0, r5
    adr     r2, 9f
    mov     r3, #@MARKLEN@
    mov     lr, pc             /* a call: pc reads as this instruction + 8, so lr = the instruction after the branch
                                   (a `bl` would leave a relocation in the object) */
    b       4f
    cmp     r0, #0
    bne     skip
run:
    adr     r0, 9f              /* a line in S-Boot's own log */
    ldr     r4, =0x23E05820
    blx     r4
@EMMC@                              /* on the way: what build_ffree.py --emmc puts here (EMMC_READ, below) */
    b       8f
9:  .asciz  "@MARKER@ ARM32 payload running: cleaning the caches, then SMC 0x82000400\\n"
    .align  2
6:  .asciz  "@MARKER@ skipped: the previous boot already ran this image\\n"
    .align  2
7:  .asciz  "PARAM ENV VERSION"
    .align  2
skip:
    adr     r0, 6b
    ldr     r4, =0x23E05820
    blx     r4
    b       0f
8:  ldr     r4, =0x24220000     /* clean the data cache from my code to the end of S-Boot's log ring:
                                   what was written through the cache must reach RAM before the core changes state */
    ldr     r5, =0x26200000
2:  mcr     p15, 0, r4, c7, c10, 1
    add     r4, r4, #64
    cmp     r4, r5
    blo     2b
    dsb     sy
    mcr     p15, 0, r4, c7, c5, 0
    dsb     sy
    isb
    ldr     r0, =0x82000400     /* the Note 4 loader's call: function, AArch64 entry, 0x800, 1 */
    ldr     r1, =A64_ENTRY
    mov     r2, #0x800
    mov     r3, #1
    smc     #0
    adr     r0, 5f              /* back in ARM32: the monitor did not switch, say so and hand back */
    ldr     r4, =0x23E05820
    blx     r4
    b       0f
5:  .asciz  "@MARKER@ the SMC returned to ARM32 (unexpected); handing back to S-Boot\\n"
    .align  2
0:  ldr     r0, =0x67B00000     /* a free block for S-Boot's later requests: the bottom of the screen */
    ldr     r1, =0x80000
    str     r1, [r0]
    mov     r1, #1
    strb    r1, [r0, #4]
    mov     r1, #0
    str     r1, [r0, #8]
    ldr     r1, =0x23EC1048
    str     r1, [r0, #12]
    ldr     r0, =0x24F00000     /* the heap head stays busy and now points there */
    ldr     r1, =0x67B00000
    str     r1, [r0, #12]
    ldr     r5, =0x23E8000C     /* what boot keeps in r5 and r6 */
    ldr     r6, [r5, #0x28]
    ldr     pc, =0x23E069DC     /* boot, right after its call */

4:                              /* rfind: r0 = from, r1 = span, r2 = a text, r3 = its length -> r0 = the highest
                                   position p, from - span <= p < from, where the ring holds that text; 0 if none.
                                   Clobbers r0-r3, r9, r10, ip, lr; r7 and r8 hold the ring's mask and address.
                                   A numbered label, called with `mov lr, pc` and a branch: `bl` and a named label
                                   each leave a relocation in the object (build_hijack.elf_text refuses them). */
    rsb     r1, r1, r0          /* the lowest position looked at */
    cmp     r1, r0
    movhi   r1, #0              /* unless it is before the counter ever was: then from the start */
    sub     r0, r0, #1
10: cmp     r0, r1
    blo     13f
    and     ip, r0, r7
    add     ip, ip, r8
    ldrb    ip, [ip]
    ldrb    r10, [r2]
    cmp     ip, r10
    bne     12f                 /* first byte differs: the next position */
    mov     r9, #1
11: cmp     r9, r3
    bhs     14f                 /* every byte is the same */
    add     ip, r0, r9
    and     ip, ip, r7
    add     ip, ip, r8
    ldrb    ip, [ip]
    ldrb    r10, [r2, r9]
    cmp     ip, r10
    bne     12f
    add     r9, r9, #1
    b       11b
12: sub     r0, r0, #1
    b       10b
13: mov     r0, #0
14: bx      lr
"""


# What stands in for @EMMC@ in SRESET_SOURCE (build_ffree.py --emmc): the eMMC read through S-Boot's
# own reader. 0x23E17808(destination, first sector, bytes) is what `load_kernel` calls: it reads the
# user area of the eMMC straight to the destination when that is at or above 0x25700000, and returns
# the number of sectors read, or an error. Stage 2 (stage2/stage2.c, built with --emmc) then checks
# what arrived. Labels 20..23: 0..14 are taken in SRESET_SOURCE.
EMMC_READ = """    ldr     r0, =0x67B00000     /* the heap is disarmed first, as at the hand-back: from now on a request
                                   S-Boot makes is served at the bottom of the screen, never on the stack */
    ldr     r1, =0x80000
    str     r1, [r0]
    mov     r1, #1
    strb    r1, [r0, #4]
    mov     r1, #0
    str     r1, [r0, #8]
    ldr     r1, =0x23EC1048
    str     r1, [r0, #12]
    ldr     r0, =0x24F00000
    ldr     r1, =0x67B00000
    str     r1, [r0, #12]
    mrc     p15, 0, r4, c2, c0, 0
    ldr     r5, =0xFFFFC000     /* S-Boot's first-level table (16 KiB aligned): is 0x40000000 mapped at all? */
    and     r4, r4, r5
    add     r4, r4, #0x1000     /* the entry for 0x40000000: index 0x400 */
    ldr     r4, [r4]
    tst     r4, #3
    beq     21f
    ldr     r0, =0x40000000      /* where the reader will put it: nothing of S-Boot's lives there. If S-Boot maps
                                   it, its lines are cleaned and invalidated by address: nothing cached may hide
                                   what the storage controller writes, from here or from EL2 */
    ldr     r1, =0x40100000
20: mcr     p15, 0, r0, c7, c14, 1
    add     r0, r0, #64
    cmp     r0, r1
    blo     20b
    dsb     sy
21: ldr     r0, =0x40000000
    ldr     r1, =92160          /* the first sector of PARAM */
    ldr     r2, =0x100000       /* 1 MiB: as far as this very image's logo */
    ldr     r4, =0x23E17808     /* S-Boot's reader: destination, first sector, bytes */
    blx     r4
    mov     r1, r0
    mov     r2, r4              /* S-Boot keeps r4: still its table entry for 0x40000000 */
    adr     r0, 22f
    ldr     r4, =0x23E05820
    blx     r4
    b       23f
22: .ascii  "@MARKER@ eMMC: S-Boot's reader put %d sectors of PARAM from sector 92160 at 0x40000000 (2048 wanted); its table entry for 0x40000000: %08x"
    .byte   10, 0
    .align  2
23:
"""


# What build_ffree.py --el1 adds after EMMC_READ: the AArch64 image for EL1, loaded the same way from
# this very PARAM (build_ffree.py stores it in the logo file so that it sits on a sector) to
# 0x40080000, where stage 2 looks for its header. Labels 24, 25. @EL1_SECTOR@, @EL1_BYTES@,
# @EL1_WANTED@ (sectors) come from build_ffree.py.
EMMC_LOAD = """    ldr     r0, =0x40080000     /* the AArch64 image for EL1 */
    ldr     r1, =@EL1_SECTOR@    /* its first sector of PARAM */
    ldr     r2, =@EL1_BYTES@     /* its size, in whole sectors */
    ldr     r4, =0x23E17808     /* S-Boot's reader: destination, first sector, bytes */
    blx     r4
    mov     r1, r0
    adr     r0, 24f
    ldr     r4, =0x23E05820
    blx     r4
    b       25f
24: .ascii  "@MARKER@ EL1: S-Boot's reader put %d sectors of the AArch64 image at 0x40080000 (@EL1_WANTED@ wanted)"
    .byte   10, 0
    .align  2
25:
"""


# What build_ffree.py --kernel adds after the eMMC check: the arm64 kernel and its device tree,
# read the same way (S-Boot's reader) from the bundle that build_ffree.py stores outside PARAM:
# the kernel in pieces of at most 4 MiB, then the device tree in one piece. r10 says whether every
# piece of the kernel was read; stage 2 starts the kernel only if the headers are as they should be.
# Labels 30..34. @K_AT@, @K_SECTOR@, @K_BYTES@, @D_AT@, @D_SECTOR@, @D_BYTES@, @D_WANTED@ (sectors)
# come from build_ffree.py.
KERNEL_LOAD = """    mov     r10, #1              /* the arm64 kernel, where stage 2 will start it */
    ldr     r6, =@K_AT@
    ldr     r7, =@K_SECTOR@
    ldr     r8, =@K_BYTES@
28: mov     r0, r6                 /* at most 4 MiB at a time */
    mov     r1, r7
    mov     r2, r8
    cmp     r2, #0x400000
    bls     29f
    mov     r2, #0x400000
29: mov     r9, r2
    ldr     r4, =0x23E17808
    blx     r4
    lsr     r2, r9, #9
    cmp     r0, r2
    addeq   r6, r6, r9
    addeq   r7, r7, r2
    subeq   r8, r8, r9
    movne   r8, #0                 /* a piece failed: no more, and the kernel will not be started */
    movne   r10, #0
    cmp     r8, #0
    bne     28b
    ldr     r0, =@D_AT@            /* its device tree */
    ldr     r1, =@D_SECTOR@
    ldr     r2, =@D_BYTES@
    ldr     r4, =0x23E17808
    blx     r4
    mov     r1, r0                 /* sectors of the device tree read */
    cmp     r10, #1
    bne     30f
    adr     r0, 31f
    b       32f
30: adr     r0, 33f
32: ldr     r4, =0x23E05820
    blx     r4
    b       34f
31: .ascii  "@MARKER@ kernel: read whole; device tree: %d of @D_WANTED@ sectors at @D_AT_X@"
    .byte   10, 0
    .align  2
33: .ascii  "@MARKER@ kernel: a piece failed to read; it will not be started (device tree: %d sectors)"
    .byte   10, 0
    .align  2
34:
"""


# The production loader: what runs at every ordinary boot once the arm64 system is installed. The
# kernel is not in PARAM (which keeps this code only) but in the CACHE partition, in one of two
# raw slots written by scripts/slot.py (a 4 KiB header, the uncompressed Image, the device tree).
#
#   1. the ledger. The line "KBOOT: try", logged before anything risky, is what the next boots look at: the arm64
#      system writes "KBOOT: up" into the kernel log (which goes on into S-Boot's RAM ring) once
#      it is running. If one of the TWO previous boots (since kboot6, 2026-11-24) logged "KBOOT: try" and,
#      later in that same boot, neither "KBOOT: up" nor a hand-back of this loader (its lines end in
#      "S-Boot's kernel boots": that boot went on to S-Boot's own kernel by itself, nothing hung) -- a
#      kernel that hung, was reset by the watchdog or panicked, or a loader that died -- this boot
#      hands straight back to S-Boot, whose own kernel starts: the tablet is never held by a bad arm64
#      kernel. Two boots, because a failed attempt can cost a detour: a watchdog reset without the
#      PMU's normal-boot markers makes S-Boot boot RECOVERY, where this loader falls back (S-Boot then
#      starts RECOVERY's kernel, the rescue), the rescue resets towards BOOT, and that boot must not
#      try again (kboot5, 2026-11-24: a loop that never reached the 32-bit system). A fallback
#      boot logs no "try", so the third boot after a failed attempt tries again. With fewer than two
#      boots before in the ring (a cold power-on), only those there are looked at.
#   2. the two slot headers are read; the valid one with the highest generation is kept, the other
#      valid one is the second choice. Image and device tree are read through S-Boot's reader, the
#      cache lines over them are cleaned, and both are hashed (FNV-1a 64, in ARM32): a slot whose
#      bytes are not as its header says is left for the other one; if neither is, S-Boot's kernel
#      boots. Only then comes the monitor call.
#   3. the watchdog is armed (15 s) before the slots are touched, so that a hang of this code ends
#      in a reset; every way back to S-Boot masks its reset again.
#   4. the record for EL2 (since 2026-11-24 kboot4): what this code verified is handed to stage 2 at
#      0x40003000 (build_ffree.KBOOT_RECORD_AT), 16 words: the chosen header's first 0x38 bytes as
#      they were checked (its own FNV-1a 64 at 0x30 included), the slot's first sector, then the
#      record's magic "T7KR" (0x524B3754), written last. The 16 words are zeroed before the slots are
#      read, written only once a slot's image and tree are read and hashed, and their cache line is
#      cleaned and invalidated before the monitor call. Stage 2 (stage2.c, SLOT_RECORD) checks the
#      record (its magic, the header's magic, version, lengths, addresses and own hash) and then the
#      kernel and the tree against the lengths and hashes it names: nothing of a particular kernel is
#      built into the loader, so a slot is updated without a new PARAM.
#
# @SLOT_A@ and @SLOT_B@ (first sectors of the slots, absolute) come from build_ffree.py, A64_ENTRY
# from -D. Labels: 4 and 40..45 are subroutines (rfind, copy_header, read_range, clean_range,
# try_slot, fnv64, header_ok); 20..27 the main code; 50..63 inside the subroutines; 65, 66 the
# record's loops; 87..89 the ledger's loop over the two boots before; 70..82 texts.
KBOOT_SOURCE = """    .syntax unified
    .arm
    .section .text,"ax",%progbits
    .global _start
_start:                         /* F2: the node the carved one points to, and the entry */
    b       stub
    .word   0                   /* free byte: the walk must skip this node */
    .word   0                   /* the allocator writes the carved node here */
    .word   0x23EC1048          /* next: the list head, so that the walk ends */
stub:
    b       69f                 /* over the texts */
70: .asciz  "PARAM ENV VERSION"
    .align  2
71: .asciz  "KBOOT: try"
    .align  2
72: .asciz  "KBOOT: up"
    .align  2
73: .asciz  "KBOOT: fallback for this boot: an attempt in one of the two boots before did not report that it was up; S-Boot's kernel boots\\n"
    .align  2
82: .asciz  "S-Boot's kernel boots"
    .align  2
74: .asciz  "KBOOT: try: the arm64 kernel of CACHE is tried this boot\\n"
    .align  2
79: .asciz  "KBOOT: S-Boot does not map 0x40000000: S-Boot's kernel boots\\n"
    .align  2
69: /* ---- the ledger: the two boots before this one ---- */
    ldr     r8, =0x26000000     /* S-Boot's log ring: 2 MiB, addressed by (position & 0x1FFFFF) */
    ldr     r7, =0x000FFFFF
    orr     r7, r7, #0x100000
    ldr     r0, =0x25FFFFFC     /* its write counter: where this boot's log ends so far */
    ldr     r4, [r0]
    ldr     r11, =0x1F0000      /* r11: the oldest position looked at, 2 MiB back less 64 KiB (what is older is written
                                   over), or 0 when the counter is lower (a cold power-on): the ring's turn is never crossed */
    subs    r11, r4, r11
    movlo   r11, #0
    mov     r0, r4
    adr     r2, 70b             /* the start of this boot's S-Boot log */
    mov     r3, #17
    mov     r1, #0x20000
    mov     lr, pc              /* a call: pc reads as this instruction + 8, so lr = the instruction after the branch
                                   (a `bl` would leave a relocation in the object) */
    b       4f
    cmp     r0, #0
    beq     go                  /* no start of this boot's log seen: nothing is held against the arm64 kernel */
    mov     r5, r0              /* r5: the end of the boot looked at (this boot's start, first) */
    mov     r6, #2              /* r6: the boots before this one still to look at */
87: cmp     r5, r11
    bls     go                  /* nothing older in the ring: nothing is held against the kernel */
    mov     r0, r5              /* the start of the boot that ends at r5 */
    sub     r1, r5, r11
    adr     r2, 70b
    mov     r3, #17
    mov     lr, pc
    b       4f
    cmp     r0, #0
    beq     go                  /* none: fewer boots in the ring than looked for (a cold power-on); nothing is held */
    mov     r4, r0              /* r4: its start */
    sub     r1, r5, r4          /* its last "KBOOT: try" (10 characters) */
    mov     r0, r5
    adr     r2, 71b
    mov     r3, #10
    mov     lr, pc
    b       4f
    cmp     r0, #0
    beq     88f                 /* that boot did not try: nothing is held against it */
    push    {r0, r1}            /* where it tried, kept across the next searches (rfind takes r0-r3, r9, r10, ip) */
    sub     r1, r5, r0          /* its last "KBOOT: up", from there to its end (9 characters: until kboot5 only 8 were
                                   compared, "KBOOT: u") */
    mov     r0, r5
    adr     r2, 72b
    mov     r3, #9
    mov     lr, pc
    b       4f
    cmp     r0, #0
    bne     89f                 /* seen: that attempt was up */
    ldr     r1, [sp]
    sub     r1, r5, r1          /* or this loader's own hand-back in that boot ("S-Boot's kernel boots", 21 characters):
                                   it gave the boot to S-Boot's kernel itself, nothing hung */
    mov     r0, r5
    adr     r2, 82b
    mov     r3, #21
    mov     lr, pc
    b       4f
    cmp     r0, #0
    bne     89f
    add     sp, sp, #8
    adr     r0, 73b             /* neither: this boot goes to S-Boot's kernel, and so does the next (it looks two back) */
    b       hand
89: add     sp, sp, #8
88: mov     r5, r4              /* the boot before that one */
    subs    r6, r6, #1
    bne     87b
    b       go                  /* the two boots before are clean: the arm64 kernel is tried */
    .ltorg
80: .word   @SLOT_A@, @SLOT_B@, 0
    .align  2

go:
    adr     r0, 74b             /* the mark: from here on, a failure of this boot means the next one goes to S-Boot's kernel */
    ldr     r4, =0x23E05820
    blx     r4
    ldr     r0, =0x67B00000     /* the heap is disarmed, as at the hand-back: from now on a request S-Boot makes is served
                                   at the bottom of the screen, never on the stack */
    ldr     r1, =0x80000
    str     r1, [r0]
    mov     r1, #1
    strb    r1, [r0, #4]
    mov     r1, #0
    str     r1, [r0, #8]
    ldr     r1, =0x23EC1048
    str     r1, [r0, #12]
    ldr     r0, =0x24F00000
    ldr     r1, =0x67B00000
    str     r1, [r0, #12]
    ldr     r5, =0xFFFFC000     /* S-Boot's first-level table (16 KiB aligned): 0x40000000, where the headers go, must be mapped */
    mrc     p15, 0, r4, c2, c0, 0
    and     r4, r4, r5
    add     r4, r4, #0x1000     /* the entry for 0x40000000: index 0x400 */
    ldr     r4, [r4]
    tst     r4, #3
    bne     mapped
    adr     r0, 79b
    b       hand
86: .asciz  "KBOOT: S-Boot's first-level entry for 0x40000000: %08x\\n"
    .align  2
mapped:
    push    {r4}                /* the entry's value says how S-Boot maps the place: logged */
    mov     r1, r4
    adr     r0, 86b
    ldr     r4, =0x23E05820
    blx     r4
    pop     {r4}
    mrc     p15, 0, r4, c2, c0, 0
    and     r4, r4, r5
    add     r4, r4, #0x400      /* the entry for 0x10000000: the watchdog's registers */
    ldr     r4, [r4]
    tst     r4, #3
    beq     21f
    mrc     p15, 0, r4, c2, c0, 0
    and     r4, r4, r5
    add     r4, r4, #0x400      /* the entry for 0x105C0000: the power management unit (index 0x105) */
    add     r4, r4, #0x14
    ldr     r4, [r4]
    tst     r4, #3
    beq     21f
    ldr     r0, =0x10040900     /* the watchdog's clock, if S-Boot left it gated */
    ldr     r1, [r0]
    orr     r1, r1, #0x20000
    str     r1, [r0]
    ldr     r0, =0x105C0408     /* the power management unit lets a watchdog reset through */
    ldr     r1, [r0]
    bic     r1, r1, #0x01000000
    bic     r1, r1, #0x00800000
    str     r1, [r0]
    ldr     r0, =0x105C040C
    ldr     r1, [r0]
    bic     r1, r1, #0x01000000
    str     r1, [r0]
    ldr     r0, =0x10020004     /* WTDAT, then WTCNT at +4: 15 s, at 2034 ticks a second */
    movw    r1, #30510
    str     r1, [r0]
    str     r1, [r0, #4]
    ldr     r0, =0x10020000
    ldr     r1, =0xFF39         /* prescaler 255, divided by 128, on, reset on, no interrupt */
    str     r1, [r0]
    ldr     r0, =0x10020000     /* the lines of the registers, in case S-Boot maps them through a cache */
    mcr     p15, 0, r0, c7, c14, 1
    ldr     r0, =0x105C0400
    mcr     p15, 0, r0, c7, c14, 1
    dsb     sy
21:
    /* ---- the slots ---- */
    ldr     r0, =0x40003000     /* the record for EL2 (16 words): none until a slot is read and hashed whole, so that
                                   stage 2 never takes what an earlier boot left there in the memory */
    mov     r1, #0
    mov     r2, #16
66: str     r1, [r0], #4
    subs    r2, r2, #1
    bne     66b
    adr     r7, 80b             /* their first sectors, ended by 0: in r7, which nothing until `chosen` takes (fnv64 has r8 to r11) */
    mov     r6, #0              /* the best one so far: none (its first sector) */
    ldr     r0, =0x40002038     /* the other one's first sector: none */
    mov     r1, #0
    str     r1, [r0]
slots:
    ldr     r12, [r7], #4       /* a slot's first sector */
    cmp     r12, #0
    beq     chosen
    ldr     r0, =0x40000000     /* where its header is read: nothing cached may hide what the storage controller writes */
    ldr     r1, =0x40001000
20: mcr     p15, 0, r0, c7, c14, 1
    add     r0, r0, #64
    cmp     r0, r1
    blo     20b
    dsb     sy
    ldr     r0, =0x40000000
    mov     r1, r12
    ldr     r2, =0x1000
    ldr     r4, =0x23E17808     /* S-Boot's reader: destination, first sector, bytes */
    push    {r3, r12}           /* r12 (ip) is the callee's to clobber (AAPCS): S-Boot's reader returns it 0, and
                                   r12 holds the slot's sector here (seen on the tablet, kboot2, 2026-11-24) */
    blx     r4
    pop     {r3, r12}
    push    {r0, r12}           /* measured from 2026-11-24, when a header was refused on the tablet and not
                                   in the emulator: what the reader answered and what is there is logged */
    b       90f
83: .asciz  "KBOOT: slot at sector %d: the reader put %d sectors\\n"
    .align  2
90: mov     r2, r0
    mov     r1, r12
    adr     r0, 83b
    ldr     r4, =0x23E05820
    blx     r4
    b       91f
84: .asciz  "KBOOT: its header's words 0, 1 and 4: %08x %08x %08x\\n"
    .align  2
91: ldr     r1, =0x40000000
    ldr     r2, [r1, #4]
    ldr     r3, [r1, #0x10]
    ldr     r1, [r1]
    adr     r0, 84b
    blx     r4
    pop     {r1, r12}
    cmp     r1, #8
    bne     slots
    ldr     r0, =0x40000000
    mov     lr, pc
    b       45f                 /* is the header as it should be? */
    cmp     r0, #1
    beq     accepted
    push    {r0, r12}
    b       92f
85: .asciz  "KBOOT: slot at sector %d: the header is refused, reason %x\\n"
    .align  2
92: mov     r2, r0
    mov     r1, r12
    adr     r0, 85b
    ldr     r4, =0x23E05820
    blx     r4
    pop     {r0, r12}
    b       slots
accepted:
    ldr     r0, =0x40000000
    ldr     r1, [r0, #8]        /* its generation */
    cmp     r6, #0
    bne     22f
    ldr     r9, =0x40001000     /* the first valid one: the best */
    mov     r3, r12
    mov     r6, r12
    mov     lr, pc
    b       40f
    b       slots
22: ldr     r9, =0x40001008
    ldr     r9, [r9]
    cmp     r1, r9
    bls     23f                 /* not the newest: the other one */
    ldr     r0, =0x40001000     /* newer than the best: the best becomes the other one */
    ldr     r9, =0x40002000
    mov     r3, r6
    mov     lr, pc
    b       40f
    ldr     r0, =0x40000000
    ldr     r9, =0x40001000
    mov     r3, r12
    mov     r6, r12
    mov     lr, pc
    b       40f
    b       slots
23: ldr     r9, =0x40002000     /* the other one */
    mov     r3, r12
    mov     lr, pc
    b       40f
    b       slots
chosen:
    cmp     r6, #0
    bne     24f
    b       95f                 /* over the text */
75: .asciz  "KBOOT: no valid kernel in CACHE: S-Boot's kernel boots\\n"
    .align  2
95: adr     r0, 75b
    b       hand
24: ldr     r12, =0x40001000
    mov     lr, pc
    b       43f                 /* the best one: read, cleaned, hashed */
    cmp     r0, #1
    beq     26f
    ldr     r1, =0x40002038
    ldr     r1, [r1]
    cmp     r1, #0
    beq     25f
    ldr     r12, =0x40002000
    mov     lr, pc
    b       43f                 /* the other one */
    cmp     r0, #1
    bne     25f
26: ldr     r10, [r12, #0x38]    /* the slot's first sector */
    ldr     r11, [r12, #8]      /* its generation */
    ldr     r3, [r12, #0x10]
    ldr     r4, =0x23E05820
    adr     r0, 76f
    mov     r1, r10
    mov     r2, r11
    push    {r3, r12}           /* r12: the chosen header's copy, across S-Boot's printf (AAPCS: ip is its to clobber) */
    blx     r4
    pop     {r3, r12}
    ldr     r1, [r12, #0x14]
    ldr     r2, [r12, #0x18]
    ldr     r3, [r12, #0x1C]
    adr     r0, 77f
    push    {r3, r12}
    blx     r4
    pop     {r3, r12}
    ldr     r0, =0x40003000     /* the record for EL2: the chosen header as it was checked (0x38 bytes, its own hash
                                   included) and the slot's first sector, as copy_header left them at r12; then "T7KR",
                                   last. Stage 2 takes the lengths and the hashes from it (stage2.c, SLOT_RECORD) */
    mov     r1, r12
    mov     r2, #15
65: ldr     r3, [r1], #4
    str     r3, [r0], #4
    subs    r2, r2, #1
    bne     65b
    ldr     r3, =0x524B3754     /* "T7KR" */
    str     r3, [r0]
    ldr     r0, =0x40003000     /* its line (64 bytes) cleaned and invalidated: in the memory before the monitor call,
                                   whatever S-Boot's map of the place, and nothing of it left in a cache for EL2 to read */
    add     r1, r0, #0x40
    mov     lr, pc
    b       42f
    b       8f
76: .asciz  "KBOOT: slot at sector %d, generation %d: the image is %d bytes\\n"
    .align  2
77: .asciz  "KBOOT: image at %08x, device tree %d bytes at %08x: both read whole and hashed as the header says\\n"
    .align  2
25: b       96f                 /* over the text */
78: .asciz  "KBOOT: the kernel in CACHE is not as its header says: S-Boot's kernel boots\\n"
    .align  2
96: adr     r0, 78b
    b       hand

8:  ldr     r4, =0x24220000     /* clean the data cache from my code to the end of S-Boot's log ring: what was written
                                   through the cache must reach RAM before the core changes state */
    ldr     r5, =0x26200000
27: mcr     p15, 0, r4, c7, c10, 1
    add     r4, r4, #64
    cmp     r4, r5
    blo     27b
    dsb     sy
    mcr     p15, 0, r4, c7, c5, 0
    dsb     sy
    isb
    ldr     r0, =0x82000400     /* the Note 4 loader's call: function, AArch64 entry, 0x800, 1 */
    ldr     r1, =A64_ENTRY
    mov     r2, #0x800
    mov     r3, #1
    smc     #0
    b       97f                 /* back in ARM32: the monitor did not switch; over the text */
81: .asciz  "KBOOT: the SMC returned to ARM32 (unexpected): S-Boot's kernel boots\\n"
    .align  2
97: adr     r0, 81b
    b       hand

hand:                           /* r0 = the line; then S-Boot's kernel boots */
    ldr     r4, =0x23E05820
    blx     r4
0:  ldr     r5, =0xFFFFC000     /* a watchdog reset is masked again (0x105C0000: index 0x105) */
    mrc     p15, 0, r4, c2, c0, 0
    and     r4, r4, r5
    add     r4, r4, #0x400
    add     r4, r4, #0x14
    ldr     r4, [r4]
    tst     r4, #3
    beq     28f
    ldr     r0, =0x105C0408
    ldr     r1, [r0]
    orr     r1, r1, #0x01000000
    orr     r1, r1, #0x00800000
    str     r1, [r0]
    ldr     r0, =0x105C040C
    ldr     r1, [r0]
    orr     r1, r1, #0x01000000
    str     r1, [r0]
    ldr     r0, =0x105C0400
    mcr     p15, 0, r0, c7, c14, 1
    dsb     sy
28: ldr     r0, =0x67B00000     /* a free block for S-Boot's later requests: the bottom of the screen */
    ldr     r1, =0x80000
    str     r1, [r0]
    mov     r1, #1
    strb    r1, [r0, #4]
    mov     r1, #0
    str     r1, [r0, #8]
    ldr     r1, =0x23EC1048
    str     r1, [r0, #12]
    ldr     r0, =0x24F00000     /* the heap head stays busy and now points there */
    ldr     r1, =0x67B00000
    str     r1, [r0, #12]
    ldr     r5, =0x23E8000C     /* what boot keeps in r5 and r6 */
    ldr     r6, [r5, #0x28]
    ldr     pc, =0x23E069DC     /* boot, right after its call */
    .ltorg
4:                              /* rfind: r0 = from, r1 = span, r2 = a text, r3 = its length -> r0 = the highest
                                   position p, from - span <= p < from, where the ring holds that text; 0 if none.
                                   Clobbers r0-r3, r9, r10, ip, lr; r7 and r8 hold the ring's mask and address.
                                   The bound is tested before the step down (since kboot6): until kboot5 the position
                                   was lowered first and compared after, so with the lowest position 0 (a search that
                                   reaches the start of the counter, as on a ring without the boot looked for, after a
                                   power-on) it wrapped to 0xffffffff and went on, the watchdog not yet armed */
    rsb     r1, r1, r0          /* the lowest position looked at */
    cmp     r1, r0
    movhi   r1, #0              /* unless it is before the counter ever was: then from the start */
10: cmp     r0, r1
    bls     13f                 /* no position left */
    sub     r0, r0, #1          /* the next one down */
    and     ip, r0, r7
    add     ip, ip, r8
    ldrb    ip, [ip]
    ldrb    r10, [r2]
    cmp     ip, r10
    bne     10b                 /* first byte differs: the next position */
    mov     r9, #1
11: cmp     r9, r3
    bhs     14f                 /* every byte is the same */
    add     ip, r0, r9
    and     ip, ip, r7
    add     ip, ip, r8
    ldrb    ip, [ip]
    ldrb    r10, [r2, r9]
    cmp     ip, r10
    bne     10b
    add     r9, r9, #1
    b       11b
13: mov     r0, #0
14: bx      lr

40: mov     r2, #14             /* copy_header: r0 = a header, r9 = where its copy goes, r3 = the slot's first sector
                                   (kept after the copy's 0x38 bytes). Clobbers r0-r3, r9, lr */
61: ldr     r1, [r0], #4
    str     r1, [r9], #4
    subs    r2, r2, #1
    bne     61b
    str     r3, [r9]
    bx      lr

41: push    {r4, lr}            /* read_range: r6 = where, r7 = the first sector, r8 = how many bytes, in pieces of at
                                   most 4 MiB -> r0 = 1 if all of it was read. Clobbers r0-r2, r4, r6-r9, lr; keeps r3 and r12 */
64: mov     r0, r6
    mov     r1, r7
    mov     r2, r8
    cmp     r2, #0x400000
    bls     63f
    mov     r2, #0x400000
63: mov     r9, r2
    ldr     r4, =0x23E17808     /* S-Boot's reader: destination, first sector, bytes */
    push    {r3, r12}           /* r12 is try_slot's pointer to the header's copy: the reader may clobber it (AAPCS) */
    blx     r4
    pop     {r3, r12}
    lsr     r2, r9, #9
    cmp     r0, r2              /* the sectors read must be the sectors asked for */
    movne   r0, #0
    popne   {r4, pc}
    add     r6, r6, r9
    add     r7, r7, r2
    sub     r8, r8, r9
    cmp     r8, #0
    bne     64b
    mov     r0, #1
    pop     {r4, pc}

42: mcr     p15, 0, r0, c7, c14, 1   /* clean_range: r0 .. r1: every line cleaned and invalidated, so that the bytes are
                                   in the memory whatever was cached. Clobbers r0, ip */
    add     r0, r0, #64
    cmp     r0, r1
    blo     42b
    dsb     sy
    bx      lr

43: push    {r4, lr}            /* try_slot: r12 = a slot's header as copied by copy_header -> r0 = 1 once its image
                                   and its device tree are read whole, cleaned, and hashed as the header says.
                                   Clobbers r0-r11, ip */
    ldr     r6, [r12, #0x14]
    ldr     r8, [r12, #0x10]
    ldr     r7, [r12, #0x38]    /* the image starts 8 sectors after the slot's first: past the 4 KiB header */
    add     r7, r7, #8
    mov     lr, pc
    b       41b
    cmp     r0, #1
    bne     62f
    ldr     r6, [r12, #0x1C]    /* the device tree right after the image */
    ldr     r8, [r12, #0x18]
    ldr     r7, [r12, #0x38]
    add     r7, r7, #8
    ldr     r0, [r12, #0x10]
    add     r7, r7, r0, lsr #9
    mov     lr, pc
    b       41b
    cmp     r0, #1
    bne     62f
    ldr     r0, [r12, #0x14]
    ldr     r1, [r12, #0x10]
    add     r1, r0, r1
    mov     lr, pc
    b       42b
    ldr     r0, [r12, #0x1C]
    ldr     r1, [r12, #0x18]
    add     r1, r0, r1
    mov     lr, pc
    b       42b
    ldr     r0, [r12, #0x14]
    ldr     r1, [r12, #0x10]
    ldr     r2, =0x84222325
    ldr     r3, =0xCBF29CE4
    mov     lr, pc
    b       44f
    ldr     r9, [r12, #0x20]
    ldr     r10, [r12, #0x24]
    cmp     r2, r9
    cmpeq   r3, r10
    bne     62f
    ldr     r0, [r12, #0x1C]
    ldr     r1, [r12, #0x18]
    ldr     r2, =0x84222325
    ldr     r3, =0xCBF29CE4
    mov     lr, pc
    b       44f
    ldr     r9, [r12, #0x28]
    ldr     r10, [r12, #0x2C]
    cmp     r2, r9
    cmpeq   r3, r10
    bne     62f
    mov     r0, #1
62: pop     {r4, pc}

44: movw    r5, #0x1B3          /* fnv64: r0 = bytes, r1 = how many, r2:r3 = the hash (low:high), taken further.
                                   hash = (hash ^ byte) * 0x100000001B3, and the prime is 2^40 + 0x1B3: with lo and hi the two words
                                   of the hash, the new words are  lo' = low32(lo * 0x1B3)  and
                                   hi' = (lo << 8) + high32(lo * 0x1B3) + low32(hi * 0x1B3), each word kept to 32 bits.
                                   Four bytes a round. The sum for hi' is kept to 32 bits and nothing more: its carry is
                                   bit 64 of the product, which FNV-1a 64 drops (until 2026-11-24 an `adds`/`adc`
                                   put it back into hi', about one byte in 10 to 20 million: the 5.6 MB kernels passed by
                                   luck, a 13 MB one did not; found on the tablet). Clobbers r0-r3, r5, r9-r11, r8, lr */
50: cmp     r1, #4
    blo     52f                 /* fewer than four left: one at a time */
    ldrb    r8, [r0, #0]
    eor     r2, r2, r8
    umull   r9, r10, r2, r5
    umull   r11, r8, r3, r5
    lsl     r8, r2, #8
    add     r10, r10, r11
    add     r3, r10, r8
    mov     r2, r9
    ldrb    r8, [r0, #1]
    eor     r2, r2, r8
    umull   r9, r10, r2, r5
    umull   r11, r8, r3, r5
    lsl     r8, r2, #8
    add     r10, r10, r11
    add     r3, r10, r8
    mov     r2, r9
    ldrb    r8, [r0, #2]
    eor     r2, r2, r8
    umull   r9, r10, r2, r5
    umull   r11, r8, r3, r5
    lsl     r8, r2, #8
    add     r10, r10, r11
    add     r3, r10, r8
    mov     r2, r9
    ldrb    r8, [r0, #3]
    eor     r2, r2, r8
    umull   r9, r10, r2, r5
    umull   r11, r8, r3, r5
    lsl     r8, r2, #8
    add     r10, r10, r11
    add     r3, r10, r8
    mov     r2, r9
    add     r0, r0, #4
    sub     r1, r1, #4
    b       50b
52: subs    r1, r1, #1
    blo     51f
    ldrb    r8, [r0], #1
    eor     r2, r2, r8
    umull   r9, r10, r2, r5
    umull   r11, r8, r3, r5
    lsl     r8, r2, #8
    add     r10, r10, r11
    add     r3, r10, r8
    mov     r2, r9
    b       52b
51: bx      lr

45: push    {r4, lr}            /* header_ok: r0 = a slot's header -> r0 = 1 if it is one of ours and says sane things,
                                   else 0x100 + the reason: 1 magic, 2 version, 3 image length, 4 tree length, 5 too
                                   big for a slot, 6 image address, 7 tree address, 8 generation, 9 the header's own
                                   hash. Calls fnv64, so its return is kept on the stack. Clobbers r0-r3, r5, r8-r11 */
    ldr     r1, [r0]
    ldr     r2, =0x314B3754     /* "T7K1" */
    cmp     r1, r2
    movne   r0, #0x101
    popne   {r4, pc}
    ldr     r1, [r0, #4]
    cmp     r1, #1              /* version 1 */
    movne   r0, #0x102
    popne   {r4, pc}
    ldr     r1, [r0, #0x10]     /* the image: some whole sectors (the shift leaves its low 9 bits: zero then) */
    cmp     r1, #0
    beq     60f
    lsls    r2, r1, #23
    bne     60f
    b       61f
60: mov     r0, #0x103
    pop     {r4, pc}
61: ldr     r2, [r0, #0x18]     /* the device tree: the same */
    cmp     r2, #0
    beq     62f
    lsls    r3, r2, #23
    bne     62f
    b       63f
62: mov     r0, #0x104
    pop     {r4, pc}
63: add     r1, r1, r2          /* header, image and tree fit a slot: 64 MiB */
    add     r1, r1, #0x1000
    ldr     r2, =0x4000000
    cmp     r1, r2
    movhi   r0, #0x105
    pophi   {r4, pc}
    ldr     r1, [r0, #0x14]     /* and they go where the code expects them */
    ldr     r2, =0x42000000
    cmp     r1, r2
    movne   r0, #0x106
    popne   {r4, pc}
    ldr     r1, [r0, #0x1C]
    ldr     r2, =0x5F000000
    cmp     r1, r2
    movne   r0, #0x107
    popne   {r4, pc}
    ldr     r1, [r0, #8]        /* a generation */
    cmp     r1, #0
    moveq   r0, #0x108
    popeq   {r4, pc}
    mov     r1, #0x30           /* the header's own hash, over its first 0x30 bytes */
    ldr     r2, =0x84222325
    ldr     r3, =0xCBF29CE4
    mov     lr, pc
    b       44b
    ldr     r0, =0x40000000     /* fnv64 took r0 further: the header again */
    ldr     r9, [r0, #0x30]
    ldr     r10, [r0, #0x34]
    cmp     r2, r9
    cmpeq   r3, r10
    movne   r0, #0x109
    popne   {r4, pc}
    mov     r0, #1
    pop     {r4, pc}
"""
