/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 elkir0
 */
/* Stage 2, where it is loaded: the first C code at EL2, inside the file buffer that holds the
   forged logo (built by scripts/build_stage2.py, placed by build_ffree.py at file offset 0x24000).
   A stack sits above the page tables of stage 1 (0x90020000). */
ENTRY(stage2_entry)
SECTIONS
{
    . = 0x24224000;
    .text : { KEEP(*(.text.entry)) *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .data : { *(.data .data.*) }
    /* 8-aligned at both ends: the entry clears it with 64-bit stores, and on the tablet (SCTLR_EL2.A = 1)
       a store to an odd address is an alignment fault (2026-11-24, image smp1) */
    .bss : ALIGN(8) { __bss_start = .; *(.bss .bss.*) *(COMMON) . = ALIGN(8); __bss_end = .; }
    /DISCARD/ : { *(.comment) *(.note.*) *(.eh_frame) *(.gnu.attributes) }
}
