/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 elkir0
 */
/* Where it is loaded: an AArch64 image for EL1, built by scripts/build_el1.py. S-Boot's reader puts
   it at 0x40080000 (build_ffree.py --el1 stores it in the logo file so that it sits on a sector of
   PARAM), and stage 2 enters it with an eret from EL2. A 16-byte header comes first: a magic, a size. */
ENTRY(el1_entry)
SECTIONS
{
    . = 0x40080000;
    .text.header : { KEEP(*(.text.header)) }
    .text : { KEEP(*(.text.entry)) *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .data : { *(.data .data.*) }
    .bss : { __bss_start = .; *(.bss .bss.*) *(COMMON) . = ALIGN(8); __bss_end = .; }
    el1_end = .;
    /DISCARD/ : { *(.comment) *(.note.*) *(.eh_frame) *(.gnu.attributes) }
}
