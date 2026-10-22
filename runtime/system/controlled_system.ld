OUTPUT_ARCH(riscv)
ENTRY(_start)
SECTIONS {
  . = 0x80000000;
  .text : { *(.text.init) *(.text .text.*) }
  .rodata : { *(.rodata .rodata.*) }
  .data : { *(.data .data.*) *(.sdata .sdata.*) }
  . = ALIGN(8);
  PROVIDE(__global_pointer$ = . + 0x800);
  __bss_start = .;
  .bss : { *(.bss .bss.*) *(.sbss .sbss.*) *(COMMON) }
  . = ALIGN(16);
  __bss_end = .;
  . += 0x10000;
  __stack_top = .;
}
