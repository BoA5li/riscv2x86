# Embench RISC-V GNU inline-assembly corpus

## Pinned source and result

This corpus contains **9 source occurrences** of real RISC-V GNU inline assembly found in [Embench-IoT](https://github.com/embench/embench-iot) at commit [`09c2ed8c3b7008c95d08b038de4a3f6dc103ed70`](https://github.com/embench/embench-iot/commit/09c2ed8c3b7008c95d08b038de4a3f6dc103ed70).  Every record has a source permalink and retains its exact GNU asm statement, operand constraints, clobbers, function, and source line.

The source files are not copied here: Embench's originals remain the authoritative GPL-3.0-or-later material.  This manifest is a provenance-preserving index for acquisition by exact commit.

## Included source files

- [`examples/riscv32/ri5cyverilator/boardsupport.c`](https://github.com/embench/embench-iot/blob/09c2ed8c3b7008c95d08b038de4a3f6dc103ed70/examples/riscv32/ri5cyverilator/boardsupport.c): 3 occurrences of `li a0, 0`.
- [`examples/riscv32/cv32e40pv2fpga/boardsupport.c`](https://github.com/embench/embench-iot/blob/09c2ed8c3b7008c95d08b038de4a3f6dc103ed70/examples/riscv32/cv32e40pv2fpga/boardsupport.c): 6 occurrences: `li a0, 0`, `csrci mcountinhibit, 0x1`, `rdcycle %0`, and `rdcycleh %0`.

The resulting mix intentionally exercises several translator-relevant shell contracts:

- fixed-register text plus a `memory` clobber with no declared C result;
- a CSR immediate instruction;
- output-only `=r` constraints;
- volatile reads of the cycle counter, including RV32-specific `rdcycleh`.

## Extraction boundary

Candidate files were searched at the pinned commit using the forms `__asm__`, `__asm__ volatile`, `asm volatile`, and `riscv`, then manually verified to be in RISC-V target directories and to use GNU inline-assembly syntax.  Each textual occurrence is a separate record; duplicate templates are not deduplicated because their enclosing function and target platform are part of the provenance.

This is a source corpus, not an assertion that every fragment is safe to lower. In particular, the `li a0, 0` records write ABI register `a0` without declaring a register output or clobber; the metadata preserves that source-level fact for fail-closed semantic analysis.
