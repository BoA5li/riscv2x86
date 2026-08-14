# VEE 2018 RISC-V GNU inline-assembly extraction

## Result

**0 fragments selected.** This is an intentional, auditable empty corpus—not a failed or incomplete extraction.

The requested source is the supplementary SQLite database for Rigger et al., *An Analysis of x86-64 Inline Assembly in C Programs* (VEE 2018):

- database repository: <https://github.com/jku-ssw/inline-assembly>
- file: `database.db`
- Git blob SHA: `4ff5a3464a6da540f9cb46f664e8ee0322da10e1`
- size at verification: 2,566,144 bytes

## Why the result is empty

The paper states that its quantitative database was built from inline-assembly occurrences **written for x86-64**, and that detailed analysis manually retained fragments used for an **x86-64 Linux** machine. Accordingly, this source cannot provide a fragment that is *actually a RISC-V GNU inline-assembly fragment*. Relabelling an x86-64 record as RISC-V would invalidate provenance and make it unsuitable as a test-corpus input for this translator.

The exact selection manifest is in [`riscv_gnu_inline_asm.json`](riscv_gnu_inline_asm.json). It deliberately contains an empty `records` list and a machine-readable rationale.

## Scope boundary

This result says only that the VEE 2018 database is not a source of RISC-V input samples. Its x86-64 fragments may still be useful for a separate study of inline-assembly syntax, operand constraints, or compiler-shell features, but they must not be treated as RISC-V source programs.

A non-empty Layer-A RISC-V corpus must be mined from RISC-V-enabled revisions/configurations of real projects (for example, project-specific RISC-V back ends), while preserving each fragment's source URL, commit, preprocessor guard, target condition, operands, clobbers, and surrounding C/C++ context.
