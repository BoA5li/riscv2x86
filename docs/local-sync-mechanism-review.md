# Registered local instruction visibility mechanism, v1

This review selects QEMU commit b67b00e6b4c7831a3f5bc684bc0df7a9bfd1bd56,
Linux user mode on an x86-64 host, and the shipped separately compiled CPUID
helper. `local_sync_mechanism.py` pins the reviewed source files and helper.
Hashes select this argument; they do not establish it or the experiment premises.

## Argument and premises

The guest is one thread and one logical execution context. Writes and later
fetches use the same private anonymous ordinary coherent mapping, with no aliases,
external writers, MMIO, DMA, active-code overwrite or cross-hart publication.
CPU affinity is an additional host scheduling constraint, not evidence that a
host CPU is itself the guest hart. The operator declares the process/mapping
premises; the bounded observer constructs its private mapping and checks affinity.

In the pinned QEMU implementation, `trans_fence_i` checks the instruction
extension, sets the succeeding guest PC and exits the translation block.
Code-page write protection and `page_unprotect` invalidate affected translated
blocks before subsequent execution. `tb-maint.c` removes the stale translations;
`user-exec.c` provides the user-mode fault path. This combination is the source
mechanism for this local mapping domain. The comment calling FENCE.I a no-op
does not justify deleting the instruction or its compiler ordering boundary.

The target helper executes a volatile CPUID with explicit register, memory and
condition-code constraints. The C calling convention contains its register
effects. The separate translation unit and no-LTO build contract preserve the
call boundary and compiler memory effects. On an x86 processor providing the
registered serializing CPUID protocol, stores followed by serialization and
execution establish the local SMC sequence. CPUID must be permitted in the
process; faults or unavailable execution are unsuccessful experiments.

The target argument follows the serializing-instruction option in Intel SDM
Volume 3A, "Handling Self- and Cross-Modifying Code":
https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3a-part-1-manual.pdf

Source references, all at the pinned commit:
https://github.com/qemu/qemu/tree/b67b00e6b4c7831a3f5bc684bc0df7a9bfd1bd56/accel/tcg
https://github.com/qemu/qemu/blob/b67b00e6b4c7831a3f5bc684bc0df7a9bfd1bd56/target/riscv/insn_trans/trans_rvi.c.inc

## Evidence boundary

The bounded observer writes distinct real instruction sequences, calls the
approved function, executes each modified sequence, and retains actual results
and scheduling observations. It checks behavior, not universal correctness.
QEMU can detect SMC even without FENCE.I: deleting the fence is not necessarily a
dynamic negative control. Scope, implementation, approval, build and identity
mutations are independently rejected. Helper overhead, physical timing,
speculative side-channel behavior, remote publication and L3 are excluded.

Selecting this file as the review basis is appropriate only when the stated
operator premises actually hold. It does not authorize a wider application or
replace Phase 6D approval, independent replay, runtime build validation or the
central evidence closer.
