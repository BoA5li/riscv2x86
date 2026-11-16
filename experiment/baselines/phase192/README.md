# Phase192 verification

Machine inventories reuse pypcode/SLEIGH with pinned tools and actual ELF bytes.
Native tests compile and link real AMD64 functions with branches/calls/accesses.
RV64GC tests use explicit instruction bytes in a synthetic sectioned ELF fixture, not an executable cross-built program.
Project tests mock compiler-owner ingress and use real native object/library/program builds.
No full ABI/object/canonical instruction coverage or real GMP acceptance is claimed.

See docs/phase192-original-machine-inventory.md for host validation.

- regression.log: 98 passed in 305.38 s before the bounded decode-window optimization.
- final.log: 39 passed in 23.49 s after the window optimization, including complete/partial decode, original L1 integration, request/program binding checks, and rehashed forged facts.

The two runs overlap; they are not 137 distinct tests. Host GMP timing and proof closure remain unmeasured for this revision.
