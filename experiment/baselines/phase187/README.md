# Phase187 validation record

Remote base: 8ccbeb8dd5003d22f0506cccbf84addf09684e2f.
Local base tree: d2477c0545d31c42a9101db12344fef1cbb71f7c (identical).

Selected 58-module expanded regression: **761 passed, 10 environment skips**,
431.84 seconds, exit 0; module list in modules.json and full results in broad.log.
This run preceded the final conservative output-expression-evaluation and
machine state-write guards. After those guards, the directly affected producer,
translation, physical materialization, verifier and evaluation modules were
rechecked: **84 passed**, 30.38 seconds, exit 0. The final joined original-route
and component tests (including shared C input/output variables) gave **30 passed**,
8.74 seconds, exit 0. Sets overlap and MUST NOT be added.

A supplementary older scalar-contract module has **18 passed, 1 failed** on
BOTH the unmodified base and the final tree. The identical existing failing test
is test_rv64_counter_csr_read_is_a_structured_runtime_route: it expects functional_c
where the current baseline returns needs_route. This CSR path is unrelated to the
new unsigned-high contract. Baseline and final logs are retained. No assertion or
production CSR gate was changed to hide the existing failure. This is NOT a claim
that the entire repository test suite passes.

Initial component checks exposed two real integration problems, corrected before
final checks: a wrong optional native-decoder module import, and c_module being a
namespace package with no verifiable source origin. Decoder identity now follows
the backend's actual class module and captures adapter/Sleigh/spec files. An explicit
c_module/__init__.py fixes source provenance without relaxing the existing verifier.
Initial diagnostic logs are kept, not counted as successful runs.

Tests use Python 3.12, pypcode 3.3.3 and Z3 4.16.0.0. z3-solver was already a declared
requirements-legacy dependency; it was installed into the isolated test environment.
PYTHONPATH is the tested checkout's pytools and PYTHONDONTWRITEBYTECODE=1.

Evidence boundaries:

* Real p-code lifting of RV32/RV64 unsigned-high machine bytes, original Phase6A--6F,
  bitvector projection/commutation lemmas, candidate materialization and replay run.
* The joined adapter test fixtures only the unavailable compiler export/source
  assembler/process boundary. Its original Pipeline, proof, renderer, physical binding,
  archive, materializer and replay checker execute. It is NOT a real GMP or Ghidra run.
* Host GCC compiles/runs generated 32/64-bit code at O0/O2/O3. Boundary/random inputs
  and aliased C input/output variables compare with arbitrary-precision multiplication.
* Real linked ELF tests distinguish a supported leaf from callee-saved modification,
  direction-flag modification and memory access; code is independently rederived.
  No complete function interface ABI or runtime coverage is inferred.
* Object tests prove/counterexample finite affine models under stated assumptions.
  They do not establish that model events describe C code or cover internal accesses.
* Plan tests freeze file identities and generate obligations. File presence or a
  successful plan checker does not prove those contracts' semantics.

No real Ghidra installation, RISC-V compiler/QEMU/Clang integration or ptrace-based
instance coverage was available locally. Environment skips are recorded verbatim.
No macro rewrite authorization, whole-GMP ABI/object closure, canonical instance
execution or program-level semantic/production acceptance was granted.
