# Phase189 verification

Base tree: `79ef3102864afc77cda4a9f903f91ef0ee00ddbe`, identical to remote
Phase188 `f3ac0ba13e3c961a155bd7e5500e57597d3faa4f`.

- `project-adapter.log`: final project module, 27 passed. Real native capture,
  object/shared-library/executable builds, duplicate library operands, exact
  process comparison, declared nonzero exits, record/command rederivation,
  case/domain validation, original request schema and provider dispatch.
- `combined-regression.log`: 95 passed, 3 skipped. This earlier combined run
  contains 22 of the project-adapter tests and 73 other tests covering original
  candidate/audit/evaluation/corpus, native input integrity, original evaluation
  orchestration and L0 interfaces. Subsequent project-only changes added explicit
  exit domains, stricter project build checking and additional tests; the
  original evaluator/compile-context/registry code did not change afterwards.
- `protocol-regression.log`: 39 passed, disjoint project build contract/profile,
  evaluation state separation and partial-program tests.

These logs cover 139 distinct passing tests, with the overlap above excluded.
They are not a full-repository or real GMP acceptance result. The 3 skips require
real Clang, RISC-V GCC/QEMU or the complete native SDK; a protocol test does not
replace those integrations. The new L0 adapter delegates to the unchanged full
18-cell original reference producer/checker. Its dispatch and ordered arguments
are tested here; the full real-GMP matrix remains a host verification task.

Compiler/frontend/Ghidra ingress used by existing original-pipeline fixtures is
explicitly mocked at those boundaries. The positive project-freeze test uses real
native capture/ELF bytes but a mocked source-ISA metadata boundary; it validates
selection/pinning/rederivation, not executable RISC-V code. Actual native rebuild
and process-comparison tests do not certify cross-ISA equivalence, machine ABI,
internal object legality, canonical instance execution, or program L2/L3.

No test relaxes missing-evidence gates, suppresses a matrix cell failure, edits
GMP thresholds or marks bounded process agreement as final approval.

Host instructions: `docs/phase189-project-evaluation-automation.md`.
