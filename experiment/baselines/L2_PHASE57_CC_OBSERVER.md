# Observer shell compatibility for scalar dependencies

Base: phase56-zero-operand-and-dependency-observers. This change addresses the
production failure L2_DEPENDENCY_OBSERVER_SHELL_UNSUPPORTED for `cc` clobbers.
It does not delete source clobbers or alter L2 verdict thresholds.

## Contract

`ObserverShellCompatibilityDecision` is an immutable typed decision. A supported
decision binds the fragment/source/compiler boundary, canonical boundary/graph,
Phase 6D proof, effect facts, shell relation, sidecar authority/relation set,
renderer, complete source statement range, source shell payload and exact target
replacement. Its identity is a hash of its serialized content, independent of
runtime samples.

The rule covers straight-line scalar register operands observed outside complete
asm/replacement statements using ordinary compiler-visible C calls. It requires:

- approved architecture and shell preservation; recomputed approval proof ID;
- parsed/rehashed complete effect proof facts with matching proof, plan,
  constraint and renderer identities;
- exact scalar-only source and target effects (no control/memory/runtime route);
- complete shell relation and approved compiler visibility, volatile placement,
  continuation and, when declared, condition-code clobber preservation;
- parsed complete sidecar with matching shell binding, source effects and
  approved effect relations, no fixed-register/memory/control/ordering authority;
- compiler-owned statement boundaries and valid scalar register constraints.

`cc` is a compiler kill contract, not a live scalar output or a requirement that
RISC-V and x86 have identical physical flags. The rule does not insert code inside
an instruction sequence that uses flags internally. It does not infer semantics
from instruction text. Exact replacement bytes are hashed and checked only for
binding and offset mapping.

`memory` and unmodelled register/state clobbers remain rejected with separate
reasons. No concurrent ordering or microarchitecture claim is granted by this
observer. Unsupported control flow and mixed internal-operation observer plans
retain their previous preconditions.

## Plan, replay and evidence

Program observation plans use `scalar-program-observation-plan.v2`; phase56 v1
plans do not acquire clobber support implicitly. Supported decisions cover every
participating fragment and are included in the plan identity. Replay recomputes
compatibility against the current report/proof/replacement. Modified clobbers,
proofs, positions or replacements invalidate the plan/cache.

The central evidence closer checks the decision coverage, point/proof/boundary
bindings and the selected fragment's proof, authority and effect-relation set.
It still rehashes the actual execution record and full program plan. A rejected
decision is reported as authority_join/precondition_rejected/not_produced with
its typed diagnostic; it does not create execution/observation identities.

## Tests performed

- Related regression matrix: 326 passed, 6 skipped.
- New positive cases: no cc, producer-only cc, consumer-only cc and both cc.
- Negatives: memory/register/unknown clobbers, missing cc/visibility/volatile/
  continuation obligations, proof/renderer/effect/fixed-register mutations,
  stale report/replacement/positions, unknown fields and modified point bindings.
- Host GCC actually compiles and executes two cc-clobbering asm statements with
  inserted observations; the intermediate observed value and final result are
  independently asserted and original cc declarations remain in the variant.
- Six real cross-ISA tests skip in the hosted environment (toolchain unavailable).
  The four dependency production variants use three inputs and add/xor, with
  intermediate values distinct from the final return.
- Full suite remains blocked by the 13 pre-existing collection errors involving
  z3/unicorn availability and the missing translate_function module.
- No hosted generated-suite run or real-seed verified claim is made.

## Local verification

Select Clang 10; rebuild the frontend before testing and set
RISCV2X86_TEST_FRONTEND to that executable. Run test_observer_shell_compatibility,
test_dependency_observer_production, test_l2_real_production_chain and the existing
L2 evidence tests. Then run automatic_batch_cli in a fresh result directory.
Inspect case018's logical_operands dimensions and the replay
`dependency-observation-plan.json` compatibility decisions plus actual
`operand-observation.json` events. Verify the previously passing 23 cases,
including case006, do not regress.
