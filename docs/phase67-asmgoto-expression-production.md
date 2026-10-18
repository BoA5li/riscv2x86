# Typed expression, asm-goto and atomic production closure

This branch connects new facts to production consumers; it does not change a
failed or unsupported verdict to verified merely to satisfy a suite.

## Implemented contracts

- Expression evaluation separates declaration, expression, pre/post values and
  lvalue addresses. Closed compiler fragment v2 rebuilds complete expression
  facts for missing memory-lvalue slots. It preserves GNU operand indexes and
  never invents a declaration for an expression. Side-effectful expressions and
  ambiguous object/address bindings remain rejected.
- Atomic object ingress proves that an expression-backed memory operand is an
  exact read-write dereference of the separately bound pointer at the access
  width. It retains object bounds, alignment, provenance and address-space
  checks. Memory-lvalue source operands retain object roles, not register roles.
- Atomic carrier widths distinguish memory width, effective input bits, C
  carrier width and ISA result extension. RV64 word AMO result sign extension
  is explicit in the approved renderer; discarded results do not invent a
  result binding. Five existing public builtin AMO contracts (exchange, add,
  and, or, xor) are reused with their approved acquire/release ordering.
- Registered atomic builtin contracts are versioned v2. Their recipes include
  explicit compiler signal fences around the RMW to preserve the GNU memory
  shell. Phase 7 checks a dedicated, content-bound shell artifact; generic C
  retains its ordinary refusal rules. Source slice and asm template digests
  are separate, and the final report rebinds the actual source slice.
- Atomic sidecar v5 represents expression-backed memory operands without
  silently adding fields to older schemas. The dedicated materializer replays
  the compiler/decoder join and checks the approved proof and function identity.
- A dedicated atomic provider observes actual old value, input, returned value,
  full before/after bounded object and RMW relationship. Logical, memory,
  atomic/order and shell dimensions have separate evidence. Static approved
  contracts and finite execution witnesses retain distinct provenance.
- asm-goto requires a finite predicate dependency region and an assembler ELF
  symbol/compiler-continuation join. llvm-mc preserves private labels with
  `-save-temp-labels`; a guessed target cannot approve the region.
- Region/join payloads remain content-bound through Phase 6D, effect facts and
  the dedicated asm-goto sidecar. A memory clobber does not turn a conditional
  asm-goto into a standalone fence.
- The continuation provider instruments compiler AST statement sites, builds
  and executes both programs, and records actual input/exit hooks. Return
  values are not proxies for selected continuations. Instrumentation maps,
  executable hashes, raw executions and independent dimension evidence persist.
- L1 memory harnesses use correctly typed object arrays and memcpy snapshots,
  avoiding incompatible-pointer aliasing for word or other integer objects.

## Explicit support boundaries

The first continuation provider requires one scalar integer parameter, one asm,
no asm outputs, one taken label plus fallthrough, direct compound-statement
insertion sites and a closed zero/nonzero predicate. The region is straight-line
and has no unmodelled memory, calls, live outputs or internal control transfer.
Multi-exit/loop regions and per-exit output definedness need further contracts.

The atomic provider requires an approved five-operation 32/64-bit AMO builtin
route, one pointer plus one integer input, a bounded aligned harness object,
and a compiler-proven sole-asm function scope. An old-value result must return
directly; a discarded result is also supported. Other output sinks require
instrumentation rather than a predicted value. LR/SC, compare-exchange, min/max,
side-effectful address expressions, general offset/lvalue alias graphs and
arbitrary function bodies remain outside this contract.

The x86 lock-instruction route still has its separate seq_cst/coupled-carrier
restrictions. Those restrictions do not apply to the existing public builtin
route. A stronger target ordering is not silently relabelled an exact relation.

Harness object bounds/alignment are experiment preconditions, not guarantees
about every possible caller. Single-thread witnesses do not prove concurrent
atomicity or absence of all forbidden memory-model outcomes. L3 remains
independent and must be configured/executed separately.

## Verification and reproduction

The route runner includes schema/join mutations, real continuation hooks,
actual native atomic renderer execution, strict per-dimension evidence reads,
and real production fixtures for all five AMOs at both widths with `+m`
expressions and distinct old-value results. Invalid source has a separate
frontend rejection test. The real production fixtures first require successful
parsing by the linked frontend.

Native provider tests inject compiler fixtures and native command routing;
they test provider contracts and actual observation, not the RISC-V pipeline.
The environment used for this change has native GCC but lacks the real Clang,
llvm-mc, RISC-V cross compiler and QEMU production chain. Tests skipped for
missing tools are not reported as production acceptance.

On the full production toolchain run:

    python3 experiment/verify_route_contracts.py --frontend build/riscv2x86 --clang10 /absolute/path/to/clang10 --output /new/empty/result-directory --suite experiment/generated-suite

The runner records regression failures and skips the suite on a prerequisite
failure. A nonzero suite status can also represent intentionally invalid or
unsupported inputs; inspect summary and per-case reasons. Provider artifact
audit must pass. Existing 24 verified cases must not regress. Do not claim
020/030 acceptance before checking their actual per-dimension evidence.

Local final targeted regression: 741 passed, 18 skipped. All changed Python
sources compiled and git diff --check passed. Eighteen real-toolchain fixtures
were skipped, including the ten AMO production combinations.

An additional legacy Phase 6/7 subset has 13 failures and 75 passes on both the
unchanged parent and this working tree, with identical failing test names.
These include removed PIC/LRSC mock entry points, legacy CFG tests and a CSR
route expectation. They are pre-existing failures, not a clean full-suite claim.

A measured violation of the approved RMW value relation retains observations
and yields failed with L2_ATOMIC_RMW_VALUE_RELATION_FAILED. Malformed traces
remain an observation/infrastructure failure rather than manufactured evidence.
