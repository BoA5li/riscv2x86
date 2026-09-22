# Structured asm-goto control-flow authority

Phase 21 replaces source-template recognition with a closed join between
frontend, CFG, decoder and operand-binding facts.

## Authority production

The Clang frontend owns the resolved C label, label index, fallthrough
continuation, taken continuation, outputs and clobbers. It no longer matches
`beqz` or `bnez` in `rawAsmText`.

Phase 6A accepts an asm-goto authority only when canonical decoder semantics
prove one finite direct `CBRANCH`. Its predicate must resolve through canonical
value nodes to exactly one runtime-bound input operand. The currently
registered route accepts comparison with integer zero (`zero` or `nonzero`).
Memory accesses, calls, returns, indirect transfers, atomics, hardware
barriers and unresolved value nodes keep the authority incomplete.

`AsmGotoControlFlowAuthority` records the operand binding, label identity,
taken and fallthrough continuations, external label index, outputs, clobbers
and compiler-memory effect. Operand spelling and source mnemonics are not
authority.

## Route and proof closure

Phase 6B selects structured control flow only for a complete authority. It no
longer emits a generic helper candidate for ordinary asm-goto. A helper route
is generated only when the source semantic model independently proves an
explicit helper/call-adapter contract.

Phase 6C validates the authority against the source shell and creates the
target operand, control-flow, `cc`, `volatile` and optional `memory` contracts.
Phase 6D proves:

- exactly one taken label plus one distinct fallthrough continuation;
- label identity and continuation orientation are unchanged;
- condition binding and zero/nonzero relation are unchanged;
- source and target width and signedness agree;
- call, return, tail-call and indirect-control-flow facts are explicitly false;
- outputs, clobbers and compiler-memory effects agree.

Phase 6F consumes only the approved structured contract. The registered
zero/nonzero recipe emits `test` plus `je`/`jne`; it never reads the source
template or recognizes a source mnemonic.

## Fail-closed cases

Missing or ambiguous decoder predicates, stale label bindings, swapped
continuations, unbound registers, unsupported output operands, hidden calls,
signedness/width mismatches and shell-clobber mismatches cannot produce a
verified replacement.
