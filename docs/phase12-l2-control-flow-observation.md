# Phase 12 L2 control-flow observation

The automatic control-flow provider is selected per fragment from the
authoritative semantic profile.  It supports only `branch` and `jump` profiles
whose Phase-6A/proof output includes a complete
`riscv2x86.l2-control-flow-proof-facts.v1` object.  File names, function names,
assembly text, and mnemonics are not classification inputs.

Automatic execution is fail closed unless the proof facts establish bound
condition/value operands, a finite encodable continuation set, direct local
control flow, no non-local transfer, exception, signal, or trap, complete
internal-value escape accounting, and an available source/target execution
profile.  GNU `asm goto` is classified as `unknown` for the automatic route and
requires a versioned explicit harness/provider.

The proof facts are bound to compiler declaration identities while the typed L2
authority sidecar is materialized.  That sidecar owns the condition kind,
operand identities, continuation identities, transfer kind, observable result,
termination contract, and exact approved effect relations.  The validator does
not derive any of those facts from execution output.

Each execution produces typed `riscv2x86.l2-control-flow-observation.v1`
events.  Conditional branches record canonical condition values, condition
result, taken state, continuation, result, and termination.  Direct jumps record
source and target continuation, direct transfer kind, result, and termination.
The comparator accepts only proof-approved `exact` relations and requires a
one-to-one complete source/target event set.  Missing events, different paths,
different continuations, signedness differences, result differences, and
termination differences cannot yield `verified`.
