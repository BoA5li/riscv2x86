# Preflight failures and non-compacting operand slots

Baseline: phase59-production-chain-evidence-contract,
75db4c884fbae67cf284357ce0ccc8f56b63d453.

The AST candidate producer formerly filtered out expressions which did not
unwrap to a DeclRefExpr. The resulting carrier count could disagree with the
GNU operand sequence. It now retains expression positions in versioned
operandSlotFacts, with compiler AST identity/range and per-slot completeness.
Unbound constants, dereferences, members, subscripts and compound expressions
are not assigned invented declaration identities. Existing declaration-based
carrier consumers remain fail-closed. This change does not add complete
constant-expression or memory-lvalue semantic translation support.

Closure distinguishes actual sequence-count disagreement from incomplete
expression authority. The latter records rejected compilerFragmentJoin and
lets the backend produce its real translation terminal outcome, without
injecting a false complete compiler authority. A genuine structural conflict
still rejects before the backend and carries operand counts, missing indexes,
expression kinds and slot details. Scalar sidecar production retains the
phase59 requirement that a rejected production join cannot be bypassed.

A fatal pre-backend failure writes <report>.preflight.json atomically. Its
content identity binds source path/digest, report path, invocation command,
return code, stage, exception and diagnostics. backendExecuted must be false.
No emitted candidate or fabricated semantic attempt is produced. Frontend,
sysroot, compiler inspection/closure, sidecar validation and backend-launch
errors use this contract. Existing output is never overwritten with a new
translation, and pre-existing preflight evidence is rejected before execution.

Evaluator priority is timeout/crash, validated preflight failure, then archive.
Known preflight failures have reason evaluation.translation-preflight-rejected
plus their original reason code. Their detail is under:
translationEvaluationLink.preflightFailure
The link uses riscv2x86.translation-preflight-evaluation-link.v1; the outer
existing evaluation-result schema and identity computation remain unchanged.
Invalid/stale records have specific ingress diagnostics. Missing archive is
retained for a genuinely missing terminal artifact, including an inconsistent
successful command which produced none. A successful exit cannot override a
preflight rejection. No stderr text or case ID selects a semantic outcome.

Run tests inside an explicit shell if/else and save logs/status. Do not turn on
set -e for experiments containing expected rejection cases. Nonzero batch
status is not automatically a framework crash. Real production-chain and
32-case generated-suite validation must run on the experiment host; no real
cross-ISA result is claimed from toolchain-skipped tests here.
