# Phase 69: AST node and replacement source-range contract

Parent: phase68-runtime-join-and-memory-projection, remote
1f5034bdfedc1e9252530b6c8a6c9091d8a157cc.

## Confirmed production defect

Both actual AMO operand forms exported identical begin offsets but different
end offsets: frontend [80,185) vs AST [80,184), and [80,173) vs [80,172).
The frontend replacement includes a statement terminator while the AST node
does not. Atomic ingress compared these different contracts directly. L2
replay also passed authority-owned offsets back as its expected offsets.

## Implementation

The linked frontend exports separate astBeginOffset/astEndOffset from compiler
token locations. Macro spelling/expansion without a separate authority exports
unavailable AST offsets and cannot authorize this new join. Statement-end
handling uses Clang raw tokens, skipping comments and whitespace before a
semicolon instead of scanning individual characters.

The compiler AST candidate key remains unchanged. At authority injection, the
actual source bytes must match its source digest; AST offsets from both compiler
producers must agree. A strict content-addressed fragment-source-range.v1
record binds the AST node range to the replacement range. The compiler-selected
suffix must be empty or only trivia followed by exactly one semicolon. This
syntax check does not infer assembly effects, variables, or instruction semantics.
The source AST slice digest and exact suffix bytes are retained in the witness.
The witness is bound to the source digest, function and fragment; its identity
is recomputed from its payload.

New production envelopes use compiler-fragment-authority.v3 and include the
range binding in authorityIdentity. v1/v2 remain explicit legacy exact-range
contracts; no old identity is retained after adding fields and no offset is
silently incremented. New frontends with incomplete AST range facts are rejected
with stage/field/expected/actual diagnostics, rather than falling back to guessed
ranges.

Translation atomic ingress, L2 atomic replay, and canonical provenance consume
the same range validator. L2 uses the current fragment replacement offsets and
checks the independently exported frontend AST offsets. It no longer supplies
its authority's own range as its expected range. Object, pointer, width,
ordering, shell, Phase 6D and dimension closure gates remain in place.

## Verification and limits

Tests cover byte offsets after non-ASCII prefixes, comments, whitespace,
terminator mutation, unexpected tokens, invalid macros/ranges, stale identities,
unknown fields, authority injection, atomic consumption, and L2 replay mutation.
The native fixtures now explicitly state their independently known [100,140)
frontend range; they no longer rely on omitted range fields defaulting to zero.
Real frontend/Clang range tests are included in the runner alongside the 20 real
AMO production cases. Failure output includes compiler join and range witnesses
as well as route decisions, to make subsequent gates diagnosable.

Full Classifier/ReportLoad compilation and RISC-V/QEMU experiments require the
production toolchain, unavailable on this editing host. Rebuild the frontend,
run verify_route_contracts.py with a new output directory, and inspect regression.log
and run-status.json. A skipped real test is not successful production acceptance.
Run the generated suite and provider audit only after the prerequisite regression
passes. L3 remains separately configured and is not established by L2 success.

Local final verification: the route-runner selection plus related operand,
authority and observation regressions passed 572 tests, with 36 production-tool
skips. Changed Python modules compile; git diff --check and native GCC C++17
syntax checking of Report.cpp pass. These results do not replace the linked
frontend/RISC-V run on the production host.
