# L2 obligations and precondition results

## Scope

This revision preserves asm-goto verification obligations and makes rejected
preconditions readable and auditable without inventing execution evidence.
It does not supply an asm-goto continuation instrumentation provider or an
expression-aware atomic production consumer. Neither route is promoted to
verified by this revision.

## Contracts

* The asm_goto semantic profile retains control_flow, logical_operands (when
  operands exist), and shell_semantics obligations. Typed memory effects add
  memory obligations. Ordinary conditional-branch providers cannot satisfy the
  continuation capability merely by returning a matching function value.
* Fragment result v4 represents precondition rejection explicitly. It records
  stage, eligibility, root reasons, precondition_rejected execution disposition,
  and not_produced evidence disposition. It cannot carry execution evidence or
  claim a verified dimension. Missing requirements have no fabricated identity.
* The strict evidence reader accepts and validates this terminal result. Root
  reasons propagate through translation validation. Provider artifact audit
  validates every case by default, including non-verified cases; it does not
  demand provider execution for rejected preconditions. --scope verified-only
  is an explicit narrower audit.
* Coverage v4 includes known precondition-blocked fragment-dimensions in the
  denominator. Incomplete classification is separate from not-applicable.
  Plan/provider missing diagnostics apply only to eligible requirements.
* The formal runner checks production tools before tests, preserving failures
  in run-status.json instead of treating unavailable production tests as proof.

## Validation and interpretation

Tests exercise structured asm-goto classification, requirement serialization,
registry rejection, strict evidence reading, coverage, audit, and mutations.
The production-chain asm-goto rejection test requires a real toolchain and must
not be cited as executed when skipped. Existing program-evidence fixtures now
include authority and requirement-staging artifacts; stale artifact identities
are rejected at ingress rather than accepted as executable evidence.

Regenerate experiment artifacts in an empty result directory. Old coverage
reports retain their old denominators and should not be merged as v4 reports.
A successful artifact audit establishes preservation and linkage contracts,
not universal semantic equivalence or concurrent atomicity. Complete asm-goto
support still needs actual continuation observations; atomic support still needs
expression/object closure, width/result contracts, approved atomic relations,
and independently closed atomic dimensions.
