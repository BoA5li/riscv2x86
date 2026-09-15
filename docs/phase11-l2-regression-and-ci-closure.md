# Phase 11 L2 regression and CI closure

The L2 regression surface is isolated from optional lifting and solver dependencies.
`requirements-test.txt`, `requirements-l2.txt`, and `requirements-legacy.txt` define the
core, L2, and historical dependency sets. CI no longer asks pytest to collect every
historical module before running L2.

`pytools/tests/l2_test_matrix.txt` is the versioned ordinary-CI matrix. It covers the
canonical dimension parser, requirement resolver, closed dimension evidence, authority
binding, approved effect relations, semantic-event ordering, functional claim scopes,
shared program execution, program closure, paper denominators, program-cluster
bootstrap, privileged v1/v2 parsing, and concurrency campaigns. In particular, a v1
privileged runner carrying the v2-only `requiredEnvironmentId` field is rejected.

The Phase 11 workflow has independent `unit-core`, `unit-l2`,
`integration-toolchain`, and `legacy` jobs. The integration job installs a real RV64
cross compiler and QEMU user runner, compiles RISC-V inline-assembly and native x86
programs, compares scalar, object-relative load, branch, and fence observations, checks
the approved runtime-mediated time relation, and archives the commands, binaries'
identities, observations, claim scopes, and outcome.

Nightly controlled jobs remain capability-gated. Their always-running capability report
records absent privileged, concurrency, or controlled L3 infrastructure as
`inconclusive` with a reason code. A skipped self-hosted job therefore cannot be
interpreted as verified evidence. Atomic/litmus, privileged system/guest, and expanded
differential campaigns remain isolated from ordinary CI and preserve their artifacts.

Workflow evidence is attached to each Phase 11 branch run as JUnit and real-toolchain
JSON artifacts.
