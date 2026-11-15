# Phase186 validation evidence

Base remote commit: 66c80853d230bea75d73d04d881c72dda62c143d.
The local base tree equals ba98eab5ffa610eb2cee1cffd34377818e7240d6.

Final 54-module regression: **689 passed, 9 skipped**, 426.20 seconds, exit 0.
The final run includes the additional CLI-import failure test. The overlapping
core and preflight-only subsets are retained; their counts must not be added.

Command: PYTHONPATH="$PWD/pytools" PYTHONDONTWRITEBYTECODE=1, then pytest -q -rs
with the files enumerated in modules.json. Python 3.12 test environment; the
already-declared legacy dependency pypcode 3.3.3 was installed for original CLI
imports. No production dependency policy was loosened.

The initial collection error was missing pypcode. Subsequent shared CLI checks
exposed two old fixture mismatches: the versioned privileged registry required
explicit mapping registry snapshots, and candidate-only CLI construction needed
--skip-verify. Fixtures now satisfy those existing protocols and also test their
rejection boundaries. No privileged production parser or semantic gate changed.
Initial diagnostic logs are retained separately from final passing results.

interrupted-broad.log is an incomplete earlier run interrupted during the quota
pause. It has no final status and is NOT a successful complete regression.
broad.log is the complete fresh rerun after resumption.

empty-path.log records a real public-command invocation with an explicitly empty
installation path: exit 2, clear configuration error, no output directory created.
The fixture-based preflight tests use actual subprocesses with synthetic query
executables. These validate transport, timeouts, protocol validation, stored-data
rederivation and failure ordering, NOT a real Ghidra language or translation.
Original-route tests stub the frontend/backend boundary explicitly; they do not
constitute real GMP translation evidence.

Nine environment skips are listed in broad.log: absent RISC-V GCC/QEMU/Clang/
frontend combinations, ptrace restrictions, and absent actual Ghidra. No skip is
counted as acceptance. Setting RV2X86_REAL_GHIDRA_INSTALL_DIR on the user's host
turns the real-query integration into a required execution that fails normally.

Preflight scope is public CLI import plus the real register query when deployed
with real tools. It binds the Python executable, launcher, query script, captured
environment and response. It does not fingerprint the entire JDK/Ghidra installation
or certify p-code execution, full toolchain equivalence, machine ABI, object-access
legality, canonical instruction execution, or whole-program semantics.

Original macro edit provenance, complete machine-fact production, internal object/
call effects, canonical-instance coverage, applicable L1-L3 evidence production and
program closure remain necessary work. No acceptance boolean was forced true.
