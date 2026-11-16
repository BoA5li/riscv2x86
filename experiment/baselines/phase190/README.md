# Phase190 checkpoint verification

Base: remote Phase189 `184f88aadd806e6713659baf0bf7ca7080b1d15d`, tree
`6b18f9e28bd9d4ad992aa554797e82855d67c50a`.

`regression.log`: 113 selected tests passed, 288.75 s. Exact invocation:

```
python -m pytest -q -rs \
 pytools/tests/test_native_project_campaign.py \
 pytools/tests/test_native_project_evaluation.py \
 pytools/tests/test_native_original_evaluation.py \
 pytools/tests/test_native_original_pipeline.py \
 pytools/tests/test_native_verifier_manifest.py \
 pytools/tests/test_evaluation_runner.py \
 pytools/tests/test_evaluation_state_separation.py \
 pytools/tests/test_partial_program_evaluation.py
```

Checkpoint tests use explicit stage-producer/checker fixtures. They verify frozen
configuration, resume, stage/receipt ownership, orphan-output handling, locks,
input/tool mutations and terminal failed/inconclusive results. They do not prove
translation semantics or real Ghidra/GMP execution. Existing adapter tests retain
real native build/process boundaries and their documented source-ISA fixtures;
original candidate tests retain their documented frontend/assembler/Ghidra mocks.

Request checks rederive all companion contracts without writing files, including
canonical bytes. Native builds reject output symlinks. The original translation,
proof gates, materializer, mandatory L0 matrix and evaluation status logic are
unchanged. No layer or missing evidence is relabeled as verified.

No complete host GMP campaign, full real 18-cell compiler matrix, machine ABI,
internal object proof or canonical-instruction coverage was executed/proved here.
Host instructions: `docs/phase190-campaign-checkpoints.md`.
