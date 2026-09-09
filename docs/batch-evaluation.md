# Batch evaluation

`riscv2x86_py.batch_evaluation_cli` runs any number of independent translation
evaluations with one command.  It reuses the normal `run_evaluation()` path, so
candidate staging, build, validation, evidence persistence, and fail-closed
status classification remain identical to a single evaluation.

## Corpus layout

Place one `riscv2x86-evaluation.json` beside each program (or program source
tree):

```text
corpus/
  integer-add/riscv2x86-evaluation.json
  integer-shift/riscv2x86-evaluation.json
  memory-load/riscv2x86-evaluation.json
```

The descriptor has exactly four top-level fields:

```json
{
  "schemaVersion": "riscv2x86.batch-evaluation-case.v1",
  "caseId": "integer-add-001",
  "category": "integer",
  "request": {
    "schemaVersion": "riscv2x86.evaluation-request.v2",
    "sourceRoot": "@CASE_DIR@/source",
    "sourceRelativePath": "case.c",
    "targetRelativePath": "case.c",
    "translatedReport": "translation-work/translated_report.json",
    "attemptArchive": "translation-work/translated_report.json.attempts.json",
    "validationPlan": "@CASE_DIR@/validation-plan.json",
    "targetEnvironment": "@CASE_DIR@/target-environment.json",
    "runtimeRegistryTemplate": {
      "schemaVersion": "riscv2x86.validation-runtime-registry.v1",
      "version": "experiment-registry-v1",
      "validators": {}
    },
    "translationArtifacts": {},
    "sourceBuild": {
      "artifactId": "source-program",
      "artifactKind": "executable",
      "outputRelativePath": "build/source.rv64",
      "command": ["riscv64-linux-gnu-gcc", "-static", "${SOURCE_PATH}", "-o", "${OUTPUT}"]
    },
    "targetBuild": {
      "artifactId": "target-program",
      "artifactKind": "executable",
      "outputRelativePath": "build/target.x86_64",
      "command": ["gcc", "${TARGET_PATH}", "-o", "${OUTPUT}"]
    },
    "translationCommand": [
      "python3", "-m", "riscv2x86_py.riscv2x86_translate",
      "--frontend", "/path/to/build/riscv2x86",
      "--input", "${SOURCE_PATH}",
      "--src-root", "${SOURCE_ROOT}",
      "--output-dir", "${WORK_DIR}/translated-output",
      "--work-dir", "${WORK_DIR}/translation-work",
      "--xlen", "64", "--skip-verify", "--allow-untranslated"
    ],
    "comparisonPolicy": "riscv2x86.comparison-policy.none.v1",
    "validationUnit": "program",
    "validationGroupId": "",
    "selectedAttemptIds": []
  }
}
```

`@CASE_DIR@` is resolved against the descriptor directory. `@BATCH_OUTPUT@` is
also available. Evaluation placeholders such as `${SOURCE_PATH}`, `${OUTPUT}`,
and `${WORK_DIR}` are deliberately retained for `run_evaluation()`.

The translation command must write its report and attempt archive to the paths
declared by `translatedReport` and `attemptArchive`; the example paths match the
standard translator's fixed work-directory layout. L1/L2/L3
validators and typed translation artifacts are configured exactly as for the
single-evaluation CLI; the batch layer does not invent semantic evidence.

## Run

```bash
PYTHONPATH=pytools python3 -m riscv2x86_py.batch_evaluation_cli \
  --input experiment/corpus \
  --output-directory experiment/runs/run-001 \
  --jobs 4
```

The output directory must not already exist. Every case gets an isolated
directory containing its resolved request, result, work tree, staging tree, and
replay evidence. A failed or inconclusive case does not prevent other cases
from running. The command exits `0` only when every case is `verified`, `1` for
a completed batch containing another status, and `2` for invalid batch
configuration.

Top-level outputs are:

* `batch-evaluation.json`: canonical status, translation-outcome, and reason-code counts;
* `batch-summary.csv`: one row per program-level evaluation;
* `cases/<caseId>/evaluation-result.json`: complete per-program evidence.

The batch summary counts each descriptor once. Fragment attempts are reported
separately through `translationOutcomeCounts`; a shared program validation is
not duplicated into multiple independent program observations.

## Evaluate every C program with one shared template

For a directory in which every `.c` is an independent test program, use one
shared template instead of copying a descriptor beside every source:

```json
{
  "schemaVersion": "riscv2x86.batch-evaluation-template.v1",
  "category": "mixed",
  "request": {
    "schemaVersion": "riscv2x86.evaluation-request.v2",
    "sourceRoot": "@INPUT_ROOT@",
    "sourceRelativePath": "@SOURCE_RELATIVE_PATH@",
    "targetRelativePath": "@SOURCE_RELATIVE_PATH@",
    "translatedReport": "translation-work/translated_report.json",
    "attemptArchive": "translation-work/translated_report.json.attempts.json",
    "validationPlan": "validation-plan.json",
    "targetEnvironment": "target-environment.json",
    "runtimeRegistryTemplate": {
      "schemaVersion": "riscv2x86.validation-runtime-registry.v1",
      "version": "experiment-registry-v1",
      "validators": {}
    },
    "translationArtifacts": {},
    "sourceBuild": {
      "artifactId": "source-@CASE_ID@",
      "artifactKind": "executable",
      "outputRelativePath": "build/source.rv64",
      "command": ["riscv64-linux-gnu-gcc", "-static", "${SOURCE_PATH}", "-o", "${OUTPUT}"]
    },
    "targetBuild": {
      "artifactId": "target-@CASE_ID@",
      "artifactKind": "executable",
      "outputRelativePath": "build/target.x86_64",
      "command": ["gcc", "${TARGET_PATH}", "-o", "${OUTPUT}"]
    },
    "translationCommand": [],
    "comparisonPolicy": "riscv2x86.comparison-policy.none.v1",
    "validationUnit": "program",
    "validationGroupId": "",
    "selectedAttemptIds": []
  }
}
```

Template-relative `validationPlan` and `targetEnvironment` paths are resolved
automatically. The orchestrator supplies `sourceRoot`, `sourceRelativePath`,
and `targetRelativePath` from discovery, preventing a template from silently
evaluating the wrong source.

```bash
PYTHONPATH=pytools python3 -m riscv2x86_py.batch_evaluation_cli \
  --input experiment/corpus-sources \
  --request-template experiment/config/batch-template.json \
  --output-directory experiment/runs/run-002 \
  --jobs 4
```

This mode deliberately treats every `.c` as a separate program. Projects with
supporting translation units must use explicit per-program descriptors so that
the statistical denominator remains unambiguous.
