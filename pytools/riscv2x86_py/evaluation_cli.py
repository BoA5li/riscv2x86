"""CLI for source-to-candidate end-to-end evaluation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .evaluation import (
    EVALUATION_RESULT_SCHEMA, load_evaluation_request,
    persist_evaluation_result, run_evaluation,
)


def main() -> int:
    parser = argparse.ArgumentParser("riscv2x86-evaluate")
    parser.add_argument("--request", required=True)
    parser.add_argument("--work-directory", required=True)
    parser.add_argument("--evaluation-output", required=True)
    args = parser.parse_args()
    try:
        request = load_evaluation_request(args.request)
        result = run_evaluation(request, work_directory=args.work_directory)
    except Exception as exc:
        result = {
            "schemaVersion": EVALUATION_RESULT_SCHEMA,
            "evaluationIdentity": "",
            "requestIdentity": "",
            "status": "inconclusive",
            "reasonCodes": ["evaluation.orchestration-error"],
            "candidateManifestId": "", "attempts": [], "commands": [],
            "replayArtifact": "", "detail": f"{type(exc).__name__}: {exc}",
        }
    persist_evaluation_result(result, args.evaluation_output)
    print(json.dumps({"status": result["status"],
                      "evaluationIdentity": result["evaluationIdentity"],
                      "output": str(Path(args.evaluation_output).resolve())}, sort_keys=True))
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())

