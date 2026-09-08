"""CLI for evaluation-bound atomic writeback promotion."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .writeback_promotion import (
    WRITEBACK_PROMOTION_SCHEMA, persist_promotion_result,
    promote_evaluated_staging,
)


def main() -> int:
    parser = argparse.ArgumentParser("riscv2x86-promote")
    parser.add_argument("--evaluation-result", required=True)
    parser.add_argument("--candidate-manifest", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--staging-root", required=True)
    parser.add_argument("--translated-report", required=True)
    parser.add_argument("--attempt-archive", required=True)
    parser.add_argument("--final-output", required=True)
    parser.add_argument("--promotion-output", required=True)
    args = parser.parse_args()
    report = Path(args.promotion_output).resolve()
    protected = tuple(Path(item).resolve() for item in (
        args.source_root, args.staging_root, args.final_output,
    ))
    if any(report == root or root in report.parents for root in protected):
        print(json.dumps({"promoted": False,
                          "reasonCode": "promotion.report-path-overlap"}, sort_keys=True))
        return 2
    try:
        result = promote_evaluated_staging(
            evaluation_result=args.evaluation_result,
            candidate_manifest=args.candidate_manifest,
            source_root=args.source_root, staging_root=args.staging_root,
            translated_report=args.translated_report,
            attempt_archive=args.attempt_archive,
            final_output=args.final_output,
        )
    except Exception as exc:
        result = {"schemaVersion": WRITEBACK_PROMOTION_SCHEMA, "promoted": False,
                  "reasonCode": "promotion.evidence-invalid",
                  "evaluationIdentity": "", "candidateManifestId": "",
                  "finalTreeDigest": "", "promotionIdentity": "",
                  "detail": f"{type(exc).__name__}: {exc}"}
    persist_promotion_result(result, report)
    print(json.dumps({"promoted": result["promoted"],
                      "reasonCode": result["reasonCode"]}, sort_keys=True))
    return 0 if result["promoted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
