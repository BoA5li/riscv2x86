from __future__ import annotations

import argparse
import json
import sys

from .candidate_materialization import materialize_candidate_tree


def main() -> int:
    parser = argparse.ArgumentParser("riscv2x86-candidate-apply")
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--staging-root", required=True)
    parser.add_argument("--translated-report", required=True)
    parser.add_argument("--attempt-archive", required=True)
    parser.add_argument("--manifest-output", required=True)
    args = parser.parse_args()
    try:
        manifest = materialize_candidate_tree(
            source_root=args.source_root, staging_root=args.staging_root,
            translated_report=args.translated_report,
            attempt_archive=args.attempt_archive,
            manifest_output=args.manifest_output,
        )
    except Exception as exc:
        print(f"candidate materialization failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"manifestId": manifest.manifest_id,
                      "targetTreeDigest": manifest.target_tree_digest,
                      "editCount": len(manifest.edits)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
