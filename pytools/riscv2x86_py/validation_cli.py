"""CLI for the versioned translation-result validation entry point."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .translation_validation import (
    ValidationProfile,
    load_validation_plan,
    load_target_environment,
    program_artifact_from_dict,
    run_translation_validation,
    translation_artifact_from_dict,
)
from .validation_observation import ExecutionObservation
from .validation_runtime_registry import load_validation_runtime_registry


def _load_json(path: str) -> dict[str, object]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {path}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser("riscv2x86-validation")
    parser.add_argument("--translation-artifact", required=True)
    parser.add_argument("--source-program-artifact", required=True)
    parser.add_argument("--target-program-artifact", required=True)
    parser.add_argument("--validation-plan", required=True)
    parser.add_argument("--target-environment", required=True)
    parser.add_argument("--runtime-registry", required=True)
    parser.add_argument("--verification-output", required=True)
    parser.add_argument("--verification-profile", choices=[item.value for item in ValidationProfile])
    parser.add_argument("--source-runner", choices=("spike", "qemu", "custom"))
    parser.add_argument("--target-runner", choices=("native", "logical-csr-runtime", "custom"))
    parser.add_argument("--verification-seed", type=int)
    parser.add_argument("--verification-timeout", type=int)
    parser.add_argument("--source-observation")
    parser.add_argument("--target-observation")
    parser.add_argument(
        "--comparison-policy",
        default="riscv2x86.comparison-policy.none.v1",
    )
    args = parser.parse_args()

    plan = load_validation_plan(args.validation_plan)
    overrides = {}
    if args.verification_profile is not None:
        overrides["profile"] = ValidationProfile(args.verification_profile)
    if args.source_runner is not None:
        overrides["source_runner"] = args.source_runner
    if args.target_runner is not None:
        overrides["target_runner"] = args.target_runner
    if args.verification_seed is not None:
        overrides["seed"] = args.verification_seed
    if args.verification_timeout is not None:
        overrides["timeout_seconds"] = args.verification_timeout
    if overrides:
        from dataclasses import replace
        plan = replace(plan, **overrides)

    target_environment = load_target_environment(args.target_environment)
    registry = load_validation_runtime_registry(args.runtime_registry)
    result = run_translation_validation(
        translation_artifact_from_dict(_load_json(args.translation_artifact)),
        program_artifact_from_dict(_load_json(args.source_program_artifact)),
        program_artifact_from_dict(_load_json(args.target_program_artifact)),
        plan, target_environment, registry,
        source_observation=(
            ExecutionObservation.from_dict(_load_json(args.source_observation))
            if args.source_observation else None
        ),
        target_observation=(
            ExecutionObservation.from_dict(_load_json(args.target_observation))
            if args.target_observation else None
        ),
        comparison_policy=args.comparison_policy,
    )
    Path(args.verification_output).write_text(
        json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    return 0 if result.status.value == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
