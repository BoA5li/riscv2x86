"""CLI for the versioned translation-result validation entry point."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .translation_validation import (
    ProgramArtifact,
    TranslationArtifact,
    ValidationPlan,
    ValidationProfile,
    ValidationRuntimeRegistry,
    load_validation_plan,
    run_translation_validation,
)
from .validation_status import PreservationMode
from .validation_observation import ExecutionObservation
from .translation_validation import ValidationLevel
from .l0_build_matrix import build_l0_validator, load_l0_build_matrix


def _load_json(path: str) -> dict[str, object]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {path}")
    return value


def _translation_artifact(data: dict[str, object]) -> TranslationArtifact:
    return TranslationArtifact(
        fragment_id=str(data.get("fragment_id", "")),
        source_model_identity=str(data.get("source_model_identity", "")),
        translation_plan_id=str(data.get("translation_plan_id", "")),
        constraint_id=str(data.get("constraint_id", "")),
        proof_identity=str(data.get("proof_identity", "")),
        preservation_mode=PreservationMode(str(data.get("preservation_mode", ""))),
        shell_facts_identity=str(data.get("shell_facts_identity", "")),
        runtime_contract_id=str(data.get("runtime_contract_id", "")),
        runtime_contract_version=str(data.get("runtime_contract_version", "")),
        recipe_id=str(data.get("recipe_id", "")),
        ignored_source_state=tuple(
            sorted(set(map(str, data.get("ignored_source_state", ()))))
        ),
        semantic_class=str(data.get("semantic_class", "")),
        target_route=str(data.get("target_route", "")),
    )


def _program_artifact(data: dict[str, object]) -> ProgramArtifact:
    return ProgramArtifact(
        artifact_id=str(data.get("artifact_id", "")),
        artifact_path=str(data.get("artifact_path", "")),
        artifact_kind=str(data.get("artifact_kind", "")),
        artifact_digest=str(data.get("artifact_digest", "")),
        build_identity=str(data.get("build_identity", "")),
    )


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

    registry_json = _load_json(args.runtime_registry)
    validators = {}
    l0_matrix = registry_json.get("l0BuildMatrix")
    if l0_matrix is not None:
        if not isinstance(l0_matrix, dict):
            raise ValueError("runtime registry l0BuildMatrix must be an object")
        validators[ValidationLevel.L0] = build_l0_validator(load_l0_build_matrix(l0_matrix))
    registry = ValidationRuntimeRegistry(version=str(registry_json.get("version", "")), layer_validators=validators)
    result = run_translation_validation(
        _translation_artifact(_load_json(args.translation_artifact)),
        _program_artifact(_load_json(args.source_program_artifact)),
        _program_artifact(_load_json(args.target_program_artifact)),
        plan, _load_json(args.target_environment), registry,
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
