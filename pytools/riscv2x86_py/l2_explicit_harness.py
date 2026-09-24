"""Versioned explicit L2 harness plug-in contract and generic runner."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Mapping, Sequence

from .l2_dimensions import L2Dimension, parse_l2_dimensions
from .translation_validation import ValidationLayerResult, ValidationLevel
from .l2_evidence_closure import (
    L2ProviderExecutionDisposition, provider_evidence_fields,
)
from .validation_status import ValidationStatus


EXPLICIT_L2_HARNESS_MANIFEST_SCHEMA = "riscv2x86.explicit-l2-harness-manifest.v1"
EXPLICIT_L2_HARNESS_RUNNER_SCHEMA = "riscv2x86.explicit-l2-harness-runner.v1"
EXPLICIT_L2_OBSERVATION_SCHEMA = "riscv2x86.explicit-l2-observation.v1"
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")


def _identity(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + sha256(raw.encode()).hexdigest()


def _file_digest(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def _strings(value: object, name: str, *, identities: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(name + " must be a string array")
    result = tuple(value)
    if result != tuple(sorted(set(result))):
        raise ValueError(name + " must be unique and sorted")
    if identities and any(_SHA.fullmatch(item) is None for item in result):
        raise ValueError(name + " contains an invalid identity")
    return result


@dataclass(frozen=True)
class ExplicitL2HarnessManifest:
    harness_id: str
    harness_version: str
    producer_digest: str
    supported_fragment_identities: tuple[str, ...]
    supported_semantic_profiles: tuple[str, ...]
    contract_id: str
    provided_dimensions: tuple[L2Dimension, ...]
    execution_profile: str
    source_harness_digest: str
    target_harness_digest: str
    observation_schema_version: str
    relation_set_identity: str
    non_interference_proof_identity: str
    complete: bool
    manifest_identity: str

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ExplicitL2HarnessManifest":
        fields = {"schemaVersion", "harnessId", "harnessVersion", "producerDigest",
                  "supportedFragmentIdentities", "supportedSemanticProfiles", "contractId",
                  "providedDimensions", "executionProfile", "sourceHarnessDigest",
                  "targetHarnessDigest", "observationSchemaVersion", "relationSetIdentity",
                  "nonInterferenceProofIdentity", "complete", "manifestIdentity"}
        if set(value) != fields or value.get("schemaVersion") != EXPLICIT_L2_HARNESS_MANIFEST_SCHEMA:
            raise ValueError("explicit L2 harness manifest schema or fields are invalid")
        payload = dict(value); identity = payload.pop("manifestIdentity")
        for name in ("harnessId", "harnessVersion", "contractId", "executionProfile",
                     "observationSchemaVersion"):
            if not isinstance(value.get(name), str) or not value[name]:
                raise ValueError("explicit L2 harness lacks " + name)
        for name in ("producerDigest", "sourceHarnessDigest", "targetHarnessDigest",
                     "relationSetIdentity", "nonInterferenceProofIdentity"):
            if not isinstance(value.get(name), str) or _SHA.fullmatch(str(value[name])) is None:
                raise ValueError("explicit L2 harness " + name + " is invalid")
        fragments = _strings(value.get("supportedFragmentIdentities"),
                             "supported fragment identities")
        profiles = _strings(value.get("supportedSemanticProfiles"),
                            "supported semantic profiles", identities=True)
        raw_dimensions = value.get("providedDimensions")
        if not isinstance(raw_dimensions, list):
            raise ValueError("explicit L2 harness dimensions are missing")
        dimensions = parse_l2_dimensions(raw_dimensions)
        if not dimensions or (not fragments and not profiles):
            raise ValueError("explicit L2 harness applicability is incomplete")
        if not isinstance(value.get("complete"), bool):
            raise ValueError("explicit L2 harness completeness is invalid")
        if identity != _identity(payload):
            raise ValueError("explicit L2 harness manifest identity is stale")
        return cls(str(value["harnessId"]), str(value["harnessVersion"]),
                   str(value["producerDigest"]), fragments, profiles,
                   str(value["contractId"]), dimensions, str(value["executionProfile"]),
                   str(value["sourceHarnessDigest"]), str(value["targetHarnessDigest"]),
                   str(value["observationSchemaVersion"]), str(value["relationSetIdentity"]),
                   str(value["nonInterferenceProofIdentity"]), bool(value["complete"]),
                   str(identity))


@dataclass(frozen=True)
class ExplicitL2HarnessRunnerConfig:
    manifest_path: str
    source_harness_path: str
    target_harness_path: str
    source_command: tuple[str, ...]
    target_command: tuple[str, ...]
    contract_id: str
    timeout_seconds: int


def load_explicit_l2_harness_runner_config(value: Mapping[str, object]) -> ExplicitL2HarnessRunnerConfig:
    fields = {"schemaVersion", "manifestPath", "sourceHarnessPath", "targetHarnessPath",
              "sourceCommand", "targetCommand", "contractId", "timeoutSeconds"}
    if set(value) != fields or value.get("schemaVersion") != EXPLICIT_L2_HARNESS_RUNNER_SCHEMA:
        raise ValueError("explicit L2 harness runner schema or fields are invalid")
    commands = []
    for name in ("sourceCommand", "targetCommand"):
        raw = value.get(name)
        if not isinstance(raw, list) or not raw or not all(isinstance(x, str) and x for x in raw):
            raise ValueError("explicit L2 harness command is invalid")
        commands.append(tuple(raw))
    timeout = value.get("timeoutSeconds")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
        raise ValueError("explicit L2 harness timeout is invalid")
    for name in ("manifestPath", "sourceHarnessPath", "targetHarnessPath", "contractId"):
        if not isinstance(value.get(name), str) or not value[name]:
            raise ValueError("explicit L2 harness runner lacks " + name)
    return ExplicitL2HarnessRunnerConfig(str(value["manifestPath"]),
        str(value["sourceHarnessPath"]), str(value["targetHarnessPath"]),
        commands[0], commands[1], str(value["contractId"]), timeout)


def load_explicit_l2_harness_manifest(path: str | Path) -> ExplicitL2HarnessManifest:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("explicit L2 harness manifest must be an object")
    return ExplicitL2HarnessManifest.from_dict(value)


def validate_explicit_l2_harness_provider(provider: object) -> None:
    """Validate the generic provider envelope against its harness contract."""
    config = load_explicit_l2_harness_runner_config(getattr(provider, "config", {}))
    manifest = load_explicit_l2_harness_manifest(config.manifest_path)
    if (tuple(getattr(provider, "supported_dimensions", ())) != manifest.provided_dimensions
            or tuple(getattr(provider, "execution_profiles", ())) != (manifest.execution_profile,)
            or tuple(getattr(provider, "fragment_ids", ())) != manifest.supported_fragment_identities
            or tuple(getattr(provider, "semantic_profile_ids", ())) != manifest.supported_semantic_profiles
            or config.contract_id != manifest.contract_id):
        raise ValueError("explicit L2 provider applicability does not match harness manifest")
    source, target = Path(config.source_harness_path), Path(config.target_harness_path)
    if (_file_digest(source) != manifest.source_harness_digest
            or _file_digest(target) != manifest.target_harness_digest):
        raise ValueError("explicit L2 provider harness digest is stale")


def _execute(command: Sequence[str], request: Mapping[str, object], timeout: int):
    binary = command[0]
    if not (Path(binary).is_file() or shutil.which(binary)):
        return None, "l2.explicit-harness.runner-unavailable"
    try:
        result = subprocess.run(command, input=json.dumps(request, sort_keys=True), text=True,
                                capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None, "l2.explicit-harness.execution-failed"
    if result.returncode:
        return None, "l2.explicit-harness.execution-failed"
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None, "l2.explicit-harness.observation-invalid"
    if not isinstance(value, Mapping):
        return None, "l2.explicit-harness.observation-invalid"
    return value, ""


def run_explicit_l2_harness(config: ExplicitL2HarnessRunnerConfig, **kwargs: object) -> ValidationLayerResult:
    try:
        manifest = load_explicit_l2_harness_manifest(config.manifest_path)
        source_path, target_path = Path(config.source_harness_path), Path(config.target_harness_path)
        if (not manifest.complete or config.contract_id != manifest.contract_id
                or _file_digest(source_path) != manifest.source_harness_digest
                or _file_digest(target_path) != manifest.target_harness_digest):
            raise ValueError("manifest/contract/harness digest binding mismatch")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        detail = {"reasonCode": "l2.explicit-harness.binding-invalid", "message": str(exc)}
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                                     detail=json.dumps(detail, sort_keys=True))
    artifact = kwargs.get("translation_artifact")
    fragment_id = str(getattr(artifact, "fragment_id", ""))
    profile_identity = str(getattr(artifact, "l2_semantic_profile_identity", ""))
    if ((manifest.supported_fragment_identities
         and fragment_id not in manifest.supported_fragment_identities)
            or (manifest.supported_semantic_profiles
                and profile_identity not in manifest.supported_semantic_profiles)):
        return ValidationLayerResult(
            ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
            detail='{"reasonCode":"l2.explicit-harness.not-applicable"}',
        )
    if manifest.execution_profile != kwargs.get("execution_profile", manifest.execution_profile):
        return ValidationLayerResult(
            ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
            detail='{"reasonCode":"l2.explicit-harness.execution-profile-mismatch"}',
        )
    if manifest.relation_set_identity != getattr(artifact, "effect_relation_set_identity", ""):
        return ValidationLayerResult(
            ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
            detail='{"reasonCode":"l2.explicit-harness.relation-set-mismatch"}',
        )
    request = {"schemaVersion": EXPLICIT_L2_HARNESS_RUNNER_SCHEMA,
               "harnessId": manifest.harness_id, "harnessVersion": manifest.harness_version,
               "contractId": manifest.contract_id, "fragmentId": fragment_id,
               "semanticProfileIdentity": profile_identity,
               "providedDimensions": [item.value for item in manifest.provided_dimensions]}
    source, reason = _execute(config.source_command, request, config.timeout_seconds)
    if source is None:
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                                     detail=json.dumps({"reasonCode": reason}))
    target, reason = _execute(config.target_command, request, config.timeout_seconds)
    if target is None:
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                                     detail=json.dumps({"reasonCode": reason}))
    expected = {"schemaVersion", "fragmentId", "semanticProfileIdentity",
                "dimensionObservations", "termination"}
    for value in (source, target):
        observations = value.get("dimensionObservations")
        if (set(value) != expected or value.get("schemaVersion") != manifest.observation_schema_version
                or value.get("fragmentId") != fragment_id
                or value.get("semanticProfileIdentity") != profile_identity
                or not isinstance(observations, Mapping)
                or set(observations) != {item.value for item in manifest.provided_dimensions}
                or not isinstance(value.get("termination"), str)):
            return ValidationLayerResult(
                ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                detail='{"reasonCode":"l2.explicit-harness.observation-invalid"}',
            )
    source_identity = _identity({"harnessDigest": manifest.source_harness_digest,
                                 "observation": source})
    target_identity = _identity({"harnessDigest": manifest.target_harness_digest,
                                 "observation": target})
    matched = source == target
    detail = {"schemaVersion": "riscv2x86.explicit-l2-harness-result.v1",
              "status": "verified" if matched else "failed", "claimScope": "architectural",
              "manifestIdentity": manifest.manifest_identity,
              "contractId": manifest.contract_id,
              "providedDimensions": [item.value for item in manifest.provided_dimensions],
              "sourceObservationIdentity": source_identity,
              "targetObservationIdentity": target_identity,
              "relationSetIdentity": manifest.relation_set_identity,
              "nonInterferenceProofIdentity": manifest.non_interference_proof_identity}
    provider_id = str(kwargs.get("l2_provider_id", ""))
    if provider_id:
        detail.update(provider_evidence_fields(
            artifact, provider_id=provider_id,
            harness_identity=_identity({
                "manifestIdentity": manifest.manifest_identity,
                "sourceHarnessDigest": manifest.source_harness_digest,
                "targetHarnessDigest": manifest.target_harness_digest,
            }),
            source_observation_identity=source_identity,
            target_observation_identity=target_identity,
            execution_nonce={"request": request,
                             "executionProfile": manifest.execution_profile},
            execution_disposition=(
                L2ProviderExecutionDisposition.EXECUTED_VERIFIED if matched else
                L2ProviderExecutionDisposition.EXECUTED_FAILED)))
    evidence = _identity({**detail, "source": source, "target": target})
    detail["evidenceIdentity"] = evidence
    return ValidationLayerResult(ValidationLevel.L2,
        ValidationStatus.VERIFIED if matched else ValidationStatus.FAILED,
        evidence, json.dumps(detail, sort_keys=True, separators=(",", ":")))


def build_explicit_l2_harness_validator(config: ExplicitL2HarnessRunnerConfig):
    return lambda **kwargs: run_explicit_l2_harness(config, **kwargs)
