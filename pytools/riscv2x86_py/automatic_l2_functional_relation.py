"""Automatic L2 validation for proof-approved functional fallback relations.

The validator deliberately reuses the executable L1 harness to produce fresh
source/target observations, then checks that the typed translation artifact is
bound to one of the registered runtime-mediated contracts.  It never promotes
the result to architectural scope.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re
from pathlib import Path
from typing import Mapping

from .automatic_validation import build_auto_l1_validator
from .l2_authority import l2_authority_sidecar_from_dict
from .l2_evidence_closure import (
    L2ProviderExecutionDisposition, identity as closure_identity,
    provider_evidence_fields,
)
from .translation_validation import ValidationLayerResult, ValidationLevel
from .validation_status import PreservationMode, ValidationStatus


SCHEMA = "riscv2x86.auto-l2-functional-relation-runner.v1"
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONTRACTS = {
    "riscv2x86_rt_monotonic_time_ns@v1": {
        "patterns": ("privileged_read",),
        "observationContracts": ("riscv2x86.time.monotonic-observation.v1",
                                 "riscv2x86.time.monotonic-relation-result.v1"),
        "verifiedProperties": ("declared-return-relation", "monotonicity", "progress"),
        "notClaimedProperties": ("absolute-value-equivalence", "epoch-equivalence",
                                 "frequency-equivalence", "resolution-equivalence"),
    },
    "riscv2x86_rt_tsc_ticks@v1": {
        "patterns": ("privileged_read",),
        "observationContracts": ("riscv2x86.cycle.tsc-observation.v1",
                                 "riscv2x86.cycle.tsc-relation-result.v1"),
        "verifiedProperties": ("declared-return-relation", "monotonicity", "progress"),
        "notClaimedProperties": ("absolute-value-equivalence", "epoch-equivalence",
                                 "frequency-equivalence", "resolution-equivalence"),
    },
    "riscv2x86_rt_instruction_stream_sync_local@v1": {
        "patterns": ("instruction_visibility_fence",),
        "observationContracts": ("process-and-declared-return-values-v1",),
        "verifiedProperties": ("normal-termination", "registered-local-thread-runtime-contract"),
        "notClaimedProperties": ("architectural-instruction-visibility-equivalence",
                                 "cross-thread-code-publication"),
    },
}


def _identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + sha256(encoded).hexdigest()


def build_auto_l2_functional_relation_validator(config: Mapping[str, object]):
    if (set(config) != {"schemaVersion", "l1Config", "translatedReport"}
            or config.get("schemaVersion") != SCHEMA):
        raise ValueError("automatic L2 functional-relation config is invalid")
    l1_config = config.get("l1Config")
    if not isinstance(l1_config, Mapping):
        raise ValueError("automatic L2 functional-relation L1 config is invalid")
    report_path = config.get("translatedReport")
    if not isinstance(report_path, str) or not report_path:
        raise ValueError("automatic L2 functional-relation report path is invalid")
    l1_validator = build_auto_l1_validator(l1_config)

    def validate(**kwargs: object) -> ValidationLayerResult:
        level = kwargs.get("level")
        if level is not ValidationLevel.L2:
            return ValidationLayerResult(
                ValidationLevel.L2, ValidationStatus.FAILED,
                detail="automatic functional-relation validator invoked for wrong level")
        artifact = kwargs.get("translation_artifact")
        runtime_id = str(getattr(artifact, "runtime_contract_id", ""))
        contract = _CONTRACTS.get(runtime_id)
        pattern = str(getattr(artifact, "l2_pattern_kind", ""))
        if (getattr(artifact, "preservation_mode", None)
                is not PreservationMode.FUNCTIONAL_EQUIVALENCE_ONLY or contract is None
                or pattern not in contract["patterns"]):
            payload = {"schemaVersion": SCHEMA, "claimScope": "none",
                       "reasonCode": "L2_FUNCTIONAL_RELATION_CONTRACT_UNREGISTERED"}
            return ValidationLayerResult(
                ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                detail=json.dumps(payload, sort_keys=True, separators=(",", ":")))
        try:
            report = json.loads(Path(report_path).read_text(encoding="utf-8"))
            findings = report.get("findings") if isinstance(report, Mapping) else None
            matches = [item for item in findings or [] if isinstance(item, Mapping)
                       and isinstance(item.get("fragment"), Mapping)
                       and (item["fragment"].get("id")
                            or item["fragment"].get("fragmentId"))
                       == getattr(artifact, "fragment_id", "")]
            approval = matches[0].get("approvalArtifact") if len(matches) == 1 else None
            raw_sidecar = approval.get("l2AuthoritySidecar") \
                if isinstance(approval, Mapping) else None
            if not isinstance(raw_sidecar, Mapping):
                raise ValueError("functional relation authority is absent")
            authority = l2_authority_sidecar_from_dict(
                raw_sidecar, expected_fragment_id=str(getattr(artifact, "fragment_id", "")),
                expected_shell_fact_identity=str(getattr(artifact, "shell_facts_identity", "")),
            )
            runtime_bindings = [item for item in authority.runtime_contracts
                                if item.runtime_contract_id == runtime_id]
            if (not authority.complete or authority.authority_identity
                    != getattr(artifact, "l2_authority_identity", "")
                    or authority.effect_relation_set_identity
                    != getattr(artifact, "effect_relation_set_identity", "")
                    or len(runtime_bindings) != 1
                    or runtime_bindings[0].contract_version
                    != getattr(artifact, "runtime_contract_version", "")
                    or any(item.relation_kind != "runtime_mediated"
                           or item.runtime_contract_id != runtime_id
                           for item in authority.approved_effect_relations)):
                raise ValueError("functional relation authority binding mismatch")
        except (OSError, ValueError, json.JSONDecodeError):
            payload = {"schemaVersion": SCHEMA, "claimScope": "none",
                       "reasonCode": "L2_FUNCTIONAL_RELATION_AUTHORITY_INVALID"}
            return ValidationLayerResult(
                ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                detail=json.dumps(payload, sort_keys=True, separators=(",", ":")))
        l1_kwargs = dict(kwargs)
        l1_kwargs["level"] = ValidationLevel.L1
        l1_result = l1_validator(**l1_kwargs)
        try:
            observation = json.loads(l1_result.detail)
        except (TypeError, json.JSONDecodeError):
            observation = None
        if not isinstance(observation, Mapping):
            payload = {"schemaVersion": SCHEMA, "claimScope": "none",
                       "reasonCode": "L2_FUNCTIONAL_RELATION_OBSERVATION_INVALID"}
            return ValidationLayerResult(
                ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                detail=json.dumps(payload, sort_keys=True, separators=(",", ":")))
        if l1_result.status is not ValidationStatus.VERIFIED:
            payload = {"schemaVersion": SCHEMA, "claimScope": "none",
                       "reasonCode": "L2_FUNCTIONAL_RELATION_EXECUTION_NOT_VERIFIED",
                       "underlyingStatus": l1_result.status.value,
                       "underlyingEvidenceIdentity": l1_result.evidence_identity}
            return ValidationLayerResult(
                ValidationLevel.L2,
                ValidationStatus.FAILED if l1_result.status is ValidationStatus.FAILED
                else ValidationStatus.INCONCLUSIVE,
                detail=json.dumps(payload, sort_keys=True, separators=(",", ":")))
        observation_contract = observation.get("observationContract")
        if observation_contract not in contract["observationContracts"]:
            payload = {"schemaVersion": SCHEMA, "claimScope": "none",
                       "reasonCode": "L2_FUNCTIONAL_RELATION_OBSERVATION_CONTRACT_MISMATCH",
                       "actualObservationContract": observation_contract}
            return ValidationLayerResult(
                ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                detail=json.dumps(payload, sort_keys=True, separators=(",", ":")))
        source = observation.get("source")
        target = observation.get("target")
        if not isinstance(source, Mapping) or not isinstance(target, Mapping):
            payload = {"schemaVersion": SCHEMA, "claimScope": "none",
                       "reasonCode": "L2_FUNCTIONAL_RELATION_OBSERVATION_INCOMPLETE"}
            return ValidationLayerResult(
                ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                detail=json.dumps(payload, sort_keys=True, separators=(",", ":")))
        source_effect_ids = sorted(item.effect_id for item in authority.source_effects)
        target_effect_ids = sorted(effect_id
            for relation in authority.approved_effect_relations
            for effect_id in relation.target_effect_ids)
        source_identity = _identity({"side": "source", "observation": source,
                                     "contract": observation_contract,
                                     "observedEffectIds": source_effect_ids})
        target_identity = _identity({"side": "target", "observation": target,
                                     "contract": observation_contract,
                                     "observedEffectIds": target_effect_ids})
        payload = {
            "schemaVersion": SCHEMA,
            "claimScope": "approved_functional_relation",
            "relationKind": "runtime_mediated",
            "runtimeContractId": runtime_id,
            "runtimeContractVersion": str(getattr(artifact, "runtime_contract_version", "")),
            "observationContract": observation_contract,
            "sourceObservationIdentity": source_identity,
            "targetObservationIdentity": target_identity,
            "sourceObservedEffectIds": source_effect_ids,
            "targetObservedEffectIds": target_effect_ids,
            "verifiedProperties": list(contract["verifiedProperties"]),
            "notClaimedProperties": list(contract["notClaimedProperties"]),
            "underlyingL1EvidenceIdentity": l1_result.evidence_identity,
        }
        provider_id = str(kwargs.get("l2_provider_id", ""))
        if provider_id:
            payload.update(provider_evidence_fields(
                artifact, provider_id=provider_id,
                harness_identity=closure_identity({"schemaVersion": SCHEMA,
                                                   "l1Config": config.get("l1Config")}),
                source_observation_identity=source_identity,
                target_observation_identity=target_identity,
                execution_nonce={"underlyingL1EvidenceIdentity": l1_result.evidence_identity,
                                 "observationContract": observation_contract},
                execution_disposition=
                    L2ProviderExecutionDisposition.EXECUTED_VERIFIED))
        evidence = _identity(payload)
        assert _SHA.fullmatch(evidence)
        return ValidationLayerResult(
            ValidationLevel.L2, ValidationStatus.VERIFIED, evidence,
            json.dumps(payload, sort_keys=True, separators=(",", ":")))

    return validate
