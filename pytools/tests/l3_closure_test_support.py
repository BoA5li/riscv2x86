"""Shared complete synthetic prerequisites for isolated historical L3 runner tests."""
import json
from types import SimpleNamespace

from riscv2x86_py.translation_validation import ValidationLayerResult, ValidationLevel
from riscv2x86_py.validation_status import PreservationMode, ValidationStatus

H = "sha256:" + "a" * 64


def prerequisites(kwargs, monkeypatch, contract, *, dimension=None, property_id=None,
                  unit="fragment", mock_profile=True):
    artifact = kwargs["translation_artifact"]
    artifact.identity = H
    artifact.preservation_mode = PreservationMode.ARCHITECTURE_EQUIVALENT
    kwargs.setdefault("source_program_artifact", SimpleNamespace(artifact_digest=H))
    kwargs.setdefault("target_program_artifact", SimpleNamespace(artifact_digest=H))
    kwargs["prior_layer_results"] = tuple(ValidationLayerResult(level, ValidationStatus.VERIFIED, H,
        json.dumps({"claimScope": "architectural", "contractIdentity": H}) if level is ValidationLevel.L2 else "")
        for level in (ValidationLevel.L0, ValidationLevel.L1, ValidationLevel.L2))
    if mock_profile:
        import riscv2x86_py.l3_intent_requirements as intents
        req = {"fragmentId": artifact.fragment_id, "programId": contract["programId"],
               "profileIdentity": contract["intentProfileIdentity"],
               "requirementIdentity": contract["requirementIdentity"], "eligibilityStatus": "eligible",
               "proofIdentity": contract["proofIdentity"],
               "approvedTargetRelationIdentity": contract["approvedTargetRelationIdentity"],
               "requiredProperties": [{"propertyId": property_id, "dimension": dimension, "unit": unit}]}
        monkeypatch.setattr(intents, "parse_l3_requirement_manifest", lambda *_:
                            SimpleNamespace(requirements=[req]))
        monkeypatch.setattr(intents, "parse_l3_intent_profile", lambda *_a, **_k:
            SimpleNamespace(profile_identity=contract["intentProfileIdentity"],
                            not_claimed_properties=tuple(contract["knownNonEquivalences"])))
    return kwargs
