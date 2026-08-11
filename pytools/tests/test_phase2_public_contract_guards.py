"""Regression guards for proof-gated Phase-1/2 public replacements."""
from __future__ import annotations

import pytest

from riscv2x86_py.riscv2x86_translate import TranslationError, validate_translated_report
from riscv2x86_py.schema import Finding


def _finding(*, status: str, contract_id: str = "public.safe.example") -> dict:
    return {
        "category": "ReplaceableByRule",
        "ruleName": "phase2.public." + contract_id,
        "suggestedReplacement": "safe_target_builtin(x)",
        "rewriteBeginOffset": 2,
        "rewriteEndOffset": 3,
        "builtin": {"calleeName": "__builtin_riscv_safe", "argumentTypeIds": ["int"], "resultTypeId": "int"},
        "publicApprovalArtifact": {
            "artifactVersion": "phase2-public-approval-v1",
            "approvalStatus": status,
            "semanticContractId": contract_id,
            "compilerFamily": "gnu",
            "compilerVersion": "10+",
            "requiredHeaders": [],
            "requiredTargetFeatures": [],
        },
    }


def test_launcher_rejects_legacy_direct_rule_without_public_artifact() -> None:
    report = {"findings": [{
        "category": "ReplaceableByRule", "ruleName": "atomic.fence",
        "suggestedReplacement": "__atomic_thread_fence(__ATOMIC_SEQ_CST)",
        "rewriteBeginOffset": 0, "rewriteEndOffset": 5,
    }]}
    with pytest.raises(TranslationError):
        validate_translated_report(report, allow_untranslated=False)


def test_launcher_rejects_pending_public_artifact() -> None:
    with pytest.raises(TranslationError):
        validate_translated_report(
            {"findings": [_finding(status="pending_target_validation")]},
            allow_untranslated=False,
        )


def test_launcher_accepts_approved_bound_public_artifact() -> None:
    assert validate_translated_report(
        {"findings": [_finding(status="approved")]},
        allow_untranslated=False,
    ) == 1


def test_launcher_rejects_approved_artifact_without_environment_contract() -> None:
    finding = _finding(status="approved")
    del finding["publicApprovalArtifact"]["requiredTargetFeatures"]
    with pytest.raises(TranslationError):
        validate_translated_report({"findings": [finding]}, allow_untranslated=False)


def test_schema_keeps_public_contract_and_builtin_facts() -> None:
    finding = Finding(
        symbolName="__builtin_riscv_safe",
        arguments=["x"],
        builtin={"calleeName": "__builtin_riscv_safe", "argumentTypeIds": ["int"]},
        publicApprovalArtifact={"artifactVersion": "phase2-public-approval-v1"},
    )
    data = finding.to_dict()
    assert data["builtin"]["argumentTypeIds"] == ["int"]
    assert data["publicApprovalArtifact"]["artifactVersion"] == "phase2-public-approval-v1"
