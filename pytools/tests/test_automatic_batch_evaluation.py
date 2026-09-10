"""Contract tests for zero-configuration corpus evaluation."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from riscv2x86_py import automatic_batch_cli as auto
from riscv2x86_py.translation_artifact_binding import translation_artifact_from_approval
from riscv2x86_py.translation_attempt import TranslationAttempt
from riscv2x86_py.schema import PublicationOutcome, TranslationOutcome, ValidationOutcome


def test_inventory_generates_translation_and_registered_l0_l1(tmp_path, monkeypatch):
    corpus = tmp_path / "corpus"; corpus.mkdir()
    (corpus / "add.c").write_text("unsigned long add(unsigned long a,unsigned long b){return a+b;}\n")
    frontend = tmp_path / "riscv2x86"; frontend.write_text("#!/bin/sh\n"); frontend.chmod(0o755)
    monkeypatch.setattr(auto, "inspect_entry_points", lambda source: (
        False, ({"name": "add", "arity": 2, "returnType": "unsigned long",
                 "parameterTypes": ["unsigned long", "unsigned long"]},),
    ))

    payload = auto.prepare_automatic_inventory(corpus, tmp_path / "inventory", frontend=frontend)
    descriptor = json.loads((tmp_path / "inventory/cases/add/riscv2x86-evaluation.json").read_text())
    request = descriptor["request"]

    assert payload["statisticsUnits"] == {
        "L1": "program", "translation": "fragment", "bootstrapCluster": "program",
    }
    assert request["translationCommand"]
    assert "@INPUT_ROOT@" not in json.dumps(request["translationCommand"])
    assert "${SOURCE_ROOT}/add.c" in request["translationCommand"]
    assert "${SOURCE_ROOT}" in request["translationCommand"]
    assert request["translationArtifacts"] == {}
    assert request["targetBuild"]["artifactKind"] == "shared_library"
    assert set(request["runtimeRegistryTemplate"]["validators"]) == {"L0", "L1"}
    assert request["runtimeRegistryTemplate"]["validators"]["L1"]["config"]["functions"][0]["name"] == "add"


def test_inventory_main_uses_executable_process_contract(tmp_path, monkeypatch):
    source = tmp_path / "main.c"; source.write_text("int main(void){return 0;}\n")
    frontend = tmp_path / "riscv2x86"; frontend.write_text("x"); frontend.chmod(0o755)
    monkeypatch.setattr(auto, "inspect_entry_points", lambda source: (True, ()))
    auto.prepare_automatic_inventory(source, tmp_path / "inventory", frontend=frontend)
    descriptor = next((tmp_path / "inventory/cases").rglob("riscv2x86-evaluation.json"))
    request = json.loads(descriptor.read_text())["request"]
    assert request["targetBuild"]["artifactKind"] == "executable"
    assert request["runtimeRegistryTemplate"]["validators"]["L1"]["config"]["mode"] == "main"


def test_no_safe_function_stops_at_build_profile(tmp_path, monkeypatch):
    source = tmp_path / "pointer.c"; source.write_text("int f(int *p){return *p;}\n")
    frontend = tmp_path / "riscv2x86"; frontend.write_text("x"); frontend.chmod(0o755)
    monkeypatch.setattr(auto, "inspect_entry_points", lambda source: (_ for _ in ()).throw(
        ValueError("no safe scalar function")))
    payload = auto.prepare_automatic_inventory(source, tmp_path / "inventory", frontend=frontend)
    assert payload["programs"][0]["inspectionError"]
    descriptor = next((tmp_path / "inventory/cases").rglob("riscv2x86-evaluation.json"))
    request = json.loads(descriptor.read_text())["request"]
    assert set(request["runtimeRegistryTemplate"]["validators"]) == {"L0"}


def test_typed_artifact_is_derived_only_from_matching_approval():
    approval = {"proofStatus": "approved", "sourceFragmentId": "fragment",
                "sourceModelId": "model", "planId": "plan", "constraintsId": "constraints",
                "targetEnvironmentId": "environment", "rendererId": "renderer",
                "rendererVersion": "v1", "rendererContractId": "recipe",
                "preservationMode": "architecture_equivalent", "shellFactsIdentity": "sha256:" + "1" * 64,
                "runtimeContractId": "runtime", "runtimeContractVersion": "v1",
                "recipeId": "recipe", "ignoredSourceState": [], "semanticClass": "integer",
                "targetRoute": "x86_inline_asm"}
    attempt = TranslationAttempt(
        "finding:0:fragment", "fragment", "x86", "route", "asm(\"nop\");",
        "sha256:2db1a8ef844cb56c5b93c72cb30123f85c20a946ec2d600b1dce8ab61ae8266d",
        "rule", TranslationOutcome.EMITTED, ValidationOutcome.NOT_RUN,
        PublicationOutcome.NOT_REQUESTED, (), "model", "decision", "plan", "constraints",
        "approved", "sha256:" + "2" * 64, "environment", "renderer", "v1", "recipe",
        "registry", "v1", True,
    )
    artifact = translation_artifact_from_approval(attempt, approval)
    assert artifact.fragment_id == "fragment"
    broken = dict(approval); broken["planId"] = "other"
    with pytest.raises(ValueError, match="binding mismatch"):
        translation_artifact_from_approval(attempt, broken)


def test_typed_artifact_derives_validation_fields_from_legacy_phase6_binding():
    replacement = 'asm("nop");'
    attempt = TranslationAttempt(
        "finding:0:fragment", "fragment", "x86_inline_asm", "phase6f_rendered",
        replacement, "sha256:2db1a8ef844cb56c5b93c72cb30123f85c20a946ec2d600b1dce8ab61ae8266d",
        "rule", TranslationOutcome.EMITTED, ValidationOutcome.NOT_RUN,
        PublicationOutcome.NOT_REQUESTED, (), "model", "decision", "plan", "constraints",
        "approved", "sha256:" + "2" * 64, "environment", "renderer", "v1", "recipe",
        "registry", "v1", True,
    )
    approval = {"proofStatus": "approved", "sourceFragmentId": "fragment",
                "sourceModelId": "model", "planId": "plan", "constraintsId": "constraints",
                "targetEnvironmentId": "environment", "rendererId": "renderer",
                "rendererVersion": "v1", "rendererContractId": "recipe"}
    artifact = translation_artifact_from_approval(attempt, approval)
    assert artifact.preservation_mode.value == "architecture_equivalent"
    assert artifact.runtime_contract_id == "riscv2x86.runtime.none"
    assert artifact.shell_facts_identity.startswith("sha256:")


def test_evaluation_artifact_does_not_require_publication_complete_binding():
    replacement = 'asm("nop");'
    attempt = TranslationAttempt(
        "finding:0:fragment", "fragment", "x86_inline_asm", "phase6f_rendered",
        replacement, "sha256:2db1a8ef844cb56c5b93c72cb30123f85c20a946ec2d600b1dce8ab61ae8266d",
        "rule", TranslationOutcome.EMITTED, ValidationOutcome.NOT_RUN,
        PublicationOutcome.NOT_REQUESTED, (), "model", "", "plan", "constraints",
        "approved", "sha256:" + "2" * 64, "", "renderer", "v1", "",
        "", "", False,
    )
    approval = {"proofStatus": "approved", "sourceFragmentId": "fragment",
                "sourceModelId": "model", "planId": "plan", "constraintsId": "constraints",
                "rendererId": "renderer", "rendererVersion": "v1"}

    assert attempt.evaluation_binding_complete
    assert not attempt.binding_complete
    artifact = translation_artifact_from_approval(attempt, approval)
    assert artifact.recipe_id.startswith("sha256:")
