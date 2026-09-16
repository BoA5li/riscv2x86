from dataclasses import replace
from hashlib import sha256
import json
from types import SimpleNamespace

import pytest

import riscv2x86_py.automatic_batch_cli as auto
from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
from riscv2x86_py.automatic_l2_effect import (
    _shell_relation, build_auto_l2_effect_validator,
)
from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
from riscv2x86_py.l2_authority import l2_authority_sidecar_from_dict
from riscv2x86_py.l2_fence_ordering import (
    L2FenceProofFacts, approved_fence_relations, fence_ordering_events,
    fence_ordering_observations_match, fence_proof_facts_from_dict,
    fence_proof_facts_from_source_model,
)
from riscv2x86_py.l2_semantic_profile import (
    L2ControlFlowShape, L2FragmentSemanticProfile, L2InternalStateShape,
    L2MemoryShape, L2OperandShape, L2OrderingShape, L2PatternKind,
    L2PrivilegedShape,
)
from riscv2x86_py.l2_dimensions import L2Dimension, L2EligibilityStatus
from riscv2x86_py.l2_validator_resolution import (
    L2BindingKind, L2FragmentRequirement, L2RuntimeCapabilities, L2ValidatorProvider,
)
from riscv2x86_py.translation_validation import ValidationLevel
from riscv2x86_py.validation_status import PreservationMode, ValidationStatus


_CONTRACT = "x86.gnu-att.mfence.full-system-seq-cst.v1"


def _digest(data):
    if isinstance(data, str):
        data = data.encode()
    return "sha256:" + sha256(data).hexdigest()


def _facts(**changes):
    values = dict(fragment_id="fragment:fence", before_effect_id="before:read",
      fence_effect_id="fence:0", after_effect_id="after:write",
      source_compiler_ordering=True, source_hardware_ordering=False,
      source_ordering="seq_cst", source_scope="compiler",
      target_compiler_ordering=True, target_hardware_ordering=True,
      target_ordering="seq_cst", target_scope="system", relation_kind="strengthened",
      target_contract_id=_CONTRACT, target_contract_version="renderer-v1",
      source_domain_complete=True, target_contract_approved=True,
      instruction_visibility=False, complete=True)
    values.update(changes)
    return L2FenceProofFacts(**values)


def _profile(fragment_id="fragment:fence", kind=L2PatternKind.FENCE):
    capabilities = (("ordering_observation", "shell_observation") if kind is L2PatternKind.FENCE
                    else ("instruction_visibility", "shell_observation"))
    return L2FragmentSemanticProfile(
      fragment_id, kind, L2OperandShape(0, 0, 0, True),
      L2ControlFlowShape(False, False, False, False, False, 0, True),
      L2MemoryShape(False, False, False, False, True),
      L2OrderingShape(kind is L2PatternKind.FENCE,
                      kind is L2PatternKind.INSTRUCTION_VISIBILITY_FENCE, True, True),
      L2PrivilegedShape(False, False, False, True),
      L2InternalStateShape(False, False, True, True),
      "rv64gc-user-to-x86_64-user", tuple(sorted(capabilities)))


def _finding(facts=None, *, kind=L2PatternKind.FENCE):
    facts = facts or _facts()
    return {"fragment":{"id":facts.fragment_id, "enclosingFunction":"synchronize_domain",
                         "outputs":[], "inputs":[]},
      "l2SemanticProfile":_profile(facts.fragment_id, kind).to_dict(),
      "approvalArtifact":{"proofStatus":"approved", "architectureSemanticsPreserved":True,
        "shellSemanticsPreserved":True, "sourceModelId":"model", "constraintsId":"constraints",
        "preservationDecisionId":"decision", "planId":"plan",
        "targetEnvironmentId":"environment", "targetCatalogVersion":"catalog",
        "rendererContractId":facts.target_contract_id,
        "rendererVersion":facts.target_contract_version,
        "l2FenceProofFacts":facts.to_dict()}}


def test_proof_export_consumes_structured_barrier_and_registered_contract():
    barrier = SimpleNamespace(present=True, complete=True, instruction_serializing=False,
      compiler_barrier=True, hardware_memory_barrier=True,
      ordering=SimpleNamespace(value="seq_cst"), scope=SimpleNamespace(value="system"))
    facts = fence_proof_facts_from_source_model(
      "fragment:fence", SimpleNamespace(barrier=barrier),
      {"rendererContractId":_CONTRACT, "rendererVersion":"renderer-v1"})
    assert facts is not None and facts.relation_kind == "exact"
    instruction_barrier = SimpleNamespace(**{**barrier.__dict__, "instruction_serializing":True})
    assert fence_proof_facts_from_source_model(
      "fragment:i", SimpleNamespace(barrier=instruction_barrier),
      {"rendererContractId":_CONTRACT, "rendererVersion":"renderer-v1"}) is None


def test_approved_strengthened_relation_and_required_edge_pass():
    facts = _facts(); relations = approved_fence_relations(facts)
    source = fence_ordering_events(facts, relations, side="source")
    target = fence_ordering_events(facts, relations, side="target")
    assert fence_ordering_observations_match(source, target, relations) == (True, "")
    fence_relation = next(item for item in relations if item.source_effect_id == "fence:0")
    assert fence_relation.relation_kind == "strengthened"
    assert [(item.before, item.after) for item in fence_relation.ordering_requirements] == [
      ("before:read", "after:write")]


def test_missing_anchor_and_missing_target_edge_fail_closed():
    facts = _facts(); relations = approved_fence_relations(facts)
    source = fence_ordering_events(facts, relations, side="source")
    target = fence_ordering_events(facts, relations, side="target")
    assert fence_ordering_observations_match(source[:-1], target, relations) == (
      False, "L2_FENCE_ORDERING_ANCHOR_MISSING")
    broken = tuple(replace(item, ordering_predecessors=())
                   if item.event_kind == "WriteMemory" else item for item in target)
    assert fence_ordering_observations_match(source, broken, relations) == (
      False, "L2_FENCE_TARGET_ORDERING_EDGE_MISSING")


def test_strengthened_relation_rejects_weaker_target_contract():
    facts = _facts(); relations = approved_fence_relations(facts)
    source = fence_ordering_events(facts, relations, side="source")
    target = fence_ordering_events(facts, relations, side="target")
    weakened = tuple(replace(item, payload={**item.payload, "ordering":"relaxed",
                                            "scope":"compiler"})
                     if item.event_kind == "Fence" else item for item in target)
    assert fence_ordering_observations_match(source, weakened, relations) == (
      False, "L2_FENCE_STRENGTHENED_RELATION_NOT_SATISFIED")


def test_stale_or_incomplete_fence_facts_are_rejected():
    stale = _facts().to_dict(); stale["sourceScope"] = "system"
    with pytest.raises(ValueError, match="identity"):
        fence_proof_facts_from_dict(stale)
    with pytest.raises(ValueError, match="completeness"):
        _facts(source_domain_complete=False)


def test_fence_authority_materializes_three_anchors(tmp_path):
    finding = _finding(); frontend = tmp_path / "frontend"; frontend.write_bytes(b"frontend")
    function = {"name":"synchronize_domain", "arity":0, "returnType":"void",
                "parameterTypes":[], "pointerParameters":[],
                "l2OperandBoundary":{"complete":True}}
    assert materialize_automatic_l2_authority(
      {"findings":[finding]}, [function], frontend) == 1
    sidecar = l2_authority_sidecar_from_dict(
      finding["approvalArtifact"]["l2AuthoritySidecar"])
    assert {item.effect_id for item in sidecar.source_effects} == {
      "before:read", "fence:0", "after:write"}
    assert sidecar.ordering[0].before_effect_id == "before:read"
    assert sidecar.ordering[0].after_effect_id == "after:write"


def test_missing_fence_proof_facts_preserve_precise_fail_closed_reason(tmp_path):
    finding = _finding()
    del finding["approvalArtifact"]["l2FenceProofFacts"]
    frontend = tmp_path / "frontend"; frontend.write_bytes(b"frontend")
    function = {"name":"synchronize_domain", "arity":0, "returnType":"void",
                "parameterTypes":[], "pointerParameters":[],
                "l2OperandBoundary":{"complete":True}}
    assert materialize_automatic_l2_authority(
      {"findings":[finding]}, [function], frontend) == 0
    approval = finding["approvalArtifact"]
    assert approval["l2AuthorityMaterializationReasonCode"] == \
      "L2_FENCE_PROOF_FACTS_MISSING"
    relation, reason = _shell_relation(finding, SimpleNamespace(fragment_id="fragment:fence"))
    assert relation is None and reason == "L2_FENCE_PROOF_FACTS_MISSING"


def test_contract_version_mismatch_is_inconclusive_before_execution(tmp_path):
    finding = _finding(); frontend = tmp_path / "frontend"; frontend.write_bytes(b"frontend")
    function = {"name":"synchronize_domain", "arity":0, "returnType":"void",
                "parameterTypes":[], "pointerParameters":[],
                "l2OperandBoundary":{"complete":True}}
    assert materialize_automatic_l2_authority(
      {"findings":[finding]}, [function], frontend) == 1
    sidecar = l2_authority_sidecar_from_dict(finding["approvalArtifact"]["l2AuthoritySidecar"])
    approval = finding["approvalArtifact"]
    proof_payload = {key:approval[key] for key in (
      "sourceModelId", "preservationDecisionId", "planId", "constraintsId",
      "proofStatus", "targetEnvironmentId", "targetCatalogVersion")}
    approval["proofIdentity"] = _digest(json.dumps(
      proof_payload, sort_keys=True, separators=(",", ":")).encode())
    source = tmp_path / "source.c"; target = tmp_path / "target.c"
    source.write_text("void synchronize_domain(void){}\n")
    target.write_text("void synchronize_domain(void){}\n")
    report = tmp_path / "report.json"; report.write_text(json.dumps({"findings":[finding]}))
    config = {"schemaVersion":"riscv2x86.auto-l2-effect-runner.v1",
      "mode":"fence-functions", "sourcePath":str(source), "sourceDigest":_digest(source.read_bytes()),
      "targetPath":str(target), "targetDigest":_digest(target.read_bytes()),
      "translatedReport":str(report), "functions":[function],
      "workDirectory":str(tmp_path / "work"), "replayDirectory":str(tmp_path / "replay"),
      "timeoutSeconds":10, "qemuBinary":"qemu-riscv64"}
    artifact = SimpleNamespace(fragment_id="fragment:fence", proof_identity=approval["proofIdentity"],
      preservation_mode=PreservationMode.ARCHITECTURE_EQUIVALENT,
      shell_facts_identity=sidecar.shell_fact_identity,
      l2_authority_identity=sidecar.authority_identity,
      effect_relation_set_identity=sidecar.effect_relation_set_identity,
      runtime_contract_id="riscv2x86.runtime.none", runtime_contract_version="v1",
      recipe_id="wrong-contract")
    result = build_auto_l2_effect_validator(config)(
      level=ValidationLevel.L2, comparison_policy=ARCHITECTURAL_COMPARISON_POLICY,
      translation_artifact=artifact)
    assert result.status is ValidationStatus.INCONCLUSIVE
    assert json.loads(result.detail)["reasonCode"] == "L2_FENCE_TARGET_CONTRACT_MISMATCH"


def test_instruction_visibility_profile_is_not_claimed_by_normal_fence_provider():
    profile = _profile("fragment:fence-i", L2PatternKind.INSTRUCTION_VISIBILITY_FENCE)
    assert profile.required_capabilities == ("instruction_visibility", "shell_observation")
    assert profile.pattern_kind is not L2PatternKind.FENCE
    requirement = L2FragmentRequirement(
      profile.fragment_id, _digest(b"requirement"), (L2Dimension.MEMORY_EFFECTS,),
      L2EligibilityStatus.ELIGIBLE, profile.profile_identity, profile.pattern_kind.value,
      profile.required_capabilities)
    provider = L2ValidatorProvider(
      "normal-fence", (L2Dimension.MEMORY_EFFECTS,), (L2PatternKind.FENCE,),
      ("ordering_observation",), (profile.execution_profile,), L2BindingKind.AUTOMATIC,
      "automatic-l2-effect-differential", "test.fence.v1",
      {"schemaVersion":"test.fence.v1"})
    environment = L2RuntimeCapabilities(
      (provider,), ("instruction_visibility", "shell_observation"),
      (profile.execution_profile,))
    match = provider.supports(requirement, profile, environment,
                              dimension=L2Dimension.MEMORY_EFFECTS)
    assert match.match_status.value == "not_matched"
    assert "l2.provider.pattern-unsupported" in match.reason_codes


def test_inventory_registers_only_normal_fence_pattern(tmp_path, monkeypatch):
    source = tmp_path / "neutral.c"; source.write_text("void synchronize_domain(void){}\n")
    frontend = tmp_path / "frontend"; frontend.write_bytes(b"frontend"); frontend.chmod(0o755)
    function = {"name":"synchronize_domain", "arity":0, "returnType":"void",
                "parameterTypes":[], "pointerParameters":[],
                "l2OperandBoundary":{"complete":True}}
    monkeypatch.setattr(auto, "inspect_entry_points", lambda _source: (False, (function,)))
    auto.prepare_automatic_inventory(source, tmp_path / "inventory", frontend=frontend)
    descriptor = json.loads(next(
      (tmp_path / "inventory/cases").rglob("riscv2x86-evaluation.json")).read_text())
    providers = descriptor["request"]["runtimeRegistryTemplate"]["validators"]["L2"]["config"]["providers"]
    fence = next(item for item in providers
                 if item["providerId"] == "automatic-l2-fence-ordering-v1")
    assert fence["supportedPatterns"] == ["fence"]
    assert "instruction_visibility_fence" not in fence["supportedPatterns"]
