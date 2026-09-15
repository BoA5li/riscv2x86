from copy import deepcopy
from hashlib import sha256
from types import SimpleNamespace

import pytest

from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
from riscv2x86_py.automatic_l2_effect import _BRANCH_CASES, _control_flow_events
from riscv2x86_py.effect_relation import ApprovedEffectRelation
from riscv2x86_py.l2_authority import (
    L2ControlFlowAuthority, l2_authority_sidecar_from_dict,
)
from riscv2x86_py.l2_control_flow import (
    L2ControlFlowObservation, L2ControlFlowProofFacts,
    control_flow_proof_facts_from_dict, exact_control_flow_observations_match,
)
from riscv2x86_py.l2_semantic_profile import (
    L2ControlFlowShape, L2FragmentSemanticProfile, L2InternalStateShape,
    L2MemoryShape, L2OperandShape, L2OrderingShape, L2PatternKind,
    L2PrivilegedShape, profile_from_source_model,
)
from riscv2x86_py.l2_dimensions import L2Dimension, L2EligibilityStatus
from riscv2x86_py.l2_validator_resolution import (
    L2BindingKind, L2FragmentRequirement, L2RuntimeCapabilities, L2ValidatorProvider,
)


def _profile(fragment_id: str, kind: L2PatternKind):
    capabilities = {
        L2PatternKind.BRANCH: ("control_flow_observation", "logical_operand_observation",
                               "shell_observation"),
        L2PatternKind.JUMP: ("control_flow_observation", "logical_operand_observation",
                             "shell_observation"),
    }[kind]
    return L2FragmentSemanticProfile(
        fragment_id, kind, L2OperandShape(4 if kind is L2PatternKind.BRANCH else 2, 1, 0, True),
        L2ControlFlowShape(kind is L2PatternKind.BRANCH, kind is L2PatternKind.JUMP,
                           False, False, False, 2 if kind is L2PatternKind.BRANCH else 1, True),
        L2MemoryShape(False, False, False, False, True),
        L2OrderingShape(False, False, True, True),
        L2PrivilegedShape(False, False, False, True),
        L2InternalStateShape(False, False, True, True),
        "rv64gc-user-to-x86_64-user", tuple(sorted(capabilities)),
    )


def _boundary(names):
    output, *inputs = names
    return {"complete": True, "parameterDeclarationIds": inputs,
            "asmOperandDeclarationIds": names, "returnDeclarationId": output,
            "declarationReferenceCounts": {
                name: names.count(name) + int(name == output) for name in set(names)},
            "declarations": {name: {"name": name, "type": "uint64_t"} for name in names}}


def _finding(fragment_id, function_name, names, facts):
    output, *inputs = names
    return {"fragment": {"id": fragment_id, "enclosingFunction": function_name,
                          "outputs": [{"constraint": "=r", "symbolicName": output}],
                          "inputs": [{"constraint": "r", "symbolicName": item}
                                     for item in inputs]},
            "l2SemanticProfile": _profile(
                fragment_id, L2PatternKind(facts.pattern_kind)).to_dict(),
            "approvalArtifact": {
                "proofStatus": "approved", "architectureSemanticsPreserved": True,
                "shellSemanticsPreserved": True, "sourceModelId": "model",
                "constraintsId": "constraints", "preservationDecisionId": "decision",
                "planId": "plan", "targetEnvironmentId": "environment",
                "targetCatalogVersion": "catalog",
                "l2ControlFlowProofFacts": facts.to_dict()}}


def _safe_facts(fragment_id, kind="branch"):
    common = dict(direct=True, no_non_local_transfer=True, no_exception=True,
                  no_signal=True, no_trap=True, internal_escape_complete=True,
                  continuations_encodable=True, complete=True)
    if kind == "branch":
        return L2ControlFlowProofFacts(
            fragment_id, "branch", "unsigned_less", (1, 2), 3, 4, None, 0,
            ("continuation:not-taken", "continuation:taken"), "entry", "", **common)
    return L2ControlFlowProofFacts(
        fragment_id, "jump", "", (), None, None, 1, 0,
        ("continuation:target",), "entry", "continuation:target", **common)


@pytest.mark.parametrize(("directory", "function_name", "fragment_id"), [
    ("unrelated-a", "choose_payload", "fragment:alpha"),
    ("other/location", "route_value", "fragment:beta"),
])
def test_branch_authority_is_semantic_not_round2_name_based(
    tmp_path, directory, function_name, fragment_id,
):
    names = ["answer", "low", "high", "yes_value", "no_value"]
    facts = _safe_facts(fragment_id)
    finding = _finding(fragment_id, function_name, names, facts)
    function = {"name": function_name, "arity": 4, "returnType": "uint64_t",
                "parameterTypes": ["uint64_t"] * 4, "pointerParameters": [],
                "l2OperandBoundary": _boundary(names)}
    frontend = tmp_path / directory / "frontend"
    frontend.parent.mkdir(parents=True); frontend.write_bytes(b"frontend")

    assert materialize_automatic_l2_authority(
        {"findings": [finding]}, [function], frontend,
    ) == 1
    sidecar = l2_authority_sidecar_from_dict(
        finding["approvalArtifact"]["l2AuthoritySidecar"])
    assert sidecar.control_flow[0].condition_kind == "unsigned_less"
    assert sidecar.control_flow[0].continuations == (
        "continuation:not-taken", "continuation:taken")
    assert len(sidecar.approved_effect_relations) == 11
    assert all(item.relation_kind == "exact" for item in sidecar.approved_effect_relations)

    relation_authority = {
        "fragmentId": sidecar.fragment_id,
        "controlFlow": [item.to_dict() for item in sidecar.control_flow],
        "operands": [item.to_dict() for item in sidecar.operands],
        "relations": [item.to_dict() for item in sidecar.approved_effect_relations],
    }
    lines = []
    for index, values in enumerate(_BRANCH_CASES):
        result = values[2] if values[0] < values[1] else values[3]
        lines.append(f"{function_name}:case={index}:return={result:016x}")
    source = _control_flow_events("\n".join(lines), function, relation_authority, side="source")
    target = _control_flow_events("\n".join(lines), function, relation_authority, side="target")
    assert source is not None and target is not None
    assert source[0].to_dict()["eventKind"] == "Branch"
    assert set(source[0].to_dict()["payload"]) == {
        "conditionInputs", "conditionResult", "taken", "continuationId",
        "result", "termination"}
    assert exact_control_flow_observations_match(
        source, target, sidecar.approved_effect_relations) == (True, "")


def test_direct_jump_authority_has_one_finite_target(tmp_path):
    fragment_id = "fragment:direct"
    names = ["destination", "selected", "unreachable"]
    facts = _safe_facts(fragment_id, "jump")
    finding = _finding(fragment_id, "dispatch_copy", names, facts)
    function = {"name": "dispatch_copy", "arity": 2, "returnType": "uint64_t",
                "parameterTypes": ["uint64_t"] * 2, "pointerParameters": [],
                "l2OperandBoundary": _boundary(names)}
    frontend = tmp_path / "frontend"; frontend.write_bytes(b"frontend")
    assert materialize_automatic_l2_authority({"findings": [finding]}, [function], frontend) == 1
    sidecar = l2_authority_sidecar_from_dict(
        finding["approvalArtifact"]["l2AuthoritySidecar"])
    control = sidecar.control_flow[0]
    assert control.transfer_kind == "direct"
    assert control.source_continuation == "entry"
    assert control.target_continuation == "continuation:target"
    authority = {"fragmentId": sidecar.fragment_id,
                 "controlFlow": [control.to_dict()],
                 "operands": [item.to_dict() for item in sidecar.operands],
                 "relations": [item.to_dict() for item in sidecar.approved_effect_relations]}
    lines = []
    for left in range(8):
        for right in range(8):
            lines.append(f"operand_trace=dispatch_copy;{left:016x};{right:016x};{left:016x}")
    source = _control_flow_events("\n".join(lines), function, authority, side="source")
    target = _control_flow_events("\n".join(lines), function, authority, side="target")
    assert source is not None and target is not None
    assert source[0].to_dict()["eventKind"] == "ControlTransfer"
    assert exact_control_flow_observations_match(
        source, target, sidecar.approved_effect_relations) == (True, "")


def _branch_event(event_id, *, taken=True, signed=False, result="u64:0x0000000000000007"):
    return L2ControlFlowObservation(
        event_id, "fragment:x", "Branch", "condition:0",
        {"conditionInputs": [
            ("i64" if signed else "u64") + ":0x0000000000000001",
            ("i64" if signed else "u64") + ":0x0000000000000002"],
         "conditionResult": taken, "taken": taken,
         "continuationId": "continuation:taken" if taken else "continuation:not-taken",
         "result": result, "termination": "normal_return"})


def _relation():
    return ApprovedEffectRelation(
        "relation:0", "source:0", ("target:0",), "exact",
        ("branch_condition", "branch_continuation", "branch_outcome", "kind", "value"),
        (), "", True)


@pytest.mark.parametrize(("target", "expected_reason"), [
    (_branch_event("target:0", taken=False), "L2_CONTROL_FLOW_OBSERVATION_MISMATCH"),
    (_branch_event("target:0", taken=False, result="u64:0x0000000000000007"),
     "L2_CONTROL_FLOW_OBSERVATION_MISMATCH"),
    (_branch_event("target:0", signed=True), "L2_CONTROL_FLOW_OBSERVATION_MISMATCH"),
])
def test_exact_branch_comparison_rejects_path_or_signedness_mismatch(target, expected_reason):
    matched, reason = exact_control_flow_observations_match(
        (_branch_event("source:0"),), (target,), (_relation(),))
    assert not matched and reason == expected_reason


def test_branch_observation_count_is_closed():
    matched, reason = exact_control_flow_observations_match(
        (_branch_event("source:0"),), (), (_relation(),))
    assert not matched and reason == "L2_CONTROL_FLOW_OBSERVATION_COUNT_MISMATCH"


def test_missing_continuation_and_unsafe_proof_are_rejected():
    with pytest.raises(ValueError, match="typed condition/value facts"):
        L2ControlFlowAuthority(
            "condition:0", ("operand:a", "operand:b"), ("continuation:taken",), True,
            "conditional", "equal", "operand:out", "operand:x", "operand:y")
    raw = _safe_facts("fragment:unsafe").to_dict()
    raw["noTrap"] = False
    raw["factsIdentity"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="completeness"):
        control_flow_proof_facts_from_dict(raw)


def test_asm_goto_profile_is_not_automatic_branch():
    operand = lambda access: SimpleNamespace(access=SimpleNamespace(value=access), address=None)
    model = SimpleNamespace(
        operands=SimpleNamespace(operands=(operand("output"), operand("input")), complete=True),
        shell=SimpleNamespace(has_asm_goto=True),
        control_flow=SimpleNamespace(cfg_ok=True, has_unknown_target=False, successors=(1, 2),
            has_internal_branch=True, has_indirect_control_flow=False,
            has_external_control_flow=False, has_multiple_exits=False),
        local_branch_select=SimpleNamespace(), local_unconditional_jump=None,
        memory=SimpleNamespace(has_atomic=False, reads_memory=False, writes_memory=False,
            has_memory_barrier=False, has_instruction_barrier=False, has_unknown_barrier=False),
        atomic=None, barrier=None, privileged_state=None, value_program=None,
        completeness=SimpleNamespace(cfg_ok=True))
    assert profile_from_source_model("fragment:goto", model).pattern_kind is L2PatternKind.UNKNOWN


def test_control_provider_rejects_missing_environment_capability():
    profile = _profile("fragment:capability", L2PatternKind.JUMP)
    requirement = L2FragmentRequirement(
        profile.fragment_id, "sha256:" + "1" * 64,
        (L2Dimension.CONTROL_FLOW,), L2EligibilityStatus.ELIGIBLE,
        profile.profile_identity, profile.pattern_kind.value, profile.required_capabilities)
    provider = L2ValidatorProvider(
        "generic-control", (L2Dimension.CONTROL_FLOW,),
        (L2PatternKind.BRANCH, L2PatternKind.JUMP),
        ("control_flow_observation", "shell_observation"),
        (profile.execution_profile,), L2BindingKind.AUTOMATIC,
        "automatic-l2-effect-differential", "test.control.v1",
        {"schemaVersion": "test.control.v1"})
    environment = L2RuntimeCapabilities(
        (provider,), ("shell_observation",), (profile.execution_profile,))

    match = provider.supports(requirement, profile, environment,
                              dimension=L2Dimension.CONTROL_FLOW)
    assert match.match_status.value == "not_matched"
    assert match.missing_capabilities == ("control_flow_observation",)
    assert "l2.environment.capability-missing" in match.reason_codes
