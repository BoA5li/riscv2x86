import copy
from dataclasses import replace
from types import SimpleNamespace

import pytest

from riscv2x86_py.l2_eligibility import L2EligibilityClassifier
from riscv2x86_py.l2_semantic_profile import (
    L2ControlFlowShape, L2MemoryShape, L2OrderingShape, L2PatternKind,
    L2PrivilegedShape, bind_approved_functional_profile,
    l2_fragment_semantic_profile_from_dict,
    profile_from_source_model,
)
from tests.l2_profile_fixtures import profile_dict
from riscv2x86_py.translation_validation import TranslationArtifact
from riscv2x86_py.validation_status import PreservationMode


def _source_model(*, branch=False, jump=False, memory_read=False):
    def operand(access):
        return SimpleNamespace(
            access=SimpleNamespace(value=access),
            address=(SimpleNamespace(address_id="object:arg0", provenance_known=True)
                     if access == "address" else None),
        )
    operands = [operand("output"), operand("input"), operand("input")]
    if memory_read:
        operands.append(operand("address"))
    return SimpleNamespace(
        operands=SimpleNamespace(
            operands=tuple(operands),
            complete=True,
        ),
        control_flow=SimpleNamespace(
            cfg_ok=True, has_unknown_target=False, successors=(),
            has_internal_branch=branch, has_indirect_control_flow=False,
            has_external_control_flow=False, has_multiple_exits=False,
        ),
        local_branch_select=(SimpleNamespace() if branch else None),
        local_unconditional_jump=(SimpleNamespace() if jump else None),
        memory=SimpleNamespace(
            has_atomic=False, reads_memory=memory_read, writes_memory=False,
            has_memory_barrier=False, has_instruction_barrier=False,
            has_unknown_barrier=False,
        ),
        privileged_state=None, value_operation=SimpleNamespace(), value_program=None,
        completeness=SimpleNamespace(cfg_ok=True),
    )


def _finding(fragment_id, profile, *, control=False):
    return {
        "translationOutcome": "emitted", "translationReasonCodes": [],
        "fragment": {
            "id": fragment_id, "outputs": [{"constraint": "=r"}],
            "inputs": [{"constraint": "r"}], "clobbers": [],
            "controlFlowSurface": "LocalCFG" if control else "StraightLine",
        },
        "l2SemanticProfile": profile.to_dict(),
    }


def test_profiles_are_per_fragment_and_do_not_consume_names_or_asm_text():
    scalar = profile_from_source_model("fragment:0", _source_model())
    branch = profile_from_source_model("fragment:1", _source_model(branch=True))
    report = {"findings": [
        dict(_finding("fragment:0", scalar), fileName="looks_like_fence.c",
             functionName="csr_read", rawAsmText="fence.i"),
        dict(_finding("fragment:1", branch, control=True), fileName="scalar.c",
             functionName="add", rawAsmText="add"),
    ]}

    manifest = L2EligibilityClassifier().classify_report(report)

    assert [item["patternKind"] for item in manifest["requirements"]] == [
        "scalar", "branch",
    ]
    assert len({item["semanticProfileIdentity"] for item in manifest["requirements"]}) == 2
    assert all(item["eligibilityStatus"] == "eligible"
               for item in manifest["requirements"])


def test_missing_or_unknown_profile_is_inconclusive():
    finding = _finding(
        "fragment:0", profile_from_source_model("fragment:0", _source_model()),
    )
    finding.pop("l2SemanticProfile")
    result = L2EligibilityClassifier().classify(finding, 0)
    assert result["eligibilityStatus"] == "inconclusive"
    assert result["patternKind"] == "unknown"
    assert result["reasonCodes"] == ["l2.semantic-profile.missing-or-invalid"]


def test_profile_parser_rejects_unknown_kind_and_stale_identity():
    value = profile_from_source_model("fragment:0", _source_model()).to_dict()
    unknown = copy.deepcopy(value); unknown["patternKind"] = "loads_by_filename"
    with pytest.raises(ValueError):
        l2_fragment_semantic_profile_from_dict(unknown)
    stale = copy.deepcopy(value); stale["operandShape"]["inputCount"] += 1
    with pytest.raises(ValueError, match="identity"):
        l2_fragment_semantic_profile_from_dict(stale)


def test_profile_identity_participates_in_requirement_and_artifact_identity():
    scalar = profile_from_source_model("fragment:0", _source_model())
    jump = profile_from_source_model("fragment:0", _source_model(jump=True))
    left = L2EligibilityClassifier().classify(_finding("fragment:0", scalar), 0)
    right = L2EligibilityClassifier().classify(
        _finding("fragment:0", jump, control=True), 0,
    )
    assert left["requirementIdentity"] != right["requirementIdentity"]

    base = dict(
        fragment_id="fragment:0", source_model_identity="source", translation_plan_id="plan",
        constraint_id="constraint", proof_identity="proof",
        preservation_mode=PreservationMode.ARCHITECTURE_EQUIVALENT,
        shell_facts_identity="shell", runtime_contract_id="runtime",
        runtime_contract_version="v1", recipe_id="recipe", ignored_source_state=(),
        semantic_class="integer", target_route="x86",
    )
    a = TranslationArtifact(**base, l2_semantic_profile_identity=scalar.profile_identity,
                            l2_pattern_kind=scalar.pattern_kind.value)
    b = TranslationArtifact(**base, l2_semantic_profile_identity=jump.profile_identity,
                            l2_pattern_kind=jump.pattern_kind.value)
    assert a.identity != b.identity


def test_scalar_profile_remains_eligible_with_canonical_capabilities():
    profile = profile_from_source_model("fragment:0", _source_model())
    result = L2EligibilityClassifier().classify(_finding("fragment:0", profile), 0)
    assert profile.pattern_kind is L2PatternKind.SCALAR
    assert result["eligibilityStatus"] == "eligible"
    assert result["requiredCapabilities"] == [
        "logical_operand_observation", "shell_observation",
    ]


def test_authoritative_memory_profile_closes_memory_requirement_without_text_hints():
    profile = profile_from_source_model(
        "fragment:0", _source_model(memory_read=True),
    )
    finding = _finding("fragment:0", profile)
    finding["translationReasonCodes"] = []
    result = L2EligibilityClassifier().classify(finding, 0)

    assert profile.pattern_kind is L2PatternKind.MEMORY_LOAD
    assert result["requiredDimensions"] == [
        "logical_operands", "memory_effects", "shell_semantics",
    ]


def test_privileged_profile_completeness_ignores_unrelated_shapes():
    profile = l2_fragment_semantic_profile_from_dict(profile_dict(
        "renamed/location:9:2", L2PatternKind.PRIVILEGED_READ))
    profile = replace(
        profile,
        control_flow_shape=L2ControlFlowShape(
            False, False, False, False, False, 0, False),
        memory_shape=L2MemoryShape(False, False, False, False, False),
        ordering_shape=L2OrderingShape(False, False, False, False),
        privileged_shape=L2PrivilegedShape(True, True, False, True),
        profile_identity="",
    )
    assert profile.complete
    finding = _finding(profile.fragment_id, profile, control=True)
    finding["translationReasonCodes"] = ["SM_TRAP", "SM_MEMORY_EFFECT"]
    finding["fragment"]["clobbers"] = ["memory"]
    result = L2EligibilityClassifier().classify(finding, 0)
    assert result["eligibilityStatus"] == "eligible"
    assert result["requiredDimensions"] == [
        "privileged_state", "shell_semantics",
    ]


def test_instruction_visibility_profile_does_not_require_branch_dimension():
    profile = l2_fragment_semantic_profile_from_dict(profile_dict(
        "other/tree/member:31:7", L2PatternKind.INSTRUCTION_VISIBILITY_FENCE))
    profile = replace(
        profile,
        control_flow_shape=L2ControlFlowShape(
            False, False, False, True, False, 0, False),
        ordering_shape=L2OrderingShape(False, True, True, True),
        profile_identity="",
    )
    assert profile.complete
    finding = _finding(profile.fragment_id, profile, control=True)
    finding["fragment"]["hasExternalControlFlow"] = True
    result = L2EligibilityClassifier().classify(finding, 0)
    assert result["eligibilityStatus"] == "eligible"
    assert result["requiredDimensions"] == [
        "memory_effects", "shell_semantics",
    ]


def test_read_only_counter_with_possible_trap_is_not_classified_as_write():
    model = _source_model()
    model.privileged_state = SimpleNamespace(
        read_only_counter=SimpleNamespace(csr_id="time"),
        complete=True,
        state=SimpleNamespace(
            present=True,
            csr_effects=(SimpleNamespace(
                operation=SimpleNamespace(value="read")),),
            trap_effects=(SimpleNamespace(kind="illegal-instruction"),),
            return_effects=(), interrupt_effects=(),
            address_translation_effects=(), virtualization_effects=(),
            debug_effects=(),
        ),
    )
    profile = profile_from_source_model("generic/counter:4:8", model)
    assert profile.pattern_kind is L2PatternKind.PRIVILEGED_READ
    assert profile.privileged_shape.reads_state
    assert not profile.privileged_shape.writes_state


def test_single_operation_privileged_profile_does_not_require_unrelated_cfg_facts():
    model = _source_model()
    model.operands.complete = False
    model.completeness.cfg_ok = False
    model.control_flow.cfg_ok = False
    model.privileged_state = SimpleNamespace(
        read_only_counter=SimpleNamespace(csr_id="cycle"),
        complete=True,
        state=SimpleNamespace(
            present=True,
            csr_effects=(SimpleNamespace(
                operation=SimpleNamespace(value="read")),),
            return_effects=(), interrupt_effects=(),
            address_translation_effects=(), virtualization_effects=(),
            debug_effects=(),
        ),
    )

    profile = profile_from_source_model("generic/counter:8:4", model)

    assert profile.pattern_kind is L2PatternKind.PRIVILEGED_READ
    assert not profile.internal_state_shape.has_internal_values
    assert profile.internal_state_shape.complete
    assert profile.internal_state_shape.escape_complete
    assert profile.complete


def test_multi_operation_profile_still_requires_internal_non_interference_facts():
    model = _source_model()
    model.value_program = SimpleNamespace(instructions=(object(), object()))
    model.operands.complete = False

    profile = profile_from_source_model("generic/composite:8:4", model)

    assert profile.internal_state_shape.has_internal_values
    assert not profile.internal_state_shape.escape_complete
    assert not profile.complete


def _functional_counter_approval(fragment_id: str) -> dict[str, object]:
    return {
        "proofStatus": "functional_approved",
        "functionalFallbackEnabled": True,
        "preservationMode": "functional_equivalence_only",
        "architectureSemanticsPreserved": False,
        "sourceFragmentId": fragment_id,
        "sourceSemanticContractId": "riscv.counter.read.v1",
        "targetSemanticContractId": "x86.monotonic-clock.v1",
        "runtimeContractId": "runtime.monotonic-clock@v1",
        "runtimeContractVersion": "v1",
        "targetEnvironmentId": "environment:x86-user",
        "targetCatalogVersion": "catalog-v1",
        "ignoredSourceState": ["csr:time:absolute", "csr:time:epoch"],
        "knownNonEquivalences": ["absolute values differ"],
    }


def test_functional_approval_closes_privileged_profile_without_architectural_claim():
    fragment_id = "generic/counter:12:3"
    model = _source_model()
    model.privileged_state = SimpleNamespace(
        read_only_counter=SimpleNamespace(csr_id="time"),
        complete=False,
        state=SimpleNamespace(
            present=True,
            csr_effects=(SimpleNamespace(
                operation=SimpleNamespace(value="read")),),
            return_effects=(), interrupt_effects=(),
            address_translation_effects=(), virtualization_effects=(),
            debug_effects=(),
        ),
    )
    strict = profile_from_source_model(fragment_id, model)
    assert strict.pattern_kind is L2PatternKind.PRIVILEGED_READ
    assert not strict.privileged_shape.complete
    assert not strict.complete

    functional = bind_approved_functional_profile(
        strict, _functional_counter_approval(fragment_id),
    )

    assert functional.privileged_shape.complete
    assert functional.complete
    assert functional.profile_identity != strict.profile_identity


@pytest.mark.parametrize("mutation", [
    lambda value: value.pop("runtimeContractVersion"),
    lambda value: value.update(sourceFragmentId="other:fragment"),
    lambda value: value.update(architectureSemanticsPreserved=True),
    lambda value: value.update(ignoredSourceState=[]),
])
def test_incomplete_functional_approval_cannot_close_privileged_profile(mutation):
    fragment_id = "generic/counter:12:3"
    model = _source_model()
    model.privileged_state = SimpleNamespace(
        read_only_counter=SimpleNamespace(csr_id="time"), complete=False,
        state=SimpleNamespace(
            present=True,
            csr_effects=(SimpleNamespace(
                operation=SimpleNamespace(value="read")),),
            return_effects=(), interrupt_effects=(),
            address_translation_effects=(), virtualization_effects=(),
            debug_effects=(),
        ),
    )
    profile = profile_from_source_model(fragment_id, model)
    approval = _functional_counter_approval(fragment_id)
    mutation(approval)

    bound = bind_approved_functional_profile(profile, approval)

    assert not bound.privileged_shape.complete
    assert not bound.complete
