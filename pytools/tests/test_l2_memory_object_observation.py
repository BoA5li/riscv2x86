from copy import deepcopy
from types import SimpleNamespace

import pytest

from riscv2x86_py.effect_relation import ApprovedEffectRelation
from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
from riscv2x86_py.l2_authority import L2OperandAuthority, l2_authority_sidecar_from_dict
from riscv2x86_py.l2_memory_object import (
    L2MemoryObservation, L2MemoryProofFacts, MemoryAccessAuthority,
    assess_memory_authority_materializability, bind_memory_object_authority,
    exact_memory_observations_match, memory_proof_facts_from_dict,
    memory_proof_facts_from_source_model,
)
from riscv2x86_py.l2_semantic_profile import (
    L2ControlFlowShape, L2FragmentSemanticProfile, L2InternalStateShape,
    L2MemoryShape, L2OperandShape, L2OrderingShape, L2PatternKind,
    L2PrivilegedShape,
)


def _facts(**changes):
    values = dict(fragment_id="fragment:any", access_kind="load",
                  address_operand_index=1, value_operand_index=0, byte_offset=8,
                  width_bytes=8, required_alignment=8,
                  object_origin_kind="function_argument",
                  object_lifetime_scope="function_call", alias_class="object:0",
                  unique_object=True, bounds_proven=True, alignment_proven=True,
                  alias_complete=True, non_atomic=True, memory_order="relaxed",
                  complete=True)
    values.update(changes)
    return L2MemoryProofFacts(**values)


def _operand(index, *, pointer=False, parameter=None):
    return L2OperandAuthority(
        f"operand:{index}", index, f"logical:{index}",
        "address" if pointer else "output", "pointer" if pointer else "integer",
        64, "not_applicable" if pointer else "unsigned", "", False, "",
        "function_argument" if pointer else "function_return", f"decl:{index}",
        parameter, "r", True,
    )


def _observation(event_id, **payload_changes):
    payload = {"objectId":"operand:1:object", "offset":8, "size":8,
               "value":"u64:0x1122334455667788", "alignment":8,
               "atomicity":"none", "memoryOrder":"relaxed"}
    payload.update(payload_changes)
    return L2MemoryObservation(event_id, "fragment:any", "ReadMemory",
                               "operand:1:object", payload, 0, ())


def _relation():
    return ApprovedEffectRelation(
        "relation:memory:0", "sample:0:memory", ("target:sample:0:memory",),
        "exact", ("kind", "memory_coordinates", "memory_order", "subject", "value"),
        (), "", True)


def test_proof_facts_identity_changes_and_parser_rejects_stale_content():
    original = _facts().to_dict()
    stale = deepcopy(original); stale["byteOffset"] = 16
    with pytest.raises(ValueError, match="identity"):
        memory_proof_facts_from_dict(stale)
    assert _facts(byte_offset=16).facts_identity != _facts().facts_identity


def test_source_model_requires_one_proven_object_and_natural_alignment():
    address = SimpleNamespace(byte_offset=8, alignment_bytes=8, provenance_known=True)
    operands = SimpleNamespace(complete=True, operands=(
        SimpleNamespace(source_operand_index=0, kind=SimpleNamespace(value="register"),
                        access=SimpleNamespace(value="output"), width_bits=64),
        SimpleNamespace(source_operand_index=1, kind=SimpleNamespace(value="address"),
                        access=SimpleNamespace(value="address"), width_bits=64,
                        address=address),
    ))
    model = SimpleNamespace(operation=SimpleNamespace(kind=SimpleNamespace(value="load")),
                            operands=operands, memory=SimpleNamespace(has_atomic=False))
    assert memory_proof_facts_from_source_model("fragment:any", model) == _facts()
    ambiguous = SimpleNamespace(operation=model.operation,
        operands=SimpleNamespace(complete=True, operands=operands.operands + (operands.operands[1],)),
        memory=model.memory)
    assert memory_proof_facts_from_source_model("fragment:any", ambiguous) is None


def test_authority_binds_object_relative_bounds_without_raw_address():
    authority = MemoryAccessAuthority(
        "fragment:any", "load", "parameter-object:decl:1", "decl:1", "decl:1",
        8, 8, 8, 8, 32, "0<=8 && 16<=32", "alias:decl:1", "c.default",
        "decl:0", False, True)
    obj, object_id = bind_memory_object_authority(
        _facts(), (_operand(0), _operand(1, pointer=True, parameter=0)), authority)
    assert object_id == "parameter-object:decl:1"
    assert obj.readable_ranges == ((8, 16),)
    assert obj.writable_ranges == ()


@pytest.mark.parametrize(("directory", "function_name"), [
    ("unrelated/location", "fetch_payload"), ("second-tree", "read_record"),
])
def test_authority_materialization_is_not_round2_name_based(tmp_path, directory, function_name):
    fragment_id = "fragment:memory:independent"
    facts = _facts(fragment_id=fragment_id)
    profile = L2FragmentSemanticProfile(
        fragment_id, L2PatternKind.MEMORY_LOAD, L2OperandShape(1, 1, 0, True),
        L2ControlFlowShape(False, False, False, False, False, 0, True),
        L2MemoryShape(True, False, False, True, True),
        L2OrderingShape(False, False, True, True),
        L2PrivilegedShape(False, False, False, True),
        L2InternalStateShape(False, False, True, True),
        "rv64gc-user-to-x86_64-user",
        ("logical_operand_observation", "object_relative_memory_observation",
         "shell_observation"),
    )
    finding = {"fragment": {"id":fragment_id, "enclosingFunction":function_name,
        "outputs":[{"constraint":"=r", "symbolicName":"result"}],
        "inputs":[{"constraint":"r", "symbolicName":"base"}]},
        "l2SemanticProfile":profile.to_dict(),
        "approvalArtifact":{"proofStatus":"approved",
          "architectureSemanticsPreserved":True, "shellSemanticsPreserved":True,
          "sourceModelId":"model", "constraintsId":"constraints",
          "preservationDecisionId":"decision", "planId":"plan",
          "targetEnvironmentId":"environment", "targetCatalogVersion":"catalog",
          "l2MemoryProofFacts":facts.to_dict()}}
    boundary = {"complete":True, "parameterDeclarationIds":["base"],
      "asmOperandDeclarationIds":["result", "base"], "returnDeclarationId":"result",
      "declarationReferenceCounts":{"result":2, "base":1},
      "declarations":{"result":{"name":"result", "type":"uint64_t"},
                      "base":{"name":"base", "type":"const uint64_t *"}},
      "memoryObjectBindings":{"base":{
          "objectIdentity":"parameter-object:base", "objectSizeBytes":32,
          "provenAlignmentBytes":8, "aliasDomainIdentity":"alias:base",
          "addressSpaceIdentity":"c.default", "volatile":False,
          "bindingOrigin":"automatic-aligned-memory-object-harness-v1"}}}
    function = {"name":function_name, "arity":1, "returnType":"uint64_t",
                "parameterTypes":["const uint64_t *"], "pointerParameters":[0],
                "l2OperandBoundary":boundary}
    frontend = tmp_path / directory / "frontend"
    frontend.parent.mkdir(parents=True); frontend.write_bytes(b"frontend")
    assert materialize_automatic_l2_authority(
        {"findings":[finding]}, [function], frontend) == 1
    sidecar = l2_authority_sidecar_from_dict(
        finding["approvalArtifact"]["l2AuthoritySidecar"])
    assert sidecar.memory_objects[0].object_id == "parameter-object:base"
    assert sidecar.memory_objects[0].readable_ranges == ((8, 16),)
    assert len(sidecar.approved_effect_relations) == 1


@pytest.mark.parametrize(("change", "reason"), [
    ({"offset": 16}, "L2_MEMORY_OBJECT_RELATIVE_TRACE_MISMATCH"),
    ({"size": 4, "value": "u32:0x55667788"}, "L2_MEMORY_OBJECT_RELATIVE_TRACE_MISMATCH"),
    ({"alignment": 4}, "L2_MEMORY_OBJECT_RELATIVE_TRACE_MISMATCH"),
])
def test_exact_comparator_rejects_same_value_with_wrong_contract(change, reason):
    source = [_observation("sample:0:memory")]
    target = [_observation("target:sample:0:memory", **change)]
    assert exact_memory_observations_match(source, target, [_relation()]) == (False, reason)


def test_extra_target_write_is_not_tolerated():
    source = [_observation("sample:0:memory")]
    target = [_observation("target:sample:0:memory"),
              _observation("target:unexpected")]
    assert exact_memory_observations_match(source, target, [_relation()])[0] is False


def test_raw_address_and_unproved_alignment_are_rejected():
    payload = dict(_observation("sample:0:memory").payload); payload["address"] = "0x7fff"
    with pytest.raises(ValueError, match="incomplete"):
        L2MemoryObservation("sample:0:memory", "fragment:any", "ReadMemory",
                            "operand:1:object", payload, 0, ())
    with pytest.raises(ValueError, match="completeness"):
        _facts(alignment_proven=False)


def _materialization_boundary():
    return {"complete": True, "asmOperandDeclarationIds": ["value", "base"],
            "declarations": {"value": {"type": "uint64_t"},
                             "base": {"type": "uint64_t *"}},
            "memoryObjectBindings": {"base": {
                "objectIdentity": "parameter-object:base", "objectSizeBytes": 32,
                "provenAlignmentBytes": 8, "aliasDomainIdentity": "alias:base",
                "addressSpaceIdentity": "c.default", "volatile": False,
                "bindingOrigin": "parameter-object-contract-v1"}}}


@pytest.mark.parametrize(("mutation", "reason"), [
    (lambda value: value.update(complete=False),
     "L2_MEMORY_ADDRESS_BINDING_MISSING"),
    (lambda value: value["memoryObjectBindings"]["base"].pop("objectIdentity"),
     "L2_MEMORY_OBJECT_IDENTITY_MISSING"),
    (lambda value: value["memoryObjectBindings"]["base"].pop("objectSizeBytes"),
     "L2_MEMORY_BOUNDS_UNPROVED"),
    (lambda value: value["memoryObjectBindings"]["base"].pop("provenAlignmentBytes"),
     "L2_MEMORY_ALIGNMENT_UNPROVED"),
    (lambda value: value["declarations"].pop("value"),
     "L2_MEMORY_VALUE_FLOW_UNPROVED"),
])
def test_materializability_requires_each_independent_authority(mutation, reason):
    boundary = _materialization_boundary()
    mutation(boundary)
    decision = assess_memory_authority_materializability(
        {"proofStatus": "approved", "architectureSemanticsPreserved": True,
         "shellSemanticsPreserved": True}, _facts(), boundary,
        {"id": "fragment:any"})
    assert not decision.materializable
    assert reason in decision.reason_codes


def test_materializability_decision_is_content_bound_and_reusable():
    decision = assess_memory_authority_materializability(
        {"proofStatus": "approved", "architectureSemanticsPreserved": True,
         "shellSemanticsPreserved": True}, _facts(), _materialization_boundary(),
        {"id": "fragment:any"})
    assert decision.materializable
    assert decision.authority.object_identity == "parameter-object:base"
    parsed = assess_memory_authority_materializability(
        {}, decision.to_dict(), None, {"id": "fragment:any"})
    assert parsed == decision
    stale = decision.to_dict(); stale["fragmentId"] = "fragment:other"
    rejected = assess_memory_authority_materializability(
        {}, stale, None, {"id": "fragment:any"})
    assert rejected.reason_codes == ("L2_MEMORY_AUTHORITY_DECISION_INVALID",)


def test_materializability_rejects_cross_fragment_memory_facts():
    decision = assess_memory_authority_materializability(
        {"proofStatus": "approved", "architectureSemanticsPreserved": True,
         "shellSemanticsPreserved": True}, _facts(fragment_id="fragment:other"),
        _materialization_boundary(), {"id": "fragment:any"})
    assert not decision.materializable
    assert "L2_FRAGMENT_IDENTITY_MISMATCH" in decision.reason_codes
