from copy import deepcopy
from hashlib import sha256
import json

import pytest

from riscv2x86_py.effect_relation import ApprovedEffectRelation
from riscv2x86_py.l2_authority import (
    LEGACY_L2_AUTHORITY_SIDECAR_SCHEMA,
    PREVIOUS_L2_AUTHORITY_SIDECAR_SCHEMA,
    L2AuthorityProducer,
    L2AuthoritySidecar,
    L2ControlFlowAuthority,
    L2InternalValueAuthority,
    L2MemoryObjectAuthority,
    L2OperandAuthority,
    L2SourceEffectAuthority,
    l2_authority_sidecar_from_dict,
    migrate_l2_authority_v1_to_v2,
    migrate_l2_authority_v2_to_v3,
)


def _digest(value: str) -> str:
    return "sha256:" + sha256(value.encode()).hexdigest()


def _identity(value):
    return "sha256:" + sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()


def _boundary(*, value_node=None, declaration="decl:lhs", access="input"):
    payload = {
        "schemaVersion": "riscv2x86.fragment-operand-boundary.v2",
        "programId": "program:1", "functionId": "function:1",
        "fragmentId": "fragment:1",
        "inputBindings": [{
            "operandIndex": 0, "declarationIdentity": declaration,
            "valueNodeIdentity": value_node or _digest("value:lhs"),
            "access": access, "widthBits": 64, "signedness": "unsigned",
            "complete": True,
        }],
        "outputBindings": [], "liveInNodes": [value_node or _digest("value:lhs")],
        "liveOutNodes": [], "complete": True, "reasonCodes": [],
        "valueFlowEdges": [], "observationSinks": [],
        "discardedOutputNodes": [], "instrumentationObservedNodes": [],
    }
    payload["boundaryIdentity"] = _identity(payload)
    return payload


def _sidecar(**changes):
    operand = L2OperandAuthority(
        "operand:lhs", 0, "lhs", "input", "integer", 64, "unsigned", "",
        False, "", "function_argument", _digest("value:lhs"), "decl:lhs", 0, "r", True,
    )
    effect = L2SourceEffectAuthority("effect:0", "continuation", "return", True)
    relation = ApprovedEffectRelation(
        "relation:0", "effect:0", ("target:0",), "exact", ("kind",), (), "", True,
    )
    values = dict(
        fragment_id="fragment:1",
        producer=L2AuthorityProducer("frontend-compiler-sidecar", "test", "v2", _digest("p")),
        shell_fact_identity=_digest("shell"), operands=(operand,), memory_objects=(),
        source_effects=(effect,), approved_effect_relations=(relation,), runtime_contracts=(),
        ignored_state=(), complete=True,
    )
    values.update(changes)
    return L2AuthoritySidecar(**values)


def test_v2_operand_missing_signedness_is_rejected():
    raw = _sidecar().to_dict()
    del raw["operands"][0]["signedness"]
    with pytest.raises(ValueError, match="operand authority fields"):
        l2_authority_sidecar_from_dict(raw)


def test_complete_memory_object_requires_explicit_bounds():
    with pytest.raises(ValueError, match="requires bounds"):
        L2MemoryObjectAuthority("arg:base", "function_argument", 32, 8,
                                "function_call", "object:0", (), (), True)


def test_incomplete_branch_continuations_cannot_make_complete_sidecar():
    control = L2ControlFlowAuthority("condition:0", ("operand:lhs",),
                                     ("continuation:taken",), False)
    with pytest.raises(ValueError, match="incomplete authority facts"):
        _sidecar(control_flow=(control,))


def test_internal_value_requires_explicit_escape_and_typed_sidecar():
    raw = _sidecar().to_dict()
    raw["internalValues"] = [{"valueId": "temp:0", "typeKind": "integer",
                              "widthBits": 64, "signedness": "unsigned", "complete": True}]
    raw["authorityIdentity"] = _digest("irrelevant")
    with pytest.raises(ValueError, match="internal value fields"):
        l2_authority_sidecar_from_dict(raw)
    with pytest.raises(TypeError, match="typed DTOs"):
        _sidecar(internal_values=({"valueId": "temp:0"},))


def test_every_typed_fact_field_is_identity_bound():
    first = _sidecar()
    second_operand = L2OperandAuthority(
        "operand:lhs", 0, "lhs", "input", "integer", 32, "unsigned", "",
        False, "", "function_argument", _digest("value:lhs"), "decl:lhs", 0, "r", True,
    )
    second = _sidecar(operands=(second_operand,))
    assert first.authority_identity != second.authority_identity


def test_v1_requires_explicit_migration_and_migration_is_fail_closed():
    current = _sidecar().to_dict()
    operand = current["operands"][0]
    legacy_operand = {
        "operandIndex": operand["operandIndex"], "operandName": operand["logicalName"],
        "operandId": operand["operandId"], "declarationId": operand["declarationId"],
        "accessMode": operand["accessMode"], "widthBits": operand["widthBits"],
        "parameterIndex": operand["parameterIndex"], "signedness": operand["signedness"],
        "tiedToOperandIndex": None, "earlyClobber": operand["earlyClobber"],
        "sourceConstraint": operand["sourceConstraint"],
        "targetContractCarriedByProof": True, "escaped": False,
        "escapeKind": operand["escapeKind"],
    }
    legacy = {key: deepcopy(current[key]) for key in (
        "fragmentId", "producer", "shellFactIdentity", "memoryObjects",
        "approvedEffectRelations", "runtimeContracts", "ignoredState", "complete")}
    legacy.update(schemaVersion=LEGACY_L2_AUTHORITY_SIDECAR_SCHEMA,
                  operands=[legacy_operand],
                  sourceEffects=[{"eventId": "effect:0", "eventKind": "continuation"}],
                  authorityIdentity=_digest("legacy"))
    with pytest.raises(ValueError, match="migrate older schemas explicitly"):
        l2_authority_sidecar_from_dict(legacy)
    migration = migrate_l2_authority_v1_to_v2(legacy)
    assert migration["sourceSchemaVersion"] == LEGACY_L2_AUTHORITY_SIDECAR_SCHEMA
    assert migration["sidecar"]["schemaVersion"] == PREVIOUS_L2_AUTHORITY_SIDECAR_SCHEMA
    with pytest.raises(ValueError, match="migrate older schemas explicitly"):
        l2_authority_sidecar_from_dict(migration["sidecar"])
    v3 = migrate_l2_authority_v2_to_v3(migration["sidecar"], _boundary())
    migrated = l2_authority_sidecar_from_dict(v3["sidecar"])
    assert migrated.complete is False
    assert migrated.source_effects[0].complete is False


def test_v3_operand_requires_content_addressed_compiler_value_node():
    raw = _sidecar().to_dict()
    del raw["operands"][0]["valueNodeIdentity"]
    with pytest.raises(ValueError, match="operand authority fields"):
        l2_authority_sidecar_from_dict(raw)
    with pytest.raises(ValueError, match="value-node identity"):
        L2OperandAuthority(
            "operand:lhs", 0, "lhs", "input", "integer", 64, "unsigned", "",
            False, "", "function_argument", "not-a-digest", "decl:lhs", 0, "r", True,
        )


def test_value_node_identity_is_bound_into_sidecar_identity():
    first = _sidecar()
    changed = L2OperandAuthority(
        "operand:lhs", 0, "lhs", "input", "integer", 64, "unsigned", "",
        False, "", "function_argument", _digest("value:other"), "decl:lhs", 0, "r", True,
    )
    second = _sidecar(operands=(changed,))
    assert first.authority_identity != second.authority_identity


def test_v2_migration_requires_unique_exact_boundary_binding():
    current = _sidecar().to_dict()
    previous = deepcopy(current)
    previous["schemaVersion"] = PREVIOUS_L2_AUTHORITY_SIDECAR_SCHEMA
    previous["operands"][0].pop("valueNodeIdentity")
    previous.pop("authorityIdentity")
    previous["authorityIdentity"] = _identity(previous)
    with pytest.raises(ValueError, match="migrate older schemas explicitly"):
        l2_authority_sidecar_from_dict(previous)
    with pytest.raises(ValueError, match="no unique compiler value-node binding"):
        migrate_l2_authority_v2_to_v3(
            previous, _boundary(declaration="decl:other"),
        )
    migrated = migrate_l2_authority_v2_to_v3(previous, _boundary())
    assert migrated["sidecar"]["operands"][0]["valueNodeIdentity"] == _digest("value:lhs")
    assert migrated["sidecar"]["authorityIdentity"] != previous["authorityIdentity"]


def test_internal_value_valid_escape_is_identity_bound():
    value = L2InternalValueAuthority("temp:0", "integer", 64, "unsigned",
                                     "non_escaping", True)
    assert _sidecar(internal_values=(value,)).internal_values == (value,)
