from copy import deepcopy
from hashlib import sha256

import pytest

from riscv2x86_py.effect_relation import ApprovedEffectRelation
from riscv2x86_py.l2_authority import (
    LEGACY_L2_AUTHORITY_SIDECAR_SCHEMA,
    L2AuthorityProducer,
    L2AuthoritySidecar,
    L2ControlFlowAuthority,
    L2InternalValueAuthority,
    L2MemoryObjectAuthority,
    L2OperandAuthority,
    L2SourceEffectAuthority,
    l2_authority_sidecar_from_dict,
    migrate_l2_authority_v1_to_v2,
)


def _digest(value: str) -> str:
    return "sha256:" + sha256(value.encode()).hexdigest()


def _sidecar(**changes):
    operand = L2OperandAuthority(
        "operand:lhs", 0, "lhs", "input", "integer", 64, "unsigned", "",
        False, "", "function_argument", "decl:lhs", 0, "r", True,
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
        False, "", "function_argument", "decl:lhs", 0, "r", True,
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
    with pytest.raises(ValueError, match="migrate v1 explicitly"):
        l2_authority_sidecar_from_dict(legacy)
    migration = migrate_l2_authority_v1_to_v2(legacy)
    assert migration["sourceSchemaVersion"] == LEGACY_L2_AUTHORITY_SIDECAR_SCHEMA
    migrated = l2_authority_sidecar_from_dict(migration["sidecar"])
    assert migrated.complete is False
    assert migrated.source_effects[0].complete is False


def test_internal_value_valid_escape_is_identity_bound():
    value = L2InternalValueAuthority("temp:0", "integer", 64, "unsigned",
                                     "non_escaping", True)
    assert _sidecar(internal_values=(value,)).internal_values == (value,)
