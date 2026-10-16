from dataclasses import replace
from types import SimpleNamespace

import pytest

from riscv2x86_py.route_authority import (
    AtomicAuthorityError, RouteAuthorityDecision, content_identity,
    validate_route_decision,
)
from riscv2x86_py.atomic_authority import atomic_runtime_object_from_compiler_authority
from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
from riscv2x86_py.schema import TranslationOutcome
from riscv2x86_py.translation_attempt import (
    DIAGNOSTIC_ATTEMPT_SCHEMA, terminal_attempt_from_finding,
    translation_attempt_from_dict, TranslationAttemptArchive,
    translation_attempt_archive_from_dict,
)
from riscv2x86_py.source_model import _normalize_asm_goto_predicate
from riscv2x86_py.pcode_ir import (
    Var, VarKind, Op, CanonicalInsn,
    _is_proven_direct_conditional_branch_fragment,
)
from tests.test_translation_attempt import _finding
from tests.test_production_route_authority import _compiler_authority, _atomic
from tests.test_asm_goto_structured_authority import _model


def _diagnostic(fragment_id="fragment:0"):
    inputs = {"machineBytes": "00", "continuations": ["fallthrough", "taken"]}
    return RouteAuthorityDecision("atomic", fragment_id, "atomic_compiler_join",
        "ATOMIC_MEMORY_OBJECT_MISSING", "No bound memory object", content_identity(inputs),
        inputs_payload=inputs).to_dict()


def test_diagnostic_input_payload_is_bound_not_just_an_unverifiable_digest():
    diagnostic = _diagnostic()
    diagnostic["inputsPayload"]["machineBytes"] = "01"
    diagnostic["decisionIdentity"] = content_identity({k:v for k,v in diagnostic.items()
                                                      if k != "decisionIdentity"})
    with pytest.raises(ValueError, match="inputs identity"):
        validate_route_decision(diagnostic)


def test_diagnostic_survives_attempt_archive_and_is_content_bound():
    finding = _finding(TranslationOutcome.UNSUPPORTED)
    finding.routeAuthorityDiagnostics = [_diagnostic()]
    attempt = terminal_attempt_from_finding(finding, 0)
    assert attempt.schema_version == DIAGNOSTIC_ATTEMPT_SCHEMA
    assert "ATOMIC_MEMORY_OBJECT_MISSING" in attempt.reason_codes
    archive = TranslationAttemptArchive((attempt,))
    restored = translation_attempt_archive_from_dict(archive.to_dict())
    assert restored.attempts[0].to_dict() == attempt.to_dict()
    raw = attempt.to_dict()
    raw["routeAuthorityDiagnostics"][0]["detail"] = "different cause"
    with pytest.raises(ValueError, match="decision identity"):
        translation_attempt_from_dict(raw)


def test_v3_cannot_drop_diagnostic_or_attach_to_another_fragment():
    finding = _finding(TranslationOutcome.UNSUPPORTED)
    finding.routeAuthorityDiagnostics = [_diagnostic()]
    raw = terminal_attempt_from_finding(finding, 0).to_dict()
    raw["routeAuthorityDiagnostics"] = []
    with pytest.raises(ValueError, match="lacks route decisions"):
        translation_attempt_from_dict(raw)
    finding.routeAuthorityDiagnostics = [_diagnostic("different-fragment")]
    with pytest.raises(ValueError, match="fragment mismatch"):
        terminal_attempt_from_finding(finding, 0)


def test_existing_goto_model_records_source_authority_not_an_l2_verdict():
    model = _model()
    decision = model.control_flow.asm_goto_authority_decision
    assert decision.accepted
    assert decision.reason_code == "ASM_GOTO_SOURCE_AUTHORITY_BOUND"
    validate_route_decision(decision.to_dict())


@pytest.mark.parametrize("field,value,expected", [
    ("schemaVersion", "unknown", "ATOMIC_MEMORY_OBJECT_PROVENANCE_INVALID"),
    ("objectSizeBytes", 7, "ATOMIC_MEMORY_OBJECT_BOUNDS_UNPROVEN"),
    ("objectSizeBytes", True, "ATOMIC_MEMORY_OBJECT_BOUNDS_UNPROVEN"),
    ("provenAlignmentBytes", 12, "ATOMIC_MEMORY_OBJECT_PROVENANCE_INVALID"),
    ("volatile", "false", "ATOMIC_MEMORY_OBJECT_PROVENANCE_INVALID"),
    ("addressSpaceIdentity", "device.mmio", "ATOMIC_ADDRESS_SPACE_UNSUPPORTED"),
    ("bindingOrigin", "static-object-guessed", "ATOMIC_OBJECT_ENVIRONMENT_CONTRACT_REQUIRED"),
])
def test_atomic_object_mutations_have_precise_root_reason(field, value, expected):
    authority = _compiler_authority()
    obj = next(iter(authority["memoryObjectBindings"].values()))
    obj[field] = value
    obj["bindingIdentity"] = content_identity({k:v for k,v in obj.items() if k != "bindingIdentity"})
    authority["authorityIdentity"] = content_identity({k:v for k,v in authority.items() if k != "authorityIdentity"})
    with pytest.raises(AtomicAuthorityError) as error:
        atomic_runtime_object_from_compiler_authority(authority, fragment_id="source.c:7:3",
            source_digest=authority["sourceDigest"], begin_offset=100, end_offset=140,
            runtime_facts=TranslationRuntimeFacts(rv_to_operand_index={"a0":0,"a1":1},
                operand_width_bits={0:64,1:64}), atomic_operation=_atomic())
    assert error.value.reason_code == expected


@pytest.mark.parametrize("semantics", ["new_value", "success_flag"])
def test_amo_cannot_claim_cas_or_new_value_result(semantics):
    authority = _compiler_authority()
    operation = _atomic()
    operation.result_semantics = semantics
    with pytest.raises(AtomicAuthorityError) as error:
        atomic_runtime_object_from_compiler_authority(authority, fragment_id="source.c:7:3",
            source_digest=authority["sourceDigest"], begin_offset=100, end_offset=140,
            runtime_facts=TranslationRuntimeFacts(rv_to_operand_index={"a0":0,"a1":1},
                operand_width_bits={0:64,1:64}), atomic_operation=operation)
    assert error.value.reason_code == "ATOMIC_RESULT_SEMANTICS_MISMATCH"


def _ops():
    register = Var(VarKind.REG, "register", 10, 8, "a0")
    predicate = Var(VarKind.UNIQUE, "unique", 1, 1)
    compare = Op(0, "INT_EQUAL", predicate, [register, Var(VarKind.CONST,"const",0,8)])
    branch = Op(1, "CBRANCH", None, [Var(VarKind.CONST,"const",0x100,8), predicate])
    return compare, branch


def test_future_predicate_definition_is_not_dominance_authority():
    compare, branch = _ops()
    assert _normalize_asm_goto_predicate([compare, branch], branch)[0] == "zero"
    assert _normalize_asm_goto_predicate([branch, compare], branch) is None


@pytest.mark.parametrize("mutation", ["none", "gap", "overlap", "loop", "memory", "prefix_branch"])
def test_straight_line_condition_region_is_closed_without_single_instruction_assumption(mutation):
    compare, branch = _ops()
    prefix = CanonicalInsn(addr=0, size=4, ops=[compare])
    exit_insn = CanonicalInsn(addr=4, size=4, ops=[branch], terminator_kind="CBRANCH",
        direct_target=8, has_branch_op=True)
    if mutation == "gap": exit_insn.addr = 8
    if mutation == "overlap": exit_insn.addr = 2
    if mutation == "loop": exit_insn.direct_target = 0
    if mutation == "memory": prefix.ops = [Op(0,"STORE",None,[])]
    if mutation == "prefix_branch": prefix.has_branch_op = True
    assert _is_proven_direct_conditional_branch_fragment([prefix, exit_insn]) == (mutation == "none")
