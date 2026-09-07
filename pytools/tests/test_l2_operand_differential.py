from copy import deepcopy
from hashlib import sha256
import json
from types import SimpleNamespace

import pytest

from riscv2x86_py.l2_operand_differential import (
    LOGICAL_OPERAND_AUTHORITY_SCHEMA, L2_OPERAND_COMPARISON_POLICY,
    L2_OPERAND_RUNNER_SCHEMA, L2OperandRunnerConfig, compare_logical_operands,
    logical_operand_authority_from_dict, run_l2_operand_differential,
)
from riscv2x86_py.translation_validation import ValidationLevel
from riscv2x86_py.validation_observation import (
    CanonicalValue, ExecutionObservation, ExecutionResult, LogicalOperandObservation,
    ObservationProvenance, RunnerCommandProfile, TextObservation, ToolIdentity,
)
from riscv2x86_py.validation_status import PreservationMode, ValidationStatus
from riscv2x86_py.validation_runtime_registry import (
    VALIDATION_RUNTIME_REGISTRY_SCHEMA, validation_runtime_registry_from_dict,
)


def _digest(value):
    return "sha256:" + sha256(value.encode()).hexdigest()


def _value(number):
    return CanonicalValue("u64", f"0x{number:016x}", 64)


def _fact(index, name, access, *, tied=None, early=False, source_fixed="", target_fixed="",
          escaped=False, role="normal", carries=False):
    return {
        "operandIndex": index, "operandName": name, "operandId": f"operand:{index}",
        "accessMode": access, "widthBits": 64, "signedness": "unsigned",
        "tiedToOperandIndex": tied, "earlyClobber": early,
        "sourceFixedRegisterConstraint": source_fixed,
        "targetFixedRegisterConstraint": target_fixed, "escaped": escaped,
        "semanticRole": role, "targetRecipeCarriesEarlyClobber": carries,
        "sourceContractSatisfied": True, "targetContractSatisfied": True,
    }


def _sidecar(operands=None, shell="verified"):
    return {
        "schemaVersion": LOGICAL_OPERAND_AUTHORITY_SCHEMA,
        "producerKind": "compiler-sidecar", "producerId": "clang-plugin",
        "producerVersion": "v1", "producerBinaryDigest": _digest("plugin"),
        "fragments": [{
            "fragmentId": "fragment-1", "shellTransportabilityStatus": shell,
            "operands": operands or [
                _fact(0, "out", "output", tied=1, early=True, source_fixed="a0",
                      target_fixed="rax", carries=True),
                _fact(1, "lhs", "input"),
                _fact(2, "acc", "read_write"),
            ],
        }],
    }


def _tool(name):
    return ToolIdentity(name, "v1", _digest(name))


def _operand(fact, identity, side, *, before=7, after=42):
    access = fact["accessMode"]
    return LogicalOperandObservation(
        "fragment-1", fact["operandIndex"], fact["operandName"], fact["operandId"], access,
        fact["widthBits"], fact["signedness"], fact["escaped"], identity,
        _value(before) if access in {"input", "read_write"} else None,
        _value(after) if access in {"output", "read_write"} else None,
        "" if fact["tiedToOperandIndex"] is None else f"operand:{fact['tiedToOperandIndex']}",
        fact["earlyClobber"],
        fact["sourceFixedRegisterConstraint"] if side == "source" else fact["targetFixedRegisterConstraint"],
    )


def _observation(sidecar, side, *, operands=None):
    authority = logical_operand_authority_from_dict(sidecar)
    facts = sidecar["fragments"][0]["operands"]
    logical = tuple(_operand(item, authority.identity, side) for item in facts) if operands is None else tuple(operands)
    empty = TextObservation("", _digest(""))
    return ExecutionObservation(
        "case-1", ("fragment-1",), _tool("qemu" if side == "source" else "native"),
        _tool("gcc"), _tool("runtime"), _tool("loader"), "-O2", "none",
        "rv64gc-user", "x86_64-user", _digest("initial"), PreservationMode.ARCHITECTURE_EQUIVALENT,
        ExecutionResult(None, 0, empty, empty), logical, (), (), (), (), (),
        ObservationProvenance(
            _digest(side + "-program"), _digest("manifest"), _digest("translation"),
            _digest("model"), _digest("proof"), authority.identity, "runtime", "v1", 7,
            _digest("inputs"), L2_OPERAND_COMPARISON_POLICY,
            RunnerCommandProfile(side, _digest(side + "-argv")),
        ),
    )


def test_l2_compares_logical_values_and_ties_not_physical_register_names():
    raw = _sidecar()
    authority = logical_operand_authority_from_dict(raw)
    source, target = _observation(raw, "source"), _observation(raw, "target")
    assert source.logical_operands[0].fixed_register_constraint == "a0"
    assert target.logical_operands[0].fixed_register_constraint == "rax"
    assert compare_logical_operands(source=source, target=target, authority=authority,
                                    fragment_id="fragment-1") == ()


def test_output_read_write_and_input_mismatches_fail_closed():
    raw = _sidecar()
    authority = logical_operand_authority_from_dict(raw)
    source, target = _observation(raw, "source"), _observation(raw, "target")
    for index, field, expected in ((0, "after", "final-value-mismatch"),
                                   (1, "before", "initial-value-mismatch"),
                                   (2, "after", "final-value-mismatch")):
        changed = list(target.logical_operands)
        changed[index] = changed[index].__class__(
            **{**changed[index].__dict__, field: _value(99)})
        result = compare_logical_operands(source=source, target=target.__class__(
            **{**target.__dict__, "logical_operands": tuple(changed)}), authority=authority,
            fragment_id="fragment-1")
        assert any(expected in item for item in result)


def test_discarded_rd_x0_and_constant_zero_inputs_may_be_unobserved():
    raw = _sidecar([
        _fact(0, "discarded", "output", role="discarded_output"),
        _fact(1, "zero", "input", role="constant_zero_input"),
    ])
    authority = logical_operand_authority_from_dict(raw)
    source = _observation(raw, "source", operands=())
    target = _observation(raw, "target", operands=())
    assert compare_logical_operands(source=source, target=target, authority=authority,
                                    fragment_id="fragment-1") == ()


def test_escape_early_clobber_shell_and_contracts_are_hard_failures():
    mutations = (
        (lambda value: value["fragments"][0]["operands"][0].update(escaped=True), "output-escape"),
        (lambda value: value["fragments"][0]["operands"][0].update(targetRecipeCarriesEarlyClobber=False), "early-clobber"),
        (lambda value: value["fragments"][0].update(shellTransportabilityStatus="inconclusive"), "shell-transportability"),
        (lambda value: value["fragments"][0]["operands"][0].update(targetContractSatisfied=False), "contract-unsatisfied"),
    )
    for mutate, expected in mutations:
        raw = _sidecar()
        mutate(raw)
        authority = logical_operand_authority_from_dict(raw)
        reasons = compare_logical_operands(source=_observation(raw, "source"),
                                           target=_observation(raw, "target"),
                                           authority=authority, fragment_id="fragment-1")
        assert any(expected in item for item in reasons)


def test_sidecar_rejects_inferred_or_noncanonical_authority():
    for mutate in (
        lambda value: value.update(producerKind="pcode-inference"),
        lambda value: value["fragments"][0]["operands"].reverse(),
        lambda value: value["fragments"][0]["operands"][0].pop("widthBits"),
        lambda value: value["fragments"][0]["operands"][0].update(tiedToOperandIndex=99),
    ):
        raw = _sidecar()
        mutate(raw)
        with pytest.raises(ValueError):
            logical_operand_authority_from_dict(raw)


def test_registered_runner_binds_authority_digest_and_emits_evidence(tmp_path):
    raw = _sidecar()
    authority = logical_operand_authority_from_dict(raw)
    path = tmp_path / "operand-sidecar.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    config = L2OperandRunnerConfig(str(path))
    result = run_l2_operand_differential(
        config, level=ValidationLevel.L2,
        translation_artifact=SimpleNamespace(fragment_id="fragment-1", shell_facts_identity=authority.identity),
        source_observation=_observation(raw, "source"), target_observation=_observation(raw, "target"),
        comparison_policy=L2_OPERAND_COMPARISON_POLICY,
    )
    assert result.status is ValidationStatus.VERIFIED
    assert result.evidence_identity.startswith("sha256:")

    stale = run_l2_operand_differential(
        config, level=ValidationLevel.L2,
        translation_artifact=SimpleNamespace(fragment_id="fragment-1", shell_facts_identity=_digest("stale")),
        source_observation=_observation(raw, "source"), target_observation=_observation(raw, "target"),
        comparison_policy=L2_OPERAND_COMPARISON_POLICY,
    )
    assert stale.status is ValidationStatus.FAILED


def test_missing_observations_are_inconclusive_not_success(tmp_path):
    raw = _sidecar()
    path = tmp_path / "operand-sidecar.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    result = run_l2_operand_differential(
        L2OperandRunnerConfig(str(path)), level=ValidationLevel.L2,
        source_observation=None, target_observation=None,
        comparison_policy=L2_OPERAND_COMPARISON_POLICY,
    )
    assert result.status is ValidationStatus.INCONCLUSIVE


def test_runtime_registry_builds_the_only_registered_l2_route(tmp_path):
    raw = _sidecar()
    path = tmp_path / "operand-sidecar.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    registry = validation_runtime_registry_from_dict({
        "schemaVersion": VALIDATION_RUNTIME_REGISTRY_SCHEMA, "version": "registry-v1",
        "validators": {"L2": {"type": "l2-logical-operand-differential", "config": {
            "schemaVersion": L2_OPERAND_RUNNER_SCHEMA,
            "authoritySidecarPath": str(path),
            "comparisonPolicy": L2_OPERAND_COMPARISON_POLICY,
        }}},
    })
    assert registry.validator_for(ValidationLevel.L2) is not None
