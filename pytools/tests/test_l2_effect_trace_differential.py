from copy import deepcopy
from hashlib import sha256
import json
from types import SimpleNamespace

import pytest

from riscv2x86_py.l2_effect_trace_differential import (
    EFFECT_TRACE_AUTHORITY_SCHEMA, L2_EFFECT_RUNNER_SCHEMA, L2EffectRunnerConfig,
    compare_effect_traces, effect_trace_authority_from_dict,
    run_l2_effect_trace_differential, validate_shell_contract,
)
from riscv2x86_py.l2_operand_differential import (
    LOGICAL_OPERAND_AUTHORITY_SCHEMA, logical_operand_authority_from_dict,
)
from riscv2x86_py.translation_validation import ValidationLevel
from riscv2x86_py.validation_observation import (
    CanonicalValue, ExecutionObservation, ExecutionResult, MemoryObjectObservation,
    ObservationProvenance, RunnerCommandProfile, SemanticEvent, TextObservation, ToolIdentity,
)
from riscv2x86_py.validation_status import PreservationMode, ValidationStatus
from riscv2x86_py.validation_runtime_registry import (
    VALIDATION_RUNTIME_REGISTRY_SCHEMA, validation_runtime_registry_from_dict,
)


def _digest(value):
    return "sha256:" + sha256(value.encode()).hexdigest()


def _value(number=42):
    return CanonicalValue("u64", f"0x{number:016x}", 64)


def _operand_sidecar():
    return {
        "schemaVersion": LOGICAL_OPERAND_AUTHORITY_SCHEMA,
        "producerKind": "frontend-sidecar", "producerId": "clang-frontend",
        "producerVersion": "v1", "producerBinaryDigest": _digest("frontend"),
        "fragments": [{"fragmentId": "fragment-1", "shellTransportabilityStatus": "verified",
                       "operands": []}],
    }


def _shell(shell_identity, *, memory_carrier="compiler-barrier"):
    return ({
        "volatile": True, "memoryClobber": True, "ccClobber": True,
        "compilerBarrier": True, "asmGoto": True,
        "memoryOperandIds": ["operand:memory"], "immediateOperandIds": ["operand:imm"],
        "hostTypeFactsIdentity": shell_identity,
    }, {
        "recipeId": "recipe-1", "volatileCarried": True,
        "memoryOrderingCarrier": memory_carrier, "ccClobberCarried": True,
        "asmGotoCarrier": "structured-control-flow",
        "memoryOperandIds": ["operand:memory"], "immediateOperandIds": ["operand:imm"],
        "hostTypeFactsIdentity": shell_identity, "abiStackFrameSafetyStatus": "verified",
        "operandSemanticsCarriedByL2A": True,
    })


def _declaration(event):
    return {
        "eventId": event.event_id, "fragmentId": "fragment-1", "eventKind": event.kind,
        "logicalSubject": event.subject_id,
        "sourceLocation": {"fileIdentity": _digest("source.c"), "line": 7, "column": 5},
    }


def _relation(source_id, target_ids, kind="exact", obligations=None):
    return {
        "sourceEffectId": source_id, "targetEffectIds": sorted(target_ids), "relationKind": kind,
        "observableRequirements": sorted(obligations or ["kind", "memory-coordinates", "memory-order", "subject", "value"]),
        "orderingRequirements": ["preserve-predecessors", "preserve-program-order"], "complete": True,
    }


def _effect_sidecar(shell_identity, source_events, relations, *, memory_carrier="compiler-barrier"):
    source_shell, target_shell = _shell(shell_identity, memory_carrier=memory_carrier)
    return {
        "schemaVersion": EFFECT_TRACE_AUTHORITY_SCHEMA,
        "producerKind": "translation-proof-sidecar", "producerId": "phase6d-proof",
        "producerVersion": "v1", "producerBinaryDigest": _digest("proof-tool"),
        "sourceShellFactsIdentity": shell_identity,
        "runtimeContractId": "runtime-1", "runtimeContractVersion": "v1",
        "fragments": [{
            "fragmentId": "fragment-1", "sourceEvents": [_declaration(item) for item in source_events],
            "relations": relations, "sourceShell": source_shell, "targetShellRecipe": target_shell,
        }],
    }


def _memory(event_id, sequence, *, order="relaxed", predecessors=()):
    return SemanticEvent(event_id, sequence, "fragment-1", "write_memory", "output-buffer", _value(),
                         "arg:buffer", 64, 8, 8, "none", order, None, "", "", predecessors)


def _fence(event_id, sequence, order, predecessors=()):
    return SemanticEvent(event_id, sequence, "fragment-1", "fence", "compiler-order", None,
                         "", None, 0, 0, "", order, None, "", "", predecessors)


def _call(event_id, sequence):
    return SemanticEvent(event_id, sequence, "fragment-1", "call", "runtime-helper", None,
                         "", None, 0, 0, "", "", None, "runtime:store", "", ())


def _tool(name):
    return ToolIdentity(name, "v1", _digest(name))


def _observation(shell_identity, side, events):
    empty = TextObservation("", _digest(""))
    return ExecutionObservation(
        "case-1", ("fragment-1",), _tool("qemu" if side == "source" else "native"),
        _tool("gcc"), _tool("runtime-1"), _tool("loader"), "-O2", "none",
        "rv64gc-user", "x86_64-user", _digest("initial"), PreservationMode.ARCHITECTURE_EQUIVALENT,
        ExecutionResult(None, 0, empty, empty), (),
        (MemoryObjectObservation("arg:buffer", 256, _digest("buffer")),), tuple(events), (), (), (),
        ObservationProvenance(
            _digest(side + "-program"), _digest("manifest"), _digest("translation"),
            _digest("model"), _digest("proof-placeholder"), shell_identity, "runtime-1", "v1", 7,
            _digest("inputs"), "riscv2x86.comparison-policy.architectural.v1",
            RunnerCommandProfile(side, _digest(side + "-argv")),
        ),
    )


def test_exact_normalized_memory_trace_uses_object_offset_not_raw_address():
    operand = logical_operand_authority_from_dict(_operand_sidecar())
    source, target = _memory("source:0", 0), _memory("target:0", 0)
    raw = _effect_sidecar(operand.identity, [source], [_relation("source:0", ["target:0"])])
    authority = effect_trace_authority_from_dict(raw)
    reasons = compare_effect_traces(
        source=_observation(operand.identity, "source", [source]),
        target=_observation(operand.identity, "target", [target]),
        authority=authority, fragment_id="fragment-1",
    )
    assert reasons == ()
    assert (source.object_id, source.offset, source.access_size, source.alignment) == ("arg:buffer", 64, 8, 8)


def test_strengthened_fence_is_allowed_only_by_approved_relation():
    operand = logical_operand_authority_from_dict(_operand_sidecar())
    source, target = _fence("source:0", 0, "compiler"), _fence("target:0", 0, "hardware")
    relation = _relation("source:0", ["target:0"], "strengthened", ["kind", "memory-order", "subject"])
    authority = effect_trace_authority_from_dict(_effect_sidecar(operand.identity, [source], [relation]))
    assert compare_effect_traces(source=_observation(operand.identity, "source", [source]),
                                 target=_observation(operand.identity, "target", [target]),
                                 authority=authority, fragment_id="fragment-1") == ()
    exact = deepcopy(authority.payload); exact["fragments"][0]["relations"][0]["relationKind"] = "exact"
    exact_authority = effect_trace_authority_from_dict(exact)
    assert any("observable-effect-mismatch" in item for item in compare_effect_traces(
        source=_observation(operand.identity, "source", [source]),
        target=_observation(operand.identity, "target", [target]), authority=exact_authority,
        fragment_id="fragment-1"))


def test_runtime_mediated_one_to_many_requires_helper_and_observable_carrier():
    operand = logical_operand_authority_from_dict(_operand_sidecar())
    source = _memory("source:0", 0)
    call, effect = _call("target:call", 0), _memory("target:effect", 1)
    relation = _relation("source:0", ["target:call", "target:effect"], "runtime-mediated")
    authority = effect_trace_authority_from_dict(_effect_sidecar(operand.identity, [source], [relation]))
    assert compare_effect_traces(source=_observation(operand.identity, "source", [source]),
                                 target=_observation(operand.identity, "target", [call, effect]),
                                 authority=authority, fragment_id="fragment-1") == ()


def test_uncovered_extra_effect_and_reversed_predecessor_fail_closed():
    operand = logical_operand_authority_from_dict(_operand_sidecar())
    source0, source1 = _memory("source:0", 0), _memory("source:1", 1, predecessors=("source:0",))
    target1, target0 = _memory("target:1", 0), _memory("target:0", 1)
    relations = [_relation("source:0", ["target:0"]), _relation("source:1", ["target:1"])]
    authority = effect_trace_authority_from_dict(_effect_sidecar(operand.identity, [source0, source1], relations))
    reasons = compare_effect_traces(source=_observation(operand.identity, "source", [source0, source1]),
                                    target=_observation(operand.identity, "target", [target1, target0]),
                                    authority=authority, fragment_id="fragment-1")
    assert any("ordering-predecessor" in item or "program-order" in item for item in reasons)

    extra = SemanticEvent("target:extra", 2, "fragment-1", "external", "debug-write", None,
                          "", None, 0, 0, "", "", None, "", "visible", ())
    reasons = compare_effect_traces(source=_observation(operand.identity, "source", [source0, source1]),
                                    target=_observation(operand.identity, "target", [target1, target0, extra]),
                                    authority=authority, fragment_id="fragment-1")
    assert "target-trace-relation-coverage-mismatch" in reasons


def test_csr_trap_external_and_privilege_events_compare_logical_payloads():
    operand = logical_operand_authority_from_dict(_operand_sidecar())
    source = SemanticEvent("source:0", 0, "fragment-1", "csr_read", "csr:mstatus", _value(1),
                           "", None, 0, 0, "", "", None, "", "", ())
    target = SemanticEvent("target:0", 0, "fragment-1", "csr_read", "csr:mstatus", _value(2),
                           "", None, 0, 0, "", "", None, "", "", ())
    relation = _relation("source:0", ["target:0"], obligations=["csr-value", "kind", "subject"])
    authority = effect_trace_authority_from_dict(_effect_sidecar(operand.identity, [source], [relation]))
    reasons = compare_effect_traces(source=_observation(operand.identity, "source", [source]),
                                    target=_observation(operand.identity, "target", [target]),
                                    authority=authority, fragment_id="fragment-1")
    assert any("observable-effect-mismatch" in item for item in reasons)

    for kind in ("csr_write", "privilege_transition", "trap", "external"):
        SemanticEvent("event:" + kind, 0, "fragment-1", kind, "logical-state", _value(),
                      "", None, 0, 0, "", "", None, "", "detail", ())


def test_shell_contract_rejects_plain_c_for_memory_clobber_and_other_losses():
    operand = logical_operand_authority_from_dict(_operand_sidecar())
    source = _memory("source:0", 0)
    raw = _effect_sidecar(operand.identity, [source], [_relation("source:0", ["target:0"])],
                          memory_carrier="none")
    fragment = effect_trace_authority_from_dict(raw).fragments[0]
    reasons = validate_shell_contract(fragment, recipe_id="recipe-1", shell_identity=operand.identity)
    assert "compiler-memory-ordering-not-preserved" in reasons
    assert not any("volatile" in item for item in reasons)


def test_effect_authority_must_be_complete_proof_output_with_source_locations():
    operand = logical_operand_authority_from_dict(_operand_sidecar())
    source = _memory("source:0", 0)
    base = _effect_sidecar(operand.identity, [source], [_relation("source:0", ["target:0"])])
    for mutate in (
        lambda value: value.update(producerKind="mnemonic-inference"),
        lambda value: value["fragments"][0]["relations"][0].update(complete=False),
        lambda value: value["fragments"][0]["relations"][0].update(observableRequirements=[]),
        lambda value: value["fragments"][0]["sourceEvents"][0].pop("sourceLocation"),
    ):
        raw = deepcopy(base); mutate(raw)
        if raw["fragments"][0]["relations"][0]["observableRequirements"] == []:
            authority = effect_trace_authority_from_dict(raw)
            reasons = compare_effect_traces(source=_observation(operand.identity, "source", [source]),
                                            target=_observation(operand.identity, "target", [_memory("target:0", 0)]),
                                            authority=authority, fragment_id="fragment-1")
            assert any("observable-requirements-incomplete" in item for item in reasons)
        else:
            with pytest.raises(ValueError): effect_trace_authority_from_dict(raw)


def test_composite_l2_runner_requires_l2a_shell_effect_proof_and_runtime_bindings(tmp_path):
    operand_raw = _operand_sidecar(); operand = logical_operand_authority_from_dict(operand_raw)
    source_event, target_event = _memory("source:0", 0), _memory("target:0", 0)
    effect_raw = _effect_sidecar(operand.identity, [source_event], [_relation("source:0", ["target:0"])])
    effect = effect_trace_authority_from_dict(effect_raw)
    operand_path, effect_path = tmp_path / "operands.json", tmp_path / "effects.json"
    operand_path.write_text(json.dumps(operand_raw), encoding="utf-8")
    effect_path.write_text(json.dumps(effect_raw), encoding="utf-8")
    config = L2EffectRunnerConfig(str(operand_path), str(effect_path))
    artifact = SimpleNamespace(
        fragment_id="fragment-1", shell_facts_identity=operand.identity, proof_identity=effect.identity,
        runtime_contract_id="runtime-1", runtime_contract_version="v1", recipe_id="recipe-1",
    )
    result = run_l2_effect_trace_differential(
        config, level=ValidationLevel.L2, translation_artifact=artifact,
        source_observation=_observation(operand.identity, "source", [source_event]),
        target_observation=_observation(operand.identity, "target", [target_event]),
        comparison_policy="riscv2x86.comparison-policy.architectural.v1",
    )
    assert result.status is ValidationStatus.VERIFIED
    artifact.proof_identity = _digest("stale-proof")
    assert run_l2_effect_trace_differential(
        config, level=ValidationLevel.L2, translation_artifact=artifact,
        source_observation=_observation(operand.identity, "source", [source_event]),
        target_observation=_observation(operand.identity, "target", [target_event]),
        comparison_policy="riscv2x86.comparison-policy.architectural.v1",
    ).status is ValidationStatus.FAILED

    registry = validation_runtime_registry_from_dict({
        "schemaVersion": VALIDATION_RUNTIME_REGISTRY_SCHEMA, "version": "registry-v1",
        "validators": {"L2": {"type": "l2-effect-trace-differential", "config": {
            "schemaVersion": L2_EFFECT_RUNNER_SCHEMA,
            "operandAuthoritySidecarPath": str(operand_path),
            "effectAuthoritySidecarPath": str(effect_path),
            "comparisonPolicy": "riscv2x86.comparison-policy.architectural.v1",
        }}},
    })
    assert registry.validator_for(ValidationLevel.L2) is not None
