from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from types import SimpleNamespace

import pytest

from riscv2x86_py.validation_observation import (
    OBSERVATION_CANONICALIZER_VERSION, CanonicalValue, EffectRelation,
    ExecutionObservation, ExecutionResult, LogicalOperandObservation,
    MemoryObjectObservation, ObservationProvenance, RunnerCommandProfile,
    SemanticEvent, TextObservation, ToolIdentity,
    canonicalize_observation_input, validation_identity,
)
from riscv2x86_py.validation_status import PreservationMode


def _digest(value):
    return "sha256:" + sha256(value.encode()).hexdigest()


def _tool(name):
    return ToolIdentity(name, "v1", _digest(name))


def _value(number=42):
    return CanonicalValue("u64", f"0x{number:016x}", 64)


def _observation(stdout="PASS\n", relations=()):
    shell = _digest("shell")
    return ExecutionObservation(
        "case-1", ("fragment-1",), _tool("qemu"), _tool("clang"),
        _tool("runtime-1"), _tool("loader-1"), "-O2", "none",
        "rv64gc-user", "x86_64-user", _digest("initial"),
        PreservationMode.FUNCTIONAL_EQUIVALENCE_ONLY,
        ExecutionResult(_value(), 0, TextObservation(stdout, _digest(stdout)),
                        TextObservation("", _digest("")), (("result", _value()),),
                        (("output.bin", _digest("file")),)),
        (LogicalOperandObservation("fragment-1", 0, "result", "operand:0", "output",
                                   64, "unsigned", False, shell, None, _value()),),
        (MemoryObjectObservation("arg:buffer", 8, _digest("memory")),),
        (
            SemanticEvent("event:0", 0, "fragment-1", "write_memory", "", _value(),
                          "arg:buffer", 0, 8, 8, "atomic", "release", None, "", "", ()),
            SemanticEvent("event:1", 1, "fragment-1", "branch", "loop", None,
                          "", None, 0, 0, "", "", True, "block:loop", "", ("event:0",)),
            SemanticEvent("event:2", 2, "fragment-1", "branch", "loop", None,
                          "", None, 0, 0, "", "", False, "block:exit", "", ("event:1",)),
        ),
        relations, (("csr:mstatus", _value(128)),), ("csr:cycle-rate",),
        ObservationProvenance(
            _digest("artifact"), _digest("manifest"), _digest("translation"),
            _digest("source-model"), _digest("proof"), shell, "runtime-contract", "v1", 7,
            _digest("inputs"), "functional-v1",
            RunnerCommandProfile("qemu-user", _digest("argv")),
        ),
    )


def test_v2_round_trip_preserves_ordered_repeated_events():
    observation = _observation()
    restored = ExecutionObservation.from_dict(observation.to_dict())
    assert restored == observation
    assert [x.branch_taken for x in restored.semantic_events[1:]] == [True, False]
    assert restored.semantic_events[2].ordering_predecessors == ("event:1",)
    assert restored.identity == observation.identity


def test_parser_rejects_instead_of_repairing_noncanonical_arrays():
    for mutate in (
        lambda value: value["fragmentIds"].append("fragment-1"),
        lambda value: value["ignoredState"].append("csr:cycle-rate"),
        lambda value: value["logicalOperands"].append(deepcopy(value["logicalOperands"][0])),
        lambda value: value["memoryObjects"].append(deepcopy(value["memoryObjects"][0])),
        lambda value: value["semanticEvents"].reverse(),
    ):
        raw = _observation().to_dict()
        mutate(raw)
        with pytest.raises(ValueError):
            ExecutionObservation.from_dict(raw)


def test_explicit_canonicalizer_records_version_and_never_reorders_events():
    raw = _observation().to_dict()
    raw["ignoredState"] = ["z", "a", "z"]
    raw["semanticEvents"].reverse()
    converted = canonicalize_observation_input(raw, version=OBSERVATION_CANONICALIZER_VERSION)
    assert converted["ignoredState"] == ["a", "z"]
    assert [x["eventId"] for x in converted["semanticEvents"]] == ["event:2", "event:1", "event:0"]
    assert converted["provenance"]["canonicalizerVersion"] == OBSERVATION_CANONICALIZER_VERSION


def test_memory_event_records_value_order_memory_order_and_fragment():
    event = _observation().semantic_events[0]
    assert (event.event_id, event.sequence, event.fragment_id) == ("event:0", 0, "fragment-1")
    assert (event.value, event.memory_order, event.ordering_predecessors) == (_value(), "release", ())


def test_effect_relation_maps_one_source_effect_to_multiple_target_effects():
    target = _observation(relations=(
        EffectRelation("source:0", ("event:0", "event:1"), "strengthened"),
    ))
    source = _observation()
    source_events = list(source.semantic_events)
    source_events[0] = replace(source_events[0], event_id="source:0")
    source_events[1] = replace(source_events[1], ordering_predecessors=("source:0",))
    source = replace(source, semantic_events=tuple(source_events))
    target.validate_effect_relations(source)


def test_structured_provenance_binds_translation_artifact_and_shell_facts():
    observation = _observation()
    artifact = SimpleNamespace(
        fragment_id="fragment-1", source_model_identity=_digest("source-model"),
        proof_identity=_digest("proof"), shell_facts_identity=_digest("shell"),
        runtime_contract_id="runtime-contract", runtime_contract_version="v1",
        preservation_mode=PreservationMode.FUNCTIONAL_EQUIVALENCE_ONLY,
    )
    observation.validate_translation_artifact(artifact)
    artifact.proof_identity = _digest("different")
    with pytest.raises(ValueError): observation.validate_translation_artifact(artifact)


def test_pointer_and_validation_identity_are_stable():
    pointer = CanonicalValue("ptr", object_id="arg:buffer", offset=64)
    assert pointer.to_dict()["objectId"] == "arg:buffer"
    args = dict(source_artifact_hash=_digest("source"), target_artifact_hash=_digest("target"),
                translation_manifest_hash=_digest("manifest"), source_model_identity=_digest("source-model"),
                runtime_contract="runtime-contract", runtime_version="v1", comparison_policy="functional-v1")
    one = validation_identity(**args, source_observation=_observation(), target_observation=_observation())
    two = validation_identity(**args, source_observation=_observation(), target_observation=_observation())
    assert one == two
