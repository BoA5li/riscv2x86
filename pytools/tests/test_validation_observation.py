from hashlib import sha256

from riscv2x86_py.validation_observation import (
    CanonicalValue,
    ExecutionObservation,
    ExecutionResult,
    LogicalOperandObservation,
    MemoryObjectObservation,
    TextObservation,
    validation_identity,
)
from riscv2x86_py.validation_status import PreservationMode


def _digest(value):
    return "sha256:" + sha256(value.encode()).hexdigest()


def _observation(stdout="PASS\n"):
    return ExecutionObservation(
        test_id="case-1", fragment_ids=("fragment-1",),
        runner="qemu", runner_version="qemu-v1", compiler="clang",
        compiler_version="18", optimization="-O2", sanitizer="none",
        source_execution_profile="rv64gc-user", target_execution_mode="x86_64-user",
        runtime_version="runtime-v1", initial_state_identity="initial:1",
        preservation_mode=PreservationMode.FUNCTIONAL_EQUIVALENCE_ONLY,
        result=ExecutionResult(
            CanonicalValue("i64", "0x000000000000002a", 64), 0,
            TextObservation(stdout, _digest(stdout)), TextObservation("", _digest("")),
            (("result", CanonicalValue("u64", "0x000000000000002a", 64)),),
            (("output.bin", _digest("file")),),
        ),
        logical_operands=(LogicalOperandObservation("operand:0", "output", None, CanonicalValue("u64", "0x000000000000002a", 64)),),
        memory_objects=(MemoryObjectObservation("arg:buffer", 8, _digest("memory"), ((0, "write", 8, 8, "none"),)),),
        control_flow=(("continuation", "return"),), traps=(("cause", "none"),),
        privileged_state=(("csr:mstatus", "0x80"),), external_events=(("event:0", "none"),),
        ignored_state=("csr:cycle-rate",),
        provenance=(
            ("artifactDigest", _digest("artifact")),
            ("comparisonPolicy", "functional-v1"),
            ("generatedInputsIdentity", _digest("inputs")),
            ("runnerCommandProfile", "qemu-user-v1"),
            ("runtimeContract", "counter-time"),
            ("runtimeContractVersion", "v1"),
            ("sourceModelIdentity", "source-model-1"),
            ("testSeed", "7"),
            ("translationManifestDigest", _digest("manifest")),
        ),
    )


def test_observation_round_trip_is_canonical_and_identity_is_stable():
    observation = _observation()
    restored = ExecutionObservation.from_dict(observation.to_dict())
    assert restored.to_dict() == observation.to_dict()
    assert restored.identity == observation.identity
    assert observation.result.to_dict()["stdoutSha256"] == _digest("PASS\n")


def test_pointer_observation_uses_logical_object_not_virtual_address():
    pointer = CanonicalValue("ptr", object_id="arg:buffer", offset=64)
    assert pointer.to_dict() == {"type": "ptr", "objectId": "arg:buffer", "offset": 64}


def test_validation_identity_changes_with_observation_or_policy():
    first, changed = _observation(), _observation("FAIL\n")
    args = dict(
        source_artifact_hash=_digest("source"), target_artifact_hash=_digest("target"),
        translation_manifest_hash=_digest("manifest"), source_model_identity="source-model-1",
        runtime_contract="counter-time", runtime_version="v1", comparison_policy="functional-v1",
    )
    one = validation_identity(**args, source_observation=first, target_observation=first)
    two = validation_identity(**args, source_observation=first, target_observation=first)
    three = validation_identity(**args, source_observation=first, target_observation=changed)
    assert one == two
    assert one != three
