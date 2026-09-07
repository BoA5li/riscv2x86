from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace

from riscv2x86_py.l1_differential import (
    CommandResult, HarnessObservation, L1RunnerConfig, ProcessObservation,
    compare_l1_observations, run_l1_differential,
)
from riscv2x86_py.translation_validation import ValidationLevel
from riscv2x86_py.validation_case import (
    ComparisonContract, INPUT_GENERATOR_VERSION, VALIDATION_CASE_SCHEMA,
)
from riscv2x86_py.validation_observation import CanonicalValue
from riscv2x86_py.validation_status import ValidationStatus


def _digest(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def _value(value: int) -> CanonicalValue:
    return CanonicalValue("u64", "0x%016x" % (value & ((1 << 64) - 1)), 64)


def _process(value=1, *, stdout="PASS\n", hidden="ignored"):
    harness = HarnessObservation(_value(value), (("ok", True),),
                                 (("out", _value(value)), ("hidden", _value(9))),
                                 (("buffer", "sha256:" + "1" * 64),),
                                 (("api", _value(value)),))
    return ProcessObservation(harness, 0, stdout, "", (("visible.bin", "sha256:" + "2" * 64),))


def test_l1_comparator_uses_only_declared_logical_observables():
    contract = ComparisonContract(True, True, True, True, True,
                                  ("out",), ("buffer",), ("api",), ("visible.bin",))
    assert compare_l1_observations(_process(), _process(), contract) == ()
    target = _process(); target = ProcessObservation(
        HarnessObservation(target.harness.return_value, target.harness.assertions,
                           (("out", _value(1)), ("hidden", _value(99))),
                           target.harness.memory_objects, target.harness.api_results),
        target.exit_code, target.stdout, target.stderr, target.files,
    )
    assert compare_l1_observations(_process(), target, contract) == ()
    assert compare_l1_observations(_process(), _process(2), contract) == (
        "returnValue", "exportedState", "apiResults",
    )


def _run(tmp_path: Path, mismatch: bool):
    source, target = tmp_path / "source.c", tmp_path / "target.c"
    source.write_text("int main(void){return 0;}", encoding="utf-8")
    target.write_text("int main(void){return 0;}", encoding="utf-8")
    case_path = tmp_path / "case.json"
    case_path.write_text(json.dumps({
        "schemaVersion": VALIDATION_CASE_SCHEMA, "testId": "add-1",
        "inputGenerator": INPUT_GENERATOR_VERSION, "seed": 7,
        "inputDomain": {"arguments": [{"name": "lhs", "type": "u64"}], "randomCases": 1},
        "comparison": {"returnValue": True, "exitCode": True,
                       "exportedState": ["out"]},
    }), encoding="utf-8")
    config = L1RunnerConfig(
        (str(case_path),), str(source), _digest(source), str(target), _digest(target),
        "riscv64-linux-gnu-gcc", "gcc", ("-march=rv64gc", "-mabi=lp64d", "-static"), (), "qemu-riscv64", "",
        str(tmp_path / "work"), str(tmp_path / "replay"), 10,
    )

    def runner(argv, cwd, timeout):
        if argv[-1] == "--version":
            return CommandResult(0, stdout=argv[0] + " version 1\n")
        if "-o" in argv:
            output = Path(argv[argv.index("-o") + 1]); output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(b"exe")
            return CommandResult(0)
        input_payload = json.loads(Path(argv[-2]).read_text(encoding="utf-8"))
        source_run = argv[0] == "qemu-riscv64"
        value = input_payload["arguments"]["lhs"] + (0 if source_run or not mismatch else 1)
        output = {
            "schemaVersion": "riscv2x86.l1-harness-output.v1", "testId": "add-1",
            "inputIdentity": input_payload["inputIdentity"],
            "returnValue": _value(value).to_dict(), "assertions": {"ok": True},
            "exportedState": {"out": _value(value).to_dict()},
            "memoryObjects": {}, "apiResults": {},
        }
        Path(argv[-1]).write_text(json.dumps(output), encoding="utf-8")
        return CommandResult(0)

    return run_l1_differential(
        config, validation_plan=SimpleNamespace(source_runner="qemu", target_runner="native", seed=7),
        target_environment={"sourceIsa": "rv64gc", "sourceAbi": "lp64d",
                            "targetIsa": "x86_64", "targetAbi": "sysv_amd64"},
        translation_artifact=SimpleNamespace(identity="sha256:" + "3" * 64),
        source_program_artifact=SimpleNamespace(artifact_digest="sha256:" + "4" * 64),
        target_program_artifact=SimpleNamespace(artifact_digest="sha256:" + "5" * 64),
        comparison_policy="riscv2x86.l1-observable-comparison.v1",
        command_runner=runner, tool_available=lambda _: True,
    )


def test_l1_runner_verifies_complete_replayable_domain(tmp_path):
    result = _run(tmp_path, False)
    assert result.level is ValidationLevel.L1
    assert result.status is ValidationStatus.VERIFIED
    assert result.evidence_identity.startswith("sha256:")


def test_l1_runner_fails_closed_and_saves_minimized_replay(tmp_path):
    result = _run(tmp_path, True)
    assert result.status is ValidationStatus.FAILED
    replays = list((tmp_path / "replay").glob("*.json"))
    assert len(replays) == 1
    replay = json.loads(replays[0].read_text(encoding="utf-8"))
    assert replay["schemaVersion"] == "riscv2x86.l1-failure-replay.v1"
    assert replay["minimization"] == "greedy-zero-1minimal-v1"
