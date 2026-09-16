import json
from hashlib import sha256
import subprocess

from riscv2x86_py import automatic_validation
from riscv2x86_py.automatic_l2_functional_relation import (
    build_auto_l2_functional_relation_validator,
)
from riscv2x86_py.effect_relation import ApprovedEffectRelation
from riscv2x86_py.l2_authority import (
    L2AuthorityProducer, L2AuthoritySidecar, L2IgnoredStateAuthority,
    L2RuntimeContractBinding, L2SourceEffectAuthority,
)
from riscv2x86_py.runtime_dependency_binding import RuntimeBuildDependencies
from riscv2x86_py.translation_validation import (
    ProgramArtifact, TranslationArtifact, ValidationLevel,
)
from riscv2x86_py.validation_status import PreservationMode, ValidationStatus


def test_counter_functional_relation_is_l2_but_not_architectural(tmp_path, monkeypatch):
    source = tmp_path / "source.c"; source.write_text("source")
    target = tmp_path / "target.c"; target.write_text("target")
    digest = lambda path: "sha256:" + sha256(path.read_bytes()).hexdigest()
    l1 = {
        "schemaVersion": "riscv2x86.auto-l1-runner.v3",
        "mode": "scalar-functions", "sourcePath": str(source),
        "sourceDigest": digest(source), "targetPath": str(target),
        "targetDigest": digest(target),
        "functions": [{"name": "read_time", "arity": 0,
                       "returnType": "uint64_t", "parameterTypes": [],
                       "counterReturnSemantics": "direct",
                       "counterRelationOperator": ""}],
        "workDirectory": str(tmp_path / "work"),
        "replayDirectory": str(tmp_path / "replay"),
        "timeoutSeconds": 10, "qemuBinary": "qemu-riscv64", "seed": 7,
        "harnessPath": "", "harnessDigest": "",
        "harnessManifestPath": "", "harnessManifestDigest": "",
        "inputDomainId": "counter-sampling-v1",
        "observationContract": "process-and-declared-return-values-v1",
        "observableDimensions": ["exit_code", "stderr", "stdout", "termination"],
        "semanticLimitations": [],
    }
    outputs = iter((
        subprocess.CompletedProcess([], 0, "", ""),
        subprocess.CompletedProcess([], 0, "", ""),
        subprocess.CompletedProcess([], 0,
            "counter=read_time;samples=16;first=1;last=2;monotonic=1;advanced=1\n", ""),
        subprocess.CompletedProcess([], 0,
            "counter=read_time;samples=16;first=10;last=20;monotonic=1;advanced=1\n", ""),
    ))
    monkeypatch.setattr(automatic_validation, "_run", lambda *args: next(outputs))
    monkeypatch.setattr(automatic_validation, "resolve_runtime_contracts",
                        lambda ids: RuntimeBuildDependencies())
    contract_identity = "sha256:" + "2" * 64
    sidecar = L2AuthoritySidecar(
        "fragment", L2AuthorityProducer(
            "translation-proof-sidecar", "test", "v1", "sha256:" + "3" * 64),
        "sha256:" + "4" * 64, (), (),
        (L2SourceEffectAuthority("functional:privileged-state", "PrivilegedRead",
                                 "csr:declared", True),),
        (ApprovedEffectRelation(
            "relation:functional:privileged-state", "functional:privileged-state",
            ("target:functional:privileged-state",), "runtime_mediated",
            ("csr_value",), (), "riscv2x86_rt_monotonic_time_ns@v1", True),),
        (L2RuntimeContractBinding(
            "riscv2x86_rt_monotonic_time_ns@v1", "v1", contract_identity, True),),
        (L2IgnoredStateAuthority("csr:time:absolute-value", "test",
                                 "non_escaping", True),), True,
    )
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"findings": [{
        "fragment": {"id": "fragment"},
        "approvalArtifact": {"l2AuthoritySidecar": sidecar.to_dict()},
    }]}))
    artifact = TranslationArtifact(
        "fragment", "model", "plan", "constraint", "proof",
        PreservationMode.FUNCTIONAL_EQUIVALENCE_ONLY, "sha256:" + "4" * 64,
        "riscv2x86_rt_monotonic_time_ns@v1", "v1", "recipe", (),
        "counter", "runtime-helper", sidecar.authority_identity,
        sidecar.effect_relation_set_identity, True,
        l2_pattern_kind="privileged_read",
        l2_semantic_profile_identity="sha256:" + "1" * 64,
    )
    program = ProgramArtifact("program", "unused", "executable", "sha256:" + "0" * 64)
    validator = build_auto_l2_functional_relation_validator({
        "schemaVersion": "riscv2x86.auto-l2-functional-relation-runner.v1",
        "l1Config": l1,
        "translatedReport": str(report),
    })
    result = validator(level=ValidationLevel.L2, translation_artifact=artifact,
                       source_program_artifact=program, target_program_artifact=program)
    assert result.status is ValidationStatus.VERIFIED
    detail = json.loads(result.detail)
    assert detail["claimScope"] == "approved_functional_relation"
    assert "absolute-value-equivalence" in detail["notClaimedProperties"]
    assert detail["sourceObservationIdentity"] != detail["targetObservationIdentity"]
