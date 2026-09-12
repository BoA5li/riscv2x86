"""Contract tests for zero-configuration corpus evaluation."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import subprocess

import pytest

from riscv2x86_py import automatic_batch_cli as auto
from riscv2x86_py import automatic_validation as automatic_validation
from riscv2x86_py.automatic_validation import (
    _branch_domain_wrapper, _counter_domain_observation,
    _counter_domain_wrapper, _counter_relation_observation,
    _counter_relation_wrapper, _memory_object_observations,
    _memory_object_wrapper, _scalar_wrapper, build_auto_l1_validator,
)
from riscv2x86_py.runtime_dependency_binding import RuntimeBuildDependencies
from riscv2x86_py.translation_validation import (
    ProgramArtifact, TranslationArtifact, ValidationLevel,
)
from riscv2x86_py.validation_status import PreservationMode, ValidationStatus
from riscv2x86_py.translation_artifact_binding import translation_artifact_from_approval
from riscv2x86_py.translation_attempt import TranslationAttempt
from riscv2x86_py.schema import PublicationOutcome, TranslationOutcome, ValidationOutcome


def test_inventory_generates_translation_and_registered_l0_l1(tmp_path, monkeypatch):
    corpus = tmp_path / "corpus"; corpus.mkdir()
    (corpus / "add.c").write_text("unsigned long add(unsigned long a,unsigned long b){return a+b;}\n")
    frontend = tmp_path / "riscv2x86"; frontend.write_text("#!/bin/sh\n"); frontend.chmod(0o755)
    monkeypatch.setattr(auto, "inspect_entry_points", lambda source: (
        False, ({"name": "add", "arity": 2, "returnType": "unsigned long",
                 "parameterTypes": ["unsigned long", "unsigned long"]},),
    ))

    payload = auto.prepare_automatic_inventory(corpus, tmp_path / "inventory", frontend=frontend)
    descriptor = json.loads((tmp_path / "inventory/cases/add/riscv2x86-evaluation.json").read_text())
    request = descriptor["request"]

    assert payload["statisticsUnits"] == {
        "L1": "program", "translation": "fragment", "bootstrapCluster": "program",
    }
    assert request["translationCommand"]
    assert "@INPUT_ROOT@" not in json.dumps(request["translationCommand"])
    assert "${SOURCE_ROOT}/add.c" in request["translationCommand"]
    assert "${SOURCE_ROOT}" in request["translationCommand"]
    assert request["translationArtifacts"] == {}
    assert request["targetBuild"]["artifactKind"] == "shared_library"
    assert set(request["runtimeRegistryTemplate"]["validators"]) == {"L0", "L1"}
    assert request["runtimeRegistryTemplate"]["validators"]["L1"]["config"]["functions"][0]["name"] == "add"


def test_inventory_main_uses_executable_process_contract(tmp_path, monkeypatch):
    source = tmp_path / "main.c"; source.write_text("int main(void){return 0;}\n")
    frontend = tmp_path / "riscv2x86"; frontend.write_text("x"); frontend.chmod(0o755)
    monkeypatch.setattr(auto, "inspect_entry_points", lambda source: (True, ()))
    auto.prepare_automatic_inventory(source, tmp_path / "inventory", frontend=frontend)
    descriptor = next((tmp_path / "inventory/cases").rglob("riscv2x86-evaluation.json"))
    request = json.loads(descriptor.read_text())["request"]
    assert request["targetBuild"]["artifactKind"] == "executable"
    assert request["runtimeRegistryTemplate"]["validators"]["L1"]["config"]["mode"] == "main"


def test_scalar_harness_links_separate_translation_unit():
    wrapper = _scalar_wrapper([{"name": "jump", "arity": 2,
                                "returnType": "uint64_t",
                                "parameterTypes": ["uint64_t", "uint64_t"]}])
    assert '#include "' not in wrapper
    assert "uint64_t jump(uint64_t, uint64_t);" in wrapper
    assert "jump((uint64_t)v[i0],(uint64_t)v[i1])" in wrapper


def test_zero_argument_void_function_has_explicit_termination_observation():
    wrapper = _scalar_wrapper([{"name": "fence_call", "arity": 0,
                                "returnType": "void", "parameterTypes": []}])
    assert "void fence_call(void);" in wrapper
    assert 'fence_call(); printf("fence_call=completed\\n");' in wrapper


def test_counter_domain_harness_compares_relation_not_absolute_value():
    function = {"name": "read_time", "arity": 0,
                "returnType": "uint64_t", "parameterTypes": [],
                "counterReturnSemantics": "direct", "counterRelationOperator": ""}
    wrapper = _counter_domain_wrapper(function)
    assert "read_time(void);" in wrapper
    assert "current<previous" in wrapper
    assert "current>previous" in wrapper
    assert "first=%llu;last=%llu;monotonic=%d;advanced=%d" in wrapper
    source = _counter_domain_observation(
        "counter=read_time;samples=16;first=100;last=200;monotonic=1;advanced=1\n"
    )
    target = _counter_domain_observation(
        "counter=read_time;samples=16;first=9000;last=12000;monotonic=1;advanced=1\n"
    )
    assert source is not None and target is not None
    assert source["first"] != target["first"]
    assert source["monotonic"] == target["monotonic"] is True
    assert source["advanced"] == target["advanced"] is True


def test_counter_domain_observation_rejects_missing_or_duplicate_trace():
    line = "counter=f;samples=16;first=1;last=2;monotonic=1;advanced=1\n"
    assert _counter_domain_observation("") is None
    assert _counter_domain_observation(line + line) is None


def test_counter_domain_validator_accepts_relationally_equal_different_values(
        tmp_path, monkeypatch):
    source = tmp_path / "source.c"; source.write_text("source")
    target = tmp_path / "target.c"; target.write_text("target")
    digest = lambda path: "sha256:" + sha256(path.read_bytes()).hexdigest()
    config = {
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
            "counter=read_time;samples=16;first=100;last=200;monotonic=1;advanced=1\n", ""),
        subprocess.CompletedProcess([], 0,
            "counter=read_time;samples=16;first=9000;last=12000;monotonic=1;advanced=1\n", ""),
    ))
    monkeypatch.setattr(automatic_validation, "_run", lambda *args: next(outputs))
    monkeypatch.setattr(
        automatic_validation, "resolve_runtime_contracts",
        lambda ids: RuntimeBuildDependencies(),
    )
    translation = TranslationArtifact(
        "fragment", "model", "plan", "constraints", "proof",
        PreservationMode.FUNCTIONAL_EQUIVALENCE_ONLY, "shell",
        "riscv2x86_rt_monotonic_time_ns@v1", "v1", "recipe",
        (), "counter", "functional-runtime",
    )
    program = ProgramArtifact("program", str(tmp_path / "unused"), "executable", "sha256:" + "0" * 64)
    result = build_auto_l1_validator(config)(
        level=ValidationLevel.L1, translation_artifact=translation,
        source_program_artifact=program, target_program_artifact=program,
    )
    assert result.status is ValidationStatus.VERIFIED
    detail = json.loads(result.detail)
    assert detail["observationContract"] == "riscv2x86.time.monotonic-observation.v1"
    assert detail["source"]["counterDomain"]["first"] == 100
    assert detail["target"]["counterDomain"]["first"] == 9000
    assert detail["semanticLimitations"] == [
        "absolute-counter-values-not-cross-isa-comparable",
        "counter-epoch-frequency-resolution-and-rollover-not-equated",
    ]


def test_counter_relation_harness_observes_boolean_relation_result():
    function = {"name": "counter_progress", "arity": 0,
                "returnType": "uint64_t", "parameterTypes": [],
                "counterReturnSemantics": "relational",
                "counterRelationOperator": ">"}
    wrapper = _counter_relation_wrapper(function)
    assert "value>1" in wrapper
    assert "true_count" in wrapper
    assert _counter_relation_observation(
        "counter_relation=counter_progress;samples=16;true=16;boolean=1\n"
    ) == {"function": "counter_progress", "samples": 16,
          "trueCount": 16, "booleanResults": True}


def test_counter_relation_validator_accepts_proved_true_relation(tmp_path, monkeypatch):
    source = tmp_path / "source.c"; source.write_text("source")
    target = tmp_path / "target.c"; target.write_text("target")
    digest = lambda path: "sha256:" + sha256(path.read_bytes()).hexdigest()
    config = {
        "schemaVersion": "riscv2x86.auto-l1-runner.v3",
        "mode": "scalar-functions", "sourcePath": str(source),
        "sourceDigest": digest(source), "targetPath": str(target),
        "targetDigest": digest(target),
        "functions": [{"name": "progress", "arity": 0, "returnType": "uint64_t",
                       "parameterTypes": [], "counterReturnSemantics": "relational",
                       "counterRelationOperator": ">"}],
        "workDirectory": str(tmp_path / "work"), "replayDirectory": str(tmp_path / "replay"),
        "timeoutSeconds": 10, "qemuBinary": "qemu-riscv64", "seed": 7,
        "harnessPath": "", "harnessDigest": "", "harnessManifestPath": "",
        "harnessManifestDigest": "", "inputDomainId": "counter-relation-v1",
        "observationContract": "process-and-declared-return-values-v1",
        "observableDimensions": ["exit_code", "stderr", "stdout", "termination"],
        "semanticLimitations": [],
    }
    line = "counter_relation=progress;samples=16;true=16;boolean=1\n"
    outputs = iter((subprocess.CompletedProcess([], 0, "", ""),
                    subprocess.CompletedProcess([], 0, "", ""),
                    subprocess.CompletedProcess([], 0, line, ""),
                    subprocess.CompletedProcess([], 0, line, "")))
    monkeypatch.setattr(automatic_validation, "_run", lambda *args: next(outputs))
    monkeypatch.setattr(automatic_validation, "resolve_runtime_contracts",
                        lambda ids: RuntimeBuildDependencies())
    translation = TranslationArtifact(
        "fragment", "model", "plan", "constraints", "proof",
        PreservationMode.FUNCTIONAL_EQUIVALENCE_ONLY, "shell",
        "riscv2x86_rt_tsc_ticks@v1", "v1", "recipe", (), "counter", "runtime",
    )
    program = ProgramArtifact("program", str(tmp_path / "unused"), "executable",
                              "sha256:" + "0" * 64)
    result = build_auto_l1_validator(config)(
        level=ValidationLevel.L1, translation_artifact=translation,
        source_program_artifact=program, target_program_artifact=program,
    )
    assert result.status is ValidationStatus.VERIFIED
    detail = json.loads(result.detail)
    assert detail["source"]["counterRelation"]["trueCount"] == 16
    assert detail["harnessDigest"].startswith("sha256:")
    assert detail["harnessManifestDigest"].startswith("sha256:")


def test_counter_contract_without_direct_value_flow_is_inconclusive(tmp_path):
    source = tmp_path / "source.c"; source.write_text("source")
    target = tmp_path / "target.c"; target.write_text("target")
    digest = lambda path: "sha256:" + sha256(path.read_bytes()).hexdigest()
    config = {
        "schemaVersion": "riscv2x86.auto-l1-runner.v3", "mode": "scalar-functions",
        "sourcePath": str(source), "sourceDigest": digest(source),
        "targetPath": str(target), "targetDigest": digest(target),
        "functions": [{"name": "derived", "arity": 0, "returnType": "uint64_t",
                       "parameterTypes": [], "counterReturnSemantics": "unproved",
                       "counterRelationOperator": ""}],
        "workDirectory": str(tmp_path / "work"), "replayDirectory": str(tmp_path / "replay"),
        "timeoutSeconds": 10, "qemuBinary": "qemu-riscv64", "seed": 7,
        "harnessPath": "", "harnessDigest": "", "harnessManifestPath": "",
        "harnessManifestDigest": "", "inputDomainId": "domain-v1",
        "observationContract": "process-and-declared-return-values-v1",
        "observableDimensions": ["exit_code", "stderr", "stdout", "termination"],
        "semanticLimitations": [],
    }
    translation = TranslationArtifact(
        "fragment", "model", "plan", "constraints", "proof",
        PreservationMode.FUNCTIONAL_EQUIVALENCE_ONLY, "shell",
        "riscv2x86_rt_monotonic_time_ns@v1", "v1", "recipe", (), "counter", "runtime",
    )
    program = ProgramArtifact("program", str(tmp_path / "unused"), "executable",
                              "sha256:" + "0" * 64)
    result = build_auto_l1_validator(config)(
        level=ValidationLevel.L1, translation_artifact=translation,
        source_program_artifact=program, target_program_artifact=program,
    )
    assert result.status is ValidationStatus.INCONCLUSIVE
    assert json.loads(result.detail)["reasonCode"] == "L1_COUNTER_RETURN_VALUE_FLOW_UNPROVED"


def test_pure_pointer_load_harness_has_no_unused_scalar_vector():
    wrapper = _memory_object_wrapper([{
        "name": "load", "arity": 1, "returnType": "uint64_t",
        "parameterTypes": ["const uint64_t *"], "pointerParameters": [0],
    }])
    assert "static const uint64_t v[8]" not in wrapper


def test_compiler_ast_counter_return_classification_is_fail_closed():
    decl0 = {"kind": "DeclRefExpr", "referencedDecl": {"id": "v0"}}
    direct = {"kind": "FunctionDecl", "inner": [
        {"kind": "GCCAsmStmt", "inner": [decl0]},
        {"kind": "ReturnStmt", "inner": [decl0]},
    ]}
    assert auto._counter_return_semantics(direct) == {
        "counterReturnSemantics": "direct", "counterRelationOperator": "",
    }
    decl1 = {"kind": "DeclRefExpr", "referencedDecl": {"id": "v1"}}
    relational = {"kind": "FunctionDecl", "inner": [
        {"kind": "GCCAsmStmt", "inner": [decl0]},
        {"kind": "GCCAsmStmt", "inner": [decl1]},
        {"kind": "ReturnStmt", "inner": [{"kind": "BinaryOperator", "opcode": ">",
                                             "inner": [decl1, decl0]}]},
    ]}
    assert auto._counter_return_semantics(relational) == {
        "counterReturnSemantics": "relational", "counterRelationOperator": ">",
    }
    transformed = {"kind": "FunctionDecl", "inner": [
        {"kind": "GCCAsmStmt", "inner": [decl0]},
        {"kind": "ReturnStmt", "inner": [{"kind": "BinaryOperator", "opcode": "+",
                                             "inner": [decl0, {"kind": "IntegerLiteral"}]}]},
    ]}
    assert auto._counter_return_semantics(transformed)["counterReturnSemantics"] == "unproved"


def test_zero_argument_void_inventory_registers_bounded_l1_claim(tmp_path, monkeypatch):
    source = tmp_path / "fence.c"; source.write_text("void fence_call(void){}\n")
    frontend = tmp_path / "riscv2x86"; frontend.write_text("x"); frontend.chmod(0o755)
    monkeypatch.setattr(auto, "inspect_entry_points", lambda source: (
        False, ({"name": "fence_call", "arity": 0, "returnType": "void",
                 "parameterTypes": []},),
    ))
    auto.prepare_automatic_inventory(source, tmp_path / "inventory", frontend=frontend)
    descriptor = next((tmp_path / "inventory/cases").rglob("riscv2x86-evaluation.json"))
    config = json.loads(descriptor.read_text())["request"]["runtimeRegistryTemplate"]["validators"]["L1"]["config"]
    assert config["observationContract"] == "process-and-declared-return-values-v1"
    assert config["semanticLimitations"] == [
        "memory-order-and-microarchitecture-not-observed-by-l1",
        "undeclared-memory-and-global-side-effects-not-observed-by-l1",
    ]


def test_memory_object_harness_observes_return_and_complete_post_state():
    wrapper = _memory_object_wrapper([
        {"name": "load_offset", "arity": 1, "returnType": "uint64_t",
         "parameterTypes": ["const uint64_t *"], "pointerParameters": [0]},
        {"name": "store_offset", "arity": 2, "returnType": "void",
         "parameterTypes": ["uint64_t *", "uint64_t"], "pointerParameters": [0]},
    ])
    assert "uint64_t load_offset(const uint64_t *);" in wrapper
    assert "void store_offset(uint64_t *, uint64_t);" in wrapper
    assert "load_offset((const uint64_t *)object)" in wrapper
    assert "store_offset((uint64_t *)object,(uint64_t)v[i0]);" in wrapper
    assert 'dump_object("load_offset:object",object);' in wrapper
    assert 'dump_object("store_offset:object",object);' in wrapper
    observations = _memory_object_observations(
        "store_offset:return=0000000000000000\n"
        "store_offset:object=[1122334455667788,8877665544332211,"
        "0000000000000001,fedcba9876543210]\n"
    )
    assert observations == [{
        "objectId": "store_offset:arg-object", "order": 1,
        "values": ["0x1122334455667788", "0x8877665544332211",
                   "0x0000000000000001", "0xfedcba9876543210"],
    }]


def test_pointer_inventory_registers_memory_object_l1_contract(tmp_path, monkeypatch):
    source = tmp_path / "load.c"
    source.write_text("#include <stdint.h>\nuint64_t load(const uint64_t *p){return p[1];}\n")
    frontend = tmp_path / "riscv2x86"; frontend.write_text("x"); frontend.chmod(0o755)
    function = {"name": "load", "arity": 1, "returnType": "uint64_t",
                "parameterTypes": ["const uint64_t *"], "pointerParameters": [0]}
    monkeypatch.setattr(auto, "inspect_entry_points", lambda source: (False, (function,)))

    payload = auto.prepare_automatic_inventory(source, tmp_path / "inventory", frontend=frontend)
    descriptor = next((tmp_path / "inventory/cases").rglob("riscv2x86-evaluation.json"))
    config = json.loads(descriptor.read_text())["request"]["runtimeRegistryTemplate"]["validators"]["L1"]["config"]
    assert payload["programs"][0]["harnessMode"] == "memory-object-functions"
    assert config["mode"] == "memory-object-functions"
    assert config["inputDomainId"] == "aligned-memory-object-boundary-v1"
    assert config["observationContract"] == "process-declared-return-and-memory-objects-v1"
    assert config["observableDimensions"] == [
        "declared_memory_objects", "exit_code", "stderr", "stdout", "termination",
    ]
    assert config["semanticLimitations"] == [
        "aliasing-and-overlap-not-observed-by-automatic-l1",
        "unaligned-and-out-of-bounds-access-not-observed-by-automatic-l1",
    ]


def test_four_argument_inventory_registers_branch_domain_l1_contract(tmp_path, monkeypatch):
    source = tmp_path / "branch.c"
    source.write_text("#include <stdint.h>\nuint64_t branch(uint64_t a,uint64_t b,uint64_t x,uint64_t y){return a==b?x:y;}\n")
    frontend = tmp_path / "riscv2x86"; frontend.write_text("x"); frontend.chmod(0o755)
    function = {"name": "branch", "arity": 4, "returnType": "uint64_t",
                "parameterTypes": ["uint64_t"] * 4, "pointerParameters": []}
    monkeypatch.setattr(auto, "inspect_entry_points", lambda source: (False, (function,)))

    payload = auto.prepare_automatic_inventory(source, tmp_path / "inventory", frontend=frontend)
    descriptor = next((tmp_path / "inventory/cases").rglob("riscv2x86-evaluation.json"))
    config = json.loads(descriptor.read_text())["request"]["runtimeRegistryTemplate"]["validators"]["L1"]["config"]
    assert payload["programs"][0]["harnessMode"] == "branch-domain-functions"
    assert config["mode"] == "branch-domain-functions"
    assert config["inputDomainId"] == "branch-four-argument-boundaries-v1"
    assert config["semanticLimitations"] == [
        "control-flow-event-trace-not-observed-by-l1",
    ]


def test_branch_domain_harness_covers_equal_unequal_and_width_boundaries():
    wrapper = _branch_domain_wrapper([{
        "name": "branch", "arity": 4, "returnType": "uint64_t",
        "parameterTypes": ["uint64_t"] * 4, "pointerParameters": [],
    }])
    assert wrapper.count("branch((uint64_t)") == 11
    assert "(uint64_t)(0),(uint64_t)(0)" in wrapper
    assert "(uint64_t)(0),(uint64_t)(1)" in wrapper
    assert "UINT64_C(0x8000000000000000)" in wrapper
    assert "case=10:return=%016llx" in wrapper


def test_explicit_harness_precedes_automatic_signature_limits(tmp_path, monkeypatch):
    corpus = tmp_path / "corpus"; corpus.mkdir()
    source = corpus / "branch.c"
    source.write_text("unsigned long branch(unsigned long a,unsigned long b,unsigned long c,unsigned long d);\n")
    harness_root = tmp_path / "harnesses"; harness_root.mkdir()
    harness = harness_root / "branch.harness.c"
    harness.write_text("int main(void){return 0;}\n")
    manifest = harness_root / "branch.harness.json"
    manifest.write_text(json.dumps({
        "schemaVersion": "riscv2x86.explicit-harness.v1",
        "sourceRelativePath": "branch.c",
        "harnessPath": "branch.harness.c",
        "inputDomainId": "branch-four-argument-boundaries-v1",
    }))
    frontend = tmp_path / "riscv2x86"; frontend.write_text("x"); frontend.chmod(0o755)
    monkeypatch.setattr(auto, "inspect_entry_points", lambda source: (_ for _ in ()).throw(
        ValueError("automatic scalar harness arity exceeded")))

    payload = auto.prepare_automatic_inventory(
        corpus, tmp_path / "inventory", frontend=frontend,
        harness_directory=harness_root,
    )
    descriptor = json.loads((tmp_path / "inventory/cases/branch/riscv2x86-evaluation.json").read_text())
    config = descriptor["request"]["runtimeRegistryTemplate"]["validators"]["L1"]["config"]
    assert payload["programs"][0]["validationProfile"] == "functional"
    assert payload["programs"][0]["harnessMode"] == "explicit-common-harness"
    assert config["schemaVersion"] == "riscv2x86.auto-l1-runner.v3"
    assert config["mode"] == "explicit-common-harness"
    assert config["harnessPath"] == str(harness.resolve())
    assert config["harnessDigest"].startswith("sha256:")
    assert config["harnessManifestDigest"].startswith("sha256:")
    assert config["observableDimensions"] == ["exit_code", "stderr", "stdout", "termination"]


def test_explicit_harness_cannot_escape_manifest_directory(tmp_path, monkeypatch):
    corpus = tmp_path / "corpus"; corpus.mkdir()
    (corpus / "case.c").write_text("int f(void){return 0;}\n")
    outside = tmp_path / "outside.c"; outside.write_text("int main(void){return 0;}\n")
    (corpus / "case.harness.json").write_text(json.dumps({
        "schemaVersion": "riscv2x86.explicit-harness.v1",
        "sourceRelativePath": "case.c", "harnessPath": "../outside.c",
        "inputDomainId": "domain-v1",
    }))
    frontend = tmp_path / "riscv2x86"; frontend.write_text("x"); frontend.chmod(0o755)
    with pytest.raises(ValueError, match="escapes"):
        auto.prepare_automatic_inventory(corpus, tmp_path / "inventory", frontend=frontend)


def test_no_safe_function_stops_at_build_profile(tmp_path, monkeypatch):
    source = tmp_path / "pointer.c"; source.write_text("int f(int *p){return *p;}\n")
    frontend = tmp_path / "riscv2x86"; frontend.write_text("x"); frontend.chmod(0o755)
    monkeypatch.setattr(auto, "inspect_entry_points", lambda source: (_ for _ in ()).throw(
        ValueError("no safe scalar function")))
    payload = auto.prepare_automatic_inventory(source, tmp_path / "inventory", frontend=frontend)
    assert payload["programs"][0]["inspectionError"]
    descriptor = next((tmp_path / "inventory/cases").rglob("riscv2x86-evaluation.json"))
    request = json.loads(descriptor.read_text())["request"]
    assert set(request["runtimeRegistryTemplate"]["validators"]) == {"L0"}


def test_typed_artifact_is_derived_only_from_matching_approval():
    approval = {"proofStatus": "approved", "sourceFragmentId": "fragment",
                "sourceModelId": "model", "planId": "plan", "constraintsId": "constraints",
                "targetEnvironmentId": "environment", "rendererId": "renderer",
                "rendererVersion": "v1", "rendererContractId": "recipe",
                "preservationMode": "architecture_equivalent", "shellFactsIdentity": "sha256:" + "1" * 64,
                "runtimeContractId": "runtime", "runtimeContractVersion": "v1",
                "recipeId": "recipe", "ignoredSourceState": [], "semanticClass": "integer",
                "targetRoute": "x86_inline_asm"}
    attempt = TranslationAttempt(
        "finding:0:fragment", "fragment", "x86", "route", "asm(\"nop\");",
        "sha256:2db1a8ef844cb56c5b93c72cb30123f85c20a946ec2d600b1dce8ab61ae8266d",
        "rule", TranslationOutcome.EMITTED, ValidationOutcome.NOT_RUN,
        PublicationOutcome.NOT_REQUESTED, (), "model", "decision", "plan", "constraints",
        "approved", "sha256:" + "2" * 64, "environment", "renderer", "v1", "recipe",
        "registry", "v1", True,
    )
    artifact = translation_artifact_from_approval(attempt, approval)
    assert artifact.fragment_id == "fragment"
    broken = dict(approval); broken["planId"] = "other"
    with pytest.raises(ValueError, match="binding mismatch"):
        translation_artifact_from_approval(attempt, broken)


def test_typed_artifact_derives_validation_fields_from_legacy_phase6_binding():
    replacement = 'asm("nop");'
    attempt = TranslationAttempt(
        "finding:0:fragment", "fragment", "x86_inline_asm", "phase6f_rendered",
        replacement, "sha256:2db1a8ef844cb56c5b93c72cb30123f85c20a946ec2d600b1dce8ab61ae8266d",
        "rule", TranslationOutcome.EMITTED, ValidationOutcome.NOT_RUN,
        PublicationOutcome.NOT_REQUESTED, (), "model", "decision", "plan", "constraints",
        "approved", "sha256:" + "2" * 64, "environment", "renderer", "v1", "recipe",
        "registry", "v1", True,
    )
    approval = {"proofStatus": "approved", "sourceFragmentId": "fragment",
                "sourceModelId": "model", "planId": "plan", "constraintsId": "constraints",
                "targetEnvironmentId": "environment", "rendererId": "renderer",
                "rendererVersion": "v1", "rendererContractId": "recipe"}
    artifact = translation_artifact_from_approval(attempt, approval)
    assert artifact.preservation_mode.value == "architecture_equivalent"
    assert artifact.runtime_contract_id == "riscv2x86.runtime.none"
    assert artifact.shell_facts_identity.startswith("sha256:")


def test_evaluation_artifact_does_not_require_publication_complete_binding():
    replacement = 'asm("nop");'
    attempt = TranslationAttempt(
        "finding:0:fragment", "fragment", "x86_inline_asm", "phase6f_rendered",
        replacement, "sha256:2db1a8ef844cb56c5b93c72cb30123f85c20a946ec2d600b1dce8ab61ae8266d",
        "rule", TranslationOutcome.EMITTED, ValidationOutcome.NOT_RUN,
        PublicationOutcome.NOT_REQUESTED, (), "model", "", "plan", "constraints",
        "approved", "sha256:" + "2" * 64, "", "renderer", "v1", "",
        "", "", False,
    )
    approval = {"proofStatus": "approved", "sourceFragmentId": "fragment",
                "sourceModelId": "model", "planId": "plan", "constraintsId": "constraints",
                "rendererId": "renderer", "rendererVersion": "v1"}

    assert attempt.evaluation_binding_complete
    assert not attempt.binding_complete
    artifact = translation_artifact_from_approval(attempt, approval)
    assert artifact.recipe_id.startswith("sha256:")


def test_functional_fallback_has_evaluation_binding_without_publication_approval():
    replacement = "riscv2x86_rt_instruction_stream_sync_local();"
    digest = "sha256:" + sha256(replacement.encode()).hexdigest()
    attempt = TranslationAttempt(
        "finding:0:fragment", "fragment", "functional_c", "runtime-helper",
        replacement, digest, "rule", TranslationOutcome.FUNCTIONAL_FALLBACK,
        ValidationOutcome.NOT_RUN, PublicationOutcome.NOT_REQUESTED, (),
        "model", "decision", "plan", "constraints", "functional_approved",
        "sha256:" + "2" * 64, "", "renderer", "v1", "", "", "", False,
    )
    approval = {
        "proofStatus": "functional_approved", "sourceFragmentId": "fragment",
        "sourceModelId": "model", "planId": "plan", "constraintsId": "constraints",
        "rendererId": "renderer", "rendererVersion": "v1",
        "preservationMode": "functional_equivalence_only",
        "runtimeContractId": "runtime", "runtimeContractVersion": "v1",
    }

    assert attempt.evaluation_binding_complete
    assert not attempt.binding_complete
    artifact = translation_artifact_from_approval(attempt, approval)
    assert artifact.preservation_mode.value == "functional_equivalence_only"


def test_functional_fallback_cannot_claim_architecture_preservation():
    replacement = "helper();"
    digest = "sha256:" + sha256(replacement.encode()).hexdigest()
    attempt = TranslationAttempt(
        "finding:0:fragment", "fragment", "functional_c", "runtime-helper",
        replacement, digest, "rule", TranslationOutcome.FUNCTIONAL_FALLBACK,
        ValidationOutcome.NOT_RUN, PublicationOutcome.NOT_REQUESTED, (),
        "model", "decision", "plan", "constraints", "functional_approved",
        "sha256:" + "2" * 64, "", "renderer", "v1", "", "", "", False,
    )
    approval = {
        "proofStatus": "functional_approved", "sourceFragmentId": "fragment",
        "sourceModelId": "model", "planId": "plan", "constraintsId": "constraints",
        "rendererId": "renderer", "rendererVersion": "v1",
        "preservationMode": "architecture_equivalent",
    }
    with pytest.raises(ValueError, match="preservation mode"):
        translation_artifact_from_approval(attempt, approval)
