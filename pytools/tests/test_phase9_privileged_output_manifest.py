"""Phase-9 privileged output manifest validation."""
from dataclasses import replace

from riscv2x86_py.plan_types import TargetLoweringKind
from riscv2x86_py.schema import Finding
from riscv2x86_py.privileged_functional_contracts import (
    PrivilegedFunctionalFallbackRegistry,
)
from riscv2x86_py.privileged_output_manifest import (
    PRIVILEGED_OUTPUT_MANIFEST_SCHEMA,
    finalize_privileged_output_manifest,
)
from riscv2x86_py.privileged_runtime_contracts import (
    PrivilegedRuntimeRegistry,
)
from riscv2x86_py.translate import translate
from tests.test_phase6_privileged_functional_fallback import (
    _environment as functional_environment,
    _registry as functional_registry,
)
from tests.test_phase6_privileged_runtime_contract import (
    _environment as strict_environment,
)
from tests.test_phase6a_privileged_state_adapter import _counter_inputs
from tests.test_phase6f_privileged_runtime_renderer import (
    _approved_strict,
    _renderer_registry,
)
from tests.test_phase6_rv64_add_contract import _IngressLift


def _translate_inputs():
    fragment, block, cfg, summary, state, observability, facts = (
        _counter_inputs()
    )
    return {
        "frag": fragment,
        "lift": _IngressLift(),
        "summary": summary,
        "machine_code": b"\0\0\0\0",
        "xlen": 64,
        "blocks": (block,),
        "cfg": cfg,
        "runtime_facts": facts,
        "privileged_state": state,
        "functional_observability": observability,
    }


def test_phase5_preserves_authoritative_target_execution_profile():
    state = _counter_inputs()[4]

    assert state.execution_profile.value == "riscv_user_process"
    assert state.target_execution_mode.value == "x86_user_process"


def test_strict_output_manifest_contains_contract_proof_and_dependencies():
    _source, environment, contract, registry, _approved = _approved_strict()
    renderer_manifest, renderer_registry = _renderer_registry(
        contract,
        registry,
        TargetLoweringKind.COUNTER_OBSERVATION_ADAPTER,
    )

    output = translate(
        **_translate_inputs(),
        target_environment=environment,
        privileged_runtime_registry=registry,
        renderer_contract_registry=renderer_registry,
    )
    manifest = output.metadata["privilegedOutputManifest"]

    assert output.kind == "privileged_runtime"
    assert manifest["schemaVersion"] == PRIVILEGED_OUTPUT_MANIFEST_SCHEMA
    assert manifest["status"] == "emitted"
    assert manifest["sourceExecutionProfile"] == "riscv_user_process"
    assert manifest["targetExecutionProfile"] == "x86_user_process"
    assert manifest["semanticContractId"] == contract.semantic_contract_id
    assert manifest["semanticContractVersion"] == contract.semantic_version
    assert manifest["sourceRegistryVersion"] == registry.version
    assert manifest["rendererManifestId"] == renderer_manifest.manifest_id
    assert manifest["preservationConclusion"] == "architecture_equivalent"
    assert manifest["ignoredStateIds"] == []
    assert manifest["proof"]["identity"].startswith("sha256:")
    assert manifest["proof"]["constraintsId"]
    assert manifest["runtimeDependencies"]["callableIdentifier"] == (
        contract.runtime_symbol
    )
    assert manifest["runtimeDependencies"]["requiredHeaders"] == [
        "riscv2x86_privileged_runtime.h"
    ]
    assert manifest["runtimeDependencies"]["requiredLibraries"] == [
        "riscv2x86_privileged_runtime"
    ]
    assert manifest["diagnostics"] == []
    assert manifest["complete"] is True


def test_functional_output_manifest_records_downgrade_and_ignored_state():
    inputs = _translate_inputs()
    source, environment, _strict, _strict_registry, _approved = (
        _approved_strict()
    )
    environment = functional_environment()
    contract, _ = functional_registry(source, environment)
    contract = replace(
        contract,
        result_operand_indexes=(0,),
        required_headers=("riscv2x86_functional.h",),
        required_library="riscv2x86_functional",
    )
    registry = PrivilegedFunctionalFallbackRegistry(
        version="phase9-functional-registry.v1",
        contracts=(contract,),
    )
    _renderer_manifest, renderer_registry = _renderer_registry(
        contract,
        registry,
        TargetLoweringKind.PRIVILEGED_FUNCTIONAL_FALLBACK,
    )

    output = translate(
        **inputs,
        target_environment=environment,
        privileged_functional_registry=registry,
        renderer_contract_registry=renderer_registry,
        allow_functional_fallbacks=True,
    )
    manifest = output.metadata["privilegedOutputManifest"]

    assert output.kind == "functional_c"
    assert manifest["status"] == "emitted"
    assert manifest["preservationConclusion"] == (
        "functional_equivalence_only"
    )
    assert manifest["ignoredStateIds"] == list(contract.ignored_state_ids)
    assert manifest["semanticContractId"] == contract.semantic_contract_id
    assert manifest["runtimeDependencies"]["requiredLibraries"] == [
        "riscv2x86_functional"
    ]
    assert manifest["proof"]["identity"].startswith("sha256:")
    assert manifest["complete"] is True


def test_unsupported_privileged_output_has_structured_diagnostics():
    output = translate(
        **_translate_inputs(),
        target_environment=strict_environment(),
    )
    manifest = output.metadata["privilegedOutputManifest"]

    assert output.kind == "unsupported"
    assert manifest["status"] == "unsupported"
    assert manifest["preservationConclusion"] == "not_preserved"
    assert manifest["semanticContractId"] is None
    assert manifest["proof"] is None
    assert manifest["runtimeDependencies"] == {
        "callableIdentifier": None,
        "requiredHeaders": [],
        "requiredLibraries": [],
    }
    assert manifest["diagnostics"]
    assert any(
        item["reasonCode"]
        == "phase6c.privileged_runtime_registry_missing"
        for item in manifest["diagnostics"]
    )
    assert manifest["complete"] is False


def test_manifest_survives_finding_report_serialization():
    output = translate(
        **_translate_inputs(),
        target_environment=strict_environment(),
    )
    finding = Finding(
        privilegedOutputManifest=output.metadata[
            "privilegedOutputManifest"
        ],
    )

    serialized = finding.to_dict()

    assert serialized["privilegedOutputManifest"] == (
        output.metadata["privilegedOutputManifest"]
    )
    assert serialized["privilegedOutputManifest"]["diagnostics"]


def test_phase8_rejection_finalizes_manifest_as_structured_unsupported():
    output = translate(
        **_translate_inputs(),
        target_environment=strict_environment(),
    )
    original = output.metadata["privilegedOutputManifest"]

    finalized = finalize_privileged_output_manifest(
        original,
        verification_status="failed",
        verification_detail="target build failed",
        accepted=False,
    )

    assert finalized["status"] == "unsupported"
    assert finalized["complete"] is False
    assert finalized["verification"] == {
        "status": "failed",
        "detail": "target build failed",
    }
    assert any(
        item["reasonCode"] == "privileged-output.validation-rejected"
        and item["stage"] == "phase8"
        for item in finalized["diagnostics"]
    )
