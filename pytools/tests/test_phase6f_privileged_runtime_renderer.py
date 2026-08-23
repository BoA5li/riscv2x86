from dataclasses import replace
from types import SimpleNamespace

from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.phase6c_constraints import derive_target_constraints
from riscv2x86_py.phase6d_common import (
    CompilerCapabilityModel,
    TargetSemanticCatalog,
    run_semantic_proof_gate,
)
from riscv2x86_py.phase6e_selection import (
    Phase6ESelectionPolicy,
    Phase6ESelectionRequest,
    ProvenCandidate,
    select_final_target_lowering_plan,
)
from riscv2x86_py.phase6f_contract_registry import (
    EMPTY_RENDERER_CONTRACT_REGISTRY,
    register_privileged_renderer_manifest,
)
from riscv2x86_py.phase6f_renderer import (
    Phase6FRenderRequest,
    RenderedReplacementKind,
    RendererContext,
    render_approved_target_lowering,
)
from riscv2x86_py.plan_types import TargetLoweringKind
from riscv2x86_py.privileged_emitted_audit import (
    PRIVILEGED_EMITTED_TEXT_AUDIT_VERSION,
    audit_privileged_emitted_text,
)
from riscv2x86_py.privileged_functional_contracts import (
    PrivilegedFunctionalFallbackRegistry,
)
from riscv2x86_py.privileged_renderer_manifest import (
    PrivilegedRecipeKind,
    PrivilegedRendererManifest,
    PrivilegedRendererManifestEntry,
)
from riscv2x86_py.privileged_runtime_contracts import (
    PrivilegedRuntimeRegistry,
)
from tests.test_phase6_privileged_functional_fallback import (
    _environment as functional_environment,
    _policy,
    _registry as functional_registry,
)
from tests.test_phase6_privileged_runtime_contract import (
    _environment as strict_environment,
    _registry as strict_registry,
    _source_model,
)
from tests.test_phase6a_privileged_state_adapter import _counter_inputs
from tests.test_phase6_rv64_add_contract import _IngressLift


def _approved_strict():
    source = _source_model()
    environment = strict_environment()
    contract, _ = strict_registry(source, environment)
    contract = replace(
        contract,
        required_headers=("riscv2x86_privileged_runtime.h",),
        required_library="riscv2x86_privileged_runtime",
        result_operand_indexes=(0,),
    )
    registry = PrivilegedRuntimeRegistry(
        version="strict-render-registry.v1", contracts=(contract,)
    )
    plan = generate_candidate_plans(source)[0]
    derived = derive_target_constraints(
        source_model=source, candidate_plan=plan,
        target_environment=environment,
        privileged_runtime_registry=registry,
    )
    catalog = TargetSemanticCatalog(
        frozenset({plan.kind}), frozenset({contract.semantic_contract_id}),
        "strict-render-catalog.v1",
    )
    capability = CompilerCapabilityModel(True, False)
    proof = run_semantic_proof_gate(
        source_model=source, candidate_plan=plan,
        constraints=derived.constraints, target_environment=environment,
        target_semantic_catalog=catalog, compiler_capabilities=capability,
        privileged_runtime_registry=registry,
    )
    catalog_id = catalog.version + ":" + ",".join(catalog.semantic_contract_ids)
    selection = select_final_target_lowering_plan(Phase6ESelectionRequest(
        source_model=source, preservation_decision=source.preservation,
        target_environment=environment,
        candidates=(ProvenCandidate(plan, derived, proof),),
        generated_plan_ids=frozenset({plan.plan_id}),
        target_catalog_version=catalog_id,
        compiler_capability_id="asm=True;goto=False",
        privileged_registry_version=registry.version,
    ))
    return source, environment, contract, registry, selection.selected_plan


def _renderer_registry(contract, registry, plan_kind):
    manifest = PrivilegedRendererManifest(
        manifest_id="riscv2x86.test.privileged-renderers",
        version="1",
        entries=(PrivilegedRendererManifestEntry(
            semantic_contract_id=contract.semantic_contract_id,
            plan_kind=plan_kind,
            renderer_contract_id="privileged.counter.runtime-call.v1",
            recipe_kind=PrivilegedRecipeKind.RUNTIME_CALL,
            callable_identifier=(
                contract.runtime_symbol
                if plan_kind is TargetLoweringKind.COUNTER_OBSERVATION_ADAPTER
                else contract.implementation_id
            ),
            argument_operand_indexes=contract.argument_operand_indexes,
            result_operand_indexes=contract.result_operand_indexes,
            required_headers=contract.required_headers,
            required_libraries=(
                () if contract.required_library is None
                else (contract.required_library,)
            ),
            required_target_capability=contract.required_target_capability,
            target_environment_id=contract.target_environment_id,
            source_registry_version=registry.version,
        ),),
    )
    return manifest, register_privileged_renderer_manifest(
        EMPTY_RENDERER_CONTRACT_REGISTRY, manifest
    )


def test_strict_privileged_runtime_renders_registered_c_call_and_manifest():
    _source, environment, contract, registry, approved = _approved_strict()
    manifest, renderer_registry = _renderer_registry(
        contract, registry, TargetLoweringKind.COUNTER_OBSERVATION_ADAPTER
    )
    renderer_contract = renderer_registry.resolve(approved)
    assert renderer_contract is not None
    rendered = render_approved_target_lowering(Phase6FRenderRequest(
        approved, environment,
        RendererContext({approved.plan.plan_id: renderer_contract}, {0: "counter"}),
    ))
    assert rendered.kind is RenderedReplacementKind.PRIVILEGED_RUNTIME_ADAPTER
    assert rendered.emitted_text == (
        "counter = rv2x86_privileged_counter_time_v1();"
    )
    assert rendered.required_headers == ("riscv2x86_privileged_runtime.h",)
    assert rendered.required_libraries == ("riscv2x86_privileged_runtime",)
    assert rendered.runtime_manifest_id == manifest.manifest_id
    assert "__asm__" not in rendered.emitted_text


def test_functional_fallback_builtin_recipe_renders_without_arch_claim():
    source = _source_model()
    environment = functional_environment()
    policy = _policy()
    contract, _ = functional_registry(source, environment)
    contract = replace(
        contract,
        result_operand_indexes=(0,),
        required_headers=("riscv2x86_functional.h",),
    )
    registry = PrivilegedFunctionalFallbackRegistry(
        version="functional-render-registry.v1", contracts=(contract,)
    )
    plan = next(item for item in generate_candidate_plans(
        source, privileged_functional_policy=policy
    ) if item.kind is TargetLoweringKind.PRIVILEGED_FUNCTIONAL_FALLBACK)
    derived = derive_target_constraints(
        source_model=source, candidate_plan=plan,
        target_environment=environment,
        privileged_functional_registry=registry,
        privileged_functional_policy=policy,
    )
    catalog = TargetSemanticCatalog(
        frozenset({plan.kind}), frozenset({contract.semantic_contract_id}),
        "functional-render-catalog.v1",
    )
    capability = CompilerCapabilityModel(True, False)
    proof = run_semantic_proof_gate(
        source_model=source, candidate_plan=plan,
        constraints=derived.constraints, target_environment=environment,
        target_semantic_catalog=catalog, compiler_capabilities=capability,
        privileged_functional_registry=registry,
        privileged_functional_policy=policy,
    )
    catalog_id = catalog.version + ":" + ",".join(catalog.semantic_contract_ids)
    selection = select_final_target_lowering_plan(Phase6ESelectionRequest(
        source_model=source, preservation_decision=source.preservation,
        target_environment=environment,
        candidates=(ProvenCandidate(plan, derived, proof),),
        generated_plan_ids=frozenset({plan.plan_id}),
        target_catalog_version=catalog_id,
        compiler_capability_id="asm=True;goto=False",
        privileged_functional_registry_version=registry.version,
        privileged_functional_policy_identity=policy.identity,
        selection_policy=Phase6ESelectionPolicy(allow_functional_fallbacks=True),
    ))
    approved = selection.selected_plan
    manifest = PrivilegedRendererManifest(
        manifest_id="riscv2x86.test.functional-builtins", version="1",
        entries=(replace(
            _renderer_registry(
                contract, registry,
                TargetLoweringKind.PRIVILEGED_FUNCTIONAL_FALLBACK,
            )[0].entries[0],
            recipe_kind=PrivilegedRecipeKind.COMPILER_BUILTIN,
        ),),
    )
    renderer_registry = register_privileged_renderer_manifest(
        EMPTY_RENDERER_CONTRACT_REGISTRY, manifest
    )
    renderer_contract = renderer_registry.resolve(approved)
    rendered = render_approved_target_lowering(Phase6FRenderRequest(
        approved, environment,
        RendererContext({approved.plan.plan_id: renderer_contract}, {0: "counter"}),
    ))
    assert rendered.kind is RenderedReplacementKind.PRIVILEGED_FUNCTIONAL_FALLBACK
    assert rendered.emitted_text == "counter = rv2x86_functional_counter_v1();"
    assert rendered.target_ast.recipe_kind is PrivilegedRecipeKind.COMPILER_BUILTIN


def test_manifest_mismatch_and_instruction_guessing_fail_closed():
    _source, _environment, contract, registry, approved = _approved_strict()
    manifest, renderer_registry = _renderer_registry(
        contract, registry, TargetLoweringKind.COUNTER_OBSERVATION_ADAPTER
    )
    bad_entry = replace(
        manifest.entries[0], source_registry_version="stale-registry.v0"
    )
    bad_registry = register_privileged_renderer_manifest(
        EMPTY_RENDERER_CONTRACT_REGISTRY,
        PrivilegedRendererManifest(
            manifest_id=manifest.manifest_id, version="bad",
            entries=(bad_entry,),
        ),
    )
    assert bad_registry.resolve(approved) is None
    assert audit_privileged_emitted_text(
        '__asm__ volatile ("rdmsr");',
        expected_callable_identifier=contract.runtime_symbol,
    ) == (
        "privileged-renderer.inline-asm-forbidden",
        "privileged-renderer.registered-callable-missing",
        "privileged-renderer.x86-privileged-instruction-forbidden",
    )


def test_phase7_requires_privileged_manifest_artifact_and_audits_text():
    import sys
    sys.modules.setdefault("pypcode", SimpleNamespace())
    sys.modules.setdefault("z3", SimpleNamespace())
    from riscv2x86_py.pipeline import phase7_gate_inline_asm
    fragment = SimpleNamespace(
        gotoLabels=[], outputs=[], inputs=[], clobbers=[], isVolatile=True,
    )
    base = {
        "artifactVersion": "phase6-approval-v1",
        "proofStatus": "approved",
        "replacementKind": "privileged_runtime_adapter",
        "preservationMode": "architecture_equivalent",
        "privilegedSemanticContractId": "privileged-runtime.counter@1",
        "privilegedRendererManifestId": "manifest",
        "privilegedRendererManifestVersion": "1",
        "rendererContractId": "renderer",
        "requiredHeaders": ["runtime.h"],
        "requiredLibraries": ["runtime"],
        "privilegedCallableIdentifier": "runtime_counter",
        "privilegedEmittedTextAuditVersion": PRIVILEGED_EMITTED_TEXT_AUDIT_VERSION,
    }
    good = SimpleNamespace(
        kind="privileged_runtime", replacement="runtime_counter();",
        metadata={"approvalArtifact": base},
    )
    assert phase7_gate_inline_asm(fragment, good) == []
    bad = SimpleNamespace(
        kind="privileged_runtime",
        replacement='__asm__ volatile ("wrmsr");',
        metadata={"approvalArtifact": base},
    )
    reasons = phase7_gate_inline_asm(fragment, bad)
    assert "privileged-renderer.inline-asm-forbidden" in reasons
    assert "privileged-renderer.x86-privileged-instruction-forbidden" in reasons


def test_translate_emits_privileged_dependency_and_audit_manifest():
    from riscv2x86_py.translate import translate
    _source, environment, contract, registry, _approved = _approved_strict()
    manifest, renderer_registry = _renderer_registry(
        contract, registry, TargetLoweringKind.COUNTER_OBSERVATION_ADAPTER
    )
    fragment, block, cfg, summary, state, observability, facts = _counter_inputs()
    output = translate(
        frag=fragment, lift=_IngressLift(), summary=summary,
        machine_code=b"\0\0\0\0", xlen=64, blocks=(block,), cfg=cfg,
        runtime_facts=facts, privileged_state=state,
        functional_observability=observability,
        target_environment=environment,
        privileged_runtime_registry=registry,
        renderer_contract_registry=renderer_registry,
    )
    assert output.kind == "privileged_runtime"
    artifact = output.metadata["approvalArtifact"]
    assert artifact["privilegedRendererManifestId"] == manifest.manifest_id
    assert artifact["requiredHeaders"] == ["riscv2x86_privileged_runtime.h"]
    assert artifact["requiredLibraries"] == ["riscv2x86_privileged_runtime"]
    assert artifact["preservationMode"] == "architecture_equivalent"
