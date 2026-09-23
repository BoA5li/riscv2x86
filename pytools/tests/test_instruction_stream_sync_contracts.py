from __future__ import annotations

from hashlib import sha256
import json
from types import SimpleNamespace

import pytest

from riscv2x86_py.instruction_stream_sync_contracts import (
    INSTRUCTION_STREAM_SYNC_REGISTRY_SCHEMA,
    InstructionStreamSyncContract,
    InstructionStreamSyncLoweringKind,
    InstructionStreamSyncRegistry,
    InstructionStreamSyncScope,
    ModifiedCodeRange,
    instruction_stream_sync_registry_from_dict,
    load_instruction_stream_sync_registry,
    prove_instruction_stream_sync,
)


def _contract(**overrides) -> InstructionStreamSyncContract:
    values = dict(
        contract_id="jit-sync", semantic_version="1",
        source_fragment_id="fragment:fence-i", target_environment_id="phase6:x86",
        lowering_kind=InstructionStreamSyncLoweringKind.RUNTIME_HELPER,
        modified_code_range=ModifiedCodeRange("object:jit", 16, 64, "as:process"),
        data_write_publication_relation_id="publication.release.v1",
        instruction_fetch_visibility_relation_id="ifetch.visible.v1",
        required_scope=InstructionStreamSyncScope.LOCAL_HART,
        cache_coherence_model_id="platform-coherence.v1",
        cross_core_invalidation_relation_id=None,
        target_cpu_profile_id="cpu:x86-64-v1",
        runtime_adapter_identity="riscv2x86_rt_instruction_stream_sync_local@v1",
        completion_acknowledgement_relation_id="adapter-return-means-complete.v1",
        helper_symbol="riscv2x86_rt_instruction_stream_sync_local",
        required_header="riscv2x86_runtime_helpers.h",
        runtime_library="libriscv2x86_runtime",
    )
    values.update(overrides)
    return InstructionStreamSyncContract(**values)


def test_complete_runtime_relation_closes_all_phase6d_obligations() -> None:
    proof = prove_instruction_stream_sync(_contract())
    assert proof.approved
    assert proof.reason_code == "ISS_PROOF_APPROVED"
    assert "instruction-fetch.visibility" in proof.obligations
    assert "data-write.publication" in proof.obligations


def test_missing_registry_contract_remains_needs_route_reason() -> None:
    proof = prove_instruction_stream_sync(None)
    assert not proof.approved
    assert proof.reason_code == "ISS_RUNTIME_CONTRACT_MISSING"


def test_local_only_contract_cannot_cover_multi_hart_scope() -> None:
    contract = _contract(
        required_scope=InstructionStreamSyncScope.MULTI_HART,
        cross_core_invalidation_relation_id=None,
    )
    proof = prove_instruction_stream_sync(contract)
    assert not proof.approved
    assert proof.reason_code == "ISS_CROSS_CORE_INVALIDATION_UNPROVEN"


def test_local_runtime_adapter_cannot_claim_multi_hart_completion() -> None:
    proof = prove_instruction_stream_sync(_contract(
        required_scope=InstructionStreamSyncScope.MULTI_HART,
        cross_core_invalidation_relation_id="shootdown.ack.v1",
    ))
    assert not proof.approved
    assert proof.reason_code == "ISS_RUNTIME_ADAPTER_SCOPE_MISMATCH"


def test_data_cache_flush_without_instruction_visibility_is_rejected() -> None:
    proof = prove_instruction_stream_sync(_contract(
        lowering_kind=InstructionStreamSyncLoweringKind.CACHE_MAINTENANCE_API,
        proves_instruction_fetch_visibility=False,
    ))
    assert not proof.approved
    assert proof.reason_code == "ISS_INSTRUCTION_FETCH_VISIBILITY_UNPROVEN"


def test_target_cpu_profile_must_match_selected_environment() -> None:
    proof = prove_instruction_stream_sync(
        _contract(target_cpu_profile_id="cpu:contract"),
        target_cpu_profile_id="cpu:selected-environment",
    )
    assert not proof.approved
    assert proof.reason_code == "ISS_TARGET_CPU_PROFILE_MISMATCH"


def test_noop_requires_positive_environment_visibility_guarantee() -> None:
    with pytest.raises(ValueError, match="positive environment guarantee"):
        _contract(
            lowering_kind=InstructionStreamSyncLoweringKind.PROVEN_NOOP,
            helper_symbol=None, required_header="", runtime_library="",
            environment_noop_guarantee_id=None,
        )
    proof = prove_instruction_stream_sync(_contract(
        lowering_kind=InstructionStreamSyncLoweringKind.PROVEN_NOOP,
        helper_symbol=None, required_header="", runtime_library="",
        environment_noop_guarantee_id="environment-ifetch-guarantee.v1",
    ))
    assert proof.approved


def test_registry_is_exact_per_fragment_and_environment() -> None:
    contract = _contract()
    registry = InstructionStreamSyncRegistry(version="test.v2", contracts=(contract,))
    assert registry.resolve("fragment:fence-i", "phase6:x86") is contract
    assert registry.resolve("fragment:other", "phase6:x86") is None
    assert registry.resolve("fragment:fence-i", "phase6:other") is None


def test_json_registry_is_source_content_bound(tmp_path) -> None:
    source = tmp_path / "case.c"
    source.write_text("void f(void) {}\n", encoding="utf-8")
    value = {
        "schemaVersion": INSTRUCTION_STREAM_SYNC_REGISTRY_SCHEMA,
        "version": "test.v2",
        "sourceDigest": "sha256:" + sha256(source.read_bytes()).hexdigest(),
        "contracts": [{
            "contractId": "jit-sync", "semanticVersion": "1",
            "sourceFragmentId": "fragment:fence-i",
            "targetEnvironmentId": "phase6:x86",
            "loweringKind": "runtime_helper",
            "modifiedCodeRange": {"objectIdentity": "object:jit", "offsetBytes": 0,
                                  "lengthBytes": 64, "addressSpaceIdentity": "as:process"},
            "dataWritePublicationRelationId": "publish.v1",
            "instructionFetchVisibilityRelationId": "ifetch.v1",
            "requiredScope": "local_hart", "cacheCoherenceModelId": "coherence.v1",
            "crossCoreInvalidationRelationId": None,
            "targetCpuProfileId": "cpu:x86",
            "runtimeAdapterIdentity": "riscv2x86_rt_instruction_stream_sync_local@v1",
            "completionAcknowledgementRelationId": "complete.v1",
            "helperSymbol": "riscv2x86_rt_instruction_stream_sync_local",
            "requiredHeader": "riscv2x86_runtime_helpers.h",
            "runtimeLibrary": "libriscv2x86_runtime", "provesDataWritePublication": True,
            "provesInstructionFetchVisibility": True,
            "provesCompletionAcknowledgement": True, "provesRequiredScope": True,
            "preservesCompilerMemoryOrdering": True,
            "preservesVolatileExecution": True, "preservesCcClobber": True,
            "environmentNoopGuaranteeId": None, "complete": True,
        }],
    }
    path = tmp_path / "case.c.instruction-stream-sync.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    assert load_instruction_stream_sync_registry(path, source_path=source).version == "test.v2"
    source.write_text("void f(void) { }\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source digest mismatch"):
        load_instruction_stream_sync_registry(path, source_path=source)


def test_unknown_schema_fails_closed() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        instruction_stream_sync_registry_from_dict({
            "schemaVersion": "unknown", "version": "1", "sourceDigest": "sha256:x",
            "contracts": [],
        })


def test_phase7_accepts_only_v2_proof_backed_instruction_stream_route() -> None:
    from riscv2x86_py.pipeline import phase7_gate_inline_asm
    from riscv2x86_py.schema import AsmFragment

    fragment = AsmFragment(id="fragment:fence-i", isVolatile=True, clobbers=["memory"])
    artifact = {
        "artifactVersion": "phase6-instruction-stream-sync-v2",
        "proofStatus": "approved", "preservationMode": "architecture_equivalent",
        "replacementKind": "helper_call", "proofId": "phase6d:jit-sync@1",
        "proofObligations": ["instruction-fetch.visibility"],
        "preservesCompilerMemoryOrdering": True,
        "preservesVolatileExecution": True, "preservesCcClobber": True,
    }
    translated = SimpleNamespace(
        kind="runtime_c", replacement="riscv2x86_rt_instruction_stream_sync_local();",
        metadata={"approvalArtifact": artifact},
    )
    assert phase7_gate_inline_asm(fragment, translated) == []
    artifact["proofStatus"] = "incomplete"
    assert phase7_gate_inline_asm(fragment, translated)
