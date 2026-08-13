"""Closed contracts for instruction-stream synchronization lowering.

This module deliberately does not identify source instructions.  Phase 6A
supplies the ``has_instruction_barrier`` semantic fact; these registrations
only decide which already-proved target representation is permitted.
"""
from __future__ import annotations

from dataclasses import dataclass


INSTRUCTION_STREAM_SYNC_REGISTRY_VERSION = "instruction-stream-sync-registry-v1"
NOOP_ELISION_CONTRACT_ID = "x86.local_smc.noop_elision.v1"
RUNTIME_LOCAL_SYNC_CONTRACT_ID = "riscv2x86_rt_instruction_stream_sync_local@v1"


@dataclass(frozen=True)
class InstructionStreamSyncContract:
    semantic_contract_id: str
    source_semantic_contract_id: str
    target_semantic_contract_id: str
    preservation_mode: str
    helper_symbol: str | None = None
    required_header: str = ""
    runtime_library: str = ""
    required_environment_capability: str = ""


X86_LOCAL_SMC_NOOP_ELISION = InstructionStreamSyncContract(
    semantic_contract_id=NOOP_ELISION_CONTRACT_ID,
    source_semantic_contract_id="riscv.instruction-stream-sync.v1",
    target_semantic_contract_id=NOOP_ELISION_CONTRACT_ID,
    preservation_mode="architecture_equivalent",
)

# This helper is intentionally local-thread only.  A cross-thread JIT/code
# publication protocol is a separate runtime contract and remains NeedsRoute.
RUNTIME_LOCAL_SYNC = InstructionStreamSyncContract(
    semantic_contract_id=RUNTIME_LOCAL_SYNC_CONTRACT_ID,
    source_semantic_contract_id="riscv.instruction-stream-sync.local.v1",
    target_semantic_contract_id="x86.local-smc.serialize.cpuid.v1",
    preservation_mode="functional_equivalence_only",
    helper_symbol="riscv2x86_rt_instruction_stream_sync_local",
    required_header="riscv2x86_runtime_helpers.h",
    runtime_library="libriscv2x86_runtime",
    required_environment_capability="runtime:riscv2x86:instruction-stream-sync-local-v1",
)
