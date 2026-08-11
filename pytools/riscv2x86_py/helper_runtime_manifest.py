"""Versioned availability manifest for shipped Phase-6 helper runtimes.

This is deliberately a closed registry.  A symbol observed in source is not a
runtime contract and must never become a generated ``helper_unknown`` call.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True)
class RuntimeHelperContract:
    runtime_contract_id: str
    semantic_family: str
    semantic_version: str
    helper_symbol: str
    calling_convention: str
    target_abi: str
    parameter_type_ids: tuple[str, ...]
    return_type_id: str | None
    parameter_width_bits: tuple[int, ...]
    return_width_bits: int | None
    memory_effect: str
    atomic_effect: str
    barrier_effect: str
    may_return: bool
    may_unwind: bool
    required_stack_alignment_bytes: int
    preserves_stack_pointer: bool
    preserves_frame_pointer: bool
    caller_saved_registers: tuple[str, ...]
    callee_saved_registers: tuple[str, ...]
    pic_plt_compatible: bool
    tls_errno_global_effect: str
    required_environment_capability: str
    required_header: str
    runtime_library: str


RUNTIME_HELPER_MANIFEST_VERSION = "riscv2x86-runtime-manifest-v1"

# First shipped helper family: unsigned RV64 multiply-high.  It has no memory,
# ordering, control-flow or FP-environment semantics, which makes its ABI
# contract auditable without creating an unsafe generic helper escape hatch.
RV64_MULHU_U64 = RuntimeHelperContract(
    runtime_contract_id="riscv2x86_rt_rv64_mulhu_u64@v1",
    semantic_family="rv64.mulhu.u64",
    semantic_version="v1",
    helper_symbol="riscv2x86_rt_rv64_mulhu_u64",
    calling_convention="sysv_amd64",
    target_abi="sysv_amd64",
    parameter_type_ids=("unsigned long", "unsigned long"),
    return_type_id="unsigned long",
    parameter_width_bits=(64, 64),
    return_width_bits=64,
    memory_effect="none",
    atomic_effect="none",
    barrier_effect="none",
    may_return=True,
    may_unwind=False,
    required_stack_alignment_bytes=16,
    preserves_stack_pointer=True,
    preserves_frame_pointer=True,
    caller_saved_registers=("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"),
    callee_saved_registers=("rbx", "rbp", "r12", "r13", "r14", "r15"),
    pic_plt_compatible=True,
    tls_errno_global_effect="none",
    required_environment_capability="runtime:riscv2x86:rv64-mulhu-u64-v1",
    required_header="riscv2x86_runtime_helpers.h",
    runtime_library="libriscv2x86_runtime",
)

DEFAULT_RUNTIME_HELPER_CONTRACTS: Mapping[str, RuntimeHelperContract] = MappingProxyType({
    RV64_MULHU_U64.runtime_contract_id: RV64_MULHU_U64,
})


def get_runtime_helper_contract(contract_id: str) -> RuntimeHelperContract | None:
    return DEFAULT_RUNTIME_HELPER_CONTRACTS.get(contract_id)
