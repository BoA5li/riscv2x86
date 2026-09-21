from __future__ import annotations

from riscv2x86_py.pcode_ir import (
    CanonicalInsn,
    Op,
    _summarize_instructions,
)
from riscv2x86_py.source_model import (
    SourceOperationKind,
    _operation_semantics_are_opaque,
)


def _op(opcode: str) -> Op:
    return Op(addr=0x1000, opcode=opcode, output=None, inputs=[])


def _assert_special_semantics_proven_absent(summary) -> None:
    assert summary.has_return is False
    assert summary.has_tail_call is False
    assert summary.has_indirect_control_flow is False
    assert summary.has_timing_source is False
    assert summary.has_cache_operation is False
    assert summary.has_speculation_control is False


def test_complete_atomic_shape_produces_authoritative_negative_facts() -> None:
    ins = CanonicalInsn(
        addr=0x1000,
        size=4,
        ops=[_op("LOAD"), _op("INT_ADD"), _op("STORE")],
        has_atomic=True,
        atomic_mnemonic="amoadd.d",
        atomic_reads_mem=True,
        atomic_writes_mem=True,
    )

    summary = _summarize_instructions([ins], is_single_block=True)

    assert summary.has_atomic is True
    assert summary.reads_mem is True
    assert summary.writes_mem is True
    _assert_special_semantics_proven_absent(summary)


def test_complete_direct_conditional_shape_produces_negative_facts() -> None:
    ins = CanonicalInsn(
        addr=0x1000,
        size=4,
        ops=[_op("INT_EQUAL"), _op("CBRANCH")],
        terminator_kind="CBRANCH",
        direct_target=0x1008,
        has_branch_op=True,
    )

    summary = _summarize_instructions([ins], is_single_block=True)

    assert summary.has_branch is True
    _assert_special_semantics_proven_absent(summary)


def test_atomic_with_unknown_operation_remains_fail_closed() -> None:
    ins = CanonicalInsn(
        addr=0x1000,
        size=4,
        ops=[_op("LOAD"), _op("UNMODELLED_ATOMIC_EFFECT"), _op("STORE")],
        has_atomic=True,
        atomic_mnemonic="amoadd.d",
        atomic_reads_mem=True,
        atomic_writes_mem=True,
    )

    summary = _summarize_instructions([ins], is_single_block=True)

    assert summary.has_return is None
    assert summary.has_timing_source is None
    assert summary.has_cache_operation is None
    assert summary.has_speculation_control is None


def test_unresolved_conditional_target_remains_fail_closed() -> None:
    ins = CanonicalInsn(
        addr=0x1000,
        size=4,
        ops=[_op("INT_EQUAL"), _op("CBRANCH")],
        terminator_kind="CBRANCH",
        direct_target=None,
        has_branch_op=True,
    )

    summary = _summarize_instructions([ins], is_single_block=True)

    assert summary.has_return is None
    assert summary.has_indirect_control_flow is None
    assert summary.has_timing_source is None


def test_only_complete_typed_atomic_closes_generic_opacity() -> None:
    assert _operation_semantics_are_opaque(
        operation_kind=SourceOperationKind.OPAQUE,
        atomic_present=True,
        atomic_complete=False,
    )
    assert _operation_semantics_are_opaque(
        operation_kind=SourceOperationKind.OPAQUE,
        atomic_present=False,
        atomic_complete=True,
    )
    assert not _operation_semantics_are_opaque(
        operation_kind=SourceOperationKind.OPAQUE,
        atomic_present=True,
        atomic_complete=True,
    )
