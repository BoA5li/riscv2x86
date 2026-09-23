"""Content-bound production ingress for frontend CSR and operand authority."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .csr_value_flow import CsrOperandAuthorityFacts
from .semantic_authority import (
    AuthorityProducerRegistry, CsrOperationFacts, OperandValueFlowFacts,
    RegisteredAuthorityProducer, SemanticAuthorityError,
    semantic_authority_bundle_from_dict,
)


CSR_AUTHORITY_PRODUCER_REGISTRY = AuthorityProducerRegistry((
    RegisteredAuthorityProducer(
        "frontend-compiler-sidecar", ("v1",),
        ("csr_operation", "operand_value_flow"),
    ),
))


def _effect_id(addr: int, ordinal: int, operation: Any) -> str:
    return f"csr-effect:{addr:#x}:{ordinal}:{getattr(operation, 'csr_id', None) or 'unknown'}"


def _access_kind(operation: Any) -> str:
    value = getattr(getattr(operation, "csr_operation", None), "value", "")
    return {
        "read": "read", "write": "write", "read_write": "read_write",
        "set_bits": "read_write", "clear_bits": "read_write",
    }.get(value, "")


def csr_operand_authority_from_bundle(
    raw_bundle: Mapping[str, object], *, fragment_id: str, source_digest: str,
    lifted_insns: tuple[Any, ...] | list[Any], operand_indexes: frozenset[int],
    fragment_shell: Any,
) -> CsrOperandAuthorityFacts:
    """Validate frontend facts and bind decoder value nodes to GNU operands."""
    operations: list[tuple[str, Any]] = []
    ordinal = 0
    known_nodes: set[str] = set()
    for insn in lifted_insns:
        for operation in tuple(getattr(insn, "privileged_operations", ()) or ()):
            if getattr(getattr(operation, "kind", None), "value", None) != "csr_access":
                continue
            ordinal += 1
            effect_id = _effect_id(getattr(insn, "addr", 0), ordinal, operation)
            operations.append((effect_id, operation))
            known_nodes.update(node for node in (
                getattr(operation, "read_value_node_id", None),
                getattr(operation, "write_value_node_id", None),
            ) if isinstance(node, str) and node)
    bundle = semantic_authority_bundle_from_dict(
        raw_bundle, expected_fragment_id=fragment_id,
        expected_source_digest=source_digest,
        producer_registry=CSR_AUTHORITY_PRODUCER_REGISTRY,
        known_decoder_node_ids=frozenset(known_nodes),
    )
    csr_envelopes = {item.payload.effect_identity: item for item in bundle.authorities
                     if isinstance(item.payload, CsrOperationFacts)}
    operand_envelopes = [item for item in bundle.authorities
                         if isinstance(item.payload, OperandValueFlowFacts)]
    if len(csr_envelopes) != len(operations) or any(not item.complete for item in bundle.authorities):
        raise SemanticAuthorityError("CSR authority must completely cover every decoded CSR effect")

    effect_authorities: dict[str, str] = {}
    effect_csrs: dict[str, str] = {}
    shell_values: set[tuple[bool, bool, bool]] = set()
    for effect_id, operation in operations:
        envelope = csr_envelopes.get(effect_id)
        if envelope is None:
            raise SemanticAuthorityError("decoded CSR effect lacks matching frontend authority")
        payload = envelope.payload
        assert isinstance(payload, CsrOperationFacts)
        expected_nodes = (getattr(operation, "read_value_node_id", None),
                          getattr(operation, "write_value_node_id", None))
        if (payload.csr_identity != getattr(operation, "csr_id", None) or
                payload.semantic_class != getattr(operation, "csr_semantic_class", None) or
                payload.access_kind != _access_kind(operation) or
                payload.width_bits != getattr(operation, "xlen_bits", None) or
                (payload.read_value_node_id, payload.write_value_node_id) != expected_nodes or
                payload.required_extension != getattr(operation, "required_extension_id", None) or
                payload.required_extensions != (getattr(operation, "required_extension_id", None),) or
                payload.privilege_mode != getattr(operation, "required_privilege_mode", None) or
                payload.may_trap != getattr(operation, "may_trap", None)):
            raise SemanticAuthorityError("frontend CSR fact conflicts with decoder/catalog authority")
        effect_authorities[effect_id] = envelope.authority_identity
        effect_csrs[effect_id] = str(payload.csr_identity)
        shell_values.add((bool(payload.volatile), bool(payload.memory_clobber),
                          bool(payload.cc_clobber)))
    if len(shell_values) != 1:
        raise SemanticAuthorityError("CSR authorities disagree on compiler shell facts")

    node_to_index: dict[str, int] = {}
    widths: dict[int, int] = {}
    signedness: dict[int, str] = {}
    access: dict[int, str] = {}
    fixed: dict[int, str | None] = {}
    escapes: dict[int, bool] = {}
    early: set[int] = set()
    tied: set[tuple[int, int]] = set()
    for envelope in operand_envelopes:
        payload = envelope.payload
        assert isinstance(payload, OperandValueFlowFacts)
        index = payload.operand_index
        if index not in operand_indexes or payload.value_node_id not in known_nodes:
            raise SemanticAuthorityError("CSR operand authority references unknown operand or decoder node")
        if payload.source_effect_identity not in effect_authorities:
            raise SemanticAuthorityError("CSR operand authority has mismatched source effect")
        if payload.value_node_id in node_to_index and node_to_index[payload.value_node_id] != index:
            raise SemanticAuthorityError("conflicting CSR decoder-node operand binding")
        node_to_index[str(payload.value_node_id)] = int(index)
        widths[int(index)] = int(payload.width_bits)
        signedness[int(index)] = str(payload.signedness)
        access[int(index)] = str(payload.access)
        fixed[int(index)] = str(payload.fixed_register_constraint_identity)
        escapes[int(index)] = bool(payload.escape_proven)
        if payload.early_clobber:
            early.add(int(index))
    for node, index in node_to_index.items():
        if sum(1 for item in node_to_index.values() if item == index) > 1:
            tied.add((index, index))
    volatile, memory, cc = next(iter(shell_values))
    actual_shell = (
        bool(getattr(fragment_shell, "isVolatile", False)),
        "memory" in tuple(getattr(fragment_shell, "clobbers", ()) or ()),
        "cc" in tuple(getattr(fragment_shell, "clobbers", ()) or ()),
    )
    if (volatile, memory, cc) != actual_shell:
        raise SemanticAuthorityError("CSR authority compiler-shell facts mismatch")
    return CsrOperandAuthorityFacts(
        fragment_id, node_to_index, widths, signedness, access,
        tuple(sorted(tied)), tuple(sorted(early)), fixed, escapes,
        {"volatile": volatile, "memory": memory, "cc": cc}, True,
        effect_authorities, effect_csrs,
    )
