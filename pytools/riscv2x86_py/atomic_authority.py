"""Production ingress for content-bound atomic object authority."""
from __future__ import annotations

from collections.abc import Mapping

from .runtime_facts import AtomicMemoryObjectRuntimeFact
from .semantic_authority import (
    AtomicOperationFacts, AuthorityProducerRegistry, RegisteredAuthorityProducer,
    SemanticAuthorityError, semantic_authority_bundle_from_dict,
)


ATOMIC_AUTHORITY_PRODUCER_REGISTRY = AuthorityProducerRegistry((
    RegisteredAuthorityProducer(
        "frontend-compiler-sidecar", ("v1",), ("atomic_operation",),
    ),
))


def atomic_runtime_objects_from_bundle(
    raw_bundle: Mapping[str, object], *, fragment_id: str, source_digest: str,
    operand_indexes: frozenset[int],
) -> dict[int, AtomicMemoryObjectRuntimeFact]:
    """Validate a sidecar and materialize only complete atomic object facts."""
    known_nodes = frozenset(f"operand:{item}" for item in operand_indexes)
    bundle = semantic_authority_bundle_from_dict(
        raw_bundle, expected_fragment_id=fragment_id,
        expected_source_digest=source_digest,
        producer_registry=ATOMIC_AUTHORITY_PRODUCER_REGISTRY,
        known_decoder_node_ids=known_nodes,
    )
    atomic = [item for item in bundle.authorities
              if item.fact_kind == "atomic_operation"]
    if len(atomic) != 1 or not atomic[0].complete:
        raise SemanticAuthorityError(
            "atomic authority bundle requires exactly one complete atomic operation"
        )
    authority = atomic[0]
    payload = authority.payload
    if not isinstance(payload, AtomicOperationFacts):
        raise SemanticAuthorityError("atomic authority payload has wrong type")
    index = payload.address_operand_index
    if index not in operand_indexes or payload.address_node_id != f"operand:{index}":
        raise SemanticAuthorityError("atomic address operand authority mismatch")
    expected_relation = {
        "exchange": "exchange", "fetch_add": "add_mod_2n",
        "fetch_and": "and_bits", "fetch_or": "or_bits",
        "fetch_xor": "xor_bits", "compare_exchange": "compare_exchange",
    }.get(payload.operation_kind)
    if expected_relation is None or payload.arithmetic_relation != expected_relation:
        raise SemanticAuthorityError("atomic arithmetic relation mismatch")
    return {index: AtomicMemoryObjectRuntimeFact(
        object_identity=str(payload.memory_object_identity),
        address_space_identity=str(payload.address_space_identity),
        alignment_bytes=int(payload.alignment_bytes),
        pointee_type_id=str(payload.pointee_type_id),
        authority_identity=authority.authority_identity,
        operation_kind=str(payload.operation_kind),
        arithmetic_relation=str(payload.arithmetic_relation),
        wraparound_width_bits=int(payload.wraparound_width_bits),
        ordering=tuple(payload.ordering),
        read_effect_identity=str(payload.read_effect_identity),
        write_effect_identity=str(payload.write_effect_identity),
    )}
