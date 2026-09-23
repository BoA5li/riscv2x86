from dataclasses import replace
from hashlib import sha256

import pytest

from riscv2x86_py.semantic_authority import (
    AtomicOperationFacts, AuthorityProducerRegistry, CsrOperationFacts,
    InstructionStreamSyncFacts, MemoryOperandBoundaryFacts,
    OperandValueFlowFacts, PrivilegedOperationFacts,
    RegisteredAuthorityProducer, SemanticAuthorityEnvelope,
    SemanticAuthorityBundle, SemanticAuthorityError, StructuredControlFlowFacts,
    adapt_legacy_authority, make_semantic_authority_envelope,
    merge_semantic_authorities, semantic_authority_bundle_from_dict,
    semantic_authority_envelope_from_dict,
)


def _digest(value: str) -> str:
    return "sha256:" + sha256(value.encode()).hexdigest()


ALL_KINDS = (
    "atomic_operation", "csr_operation", "instruction_stream_sync",
    "memory_operand_boundary", "operand_value_flow", "privileged_operation",
    "structured_control_flow",
)
REGISTRY = AuthorityProducerRegistry((
    RegisteredAuthorityProducer("clang-semantic-export", ("17.0.0",), ALL_KINDS),
))


def _memory(**changes):
    value = MemoryOperandBoundaryFacts(
        object_identity="object:p", address_node_id="node:addr",
        base_operand_identity="operand:0", offset_bytes=8, width_bytes=8,
        alignment_bytes=8, bounds_proven=True, value_node_id="node:value",
        address_space_identity="c.object-space",
    )
    return replace(value, **changes)


def _envelope(payload=None):
    return make_semantic_authority_envelope(
        fragment_id="fragment:1", source_digest=_digest("source-a"),
        producer_identity="clang-semantic-export", producer_version="17.0.0",
        payload=payload or _memory(),
    )


def _parse(envelope, **changes):
    raw = envelope.to_dict()
    raw.update(changes)
    if changes:
        # The caller is intentionally testing a binding before identity checking.
        pass
    return semantic_authority_envelope_from_dict(
        raw, expected_fragment_id="fragment:1", expected_source_digest=_digest("source-a"),
        producer_registry=REGISTRY,
        known_decoder_node_ids=frozenset({"node:addr", "node:value"}),
    )


def test_missing_required_field_is_incomplete_and_cannot_claim_complete():
    envelope = _envelope(_memory(alignment_bytes=None))
    assert envelope.complete is False
    assert "semantic-authority.required-field-missing:alignment_bytes" in envelope.reason_codes
    with pytest.raises(SemanticAuthorityError, match="missing required fields"):
        SemanticAuthorityEnvelope(
            envelope.schema_version, envelope.fragment_id, envelope.source_digest,
            envelope.producer_identity, envelope.producer_version, envelope.fact_kind,
            True, (), envelope.payload,
        )


def test_sidecar_copied_to_another_case_is_rejected_by_fragment_and_digest():
    raw = _envelope().to_dict()
    with pytest.raises(SemanticAuthorityError, match="fragment identity mismatch"):
        semantic_authority_envelope_from_dict(
            raw, expected_fragment_id="fragment:other",
            expected_source_digest=_digest("source-a"), producer_registry=REGISTRY,
            known_decoder_node_ids=frozenset({"node:addr", "node:value"}),
        )
    with pytest.raises(SemanticAuthorityError, match="source digest mismatch"):
        semantic_authority_envelope_from_dict(
            raw, expected_fragment_id="fragment:1",
            expected_source_digest=_digest("source-b"), producer_registry=REGISTRY,
            known_decoder_node_ids=frozenset({"node:addr", "node:value"}),
        )


def test_conflicting_authorities_are_rejected_without_selecting_a_winner():
    first = _envelope()
    second = _envelope(_memory(alignment_bytes=16))
    with pytest.raises(SemanticAuthorityError, match="conflicting authorities"):
        merge_semantic_authorities((first, second))
    assert merge_semantic_authorities((first, first)) == (first,)


def test_conflict_key_does_not_hide_disagreement_in_operand_mapping():
    first = _envelope(OperandValueFlowFacts(
        "node:value", 0, "output", 64, "unsigned", "decl:x", True,
        "effect:value", "unconstrained", False))
    second = _envelope(OperandValueFlowFacts(
        "node:value", 1, "output", 64, "unsigned", "decl:x", True,
        "effect:value", "unconstrained", False))
    with pytest.raises(SemanticAuthorityError, match="conflicting authorities"):
        merge_semantic_authorities((first, second))


def test_unknown_schema_and_unregistered_producer_fail_closed():
    envelope = _envelope()
    raw = envelope.to_dict()
    raw["schemaVersion"] = "riscv2x86.semantic-authority-envelope.v999"
    with pytest.raises(SemanticAuthorityError, match="schema is unsupported"):
        semantic_authority_envelope_from_dict(
            raw, expected_fragment_id="fragment:1",
            expected_source_digest=_digest("source-a"), producer_registry=REGISTRY,
            known_decoder_node_ids=frozenset({"node:addr", "node:value"}),
        )
    raw = envelope.to_dict()
    raw["producerIdentity"] = "unregistered-exporter"
    with pytest.raises(SemanticAuthorityError, match="producer is not registered"):
        semantic_authority_envelope_from_dict(
            raw, expected_fragment_id="fragment:1",
            expected_source_digest=_digest("source-a"), producer_registry=REGISTRY,
            known_decoder_node_ids=frozenset({"node:addr", "node:value"}),
        )


def test_unknown_decoder_value_node_is_rejected_even_when_content_is_bound():
    with pytest.raises(SemanticAuthorityError, match="unknown decoder/value nodes"):
        semantic_authority_envelope_from_dict(
            _envelope().to_dict(), expected_fragment_id="fragment:1",
            expected_source_digest=_digest("source-a"), producer_registry=REGISTRY,
            known_decoder_node_ids=frozenset({"node:addr"}),
        )


def test_legacy_adapter_is_explicitly_incomplete_and_invents_no_nodes():
    envelope = adapt_legacy_authority(
        legacy_schema_version="riscv2x86.compiler-operand-boundary.v2",
        fact_kind="operand_value_flow", fragment_id="fragment:1",
        source_digest=_digest("source-a"), producer_identity="clang-semantic-export",
        producer_version="17.0.0",
    )
    assert envelope.complete is False
    assert envelope.payload.referenced_node_ids() == ()
    assert "semantic-authority.legacy-format-incomplete" in envelope.reason_codes


@pytest.mark.parametrize("payload", [
    OperandValueFlowFacts("node:value", 0, "output", 64, "unsigned", "decl:x", True,
                          "effect:value", "unconstrained", False),
    StructuredControlFlowFacts("node:entry", ("node:taken", "node:fallthrough"),
                               "cont:taken", "cont:fallthrough", "zero",
                               ("node:condition",), "label:taken"),
        AtomicOperationFacts("effect:amo", "fetch_add", 64, "node:addr", "node:input",
                             "node:result", "old_value", ("acquire", "release"),
                             "hart", 8, "object:atomic", "riscv.data", "uint64_t",
                             "add_mod_2n", 64, 0, "effect:read", "effect:write"),
    PrivilegedOperationFacts("effect:ecall", "environment_call", "trap_entry", "U",
                             ("effect:pc", "effect:cause"), (), "trap:ecall"),
    InstructionStreamSyncFacts("effect:fence-i", "hart", "range:written-code",
                               "effect:publish", "effect:fetch", "riscv-unified"),
    CsrOperationFacts("effect:time", "riscv.csr.time", "read", "node:result", None,
                      "U", "zicsr", "trap-policy:user-counter",
                      "user_counter_observation", 64, ("zicsr",), False,
                      "policy:user-counter", True, False, False),
])
def test_all_payload_families_have_closed_complete_construction(payload):
    envelope = _envelope(payload)
    assert envelope.complete is True
    assert envelope.fact_kind == payload.FACT_KIND


def test_parser_accepts_registered_content_bound_authority():
    envelope = _envelope()
    assert _parse(envelope) == envelope


def test_bundle_parser_checks_content_identity_and_conflicts_as_one_ingress():
    envelope = _envelope()
    bundle = SemanticAuthorityBundle(_digest("source-a"), "fragment:1", (envelope,))
    parsed = semantic_authority_bundle_from_dict(
        bundle.to_dict(), expected_fragment_id="fragment:1",
        expected_source_digest=_digest("source-a"), producer_registry=REGISTRY,
        known_decoder_node_ids=frozenset({"node:addr", "node:value"}),
    )
    assert parsed == bundle
    raw = bundle.to_dict()
    raw["authorities"] = [envelope.to_dict(), envelope.to_dict()]
    with pytest.raises(SemanticAuthorityError, match="duplicate authority"):
        semantic_authority_bundle_from_dict(
            raw, expected_fragment_id="fragment:1",
            expected_source_digest=_digest("source-a"), producer_registry=REGISTRY,
            known_decoder_node_ids=frozenset({"node:addr", "node:value"}),
        )


def test_complete_payload_rejects_invalid_scalar_types():
    with pytest.raises(SemanticAuthorityError, match="invalid fields"):
        _envelope(_memory(width_bytes=-1))
