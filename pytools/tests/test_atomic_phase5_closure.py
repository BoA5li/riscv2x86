from copy import deepcopy
from hashlib import sha256
import json

import pytest

from riscv2x86_py.atomic_authority import atomic_runtime_objects_from_bundle
from riscv2x86_py.automatic_translation_command import _identity, _inject_atomic_authority
from riscv2x86_py.atomic_metadata_ingress import (
    ATOMIC_COMPARE_EXCHANGE_CAPABILITY_REASON, decode_atomic_operation,
)
from riscv2x86_py.semantic_authority import (
    AtomicOperationFacts, SemanticAuthorityBundle, SemanticAuthorityError,
    make_semantic_authority_envelope,
)


def _word(operation, width, before, after, result):
    funct5 = {"exchange": 1, "fetch_add": 0, "fetch_xor": 4,
              "fetch_and": 12, "fetch_or": 8}[operation]
    aq, rl = after == "acquire", before == "release"
    funct3 = 3 if width == 64 else 2
    rd = 0 if result == "none" else 10
    return ((funct5 << 27) | (aq << 26) | (rl << 25) | (10 << 20) |
            (11 << 15) | (funct3 << 12) | (rd << 7) | 0x2f)


@pytest.mark.parametrize("operation", [
    "exchange", "fetch_add", "fetch_and", "fetch_or", "fetch_xor",
])
@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("before,after", [
    ("relaxed", "relaxed"), ("relaxed", "acquire"),
    ("release", "relaxed"), ("release", "acquire"),
])
@pytest.mark.parametrize("result", ["old_value", "none"])
def test_operation_width_ordering_result_matrix(operation, width, before, after, result):
    decoded = decode_atomic_operation(
        _word(operation, width, before, after, result).to_bytes(4, "little"),
        xlen_bits=64,
    )
    assert decoded is not None
    assert (decoded.operation_kind, decoded.width_bits) == (operation, width)
    assert (decoded.ordering_before, decoded.ordering_after) == (before, after)
    assert decoded.result_semantics == result


def _bundle():
    digest = "sha256:" + sha256(b"case_030").hexdigest()
    payload = AtomicOperationFacts(
        effect_identity="effect:amoadd", operation_kind="fetch_add", width_bits=64,
        address_node_id="operand:1", input_value_node_id="operand:0",
        result_value_node_id="operand:0", result_semantics="old_value",
        ordering=("before:release", "after:acquire"), atomicity_scope="system",
        alignment_bytes=8, memory_object_identity="parameter-object:ptr",
        address_space_identity="riscv.default-data-address-space",
        pointee_type_id="uint64_t", arithmetic_relation="add_mod_2n",
        wraparound_width_bits=64, address_operand_index=1,
        read_effect_identity="effect:read", write_effect_identity="effect:write",
    )
    envelope = make_semantic_authority_envelope(
        fragment_id="fragment:case030", source_digest=digest,
        producer_identity="frontend-compiler-sidecar", producer_version="v1",
        payload=payload,
    )
    return digest, SemanticAuthorityBundle(
        digest, "fragment:case030", (envelope,),
    ).to_dict()


def test_content_bound_authority_materializes_production_runtime_fact():
    digest, bundle = _bundle()
    facts = atomic_runtime_objects_from_bundle(
        bundle, fragment_id="fragment:case030", source_digest=digest,
        operand_indexes=frozenset({0, 1}),
    )
    fact = facts[1]
    assert fact.authority_complete
    assert fact.arithmetic_relation == "add_mod_2n"
    assert fact.wraparound_width_bits == 64


@pytest.mark.parametrize("mutation", ["digest", "fragment", "producer", "node"])
def test_stale_or_untrusted_atomic_authority_fails_closed(mutation):
    digest, bundle = _bundle()
    changed = deepcopy(bundle)
    if mutation == "digest":
        expected_digest = "sha256:" + "0" * 64
    else:
        expected_digest = digest
    if mutation == "fragment":
        expected_fragment = "fragment:other"
    else:
        expected_fragment = "fragment:case030"
    if mutation == "producer":
        changed["authorities"][0]["producerIdentity"] = "unknown-producer"
    if mutation == "node":
        changed["authorities"][0]["payload"]["addressNodeId"] = "operand:99"
    with pytest.raises(SemanticAuthorityError):
        atomic_runtime_objects_from_bundle(
            changed, fragment_id=expected_fragment, source_digest=expected_digest,
            operand_indexes=frozenset({0, 1}),
        )


def test_compare_exchange_is_explicit_future_capability():
    assert ATOMIC_COMPARE_EXCHANGE_CAPABILITY_REASON == (
        "atomic.compare-exchange-requires-lrsc-sequence-authority"
    )


def test_production_sidecar_is_bound_to_source_and_frontend_fragment(tmp_path):
    source = tmp_path / "case_030.c"
    source.write_text("void probe(void) {}\n", encoding="utf-8")
    digest = "sha256:" + sha256(source.read_bytes()).hexdigest()
    _, bundle = _bundle()
    # Rebind the independently tested bundle to this exact source.
    payload = bundle["authorities"][0]["payload"]
    authority = make_semantic_authority_envelope(
        fragment_id="fragment:case030", source_digest=digest,
        producer_identity="frontend-compiler-sidecar", producer_version="v1",
        payload=AtomicOperationFacts(**{
            key: (tuple(value) if key == "ordering" else value)
            for key, value in payload.items()
        }),
    )
    bundle = SemanticAuthorityBundle(
        digest, "fragment:case030", (authority,),
    ).to_dict()
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps({"findings": [{
        "fragment": {"fragmentId": "fragment:case030"}
    }]}), encoding="utf-8")
    body = {"schemaVersion": "riscv2x86.atomic-authority-binding.v1",
            "sourceDigest": digest, "bundles": [bundle]}
    sidecar = tmp_path / "case_030.c.atomic-authority.json"
    sidecar.write_text(json.dumps({**body, "manifestIdentity": _identity(body)}),
                       encoding="utf-8")
    _inject_atomic_authority(raw, source, sidecar)
    finding = json.loads(raw.read_text(encoding="utf-8"))["findings"][0]
    assert finding["sourceDigest"] == digest
    assert finding["fragment"]["atomicAuthorityBundle"]["bundleIdentity"]
