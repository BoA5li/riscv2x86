import json
from hashlib import sha256
from types import SimpleNamespace

import pytest

from riscv2x86_py.atomic_authority import (
    COMPILER_FRAGMENT_AUTHORITY_SCHEMA,
    atomic_runtime_object_from_compiler_authority,
)
from riscv2x86_py.automatic_translation_command import (
    _inject_compiler_fragment_authority,
)
from riscv2x86_py.compiler_fragment_closure import (
    close_compiler_fragment_candidate,
)
from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
from riscv2x86_py.semantic_authority import SemanticAuthorityError


def _identity(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode()
    return "sha256:" + sha256(encoded).hexdigest()


def _compiler_authority(*, fragment_id="source.c:7:3", carrier_kind="pointer", source_digest=None):
    digest = source_digest or "sha256:" + "1" * 64
    declaration = "sha256:" + "2" * 64
    node = "sha256:" + "3" * 64
    key = {"sourceDigest": digest, "sourceFile": "/tmp/source.c",
           "functionIdentity": "sha256:" + "4" * 64,
           "beginOffset": 100, "endOffset": 140,
           "beginLine": 7, "beginColumn": 3}
    binding = {"operandIndex": 1, "declarationIdentity": declaration,
               "valueNodeIdentity": node, "access": "input", "widthBits": 64,
               "signedness": "unsigned", "complete": True}
    carrier = {"operandIndex": 1, "declarationIdentity": declaration,
               "valueNodeIdentity": node, "carrierKind": carrier_kind,
               "widthBits": 64, "signedness": "unsigned",
               "addressSpaceIdentity": "c.default" if carrier_kind == "pointer" else "",
               "complete": True}
    value_binding = {"operandIndex": 0,
                     "declarationIdentity": "sha256:" + "5" * 64,
                     "valueNodeIdentity": "sha256:" + "6" * 64,
                     "access": "read_write", "widthBits": 64,
                     "signedness": "unsigned", "complete": True}
    value_carrier = {**value_binding, "carrierKind": "integer",
                     "addressSpaceIdentity": ""}
    value_carrier.pop("access")
    obj = {"schemaVersion": "riscv2x86.memory-object-binding.v1",
           "objectIdentity": "parameter-object:" + declaration,
           "baseDeclarationIdentity": declaration, "objectSizeBytes": 32,
           "provenAlignmentBytes": 8,
           "aliasDomainIdentity": "parameter-alias-domain:" + declaration,
           "addressSpaceIdentity": "c.default", "volatile": False,
           "bindingOrigin": "automatic-aligned-memory-object-harness-v1",
           "producerIdentity": "automatic-l1-memory-harness.v1",
           "sourceDigest": digest}
    obj["bindingIdentity"] = _identity(obj)
    candidate = {"schemaVersion": "riscv2x86.compiler-fragment-boundary-candidate.v2",
                 "candidateIdentity": _identity({"schemaVersion": "riscv2x86.compiler-fragment-binding-key.v2", **key}),
                 "fragmentBindingKey": key, "complete": True,
                 "compilerStructureComplete": True,
                 "operandClassificationComplete": True,
                 "operandBindings": [value_binding, binding],
                 "operandCarriers": [value_carrier, carrier],
                 "valueNodes": [
                     {"nodeIdentity": value_binding["valueNodeIdentity"]},
                     {"nodeIdentity": binding["valueNodeIdentity"]},
                 ],
                 "downstreamUses": [],
                 "downstreamUseEnumerationComplete": True}
    candidate = close_compiler_fragment_candidate(
        candidate,
        {"fragmentId": fragment_id,
         "outputs": [{"constraint": "+r"}],
         "inputs": [{"constraint": "r"}]},
        source_digest=digest, function_identity=key["functionIdentity"],
    )
    authority = {"schemaVersion": COMPILER_FRAGMENT_AUTHORITY_SCHEMA,
                 "sourceDigest": digest, "fragmentId": fragment_id,
                 "targetTriple": "riscv64-linux-gnu",
                 "functionIdentity": key["functionIdentity"],
                 "fragmentBindingKey": key, "candidate": candidate,
                 "memoryObjectBindings": {declaration: obj}}
    authority["schemaVersion"] = "riscv2x86.compiler-fragment-authority.v2"
    authority["compilerTypeBindings"] = {"1": {"operandIndex": 1, "valueNodeIdentity": node,
        "compilerType": {"schemaVersion": "riscv2x86.clang-operand-type.v1",
            "canonicalType": "unsigned long *", "widthBits": 64, "alignmentBytes": 8,
            "isInteger": False, "isPointer": True, "isSigned": False,
            "pointeeType": "unsigned long", "pointeeWidthBits": 64,
            "pointeeAlignmentBytes": 8, "pointeeIsInteger": True,
            "sideEffectFree": True, "modifiableLvalue": False,
            "qualifiers": "", "pointeeQualifiers": "", "expressionRepeatable": True}}}
    authority["authorityIdentity"] = _identity(authority)
    return authority


def _atomic():
    return SimpleNamespace(
        operation_kind="fetch_add", width_bits=64, address_binding="a1",
        input_value_binding="a0", result_binding="a0",
        result_semantics="old_value", ordering_before="release",
        ordering_after="acquire", atomicity_scope="system",
        address_space_identity="riscv.default-data-address-space",
        complete=True,
    )


def test_compiler_decoder_join_materializes_atomic_object_without_guessing_text():
    authority = _compiler_authority()
    facts = TranslationRuntimeFacts(rv_to_operand_index={"a0": 0, "a1": 1},
                                    operand_width_bits={0: 64, 1: 64})
    result = atomic_runtime_object_from_compiler_authority(
        authority, fragment_id="source.c:7:3",
        source_digest=authority["sourceDigest"], begin_offset=100,
        end_offset=140, runtime_facts=facts, atomic_operation=_atomic())
    assert set(result) == {1}
    assert result[1].authority_complete
    assert result[1].operation_kind == "fetch_add"
    assert result[1].arithmetic_relation == "add_mod_2n"
    assert result[1].address_space_relation_identity


@pytest.mark.parametrize("mutation", ["wrong-range", "not-pointer", "unaligned"])
def test_compiler_decoder_join_fails_closed_on_unproved_object_binding(mutation):
    authority = _compiler_authority(carrier_kind=(
        "integer" if mutation == "not-pointer" else "pointer"))
    begin = 101 if mutation == "wrong-range" else 100
    if mutation == "unaligned":
        obj = next(iter(authority["memoryObjectBindings"].values()))
        obj["provenAlignmentBytes"] = 4
        unsigned = {k: v for k, v in obj.items() if k != "bindingIdentity"}
        obj["bindingIdentity"] = _identity(unsigned)
        unsigned_authority = {k: v for k, v in authority.items()
                              if k != "authorityIdentity"}
        authority["authorityIdentity"] = _identity(unsigned_authority)
    with pytest.raises(SemanticAuthorityError):
        atomic_runtime_object_from_compiler_authority(
            authority, fragment_id="source.c:7:3",
            source_digest=authority["sourceDigest"], begin_offset=begin,
            end_offset=140,
            runtime_facts=TranslationRuntimeFacts(
                rv_to_operand_index={"a0": 0, "a1": 1},
                operand_width_bits={0: 64, 1: 64}),
            atomic_operation=_atomic())


def test_automatic_wrapper_binds_candidate_by_exact_source_range(tmp_path):
    source = tmp_path / "source.c"
    source.write_text("void f(void) {}\n")
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps({"findings": [{"fragment": {
        "id": "source.c:7:3", "fileName": "/tmp/source.c",
        "beginOffset": 100, "endOffset": 140,
        "outputs": [{"constraint": "+r"}],
        "inputs": [{"constraint": "r"}]}}]}))
    authority = _compiler_authority()
    function = {"sourceDigest": authority["sourceDigest"],
                "functionId": authority["functionIdentity"],
                "l2OperandBoundary": {
                    "fragmentCandidates": [authority["candidate"]],
                    "memoryObjectBindings": authority["memoryObjectBindings"]}}
    _inject_compiler_fragment_authority(raw, source, (function,))
    fragment = json.loads(raw.read_text())["findings"][0]["fragment"]
    assert fragment["compilerFragmentAuthority"]["authorityIdentity"]
    assert fragment["compilerFragmentAuthority"]["fragmentId"] == "source.c:7:3"
    closed = fragment["compilerFragmentAuthority"]["candidate"]
    assert closed["schemaVersion"] == "riscv2x86.closed-compiler-fragment.v1"
    assert [item["access"] for item in closed["operandBindings"]] == [
        "read_write", "input"]


def test_automatic_wrapper_rejects_frontend_compiler_operand_disagreement(tmp_path):
    source = tmp_path / "source.c"
    source.write_text("void f(void) {}\n")
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps({"findings": [{"fragment": {
        "id": "source.c:7:3", "fileName": "/tmp/source.c",
        "beginOffset": 100, "endOffset": 140,
        "outputs": [], "inputs": [{"constraint": "r"}]}}]}))
    authority = _compiler_authority()
    function = {"sourceDigest": authority["sourceDigest"],
                "functionId": authority["functionIdentity"],
                "l2OperandBoundary": {
                    "fragmentCandidates": [authority["candidate"]],
                    "memoryObjectBindings": authority["memoryObjectBindings"]}}
    with pytest.raises(ValueError, match="arity mismatch"):
        _inject_compiler_fragment_authority(raw, source, (function,))


def test_atomic_join_rejects_tampered_closed_candidate():
    authority = _compiler_authority()
    authority["candidate"]["operandBindings"][0]["access"] = "output"
    unsigned = {key: value for key, value in authority.items()
                if key != "authorityIdentity"}
    authority["authorityIdentity"] = _identity(unsigned)
    with pytest.raises(SemanticAuthorityError,
                       match="closed compiler fragment identity"):
        atomic_runtime_object_from_compiler_authority(
            authority, fragment_id="source.c:7:3",
            source_digest=authority["sourceDigest"], begin_offset=100,
            end_offset=140,
            runtime_facts=TranslationRuntimeFacts(
                rv_to_operand_index={"a0": 0, "a1": 1},
                operand_width_bits={0: 64, 1: 64}),
            atomic_operation=_atomic())
