from copy import deepcopy
from hashlib import sha256
from types import SimpleNamespace
import json

import pytest

from riscv2x86_py.csr_authority import csr_operand_authority_from_bundle
from riscv2x86_py.automatic_translation_command import _identity, _inject_csr_authority
from riscv2x86_py.csr_value_flow import join_csr_operand_bindings
from riscv2x86_py.semantic_authority import (
    CsrOperationFacts, OperandValueFlowFacts, SemanticAuthorityBundle,
    SemanticAuthorityError, make_semantic_authority_envelope,
)


def _operation():
    return SimpleNamespace(
        kind=SimpleNamespace(value="csr_access"),
        csr_id="riscv.csr.time", csr_semantic_class="user_counter_observation",
        csr_operation=SimpleNamespace(value="read"), xlen_bits=64,
        read_value_node_id="decoder-csr:0x100:rd:x10",
        write_value_node_id=None, read_result_suppressed=False,
        write_value_suppressed=True, immediate_mask=None,
        required_extension_id="zicsr", required_privilege_mode="U",
        may_trap=False,
    )


def _bundle():
    digest = "sha256:" + sha256(b"case_029").hexdigest()
    fragment = "fragment:case029"
    effect = "csr-effect:0x100:1:riscv.csr.time"
    csr = make_semantic_authority_envelope(
        fragment_id=fragment, source_digest=digest,
        producer_identity="frontend-compiler-sidecar", producer_version="v1",
        payload=CsrOperationFacts(
            effect, "riscv.csr.time", "read", "decoder-csr:0x100:rd:x10", None,
            "U", "zicsr", "trap-policy:user-counter",
            "user_counter_observation", 64, ("zicsr",), False,
            "access-policy:user-counter", True, False, False,
        ),
    )
    operand = make_semantic_authority_envelope(
        fragment_id=fragment, source_digest=digest,
        producer_identity="frontend-compiler-sidecar", producer_version="v1",
        payload=OperandValueFlowFacts(
            "decoder-csr:0x100:rd:x10", 0, "output", 64, "unsigned",
            "decl:time-result", False, effect, "unconstrained", False,
        ),
    )
    return digest, SemanticAuthorityBundle(digest, fragment, (csr, operand)).to_dict()


def test_real_frontend_bundle_closes_csr_operand_join():
    digest, bundle = _bundle()
    operation = _operation()
    authority = csr_operand_authority_from_bundle(
        bundle, fragment_id="fragment:case029", source_digest=digest,
        lifted_insns=(SimpleNamespace(addr=0x100, privileged_operations=(operation,)),),
        operand_indexes=frozenset({0}),
        fragment_shell=SimpleNamespace(isVolatile=True, clobbers=[]),
    )
    binding = join_csr_operand_bindings(
        lifted_insns=(SimpleNamespace(addr=0x100, privileged_operations=(operation,)),),
        authority=authority,
    )[0]
    assert binding.complete
    assert binding.source_effect_id == "csr-effect:0x100:1:riscv.csr.time"
    assert binding.read_result_operand_index == 0


@pytest.mark.parametrize("mutation", ["csr", "effect", "node", "fragment", "digest"])
def test_stale_or_conflicting_csr_frontend_bundle_fails_closed(mutation):
    digest, bundle = _bundle()
    changed = deepcopy(bundle)
    expected_fragment = "fragment:case029"
    expected_digest = digest
    if mutation == "csr": changed["authorities"][0]["payload"]["csr_identity"] = "riscv.csr.cycle"
    if mutation == "effect": changed["authorities"][1]["payload"]["source_effect_identity"] = "effect:other"
    if mutation == "node": changed["authorities"][1]["payload"]["value_node_id"] = "decoder-csr:other"
    if mutation == "fragment": expected_fragment = "fragment:other"
    if mutation == "digest": expected_digest = "sha256:" + "0" * 64
    with pytest.raises(SemanticAuthorityError):
        csr_operand_authority_from_bundle(
            changed, fragment_id=expected_fragment, source_digest=expected_digest,
            lifted_insns=(SimpleNamespace(addr=0x100, privileged_operations=(_operation(),)),),
            operand_indexes=frozenset({0}),
            fragment_shell=SimpleNamespace(isVolatile=True, clobbers=[]),
        )


def test_automatic_command_injects_exact_csr_sidecar(tmp_path):
    source = tmp_path / "case_029.c"
    source.write_bytes(b"case_029")
    digest, bundle = _bundle()
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps({"findings": [{
        "fragment": {"fragmentId": "fragment:case029"}
    }]}), encoding="utf-8")
    body = {"schemaVersion": "riscv2x86.csr-authority-binding.v1",
            "sourceDigest": digest, "bundles": [bundle]}
    sidecar = tmp_path / "case_029.c.csr-authority.json"
    sidecar.write_text(json.dumps({**body, "manifestIdentity": _identity(body)}),
                       encoding="utf-8")
    _inject_csr_authority(raw, source, sidecar)
    finding = json.loads(raw.read_text(encoding="utf-8"))["findings"][0]
    assert finding["sourceDigest"] == digest
    assert finding["fragment"]["csrAuthorityBundle"]["bundleIdentity"]
