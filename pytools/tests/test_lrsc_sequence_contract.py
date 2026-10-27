from copy import deepcopy
import json
from pathlib import Path
import runpy

import pytest

from riscv2x86_py.lrsc_sequence import candidate, replay, successful_projection, SequenceError
from riscv2x86_py.lrsc_diagnostics import decision
from riscv2x86_py.route_authority import content_identity, validate_route_decision
from riscv2x86_py.schema import AsmFragment, AsmOperand


def code(bits=64, operation="fetch_add", registers=(5, 6, 9, 10, 11),
         order=(True, False, False, True), compressed=False, word_alu=False):
    old, nxt, status, address, value = registers
    funct3 = 3 if bits == 64 else 2
    la, lr, sa, sr = order
    load = (2 << 27) | (la << 26) | (lr << 25) | (address << 15) | (funct3 << 12) | (old << 7) | 0x2f
    store = (3 << 27) | (sa << 26) | (sr << 25) | (nxt << 20) | (address << 15) | (funct3 << 12) | (status << 7) | 0x2f
    alu = (value << 20) | (old << 15) | ({"fetch_add": 0, "fetch_and": 7, "fetch_or": 6, "fetch_xor": 4}[operation] << 12) | (nxt << 7) | (0x3b if word_alu else 0x33)
    imm = (-12) & 8191
    branch = ((imm >> 12) << 31) | (((imm >> 5) & 63) << 25) | (status << 15) | (1 << 12) | (((imm >> 1) & 15) << 8) | (((imm >> 11) & 1) << 7) | 0x63
    end = branch.to_bytes(4, "little")
    if compressed:
        imm = (-12) & 511
        cb = (7 << 13) | (((imm >> 8) & 1) << 12) | (((imm >> 3) & 3) << 10) | ((status - 8) << 7) | (((imm >> 6) & 3) << 5) | (((imm >> 1) & 3) << 3) | (((imm >> 5) & 1) << 2) | 1
        end = cb.to_bytes(2, "little")
    return b"".join(w.to_bytes(4, "little") for w in (load, alu, store)) + end


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("operation", ["fetch_add", "fetch_and", "fetch_or", "fetch_xor"])
@pytest.mark.parametrize("compressed", [False, True])
@pytest.mark.parametrize("order", [(False, False, False, False), (True, False, False, True), (True, True, True, True)])
def test_decode_and_exact_replay(bits, operation, compressed, order):
    value = candidate(code(bits, operation, compressed=compressed, order=order), base_address=0x1000)
    assert replay(value) == value
    assert value["operation"] == operation and value["memoryWidthBits"] == bits
    assert value["successExit"] == 0x1000 + (14 if compressed else 16)
    assert value["semanticApproval"] is False and value["compilerBindingComplete"] is False
    assert value["lrOrderingBits"] == dict(aq=order[0], rl=order[1])
    assert value["scOrderingBits"] == dict(aq=order[2], rl=order[3])


@pytest.mark.parametrize("registers", [(5, 6, 9, 10, 11), (11, 12, 13, 14, 15), (1, 2, 3, 4, 0)])
def test_register_roles_not_operand_position(registers):
    value = candidate(code(registers=registers))
    assert [value[k] for k in ("oldRegister", "nextRegister", "statusRegister", "addressRegister", "inputRegister")] == list(registers)


@pytest.mark.parametrize("operation", ["fetch_add", "fetch_and", "fetch_or", "fetch_xor"])
@pytest.mark.parametrize("bits", [32, 64])
def test_reference_all_success_outputs(operation, bits):
    value = candidate(code(bits, operation))
    mask64, mask = (1 << 64) - 1, (1 << bits) - 1
    for old in (0, 1, 0x7fffffff, 0x80000000, 0xffffffff, 1 << 63, mask64):
        for arg in (0, 1, 0xffffffff, 1 << 32, mask64):
            signed = old & mask
            if signed & (1 << (bits - 1)):
                signed -= 1 << bits
            loaded = signed & mask64
            expected = {"fetch_add": loaded + arg, "fetch_and": loaded & arg,
                        "fetch_or": loaded | arg, "fetch_xor": loaded ^ arg}[operation] & mask64
            assert successful_projection(value, old=old, input_value=arg) == {
                "oldRegisterValue": loaded, "nextRegisterValue": expected,
                "statusRegisterValue": 0, "storedValue": expected & mask}


def test_word_alu_distinct_from_store_width():
    regular = candidate(code(32))
    word = candidate(code(32, word_alu=True))
    a = successful_projection(regular, old=0x7fffffff, input_value=1)
    b = successful_projection(word, old=0x7fffffff, input_value=1)
    assert a["storedValue"] == b["storedValue"] == 0x80000000
    assert a["nextRegisterValue"] == 0x80000000
    assert b["nextRegisterValue"] == 0xffffffff80000000


@pytest.mark.parametrize("mutation", ["extra", "short", "loadrs2", "width", "address", "scvalue", "alias", "branchstatus", "branchop", "backedge", "aluop", "olddep"])
def test_invalid_sequences_rejected(mutation):
    raw = bytearray(code())
    if mutation == "extra": raw += b"\x13\x00\x00\x00"
    elif mutation == "short": raw = raw[:12]
    else:
        index, xor = {"loadrs2": (0, 1 << 20), "width": (8, 1 << 12),
                      "address": (8, 1 << 15), "scvalue": (8, 1 << 20),
                      "alias": (0, 5 << 7), "branchstatus": (12, 1 << 15),
                      "branchop": (12, 1 << 12), "backedge": (12, 1 << 8),
                      "aluop": (4, 1 << 25), "olddep": (4, 1 << 15)}[mutation]
        word = int.from_bytes(raw[index:index+4], "little") ^ xor
        raw[index:index+4] = word.to_bytes(4, "little")
    with pytest.raises(SequenceError): candidate(bytes(raw))


@pytest.mark.parametrize("key,value", [("operation", "fetch_or"), ("semanticApproval", True),
                                      ("compilerBindingComplete", True), ("nextRegister", 28),
                                      ("successExit", 99), ("extra", True)])
def test_rehashing_does_not_make_assertions_authoritative(key, value):
    changed = deepcopy(candidate(code()))
    changed[key] = value
    changed["sequenceIdentity"] = content_identity({k: v for k, v in changed.items() if k != "sequenceIdentity"})
    with pytest.raises(SequenceError): replay(changed)


def test_diagnostic_retains_memory_slot_and_never_approves():
    fragment = AsmFragment(id="fragment:test", outputs=[
        AsmOperand(constraint="=&r", exprText=n, isOutput=True) for n in ("old", "next", "status")
    ] + [AsmOperand(constraint="+A", exprText="*p", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText=n) for n in ("p", "v")])
    result = decision(fragment, code())
    validate_route_decision(result)
    payload = result["inputsPayload"]
    assert (payload["frontendOutputCount"], payload["frontendInputCount"], payload["frontendReadWriteCount"]) == (4, 2, 1)
    assert result["accepted"] is False and payload["semanticApproval"] is False
    assert payload["sequenceCandidate"]["semanticApproval"] is False
    assert decision(fragment, b"\x13\0\0\0") is None
    bad = decision(fragment, code() + b"\x13\0\0\0")
    assert bad["reasonCode"] == "LRSC_REGION_SHAPE_UNSUPPORTED"
    assert bad["accepted"] is False


def test_collector_preserves_frontend_and_python_mismatch(tmp_path):
    collect = runpy.run_path(str(Path(__file__).resolve().parents[2] / "experiment/inspect_lrsc_basis.py"))["collect"]
    for name, count in (("frontend-report.json", 4), ("translated_report.json", 3)):
        (tmp_path/name).write_text(json.dumps({"findings": [{"fragment": {
            "id": "same", "outputs": [{"constraint": "=&r"} for _ in range(count - 1)] + [{"constraint": "+A"}],
            "inputs": [{"constraint": "r"}, {"constraint": "r"}]}}]}))
    data = collect(tmp_path)
    assert [r["findings"][0]["outputCount"] for r in data["records"]] == [4, 3]
    assert not data["errors"] and data["semanticApproval"] is False
    (tmp_path/"raw_report.json").write_text("not json")
    assert collect(tmp_path)["errors"]
