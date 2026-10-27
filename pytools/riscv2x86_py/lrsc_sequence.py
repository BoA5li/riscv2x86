"""Machine-owned LR/SC RMW candidates, never translation approval.

The initial closed domain is four RV64 instructions: LR, register ALU,
SC, BNE(status, zero, LR). No mnemonic or GNU operand-position inference.
Compiler object/operand closure, ordering refinement, output liveness, and
termination remain separate obligations. A candidate must not populate the
single-AMO canonical operation field.
"""
from collections.abc import Mapping
from hashlib import sha256

from .route_authority import content_identity


SCHEMA = "riscv2x86.lrsc-machine-sequence.v1"
_ALU = {0: "fetch_add", 4: "fetch_xor", 6: "fetch_or", 7: "fetch_and"}


class SequenceError(ValueError):
    def __init__(self, code):
        self.reason_code = code
        super().__init__(code)


def _require(condition, code):
    if not condition:
        raise SequenceError(code)


def _reg(word, shift):
    return (word >> shift) & 31


def _signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def _atomic(word, kind):
    _require(word & 127 == 0x2f and word >> 27 == kind,
             "LRSC_INSTRUCTION_KIND_UNSUPPORTED")
    bits = {2: 32, 3: 64}.get((word >> 12) & 7)
    _require(bits is not None, "LRSC_WIDTH_UNSUPPORTED")
    return {"widthBits": bits, "rd": _reg(word, 7),
            "rs1": _reg(word, 15), "rs2": _reg(word, 20),
            "aq": bool(word & (1 << 26)), "rl": bool(word & (1 << 25))}


def candidate(machine_bytes, *, base_address=0, xlen_bits=64):
    """Decode and verify this finite machine region; no source names used."""
    _require(type(machine_bytes) is bytes, "LRSC_BYTES_REQUIRED")
    _require(type(base_address) is int and base_address >= 0
             and base_address % 2 == 0, "LRSC_BASE_ADDRESS_INVALID")
    _require(type(xlen_bits) is int and xlen_bits == 64, "LRSC_XLEN_UNSUPPORTED")
    # Three standard instructions plus a standard or compressed retry branch.
    _require(len(machine_bytes) in (14, 16), "LRSC_REGION_SHAPE_UNSUPPORTED")
    words = [int.from_bytes(machine_bytes[i:i+4], "little") for i in (0, 4, 8)]
    lr, sc = _atomic(words[0], 2), _atomic(words[2], 3)
    _require(lr["rs2"] == 0, "LRSC_LR_ENCODING_INVALID")
    _require(lr["widthBits"] == sc["widthBits"], "LRSC_ACCESS_WIDTH_MISMATCH")
    _require(lr["rs1"] == sc["rs1"] != 0, "LRSC_ADDRESS_MISMATCH")
    alu = words[1]
    _require(alu & 127 in (0x33, 0x3b) and alu >> 25 == 0,
             "LRSC_ALU_UNSUPPORTED")
    operation = _ALU.get((alu >> 12) & 7)
    _require(operation is not None, "LRSC_ALU_UNSUPPORTED")
    arithmetic_bits = 32 if alu & 127 == 0x3b else 64
    _require(arithmetic_bits == 64 or (operation == "fetch_add" and lr["widthBits"] == 32),
             "LRSC_ALU_WIDTH_UNSUPPORTED")
    next_reg, left, right = _reg(alu, 7), _reg(alu, 15), _reg(alu, 20)
    _require((left == lr["rd"]) != (right == lr["rd"]),
             "LRSC_OLD_VALUE_DEPENDENCY_INVALID")
    input_reg = right if left == lr["rd"] else left
    _require(sc["rs2"] == next_reg, "LRSC_STORE_VALUE_MISMATCH")
    # Other aliasing forms need their own state/output proof, not a guess.
    roles = [lr["rd"], next_reg, sc["rd"], lr["rs1"]]
    _require(all(roles) and len(set(roles)) == 4 and input_reg not in roles,
             "LRSC_REGISTER_INTERFERENCE_UNSUPPORTED")
    branch = int.from_bytes(machine_bytes[12:], "little")
    if len(machine_bytes) == 16:
        _require(branch & 127 == 0x63 and (branch >> 12) & 7 == 1,
                 "LRSC_RETRY_BRANCH_UNSUPPORTED")
        _require({_reg(branch, 15), _reg(branch, 20)} == {sc["rd"], 0},
                 "LRSC_RETRY_STATUS_MISMATCH")
        offset = _signed(((branch >> 31) << 12) | (((branch >> 7) & 1) << 11)
                         | (((branch >> 25) & 63) << 5) | (((branch >> 8) & 15) << 1), 13)
    else:
        _require(branch & 3 == 1 and branch >> 13 == 7,
                 "LRSC_RETRY_BRANCH_UNSUPPORTED")
        _require(8 + ((branch >> 7) & 7) == sc["rd"], "LRSC_RETRY_STATUS_MISMATCH")
        offset = _signed((((branch >> 12) & 1) << 8) | (((branch >> 10) & 3) << 3)
                         | (((branch >> 5) & 3) << 6) | (((branch >> 3) & 3) << 1)
                         | (((branch >> 2) & 1) << 5), 9)
    _require(offset == -12, "LRSC_RETRY_TARGET_MISMATCH")
    _require(base_address + len(machine_bytes) <= 1 << xlen_bits,
             "LRSC_ADDRESS_OVERFLOW")
    body = {
        "schemaVersion": SCHEMA, "machineBytes": machine_bytes.hex(),
        "machineDigest": "sha256:" + sha256(machine_bytes).hexdigest(),
        "baseAddress": base_address, "xlenBits": xlen_bits,
        "memoryWidthBits": lr["widthBits"], "arithmeticWidthBits": arithmetic_bits,
        "operation": operation, "addressRegister": lr["rs1"],
        "inputRegister": input_reg, "oldRegister": lr["rd"],
        "nextRegister": next_reg, "statusRegister": sc["rd"],
        "lrOrderingBits": {k: lr[k] for k in ("aq", "rl")},
        "scOrderingBits": {k: sc[k] for k in ("aq", "rl")},
        "instructionAddresses": [base_address + i for i in (0, 4, 8, 12)],
        "retryTarget": base_address, "successExit": base_address + len(machine_bytes),
        "compilerBindingComplete": False, "semanticApproval": False,
        "notProved": ["compiler-object-and-operand-binding", "shell-and-output-projection",
                      "source-target-ordering-refinement", "termination-and-concurrent-progress",
                      "physical-microarchitecture-equivalence"],
    }
    return dict(body, sequenceIdentity=content_identity(body))


def replay(value):
    """Re-decode bytes and require exact content equality, including field set."""
    _require(isinstance(value, Mapping), "LRSC_SEQUENCE_INVALID")
    try:
        result = candidate(bytes.fromhex(value["machineBytes"]),
                           base_address=value["baseAddress"], xlen_bits=value["xlenBits"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SequenceError("LRSC_SEQUENCE_REPLAY_FAILED") from exc
    _require(dict(value) == result, "LRSC_SEQUENCE_REPLAY_MISMATCH")
    return result


def successful_projection(value, *, old, input_value):
    """Pure reference model for one successful iteration, not measured values.

    Preserve next's full XLEN result: the SC store and old return projections
    need not have the same width as the ALU. Failure rd is not assigned 1.
    """
    spec = replay(value)
    _require(type(old) is int and type(input_value) is int,
             "LRSC_REFERENCE_INTEGER_REQUIRED")
    width, arithmetic = spec["memoryWidthBits"], spec["arithmeticWidthBits"]
    mask = (1 << width) - 1
    old_reg = _signed(old & mask, width) & ((1 << 64) - 1)
    arg = input_value & ((1 << 64) - 1)
    op = spec["operation"]
    next_value = {"fetch_add": lambda: old_reg + arg,
                  "fetch_and": lambda: old_reg & arg,
                  "fetch_or": lambda: old_reg | arg,
                  "fetch_xor": lambda: old_reg ^ arg}[op]() & ((1 << arithmetic) - 1)
    if arithmetic == 32:
        next_value = _signed(next_value, 32) & ((1 << 64) - 1)
    return {"oldRegisterValue": old_reg, "nextRegisterValue": next_value,
            "statusRegisterValue": 0, "storedValue": next_value & mask}
