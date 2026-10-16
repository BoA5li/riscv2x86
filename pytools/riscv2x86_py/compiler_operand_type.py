"""Clang API type facts. Never substitute a value identity for a C type."""
from dataclasses import dataclass
from .route_authority import content_identity

SCHEMA = "riscv2x86.clang-operand-type.v1"


@dataclass(frozen=True)
class CompilerOperandType:
    canonical_type: str
    width_bits: int
    alignment_bytes: int
    is_integer: bool
    is_pointer: bool
    is_signed: bool
    pointee_type: str
    pointee_width_bits: int
    pointee_alignment_bytes: int
    pointee_is_integer: bool
    side_effect_free: bool
    modifiable_lvalue: bool
    qualifiers: str
    pointee_qualifiers: str
    expression_repeatable: bool

    @property
    def type_identity(self):
        return content_identity({"schemaVersion": "riscv2x86.compiler-c-type.v1",
            "canonicalType": self.canonical_type, "widthBits": self.width_bits,
            "alignmentBytes": self.alignment_bytes})

    @property
    def pointee_type_identity(self):
        if not self.is_pointer or not self.pointee_is_integer:
            return ""
        return content_identity({"schemaVersion": "riscv2x86.compiler-c-type.v1",
            "canonicalType": self.pointee_type, "widthBits": self.pointee_width_bits,
            "alignmentBytes": self.pointee_alignment_bytes})


def compiler_operand_type_from_dict(value):
    fields = ("canonicalType", "widthBits", "alignmentBytes", "isInteger",
        "isPointer", "isSigned", "pointeeType", "pointeeWidthBits",
        "pointeeAlignmentBytes", "pointeeIsInteger", "sideEffectFree", "modifiableLvalue",
        "qualifiers", "pointeeQualifiers", "expressionRepeatable")
    if not isinstance(value, dict) or set(value) != {*fields, "schemaVersion"} or value["schemaVersion"] != SCHEMA:
        raise ValueError("COMPILER_OPERAND_TYPE_SCHEMA_INVALID")
    if any(type(value[k]) is not bool for k in ("isInteger", "isPointer", "isSigned",
            "pointeeIsInteger", "sideEffectFree", "modifiableLvalue", "expressionRepeatable")):
        raise ValueError("COMPILER_OPERAND_TYPE_FLAGS_INVALID")
    if (not isinstance(value["canonicalType"], str) or not value["canonicalType"]
            or not isinstance(value["pointeeType"], str)
            or not isinstance(value["qualifiers"], str) or not isinstance(value["pointeeQualifiers"], str)
            or any(type(value[k]) is not int or value[k] < 0 for k in
                ("widthBits", "alignmentBytes", "pointeeWidthBits", "pointeeAlignmentBytes"))
            or value["widthBits"] == 0 or value["alignmentBytes"] == 0
            or value["isPointer"] == value["isInteger"]
            or (value["isPointer"] and (not value["pointeeIsInteger"] or not value["pointeeType"]
                or value["pointeeWidthBits"] not in {8,16,32,64} or value["pointeeAlignmentBytes"] == 0))
            or (not value["isPointer"] and (value["pointeeType"] or value["pointeeWidthBits"]
                or value["pointeeAlignmentBytes"] or value["pointeeIsInteger"]))):
        raise ValueError("COMPILER_OPERAND_TYPE_INCOMPLETE")
    return CompilerOperandType(*(value[k] for k in fields))
