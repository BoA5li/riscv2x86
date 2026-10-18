"""Compiler expression identities, separate from declaration/value identities.

This ingress preserves typed AST operations.  It does not prove memory bounds,
alignment or repeatability and never invents a declaration for an expression.
Unsupported nodes are retained as explicit rejected slots by the caller.
"""
from __future__ import annotations

from collections.abc import Mapping
import re

from .compiler_value_flow import identity
from .compiler_operand_type import compiler_operand_type_from_dict

SCHEMA = "riscv2x86.compiler-expression.v1"
_SHA = re.compile(r"sha256:[0-9a-f]{64}")
_FIELDS = {"schemaVersion", "sourceDigest", "functionIdentity", "sourceRange",
           "kind", "valueCategory", "canonicalType", "operation", "declarationIdentity",
           "literalValue", "children", "expressionIdentity"}
_CASTS = {"NoOp", "LValueToRValue", "IntegralCast", "IntegralToBoolean",
          "BitCast", "ArrayToPointerDecay"}


class CompilerExpressionError(ValueError):
    def __init__(self, reason_code, detail):
        super().__init__(detail)
        self.reason_code = reason_code


def _reject(code, detail):
    raise CompilerExpressionError(code, detail)


def expression_from_ast(node, *, source_digest, function_identity,
                        declaration_identity, source_range, type_resolver=None):
    """Encode a bounded AST grammar without stripping casts or evaluating C.

    `declaration_identity` and `source_range` are compiler-index callbacks.
    Names, raw Clang process pointers and runtime values are never join keys.
    """
    if not isinstance(node, Mapping):
        _reject("COMPILER_EXPRESSION_NODE_INVALID", "AST expression is not an object")
    children = node.get("inner", [])
    if not isinstance(children, list) or any(not isinstance(x, Mapping) for x in children):
        _reject("COMPILER_EXPRESSION_CHILDREN_INVALID", "AST children are malformed")
    kind = node.get("kind")
    operation = ""
    declaration = ""
    literal = ""
    if kind == "DeclRefExpr":
        referenced = node.get("referencedDecl", {})
        if not isinstance(referenced, Mapping):
            _reject("COMPILER_EXPRESSION_DECLARATION_UNBOUND", "Declaration reference is malformed")
        declaration = declaration_identity(referenced.get("id", ""))
        if not declaration or children:
            _reject("COMPILER_EXPRESSION_DECLARATION_UNBOUND", "Declaration is not in the compiler index")
    elif kind in {"IntegerLiteral", "CharacterLiteral"}:
        literal = str(node.get("value", ""))
        if not re.fullmatch(r"-?[0-9]+", literal) or children:
            _reject("COMPILER_EXPRESSION_LITERAL_INVALID", "Integer literal is missing")
    elif kind in {"ImplicitCastExpr", "CStyleCastExpr"}:
        operation = node.get("castKind", "")
        if operation not in _CASTS or len(children) != 1:
            _reject("COMPILER_EXPRESSION_CAST_UNSUPPORTED", "Cast kind/arity is not supported")
    elif kind == "ParenExpr":
        if len(children) != 1:
            _reject("COMPILER_EXPRESSION_ARITY_INVALID", "Parenthesized expression needs one child")
    elif kind == "UnaryOperator":
        operation = node.get("opcode", "")
        if operation not in {"*", "&", "+", "-", "~", "!"} or len(children) != 1:
            _reject("COMPILER_EXPRESSION_UNARY_UNSUPPORTED", "Unary operation has unsupported evaluation semantics")
    elif kind == "BinaryOperator":
        operation = node.get("opcode", "")
        if operation not in {"+", "-", "*", "&", "|", "^", "==", "!=", "<", "<=", ">", ">="} or len(children) != 2:
            _reject("COMPILER_EXPRESSION_BINARY_UNSUPPORTED", "Binary operation has unsupported evaluation semantics")
    elif kind == "ArraySubscriptExpr":
        if len(children) != 2:
            _reject("COMPILER_EXPRESSION_ARITY_INVALID", "Subscript requires base and index")
    else:
        _reject("COMPILER_EXPRESSION_KIND_UNSUPPORTED", "Unsupported compiler expression: " + str(kind))
    raw_type = node.get("type", {})
    if not isinstance(raw_type, Mapping):
        _reject("COMPILER_EXPRESSION_PROVENANCE_INCOMPLETE", "Expression type is malformed")
    canonical = raw_type.get("desugaredQualType") or raw_type.get("qualType", "")
    if type_resolver is not None:canonical=type_resolver(canonical)
    extent = source_range(node)
    category = node.get("valueCategory", "")
    if (not canonical or extent is None or category not in {"lvalue", "rvalue", "prvalue"}
            or not isinstance(source_digest, str) or not isinstance(function_identity, str)
            or _SHA.fullmatch(source_digest) is None or _SHA.fullmatch(function_identity) is None):
        _reject("COMPILER_EXPRESSION_PROVENANCE_INCOMPLETE", "Expression type/range/category/source is unavailable")
    result = {"schemaVersion": SCHEMA, "sourceDigest": source_digest,
        "functionIdentity": function_identity, "sourceRange": list(extent),
        "kind": kind, "valueCategory": category, "canonicalType": canonical,
        "operation": operation, "declarationIdentity": declaration,
        "literalValue": literal, "children": [expression_from_ast(x,
            source_digest=source_digest, function_identity=function_identity,
            declaration_identity=declaration_identity, source_range=source_range,
            type_resolver=type_resolver) for x in children]}
    result["expressionIdentity"] = identity(result)
    validate_expression(result, source_digest=source_digest, function_identity=function_identity)
    return result


def validate_expression(value, *, source_digest, function_identity):
    if not isinstance(value, Mapping) or set(value) != _FIELDS or value.get("schemaVersion") != SCHEMA:
        _reject("COMPILER_EXPRESSION_SCHEMA_INVALID", "Expression schema/fields are invalid")
    if (value["sourceDigest"] != source_digest or value["functionIdentity"] != function_identity
            or not isinstance(source_digest, str) or not isinstance(function_identity, str)
            or _SHA.fullmatch(source_digest) is None or _SHA.fullmatch(function_identity) is None):
        _reject("COMPILER_EXPRESSION_SOURCE_MISMATCH", "Expression source/function binding differs")
    if value["expressionIdentity"] != identity({k:v for k,v in value.items() if k != "expressionIdentity"}):
        _reject("COMPILER_EXPRESSION_IDENTITY_MISMATCH", "Expression identity is stale")
    extent = value["sourceRange"]
    if (not isinstance(extent, list) or len(extent) != 2 or any(type(x) is not int for x in extent)
            or not 0 <= extent[0] < extent[1] or not isinstance(value["children"], list)):
        _reject("COMPILER_EXPRESSION_RANGE_INVALID", "Expression extent/children are invalid")
    kind, operation, children = value["kind"], value["operation"], value["children"]
    if (value["valueCategory"] not in {"lvalue", "rvalue", "prvalue"}
            or not isinstance(value["canonicalType"], str) or not value["canonicalType"]
            or not isinstance(value["declarationIdentity"], str)
            or not isinstance(value["literalValue"], str)):
        _reject("COMPILER_EXPRESSION_PAYLOAD_INVALID", "Expression type/category/identity fields are invalid")
    arity = {"DeclRefExpr": 0, "IntegerLiteral": 0, "CharacterLiteral": 0,
        "ParenExpr": 1, "ImplicitCastExpr": 1, "CStyleCastExpr": 1,
        "UnaryOperator": 1, "BinaryOperator": 2, "ArraySubscriptExpr": 2}.get(kind)
    if arity is None or len(children) != arity:
        _reject("COMPILER_EXPRESSION_ARITY_INVALID", "Expression kind/arity is unsupported")
    allowed = (_CASTS if kind in {"ImplicitCastExpr", "CStyleCastExpr"} else
        {"*", "&", "+", "-", "~", "!"} if kind == "UnaryOperator" else
        {"+", "-", "*", "&", "|", "^", "==", "!=", "<", "<=", ">", ">="}
        if kind == "BinaryOperator" else {""})
    if operation not in allowed:
        _reject("COMPILER_EXPRESSION_OPERATION_INVALID", "Expression operation is unsupported")
    if ((kind == "DeclRefExpr") != bool(value["declarationIdentity"])
            or value["declarationIdentity"] and _SHA.fullmatch(value["declarationIdentity"]) is None
            or (kind in {"IntegerLiteral", "CharacterLiteral"}) != bool(value["literalValue"])
            or value["literalValue"] and re.fullmatch(r"-?[0-9]+", value["literalValue"]) is None):
        _reject("COMPILER_EXPRESSION_PAYLOAD_INVALID", "Declaration/literal roles are inconsistent")
    for child in value["children"]:
        validate_expression(child, source_digest=source_digest, function_identity=function_identity)
        if not extent[0] <= child["sourceRange"][0] < child["sourceRange"][1] <= extent[1]:
            _reject("COMPILER_EXPRESSION_RANGE_INVALID", "Child expression is outside parent extent")


def direct_declaration_carrier(expression):
    """Return a declaration only for a proven type-preserving carrier path.

    A numeric/pointer conversion is an expression, not the original carrier.
    It must use a future expression-aware route rather than a declaration alias.
    """
    current = expression
    while current["kind"] in {"ParenExpr", "ImplicitCastExpr", "CStyleCastExpr"}:
        child = current["children"][0]
        if (current["kind"] != "ParenExpr" and current["operation"] not in {"NoOp", "LValueToRValue"}
                or current["canonicalType"] != child["canonicalType"]):
            return ""
        current = child
    return current["declarationIdentity"] if current["kind"] == "DeclRefExpr" else ""


def validate_expression_slots(value, *, source_digest, function_identity,
                              candidate_identity, operand_count):
    fields = {"schemaVersion", "sourceDigest", "functionIdentity", "candidateIdentity",
              "slots", "complete", "factsIdentity"}
    if (not isinstance(value, Mapping) or set(value) != fields
            or value["schemaVersion"] != "riscv2x86.compiler-expression-slots.v1"
            or value["sourceDigest"] != source_digest
            or value["functionIdentity"] != function_identity
            or value["candidateIdentity"] != candidate_identity
            or value["factsIdentity"] != identity({k:v for k,v in value.items() if k != "factsIdentity"})):
        _reject("COMPILER_EXPRESSION_SLOTS_IDENTITY_INVALID", "Expression slots envelope is stale or unbound")
    slots = value["slots"]
    if not isinstance(slots, list) or len(slots) != operand_count or type(value["complete"]) is not bool:
        _reject("COMPILER_EXPRESSION_SLOTS_ARITY_INVALID", "Expression slots arity is invalid")
    for index, slot in enumerate(slots):
        if (not isinstance(slot, Mapping) or set(slot) != {
                "operandIndex", "complete", "expression", "reasonCode", "detail"}
                or type(slot["operandIndex"]) is not int or slot["operandIndex"] != index
                or type(slot["complete"]) is not bool):
            _reject("COMPILER_EXPRESSION_SLOT_INVALID", "Expression slot index/schema is invalid")
        if slot["complete"]:
            validate_expression(slot["expression"], source_digest=source_digest,
                                function_identity=function_identity)
            if slot["reasonCode"] or slot["detail"]:
                _reject("COMPILER_EXPRESSION_SLOT_INVALID", "Complete expression carries rejection")
        elif slot["expression"] is not None or not slot["reasonCode"] or not slot["detail"]:
            _reject("COMPILER_EXPRESSION_SLOT_INVALID", "Rejected expression has no precise reason")
    if value["complete"] != all(x["complete"] for x in slots):
        _reject("COMPILER_EXPRESSION_SLOT_INVALID", "Expression completeness differs from slots")


def bind_expression_operands(candidate, fragment, *, source_digest, function_identity):
    """Bind AST expressions to Clang API types/GNU roles before legacy closure.

    A successful join establishes identity and evaluation facts only. It does
    not establish object bounds, route support, instruction semantics or L2
    eligibility. Memory constraints with alternatives remain unclassified.
    """
    outputs, inputs = fragment.get("outputs"), fragment.get("inputs")
    if (not isinstance(outputs, list) or not isinstance(inputs, list)
            or any(not isinstance(x, Mapping) for x in outputs + inputs)):
        _reject("COMPILER_EXPRESSION_FRONTEND_OPERANDS_INVALID", "Frontend GNU operand partition is malformed")
    operands = outputs + inputs
    facts = candidate.get("compilerExpressionFacts")
    validate_expression_slots(facts, source_digest=source_digest,
        function_identity=function_identity, candidate_identity=candidate.get("candidateIdentity"),
        operand_count=len(operands))
    if not facts["complete"]:
        first = next(x for x in facts["slots"] if not x["complete"])
        _reject(first["reasonCode"], first["detail"])
    bound = []
    for index, (slot, operand) in enumerate(zip(facts["slots"], operands)):
        expression = slot["expression"]
        try:
            ctype = compiler_operand_type_from_dict(operand.get("compilerType"))
        except ValueError as exc:
            _reject("COMPILER_EXPRESSION_TYPE_AUTHORITY_INVALID", str(exc))
        # Compare canonical names, not typedef spelling. Qualifiers remain in
        # the compiler type record and require a route-specific contract.
        expression_type = " ".join(expression["canonicalType"].split())
        qualified = " ".join((ctype.qualifiers + " " + ctype.canonical_type).split())
        if expression_type not in {ctype.canonical_type, qualified}:
            _reject("COMPILER_EXPRESSION_TYPE_MISMATCH", "AST/API expression types disagree at operand " + str(index))
        if not ctype.side_effect_free:
            _reject("COMPILER_EXPRESSION_EVALUATION_CONTRACT_REQUIRED", "Side-effecting expression needs an evaluate-once contract")
        constraint = operand.get("constraint")
        if not isinstance(constraint, str) or not constraint:
            _reject("COMPILER_EXPRESSION_CONSTRAINT_MISSING", "GNU constraint is missing")
        output = index < len(fragment.get("outputs", []))
        access = "read_write" if output and constraint.startswith("+") else "output" if output else "input"
        if output and not ctype.modifiable_lvalue:
            _reject("COMPILER_EXPRESSION_OUTPUT_NOT_MODIFIABLE", "Output expression is not a modifiable lvalue")
        # This is the compiler operand constraint, not an asm-template match.
        from .gnu_operand_contract import parse_riscv_operand
        try:contract=parse_riscv_operand(constraint,output=output)
        except ValueError as exc:
            _reject('COMPILER_EXPRESSION_CONSTRAINT_CONTRACT_REQUIRED',
                str(exc)+' at operand '+str(index)+' constraint '+repr(constraint))
        body = constraint.lstrip("=+&%")
        if contract.role == "memory_lvalue":
            role = "memory_lvalue"
            if expression["valueCategory"] != "lvalue":
                _reject("COMPILER_EXPRESSION_MEMORY_NOT_LVALUE", "Memory operand is not an lvalue")
        elif body in {"r", "i", "n"} or body.isdecimal():
            role = "address_value" if ctype.is_pointer else "scalar_value"
        else:
            _reject("COMPILER_EXPRESSION_CONSTRAINT_CONTRACT_REQUIRED", "Constraint alternative/fixed-register contract is unavailable")
        bound.append({"operandIndex": index, "expressionIdentity": expression["expressionIdentity"],
            "declarationIdentity": direct_declaration_carrier(expression), "role": role,
            "access": access, "sourceConstraint": constraint, "compilerType": operand["compilerType"],
            "compilerTypeIdentity": ctype.type_identity, "expression": expression})
    result = {"schemaVersion": "riscv2x86.compiler-expression-join.v1",
        "sourceDigest": source_digest, "functionIdentity": function_identity,
        "candidateIdentity": candidate["candidateIdentity"],
        "fragmentId": fragment.get("fragmentId") or fragment.get("id"),
        "expressionFactsIdentity": facts["factsIdentity"], "operands": bound,
        "complete": True, "semanticRouteApproved": False}
    result["joinIdentity"] = identity(result)
    return result
