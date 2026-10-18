"""Authoritative closure of compiler AST and GNU inline-asm fragment facts.

Clang JSON AST versions do not consistently export the output/input partition
of ``GCCAsmStmt.inner``.  The C++ frontend does export that partition and the
GNU constraints.  This module performs the content-bound join once so typed
consumers never guess operand roles from assembly text or variable names.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from typing import Mapping
from .compiler_expression import validate_expression_slots, direct_declaration_carrier
from .compiler_expression_evaluation import close_expression_evaluation
from .compiler_operand_type import compiler_operand_type_from_dict


CLOSED_COMPILER_FRAGMENT_SCHEMA = "riscv2x86.closed-compiler-fragment.v1"


def _identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def _operand_access(operand: Mapping[str, object], *, output: bool) -> str:
    constraint = operand.get("constraint")
    if not isinstance(constraint, str) or not constraint:
        raise ValueError("frontend operand constraint is missing")
    return "read_write" if output and constraint.startswith("+") else (
        "output" if output else "input")



class CompilerOperandClosureError(ValueError):
    def __init__(self, message, *, incomplete=False, diagnostics=None):
        super().__init__(message)
        self.incomplete = incomplete
        self.reason_code = ("COMPILER_OPERAND_EXPRESSION_AUTHORITY_INCOMPLETE" if incomplete
                            else "COMPILER_FRONTEND_OPERAND_ARITY_MISMATCH")
        self.diagnostics = diagnostics or {}

def _close_declaration_candidate(
    candidate: Mapping[str, object], fragment: Mapping[str, object], *,
    source_digest: str, function_identity: str,
) -> dict[str, object]:
    """Join compiler carriers to frontend-owned operand roles, fail closed.

    The ordered carrier list is compiler authority.  The output/input split
    and constraints are frontend authority.  Both identities are included in
    the closure identity, and disagreement is rejected instead of repaired.
    """
    key = candidate.get("fragmentBindingKey")
    carriers = candidate.get("operandCarriers")
    nodes = candidate.get("valueNodes")
    outputs, inputs = fragment.get("outputs"), fragment.get("inputs")
    if not isinstance(key, Mapping):
        raise ValueError("compiler fragment binding key is missing")
    if (key.get("sourceDigest") != source_digest
            or key.get("functionIdentity") != function_identity):
        raise ValueError("compiler fragment authority identity mismatch")
    if not isinstance(carriers, list) or not isinstance(nodes, list):
        raise ValueError("compiler fragment carriers/value nodes are missing")
    if not isinstance(outputs, list) or not isinstance(inputs, list):
        raise ValueError("frontend fragment operand partition is missing")
    frontend_operands = outputs + inputs
    expression_facts = candidate.get("compilerExpressionFacts")
    if expression_facts is not None:
        validate_expression_slots(expression_facts, source_digest=source_digest,
            function_identity=function_identity, candidate_identity=candidate.get("candidateIdentity"),
            operand_count=len(frontend_operands))
    slots = candidate.get("operandSlotFacts")
    records = slots.get("slots") if isinstance(slots, Mapping) else None
    slot_count = len(records) if isinstance(records, list) else len(carriers)
    diagnostics = {
        "frontendOutputCount": len(outputs), "frontendInputCount": len(inputs),
        "compilerOperandSlotCount": slot_count, "materializedCarrierCount": len(carriers),
        "missingOperandIndexes": sorted(set(range(len(frontend_operands))) -
            {x.get("operandIndex") for x in carriers if isinstance(x, Mapping)}),
        "unsupportedExpressionKinds": sorted({str(x.get("expressionKind", ""))
            for x in records or [] if x.get("complete") is not True}),
        "operandSlots": records or [],
        "compilerExpressionFacts": expression_facts,
    }
    if slot_count != len(frontend_operands):
        raise CompilerOperandClosureError("compiler/frontend operand arity mismatch",
                                          diagnostics=diagnostics)
    if records is not None and any(x.get("complete") is not True for x in records):
        raise CompilerOperandClosureError("compiler operand expression authority is incomplete",
                                          incomplete=True, diagnostics=diagnostics)
    if candidate.get("compilerStructureComplete") is not True:
        raise ValueError("compiler fragment structure is incomplete")
    if len(carriers) != len(frontend_operands):
        raise CompilerOperandClosureError("compiler/frontend operand arity mismatch",
                                          diagnostics=diagnostics)

    node_ids = {item.get("nodeIdentity") for item in nodes
                if isinstance(item, Mapping)}
    bindings: list[dict[str, object]] = []
    for index, (carrier, operand) in enumerate(zip(carriers, frontend_operands)):
        if not isinstance(carrier, Mapping) or not isinstance(operand, Mapping):
            raise ValueError("compiler/frontend operand record is malformed")
        if carrier.get("operandIndex") != index or carrier.get("complete") is not True:
            raise ValueError("compiler operand carrier ordering is incomplete")
        declaration = carrier.get("declarationIdentity")
        value_node = carrier.get("valueNodeIdentity")
        width = carrier.get("widthBits")
        signedness = carrier.get("signedness")
        if expression_facts is not None:
            expression_slot = expression_facts["slots"][index]
            if expression_slot["complete"] and direct_declaration_carrier(
                    expression_slot["expression"]) != declaration:
                raise ValueError("COMPILER_EXPRESSION_DECLARATION_CARRIER_MISMATCH")
        if (not isinstance(declaration, str) or not declaration
                or value_node not in node_ids
                or isinstance(width, bool) or not isinstance(width, int) or width <= 0
                or signedness not in {"signed", "unsigned"}):
            raise ValueError("compiler operand carrier is incomplete")
        bindings.append({
            "operandIndex": index,
            "declarationIdentity": declaration,
            "valueNodeIdentity": value_node,
            "access": _operand_access(operand, output=index < len(outputs)),
            "widthBits": width,
            "signedness": signedness,
            "complete": True,
        })

    uses = candidate.get("downstreamUses")
    if candidate.get("downstreamUseEnumerationComplete") is not True \
            or not isinstance(uses, list):
        raise ValueError("compiler downstream-use enumeration is incomplete")
    uses = [dict(item) for item in uses if isinstance(item, Mapping)]
    used = {item.get("valueNodeIdentity") for item in uses}
    for binding in bindings[:len(outputs)]:
        node = binding["valueNodeIdentity"]
        if node in used:
            continue
        use = {
            "valueNodeIdentity": node,
            "useNodeIdentity": _identity({
                "schemaVersion": "riscv2x86.compiler-dead-output.v1",
                "candidateIdentity": candidate.get("candidateIdentity"),
                "declarationIdentity": binding["declarationIdentity"],
                "valueNodeIdentity": node,
            }),
            "useKind": "discarded",
            "consumerFragmentIdentity": "",
            "observationSinkIdentity": "",
            "relationKind": "discarded",
            "complete": True,
        }
        uses.append(use)

    result = dict(candidate)
    result.update({
        "schemaVersion": CLOSED_COMPILER_FRAGMENT_SCHEMA,
        "sourceCandidateSchemaVersion": candidate.get("schemaVersion"),
        "operandBindings": bindings,
        "operandClassificationComplete": True,
        "downstreamUses": uses,
        "complete": True,
        "reasonCodes": [],
        "classificationReasonCodes": [],
        "closureProvenance": {
            "compilerCandidateIdentity": candidate.get("candidateIdentity"),
            "frontendFragmentIdentity": (
                fragment.get("fragmentId") or fragment.get("id")),
            "producerIdentities": [
                "clang-json-ast.compiler-value-flow.v2",
                "clang-tooling.gnu-inline-asm-fragment.v1",
            ],
        },
    })
    unsigned = dict(result)
    unsigned.pop("closureIdentity", None)
    result["closureIdentity"] = _identity(unsigned)
    return result


EXPRESSION_CLOSED_SCHEMA = "riscv2x86.closed-compiler-fragment.v2"


def close_compiler_fragment_candidate(candidate, fragment, *, source_digest, function_identity):
    try:
        return _close_declaration_candidate(candidate, fragment,
            source_digest=source_digest, function_identity=function_identity)
    except CompilerOperandClosureError as exc:
        if not exc.incomplete:
            raise
        facts = candidate.get('compilerExpressionFacts')
        if not isinstance(facts, Mapping) or facts.get('complete') is not True:
            raise
        try:
            return _close_expression_candidate(candidate, fragment,
                source_digest=source_digest, function_identity=function_identity)
        except ValueError as evaluation_error:
            exc.diagnostics['expressionClosureFailure'] = {
                'reasonCode': getattr(evaluation_error, 'reason_code', 'COMPILER_EXPRESSION_CLOSURE_REJECTED'),
                'detail': str(evaluation_error)}
            raise exc from evaluation_error


def _close_expression_candidate(candidate, fragment, *, source_digest, function_identity):
    """Close memory lvalues without pretending they are declaration values.

    Only legacy incompleteness caused by non-declaration memory slots is
    recovered. Scalar expression outputs require a separate def-use producer.
    Object/effect approval remains a downstream semantic obligation.
    """
    evaluation = close_expression_evaluation(candidate, fragment,
        source_digest=source_digest, function_identity=function_identity)
    key = candidate.get('fragmentBindingKey', {})
    if (key.get('sourceDigest') != source_digest or key.get('functionIdentity') != function_identity
            or type(key.get('beginOffset')) is not int or type(key.get('endOffset')) is not int
            or key['beginOffset'] < 0 or key['endOffset'] < key['beginOffset']
            or set(candidate.get('reasonCodes', [])) - {
                'L2_FRAGMENT_DECLARATION_IDENTITY_MISSING', 'L2_FRAGMENT_VALUE_NODE_MISSING'}
            or candidate.get('downstreamUseEnumerationComplete') is not True):
        raise ValueError('COMPILER_EXPRESSION_FRAGMENT_STRUCTURE_UNPROVEN')
    existing = {x['operandIndex']: x for x in candidate['operandCarriers']}
    if len(existing) != len(candidate['operandCarriers']):
        raise ValueError('COMPILER_EXPRESSION_DUPLICATE_CARRIER')
    carriers, bindings, nodes = [], [], list(candidate['valueNodes'])
    node_ids = {x['nodeIdentity'] for x in nodes}
    for item, joined in zip(evaluation['bindings'], evaluation['expressionJoin']['operands']):
        index = item['operandIndex']
        carrier = existing.get(index)
        if carrier is not None:
            if (carrier['declarationIdentity'] != item['declarationIdentity']
                    or carrier['valueNodeIdentity'] not in node_ids or carrier.get('complete') is not True):
                raise ValueError('COMPILER_EXPRESSION_DECLARATION_CARRIER_MISMATCH')
            typ = compiler_operand_type_from_dict(joined['compilerType'])
            if (carrier.get('widthBits') != typ.width_bits
                    or carrier.get('signedness') != ('signed' if typ.is_signed else 'unsigned')
                    or carrier.get('carrierKind') != ('pointer' if typ.is_pointer else 'integer')):
                raise ValueError('COMPILER_EXPRESSION_TYPE_CARRIER_MISMATCH')
            carrier = dict(carrier)
        else:
            if item['role'] != 'memory_lvalue' or item['declarationIdentity']:
                raise ValueError('COMPILER_EXPRESSION_SCALAR_VALUE_FLOW_REQUIRED')
            typ = compiler_operand_type_from_dict(joined['compilerType'])
            address = item['addressNode']
            node = {**address, 'nodeIdentity': address['valueNodeIdentity'],
                    'complete': True}
            nodes.append(node)
            carrier = {'schemaVersion': 'riscv2x86.compiler-expression-carrier.v1',
                'operandIndex': index, 'declarationIdentity': '',
                'expressionIdentity': item['expressionIdentity'],
                'valueNodeIdentity': address['valueNodeIdentity'],
                'carrierKind': 'memory_lvalue', 'widthBits': typ.width_bits,
                'signedness': 'signed' if typ.is_signed else 'unsigned',
                'addressSpaceIdentity': '', 'complete': True,
                'evaluationBindingIdentity': item['bindingIdentity']}
        carriers.append(carrier)
        bindings.append({'operandIndex': index, 'declarationIdentity': carrier['declarationIdentity'],
            'valueNodeIdentity': carrier['valueNodeIdentity'], 'access': item['access'],
            'widthBits': carrier['widthBits'], 'signedness': carrier['signedness'], 'complete': True})
    result = dict(candidate)
    result.update(schemaVersion=EXPRESSION_CLOSED_SCHEMA,
        sourceCandidateSchemaVersion=candidate['schemaVersion'],
        compilerStructureComplete=True, operandClassificationComplete=True,
        complete=True, reasonCodes=[], classificationReasonCodes=[],
        operandCarriers=carriers, operandBindings=bindings, valueNodes=nodes,
        expressionEvaluation=evaluation,
        expressionClosureInputs={'candidate': deepcopy(candidate), 'fragment': deepcopy({
            'id': fragment.get('fragmentId') or fragment.get('id'),
            'outputs': fragment['outputs'], 'inputs': fragment['inputs']})},
        closureProvenance={'compilerCandidateIdentity': candidate['candidateIdentity'],
            'frontendFragmentIdentity': fragment.get('fragmentId') or fragment.get('id'),
            'producerIdentities': ['clang-json-ast.compiler-value-flow.v2',
                                   'clang-tooling.gnu-inline-asm-fragment.v1']})
    result['closureIdentity'] = _identity(result)
    return result


def validate_closed_compiler_fragment_candidate(
    candidate: Mapping[str, object],
) -> None:
    """Validate the closed payload before a typed semantic consumer uses it."""
    if candidate.get('schemaVersion') == EXPRESSION_CLOSED_SCHEMA:
        inputs = candidate.get('expressionClosureInputs')
        if not isinstance(inputs, Mapping) or set(inputs) != {'candidate', 'fragment'}:
            raise ValueError('COMPILER_EXPRESSION_CLOSURE_INPUTS_MISSING')
        original = inputs['candidate']
        key = original.get('fragmentBindingKey', {})
        rebuilt = _close_expression_candidate(original, inputs['fragment'],
            source_digest=key.get('sourceDigest'), function_identity=key.get('functionIdentity'))
        if dict(candidate) != rebuilt:
            raise ValueError('COMPILER_EXPRESSION_CLOSURE_MISMATCH')
        return
    if candidate.get("schemaVersion") != CLOSED_COMPILER_FRAGMENT_SCHEMA:
        raise ValueError("closed compiler fragment schema is unsupported")
    declared = candidate.get("closureIdentity")
    unsigned = dict(candidate)
    unsigned.pop("closureIdentity", None)
    if not isinstance(declared, str) or declared != _identity(unsigned):
        raise ValueError("closed compiler fragment identity is invalid")
    provenance = candidate.get("closureProvenance")
    if (not isinstance(provenance, Mapping)
            or not provenance.get("compilerCandidateIdentity")
            or not provenance.get("frontendFragmentIdentity")
            or provenance.get("producerIdentities") != [
                "clang-json-ast.compiler-value-flow.v2",
                "clang-tooling.gnu-inline-asm-fragment.v1",
            ]):
        raise ValueError("closed compiler fragment provenance is incomplete")
    if (candidate.get("complete") is not True
            or candidate.get("compilerStructureComplete") is not True
            or candidate.get("operandClassificationComplete") is not True
            or candidate.get("downstreamUseEnumerationComplete") is not True):
        raise ValueError("closed compiler fragment is incomplete")
