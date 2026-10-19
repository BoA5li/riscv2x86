"""Compiler-owned scalar result uses, distinct from hidden CSR state escape."""
from dataclasses import dataclass
from .compiler_value_flow import compiler_downstream_use_from_dict
from .semantic_content import semantic_identity
import re

_SHA = re.compile(r'sha256:[0-9a-f]{64}')
_RELATIONS = {
    'function_return': {'function_return', 'identity'},
    'c_expression': {'pure_integer_expression', 'integer_cast', 'bit_preserving_cast', 'identity'},
    'subsequent_asm_input': {'fragment_operand', 'identity'},
    'branch_condition': {'control_predicate', 'identity'},
    'discarded': {'discarded'}, 'dead': {'discarded'},
}


@dataclass(frozen=True)
class CsrResultValueFlow:
    fragment_id: str
    compiler_authority_identity: str
    closure_identity: str
    operand_index: int
    value_node_identity: str
    uses: tuple
    enumeration_complete: bool

    def validate(self):
        if (not self.fragment_id or type(self.operand_index) is not int or self.operand_index < 0
                or any(not isinstance(x, str) or _SHA.fullmatch(x) is None for x in (
                    self.compiler_authority_identity, self.closure_identity, self.value_node_identity))
                or type(self.enumeration_complete) is not bool):
            raise ValueError('CSR_RESULT_FLOW_BINDING_INVALID')
        identities = set()
        for use in self.uses:
            # Replay the producer schema as well as the CSR-specific relation.
            parsed = compiler_downstream_use_from_dict(use.to_dict())
            if parsed.value_node_identity != self.value_node_identity or parsed.use_node_identity in identities:
                raise ValueError('CSR_RESULT_FLOW_USE_BINDING_INVALID')
            identities.add(parsed.use_node_identity)
            if parsed.complete and parsed.relation_kind not in _RELATIONS.get(parsed.use_kind, set()):
                raise ValueError('CSR_RESULT_FLOW_RELATION_MISMATCH')
            if parsed.use_kind == 'subsequent_asm_input' and not parsed.consumer_fragment_identity:
                raise ValueError('CSR_RESULT_FLOW_CONSUMER_MISSING')
            if parsed.use_kind in {'dead', 'discarded'} and (parsed.observation_sink_identity or parsed.consumer_fragment_identity):
                raise ValueError('CSR_RESULT_FLOW_DISCARD_HAS_SINK')
        if len(self.uses) > 1 and any(x.use_kind in {'dead', 'discarded'} for x in self.uses):
            raise ValueError('CSR_RESULT_FLOW_DISCARD_CONFLICT')

    @property
    def complete(self):
        self.validate()
        return self.enumeration_complete and bool(self.uses) and all(x.complete for x in self.uses)

    @property
    def flow_identity(self):
        self.validate()
        return semantic_identity({'schemaVersion': 'riscv2x86.csr-result-value-flow.v1',
                                  'flow': self})


def result_flows_from_compiler(fragment_id, authority):
    """Called only after the common compiler envelope/closure validator."""
    candidate = authority['candidate']
    uses = tuple(compiler_downstream_use_from_dict(x) for x in candidate['downstreamUses'])
    flows = {}
    for binding in candidate['operandBindings']:
        if binding['access'] not in {'output', 'read_write'}:
            continue
        flow = CsrResultValueFlow(fragment_id, authority['authorityIdentity'], candidate['closureIdentity'],
            binding['operandIndex'], binding['valueNodeIdentity'],
            tuple(x for x in uses if x.value_node_identity == binding['valueNodeIdentity']),
            candidate.get('downstreamUseEnumerationComplete') is True)
        flow.validate()
        flows[binding['operandIndex']] = flow
    return flows
