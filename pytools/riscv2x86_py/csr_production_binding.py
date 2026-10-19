"""CSR decoder/compiler join. Static binding never grants execution permission."""
from dataclasses import asdict
from types import SimpleNamespace

from .compiler_provenance import bind_compiler_provenance
from .csr_value_flow import CsrOperandAuthorityFacts, _effect_id
from .csr_result_flow import result_flows_from_compiler
from .gnu_operand_contract import parse_riscv_operand
from .route_authority import content_identity
from .runtime_facts import canonicalize_riscv_register_name


class CsrProductionBindingError(ValueError):
    def __init__(self, code):
        self.reason_code = code
        super().__init__(code)


def bind_csr_compiler_operands(fragment, runtime_facts, lifted_insns, *, source_digest, architecture_profile):
    """Join one decoded CSR instruction using assembler-owned register roles.

    No assembly/expression/p-code text is read. Unknown, mixed and implicit
    register carriers remain unsupported. The complete bit covers the static
    join only; access/traps and target equivalence retain independent gates.
    """
    raw = fragment.compilerFragmentAuthority
    if not raw:
        raise CsrProductionBindingError('CSR_COMPILER_AUTHORITY_MISSING')
    if raw.get('sourceDigest') != source_digest:
        raise CsrProductionBindingError('CSR_COMPILER_SOURCE_DIGEST_MISMATCH')
    candidate = raw.get('candidate', {})
    bindings = candidate.get('operandBindings', [])
    operands = [SimpleNamespace(operand_index=b['operandIndex'],
        declaration_id=b['declarationIdentity'], value_node_identity=b['valueNodeIdentity'],
        access_mode=b['access'], width_bits=b['widthBits'], signedness=b['signedness'])
        for b in bindings]
    bind_compiler_provenance(asdict(fragment), SimpleNamespace(
        fragment_id=fragment.id, operands=operands,
        authority_identity=content_identity({"staticCompilerOperandBindings":bindings})))
    if len(lifted_insns) != 1:
        raise CsrProductionBindingError('CSR_REGION_CLOSURE_REQUIRED')
    insn = lifted_insns[0]
    decoded = getattr(insn, 'decoded_csr_instruction', None)
    effects = tuple(getattr(insn, 'privileged_operations', ()))
    if (decoded is None or not decoded.complete or len(effects) != 1
            or getattr(effects[0].kind, 'value', '') != 'csr_access'):
        raise CsrProductionBindingError('CSR_DECODER_EFFECT_INCOMPLETE')
    op = effects[0]
    from .csr_metadata_ingress import canonical_csr_operations_from_decoded
    if architecture_profile is None:
        raise CsrProductionBindingError('CSR_ARCHITECTURE_PROFILE_REQUIRED')
    structural = canonical_csr_operations_from_decoded(addr=insn.addr,
        decoded=decoded, xlen_bits=op.xlen_bits, profile=architecture_profile)[0]
    for field in ('csr_numeric_address','decoder_opcode_kind','csr_operation',
                  'read_value_node_id','write_value_node_id','immediate_mask',
                  'read_result_suppressed','write_value_suppressed','read_modify_write',
                  'csr_id','csr_semantic_class','required_privilege_mode',
                  'affected_csr_fields','access_gate_ids','state_complete'):
        if getattr(op,field) != getattr(structural,field):
            raise CsrProductionBindingError('CSR_DECODER_EFFECT_MISMATCH')
    if not op.csr_id or not op.state_complete:
        raise CsrProductionBindingError('CSR_ARCHITECTURE_PROFILE_REQUIRED')
    gnu = list(fragment.outputs) + list(fragment.inputs)
    if sorted(b['operandIndex'] for b in bindings) != list(range(len(gnu))):
        raise CsrProductionBindingError('CSR_OPERAND_ARITY_MISMATCH')
    by_index = {b['operandIndex']: b for b in bindings}
    from .compiler_operand_type import compiler_operand_type_from_dict
    types = raw.get('compilerTypeBindings', {})
    for i, binding in by_index.items():
        record = types.get(str(i))
        if not record:
            raise CsrProductionBindingError('CSR_COMPILER_TYPE_AUTHORITY_MISSING')
        typ = compiler_operand_type_from_dict(record['compilerType'])
        if (not typ.is_integer or typ.is_pointer or not typ.side_effect_free
                or typ.width_bits != binding['widthBits']
                or ('signed' if typ.is_signed else 'unsigned') != binding['signedness']):
            raise CsrProductionBindingError('CSR_COMPILER_TYPE_MISMATCH')
    contracts = {}
    for i, operand in enumerate(gnu):
        c = parse_riscv_operand(operand.constraint, output=i < len(fragment.outputs))
        if c.role != 'value' or operand.constraint.lstrip('=+&') != 'r' or c.early_clobber:
            raise CsrProductionBindingError('CSR_OPERAND_CONSTRAINT_UNSUPPORTED')
        if c.access != by_index[i]['access']:
            raise CsrProductionBindingError('CSR_OPERAND_ACCESS_MISMATCH')
        contracts[i] = c
    regmap = {}
    for reg, index in runtime_facts.rv_to_operand_index.items():
        key = canonicalize_riscv_register_name(reg)
        if not key or (key in regmap and regmap[key] != index):
            raise CsrProductionBindingError('CSR_ASSEMBLER_BINDING_AMBIGUOUS')
        regmap[key] = index
    nodes = {}; roles = []
    for node, reg, access in (
        (op.read_value_node_id, decoded.rd_register_id, {'output','read_write'}),
        (op.write_value_node_id, decoded.rs1_register_id, {'input','read_write'})):
        if node is None:
            continue
        index = regmap.get(canonicalize_riscv_register_name(reg or ''))
        if type(index) is not int or index not in by_index:
            raise CsrProductionBindingError('CSR_DECODER_OPERAND_BINDING_MISSING')
        b = by_index[index]
        if b['access'] not in access:
            raise CsrProductionBindingError('CSR_OPERAND_ACCESS_MISMATCH')
        if b['widthBits'] != op.xlen_bits or runtime_facts.operand_width_bits.get(index) != b['widthBits']:
            raise CsrProductionBindingError('CSR_OPERAND_WIDTH_MISMATCH')
        nodes[node] = index
        roles.append({'decoderNodeIdentity': node, 'operandIndex': index,
                      'compilerValueNodeIdentity': b['valueNodeIdentity']})
    if set(nodes.values()) != set(by_index):
        raise CsrProductionBindingError('CSR_OPERAND_EFFECT_COVERAGE_INCOMPLETE')
    try:
        result_flows = result_flows_from_compiler(fragment.id, raw)
    except ValueError as exc:
        code = str(exc) if str(exc).startswith("CSR_RESULT_FLOW_") else "CSR_RESULT_FLOW_PRODUCER_SCHEMA_INVALID"
        raise CsrProductionBindingError(code) from exc
    effect_id = _effect_id(insn.addr, 1, op)
    witness = {'schemaVersion':'riscv2x86.csr-compiler-decoder-join.v1',
        'fragmentId':fragment.id, 'sourceDigest':raw['sourceDigest'],
        'compilerAuthorityIdentity':raw['authorityIdentity'],
        'architectureProfile':asdict(architecture_profile),
        'decoder':asdict(decoded), 'effect':asdict(op),
        'assemblerRegisterBindings':dict(runtime_facts.rv_to_operand_index),
        'operandRoles':roles, 'resultValueFlows':{str(i):flow.flow_identity for i,flow in result_flows.items()}}
    # Enum values are strings in the canonical DTOs.
    join_identity = content_identity(witness)
    return CsrOperandAuthorityFacts(fragment.id, nodes,
        {i:b['widthBits'] for i,b in by_index.items()},
        {i:b['signedness'] for i,b in by_index.items()},
        {i:b['access'] for i,b in by_index.items()},
        tuple((i,i) for i,c in contracts.items() if c.access == 'read_write'), (),
        {i:'gnu:r' for i in by_index}, {},
        {'volatile':bool(fragment.isVolatile),'memory':'memory' in fragment.clobbers,
         'cc':'cc' in fragment.clobbers}, True, {effect_id:join_identity},
        {effect_id:op.csr_id}, result_flows), witness
