"""Bounded compiler-shell proof for the canonical separate-object runtime build."""
from dataclasses import asdict, is_dataclass
from .semantic_content import semantic_identity

AUTOMATIC_RUNTIME_BUILD_CONTRACT = 'automatic-gcc-separate-tu-no-lto-v1'


def prove_runtime_shell(fragment, implementation_identity, build_contract, *, operand_binding=None, time_contract=None):
    raw = asdict(fragment) if is_dataclass(fragment) else dict(fragment)
    if build_contract != AUTOMATIC_RUNTIME_BUILD_CONTRACT:
        raise ValueError('CSR_RUNTIME_SHELL_BUILD_CONTRACT_REQUIRED')
    if raw.get('isAsmGoto') or raw.get('gotoLabels'):
        raise ValueError('CSR_RUNTIME_SHELL_CONTROL_UNSUPPORTED')
    outputs, inputs = raw.get('outputs', []), raw.get('inputs', [])
    # First supported runtime shape: one read result, or a discarded read.
    # Write/RMW argument evaluation needs a separate shell proof.
    if inputs or any(x.get("constraint", "").startswith("+") for x in outputs):
        return _prove_value_shell(raw, implementation_identity, build_contract, operand_binding)
    if len(outputs) > 1:
        raise ValueError('CSR_RUNTIME_SHELL_OPERAND_SHAPE_UNSUPPORTED')
    if any(x.get('constraint') != '=r' or x.get('isEarlyClobber') for x in outputs):
        raise ValueError('CSR_RUNTIME_SHELL_CONSTRAINT_UNSUPPORTED')
    clobbers = tuple(raw.get('clobbers') or ())
    if any(x not in ('memory', 'cc') for x in clobbers):
        raise ValueError('CSR_RUNTIME_SHELL_CLOBBER_UNSUPPORTED')
    if not implementation_identity:
        raise ValueError('CSR_RUNTIME_SHELL_IMPLEMENTATION_REQUIRED')
    if time_contract is not None:
        from .compiler_time_scope import validate_scope as validate_time_scope
        validate_time_scope(raw.get('compilerTimeReturnScope'),raw,(raw.get('compilerFragmentAuthority') or {}).get('sourceDigest'))
        from .time_trace_contract import validate_time_contract
        validate_time_contract(time_contract, fragment_id=raw.get('id') or raw.get('fragmentId'),
            source_digest=(raw.get('compilerFragmentAuthority') or {}).get('sourceDigest'))
        if (not raw.get('isVolatile') or inputs or len(outputs) != 1 or clobbers):
            raise ValueError('TIME_SHELL_SHAPE_UNSUPPORTED')
    payload = {'schemaVersion': 'riscv2x86.csr-runtime-shell.v1',
               'fragmentId': raw.get('id') or raw.get('fragmentId'),
               'outputConstraints': [x['constraint'] for x in outputs],
               'inputConstraints': [], 'clobbers': list(clobbers),
               'volatile': raw.get('isVolatile') is True,
               'implementationIdentity': implementation_identity,
               'buildContract': build_contract,
               'invocation': 'one-opaque-external-call-at-source-statement',
               'continuation': 'fallthrough',
               'barrierPlacement': 'before-and-after-call', 'complete': True}
    if time_contract is not None:
        payload.update(timeContractIdentity=time_contract['contractIdentity'],
            timeScopeIdentity=raw['compilerTimeReturnScope']['scopeIdentity'],
            claimBoundary='logical-read-events-no-wall-time-no-memory-order-claim')
    return {**payload, 'shellIdentity': semantic_identity(payload)}


def render_runtime_shell(call, shell):
    if shell.get('complete') is not True:
        raise ValueError('CSR_RUNTIME_SHELL_PROOF_REQUIRED')
    clobbers = shell['clobbers']
    suffix = ' ::: ' + ', '.join('"' + x + '"' for x in clobbers) if clobbers else ''
    barrier = '__asm__ __volatile__(""' + suffix + ');'
    return 'do { ' + barrier + ' ' + call + ' ' + barrier + ' } while (0);'


def _prove_value_shell(raw, implementation_identity, build_contract, binding):
    """One scalar CSR effect, direct compiler carriers, one call and writeback.

    This does not approve side-effecting lvalues, alternatives, memory operands,
    fixed-register constraints or multiple effects. Those need other proofs.
    """
    from types import SimpleNamespace
    from .compiler_provenance import bind_compiler_provenance
    from .compiler_operand_type import compiler_operand_type_from_dict
    outputs, inputs = raw.get('outputs', []), raw.get('inputs', [])
    if not implementation_identity or binding is None or not getattr(binding, 'complete', False):
        raise ValueError('CSR_RUNTIME_SHELL_OPERAND_PROOF_REQUIRED')
    if len(outputs) > 1 or len(inputs) > 1:
        raise ValueError('CSR_RUNTIME_SHELL_OPERAND_SHAPE_UNSUPPORTED')
    if any(x.get('constraint') not in {'=r', '+r'} or x.get('isEarlyClobber') for x in outputs):
        raise ValueError('CSR_RUNTIME_SHELL_CONSTRAINT_UNSUPPORTED')
    if any(x.get('constraint') != 'r' for x in inputs):
        raise ValueError('CSR_RUNTIME_SHELL_CONSTRAINT_UNSUPPORTED')
    authority = raw.get('compilerFragmentAuthority')
    if not authority:
        raise ValueError('CSR_RUNTIME_SHELL_COMPILER_AUTHORITY_REQUIRED')
    candidate = authority['candidate']
    bindings = candidate['operandBindings']
    bind_compiler_provenance(raw, SimpleNamespace(fragment_id=raw.get('id') or raw.get('fragmentId'),
        operands=[SimpleNamespace(operand_index=b['operandIndex'], declaration_id=b['declarationIdentity'],
            value_node_identity=b['valueNodeIdentity'], access_mode=b['access'], width_bits=b['widthBits'],
            signedness=b['signedness']) for b in bindings], authority_identity=implementation_identity))
    ordered = outputs + inputs
    if len(bindings) != len(ordered):
        raise ValueError('CSR_RUNTIME_SHELL_OPERAND_COVERAGE_MISMATCH')
    read = getattr(binding, 'read_result_operand_index', None)
    write = getattr(binding, 'write_value_operand_index', None)
    if read != (0 if outputs else None):
        raise ValueError('CSR_RUNTIME_SHELL_OUTPUT_BINDING_MISMATCH')
    rw = bool(outputs and outputs[0]['constraint'] == '+r')
    expected_write = 0 if rw else len(outputs) if inputs else None
    if write != expected_write or (rw and inputs):
        raise ValueError('CSR_RUNTIME_SHELL_INPUT_BINDING_MISMATCH')
    if set(i for i in (read, write) if i is not None) != set(range(len(ordered))):
        raise ValueError('CSR_RUNTIME_SHELL_OPERAND_COVERAGE_MISMATCH')
    for i, item in enumerate(ordered):
        carrier = next((x for x in candidate['operandCarriers'] if x['operandIndex'] == i), None)
        record = authority.get('compilerTypeBindings', {}).get(str(i))
        if carrier is None or carrier.get('carrierKind') != 'integer' or not record:
            raise ValueError('CSR_RUNTIME_SHELL_SCALAR_CARRIER_REQUIRED')
        typ = compiler_operand_type_from_dict(record['compilerType'])
        expected_access = ('read_write' if rw else 'output') if i < len(outputs) else 'input'
        if bindings[i]['access'] != expected_access:
            raise ValueError('CSR_RUNTIME_SHELL_ACCESS_MISMATCH')
        if (not typ.is_integer or typ.is_pointer or not typ.side_effect_free or typ.qualifiers
                or (i < len(outputs) and not typ.modifiable_lvalue)):
            raise ValueError('CSR_RUNTIME_SHELL_EVALUATION_UNPROVEN')
        if typ.width_bits != 64 or bindings[i]['widthBits'] != 64 or typ.is_signed:
            raise ValueError('CSR_RUNTIME_SHELL_CONVERSION_REQUIRED')
    clobbers = tuple(raw.get('clobbers') or ())
    if any(x not in ('memory','cc') for x in clobbers):
        raise ValueError('CSR_RUNTIME_SHELL_CLOBBER_UNSUPPORTED')
    payload = {'schemaVersion':'riscv2x86.csr-runtime-shell.v2',
        'fragmentId':raw.get('id') or raw.get('fragmentId'),
        'outputConstraints':[x['constraint'] for x in outputs],
        'inputConstraints':[x['constraint'] for x in inputs], 'clobbers':list(clobbers),
        'volatile':raw.get('isVolatile') is True,'implementationIdentity':implementation_identity,
        'buildContract':build_contract,'invocation':'one-opaque-external-call-at-source-statement',
        'continuation':'fallthrough','barrierPlacement':'before-and-after-call',
        'compilerAuthorityIdentity':authority['authorityIdentity'],
        'operandBindingIdentity':semantic_identity(binding),
        'evaluation':'direct-scalar-input-once-before-call-output-once-after-call', 'complete':True}
    return {**payload,'shellIdentity':semantic_identity(payload)}
