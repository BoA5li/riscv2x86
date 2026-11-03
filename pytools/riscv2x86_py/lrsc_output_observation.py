"""Compiler-bound completion outputs; reference values are never observations.

Only a direct C return of one proved output is observed by this interface.
Other live uses still require a different, explicit observation contract.
"""


def return_role(finding, function, source):
    candidate = finding['fragment']['compilerFragmentAuthority']['candidate']
    roles = dict(source.lrsc_sequence.role_operand_indexes)
    bindings = candidate['operandBindings']
    returned = function['l2OperandBoundary'].get('returnDeclarationId')
    matches = [role for role in ('old', 'next', 'status')
               if returned and bindings[roles[role]]['declarationIdentity'] == returned]
    if len(matches) != 1:
        raise ValueError('L2_LRSC_RETURN_OUTPUT_BINDING_REQUIRED')
    role = matches[0]
    if candidate.get('downstreamUseEnumerationComplete') is not True:
        raise ValueError('L2_LRSC_ADDITIONAL_OUTPUT_OBSERVATION_REQUIRED:use-enumeration')
    for name in ('old', 'next', 'status'):
        node = bindings[roles[name]]['valueNodeIdentity']
        uses = [use for use in candidate['downstreamUses'] if use['valueNodeIdentity'] == node]
        if any(use.get('complete') is not True or use.get('useKind') not in
               ({'function_return', 'dead', 'discarded'} if name == role else {'dead', 'discarded'})
               for use in uses):
            raise ValueError('L2_LRSC_ADDITIONAL_OUTPUT_OBSERVATION_REQUIRED:' + name)
    return role


def completion_values(width, arithmetic, operation, old, value):
    """Approved RV64 successful iteration, including full-XLEN next.

    This calculates an expectation to compare with the actual C return. It
    must not be placed in a measured register field or used for failed SC.
    """
    if (type(width) is not int or width not in (32, 64)
            or type(arithmetic) is not int or arithmetic not in (32, 64)
            or (arithmetic == 32 and (width != 32 or operation not in ('fetch_add','fetch_sub')))):
        raise ValueError('L2_LRSC_OUTPUT_WIDTH_DOMAIN_UNSUPPORTED')
    mask = (1 << 64) - 1
    old &= (1 << width) - 1
    if old & (1 << (width - 1)):
        old -= 1 << width
    old &= mask
    value &= mask
    result = {'fetch_add': lambda: old + value, 'fetch_sub': lambda: old - value, 'fetch_and': lambda: old & value,
              'fetch_or': lambda: old | value, 'fetch_xor': lambda: old ^ value}[operation]()
    result &= (1 << arithmetic) - 1
    if arithmetic == 32 and result & (1 << 31):
        result -= 1 << 32
    return {'old': old, 'next': result & mask, 'status': 0}
