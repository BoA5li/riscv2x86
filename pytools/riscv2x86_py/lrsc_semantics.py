"""Closed RV64 LR/ALU/SC completion domain, separate from direct AMOs.

SUB is ordered old-minus-input; swapping its inputs changes the contract.
Neither this registry nor reference arithmetic grants translation approval.
"""
ALU_OPERATIONS = {'fetch_add':'add', 'fetch_sub':'sub', 'fetch_and':'and',
                  'fetch_or':'or', 'fetch_xor':'xor'}


def valid_shape(width, arithmetic, operation):
    return (type(width) is int and width in (32,64)
            and type(arithmetic) is int and arithmetic in (32,64)
            and operation in ALU_OPERATIONS
            and (arithmetic == 64 or (width == 32 and operation in ('fetch_add','fetch_sub'))))


def stored_result(operation, old, value, width):
    if not valid_shape(width,64,operation):
        raise ValueError('LRSC_OPERATION_OR_WIDTH_UNSUPPORTED')
    mask=(1<<width)-1
    old &= mask
    value &= mask
    return {'fetch_add':lambda:old+value, 'fetch_sub':lambda:old-value,
            'fetch_and':lambda:old&value, 'fetch_or':lambda:old|value,
            'fetch_xor':lambda:old^value}[operation]() & mask
