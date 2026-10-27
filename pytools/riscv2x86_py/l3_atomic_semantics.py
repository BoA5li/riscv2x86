"""Explicit modular RMW semantics; unknown operations never become exchange."""
OPERATIONS = {
    name: 'c.builtin.atomic-' + name.replace('_', '-') + '.u32-u64.v2'
    for name in ('fetch_add', 'fetch_and', 'fetch_or', 'fetch_xor', 'exchange')
}
RV_OPERATIONS = {0: 'fetch_add', 1: 'exchange', 4: 'fetch_xor', 8: 'fetch_or', 12: 'fetch_and'}


def result(operation, old, value, width):
    if operation not in OPERATIONS or width not in (32, 64):
        raise ValueError('L3_ATOMIC_OPERATION_UNSUPPORTED')
    mask = (1 << width) - 1
    old, value = old & mask, value & mask
    return {'fetch_add': lambda: old + value, 'fetch_and': lambda: old & value,
            'fetch_or': lambda: old | value, 'fetch_xor': lambda: old ^ value,
            'exchange': lambda: value}[operation]() & mask
