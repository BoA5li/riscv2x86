"""Integer register lanes common to Linux RV64 LP64 and x86-64 SysV.

Six is the intersection of their integer argument register capacities. This
module describes locations, not permission to invoke or proof of function effects.
Stack-passed arguments and floating/vector/aggregate ABI classes remain outside
this contract. Consumers must validate compiler types and each live output.
"""
RV64_INTEGER_ARGUMENTS = (10, 11, 12, 13, 14, 15, 16, 17)
X86_64_INTEGER_ARGUMENTS = (7, 6, 2, 1, 8, 9)
MAX_ATOMIC_PARAMETERS = min(len(RV64_INTEGER_ARGUMENTS), len(X86_64_INTEGER_ARGUMENTS))


def integer_arguments(machine):
    if machine == 243:
        return RV64_INTEGER_ARGUMENTS[:MAX_ATOMIC_PARAMETERS]
    if machine == 62:
        return X86_64_INTEGER_ARGUMENTS[:MAX_ATOMIC_PARAMETERS]
    raise ValueError('REGISTER_CALL_ABI_MACHINE_UNSUPPORTED')
