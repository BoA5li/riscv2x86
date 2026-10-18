"""Finite RISC-V GNU constraints shared by semantic consumers.

A is a RISC-V address-in-register memory constraint; it is not an arbitrary
fixed register or a constraint alternative. Unsupported combinations fail.
"""
from dataclasses import dataclass

@dataclass(frozen=True)
class GnuOperandContract:
    role: str
    access: str
    matching_output: int | None
    early_clobber: bool
    address_in_register: bool


def parse_riscv_operand(constraint, *, output):
    if not isinstance(constraint,str) or not constraint:
        raise ValueError('GNU_CONSTRAINT_MISSING')
    text=constraint;access='input'
    if output:
        if text[0] not in '=+':raise ValueError('GNU_OUTPUT_ACCESS_MISSING')
        access='read_write' if text[0]=='+' else 'output';text=text[1:]
    elif text[0] in '=+':raise ValueError('GNU_INPUT_ACCESS_INVALID')
    early=text.startswith('&')
    if early:text=text[1:]
    if early and not output:raise ValueError('GNU_EARLY_CLOBBER_INPUT_INVALID')
    if text in {'m','A'}:return GnuOperandContract('memory_lvalue',access,None,early,text=='A')
    if text in {'r','i','n'}:return GnuOperandContract('value',access,None,early,False)
    if text.isdecimal() and not output:return GnuOperandContract('value',access,int(text),early,False)
    raise ValueError('GNU_CONSTRAINT_CONTRACT_UNSUPPORTED')
