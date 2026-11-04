"""Typed floating operand facts. These facts never authorize a translation."""
from dataclasses import dataclass
from .project_build_records import identity

SCHEMA='riscv2x86.clang-operand-type.v2'


@dataclass(frozen=True)
class CompilerFloatingType:
    canonical_type: str
    width_bits: int
    alignment_bytes: int
    floating_format: str
    qualifiers: str
    side_effect_free: bool
    modifiable_lvalue: bool
    expression_repeatable: bool

    @property
    def format_modelled(self):
        return (self.width_bits,self.floating_format) in {
            (32,'ieee754-binary32'),(64,'ieee754-binary64')}

    @property
    def type_identity(self):
        return identity({'schemaVersion':'riscv2x86.compiler-floating-type.v1',
            'canonicalType':self.canonical_type,'widthBits':self.width_bits,
            'alignmentBytes':self.alignment_bytes,'floatingFormat':self.floating_format,
            'qualifiers':self.qualifiers})


def parse(value):
    fields={'schemaVersion','canonicalType','widthBits','alignmentBytes','isInteger','isPointer',
        'isSigned','pointeeType','pointeeWidthBits','pointeeAlignmentBytes','pointeeIsInteger',
        'sideEffectFree','modifiableLvalue','qualifiers','pointeeQualifiers','expressionRepeatable',
        'isFloating','floatingFormat'}
    if not isinstance(value,dict) or set(value)!=fields or value['schemaVersion']!=SCHEMA:
        raise ValueError('COMPILER_FLOATING_TYPE_SCHEMA_INVALID')
    for key in ('isInteger','isPointer','isSigned','pointeeIsInteger','sideEffectFree',
                'modifiableLvalue','expressionRepeatable','isFloating'):
        if type(value[key]) is not bool:raise ValueError('COMPILER_FLOATING_TYPE_FLAGS_INVALID')
    if (value['isFloating'] is not True or any(value[k] for k in
            ('isInteger','isPointer','isSigned','pointeeIsInteger'))
            or any(type(value[k]) is not int or not 0<value[k]<=0xffffffff for k in ('widthBits','alignmentBytes'))
            or any(type(value[k]) is not int or value[k]!=0 for k in ('pointeeWidthBits','pointeeAlignmentBytes'))
            or value['pointeeType']!='' or value['pointeeQualifiers']!=''
            or not isinstance(value['canonicalType'],str) or not value['canonicalType']
            or not isinstance(value['qualifiers'],str)):
        raise ValueError('COMPILER_FLOATING_TYPE_INCOMPLETE')
    if (not isinstance(value['floatingFormat'], str)
            or value['floatingFormat'] not in {'ieee754-binary32','ieee754-binary64','unmodelled'}
            or value['floatingFormat']=='ieee754-binary32' and value['widthBits']!=32
            or value['floatingFormat']=='ieee754-binary64' and value['widthBits']!=64):
        raise ValueError('COMPILER_FLOATING_TYPE_FORMAT_MISMATCH')
    return CompilerFloatingType(value['canonicalType'],value['widthBits'],value['alignmentBytes'],
        value['floatingFormat'],value['qualifiers'],value['sideEffectFree'],
        value['modifiableLvalue'],value['expressionRepeatable'])
