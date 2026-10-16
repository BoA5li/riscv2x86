from copy import deepcopy
import pytest

from riscv2x86_py.pcode_ir import Var, VarKind, Op, conditional_transfer_from_op
from riscv2x86_py.source_model import _normalize_asm_goto_predicate
from riscv2x86_py.compiler_operand_type import compiler_operand_type_from_dict
from riscv2x86_py.atomic_authority import atomic_runtime_object_from_compiler_authority
from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
from riscv2x86_py.route_authority import AtomicAuthorityError, content_identity
from riscv2x86_py.schema import AsmOperand
from riscv2x86_py.shell_model import SourceAsmOperandModel
from tests.test_production_route_authority import _compiler_authority, _atomic


def test_actual_compressed_branch_ram_target_does_not_become_second_predicate():
    register = Var(VarKind.REG, 'register', 8272, 8, 'a0')
    condition = Var(VarKind.UNIQUE, 'unique', 89216, 1)
    compare = Op(65536, 'INT_EQUAL', condition,
                 [register, Var(VarKind.CONST, 'const', 0, 8)])
    branch = Op(65536, 'CBRANCH', None,
                [Var(VarKind.MEM, 'ram', 65538, 8), condition])
    transfer = conditional_transfer_from_op(branch)
    assert transfer.target_kind == 'machine_address'
    assert transfer.condition is condition
    assert _normalize_asm_goto_predicate([compare, branch], branch) == ('zero', register)


def test_constant_target_preserves_pcode_relative_role_and_constant_condition_role():
    branch = Op(0, 'CBRANCH', None, [Var(VarKind.CONST,'const',2,8),
                                  Var(VarKind.CONST,'const',1,1)])
    result = conditional_transfer_from_op(branch)
    assert result.target_kind == 'pcode_relative'
    assert result.target.offset == 2
    assert result.condition.offset == 1


@pytest.mark.parametrize('mutation,reason', [
    ('arity','CBRANCH_INPUT_CONTRACT_INVALID'),
    ('space','CBRANCH_TARGET_SPACE_UNSUPPORTED'),
    ('width','CBRANCH_BOOLEAN_CONDITION_INVALID'),
    ('target','CBRANCH_TARGET_UNRESOLVED'),
])
def test_conditional_transfer_rejects_bad_roles(mutation, reason):
    target = Var(VarKind.MEM,'ram',4,8)
    condition = Var(VarKind.UNIQUE,'unique',2,1)
    if mutation == 'space': target = Var(VarKind.MEM,'stack',4,8)
    if mutation == 'width': condition = Var(VarKind.UNIQUE,'unique',2,8)
    if mutation == 'target': target = Var(VarKind.REG,'register',4,8,'a0')
    branch = Op(0,'CBRANCH',None,[target,condition] if mutation != 'arity' else [condition])
    with pytest.raises(ValueError, match=reason): conditional_transfer_from_op(branch)


def _call(authority):
    return atomic_runtime_object_from_compiler_authority(authority,
        fragment_id='source.c:7:3', source_digest=authority['sourceDigest'],
        begin_offset=100, end_offset=140,
        runtime_facts=TranslationRuntimeFacts(rv_to_operand_index={'a0':0,'a1':1},
            operand_width_bits={0:64,1:64}), atomic_operation=_atomic())


def _resign(authority):
    authority['authorityIdentity'] = content_identity({k:v for k,v in authority.items()
                                                     if k != 'authorityIdentity'})


def test_atomic_pointee_type_is_compiler_type_not_pointer_or_value_identity():
    authority = _compiler_authority()
    fact = _call(authority)[1]
    record = authority['compilerTypeBindings']['1']
    parsed = compiler_operand_type_from_dict(record['compilerType'])
    assert fact.pointee_type_id == parsed.pointee_type_identity
    assert fact.pointee_type_id != parsed.type_identity
    assert fact.pointee_type_id != record['valueNodeIdentity']
    shell = SourceAsmOperandModel.from_operand(AsmOperand(compilerType=record['compilerType']))
    assert shell.compiler_type.type_identity == parsed.type_identity


def test_legacy_authority_never_substitutes_value_node_for_missing_type():
    authority = _compiler_authority()
    authority.pop('compilerTypeBindings')
    authority['schemaVersion'] = 'riscv2x86.compiler-fragment-authority.v1'
    _resign(authority)
    with pytest.raises(AtomicAuthorityError) as error: _call(authority)
    assert error.value.reason_code == 'ATOMIC_POINTEE_TYPE_AUTHORITY_MISSING'


@pytest.mark.parametrize('mutation,reason', [
    ('node','ATOMIC_POINTEE_TYPE_AUTHORITY_MISSING'),
    ('schema','ATOMIC_POINTEE_TYPE_AUTHORITY_INVALID'),
    ('pointee_width','ATOMIC_POINTEE_WIDTH_MISMATCH'),
    ('qualified','ATOMIC_POINTEE_QUALIFIER_CONTRACT_REQUIRED'),
])
def test_type_mutations_cannot_be_hidden_by_rehashing_envelope(mutation,reason):
    authority = _compiler_authority()
    binding = authority['compilerTypeBindings']['1']
    if mutation == 'node': binding['valueNodeIdentity'] = 'sha256:'+'9'*64
    if mutation == 'schema': binding['compilerType']['schemaVersion'] = 'unknown'
    if mutation == 'pointee_width': binding['compilerType']['pointeeWidthBits'] = 32
    if mutation == 'qualified': binding['compilerType']['pointeeQualifiers'] = 'volatile'
    _resign(authority)
    with pytest.raises(AtomicAuthorityError) as error: _call(authority)
    assert error.value.reason_code == reason
