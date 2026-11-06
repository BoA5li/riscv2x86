from copy import deepcopy
import ctypes
import json
import os
from pathlib import Path
import random
import shutil
import subprocess

import pytest

from riscv2x86_py.native_integer_contracts import term, builtin_contract, decode_mulhu, multiply_high_term
from riscv2x86_py import native_project_translation as route
from riscv2x86_py.compiler_native_instance_binding import derive
from riscv2x86_py.project_build_records import identity
from .test_native_instance_binding import example
from .test_native_call_obligations import builtin

MODEL = {'__CHAR_BIT__': '8', '__SIZEOF_SHORT__': '2', '__SIZEOF_INT__': '4',
    '__SIZEOF_LONG__': '8', '__SIZEOF_LONG_LONG__': '8', '__SIZEOF_POINTER__': '8',
    '__SIZEOF_WCHAR_T__': '4', '__WCHAR_TYPE__': 'int', '__CHAR_UNSIGNED__': None,
    '__STDC_VERSION__': '201112L', '__BYTE_ORDER__': '1234'}


def literal(value, typ='int'):
    return {'kind': 'IntegerLiteral', 'value': str(value), 'type': {'qualType': typ}}


def variable(ref, typ='unsigned long'):
    return {'kind': 'DeclRefExpr', 'type': {'qualType': typ},
        'referencedDecl': {'id': ref, 'kind': 'VarDecl'}}


def cast(child, typ):
    return {'kind': 'CStyleCastExpr', 'castKind': 'IntegralCast',
            'type': {'qualType': typ}, 'inner': [child]}


def binary(op, left, right, typ):
    return {'kind': 'BinaryOperator', 'opcode': op, 'type': {'qualType': typ}, 'inner': [left, right]}


@pytest.mark.parametrize('value,typ', [(0, 'int'), (193, 'int'), (2**31-1, 'int'),
    (2**32-1, 'unsigned int'), (2**63-1, 'long'), (2**64-1, 'unsigned long')])
def test_literal_builtin_rule_is_not_bound_to_observed_values(value, typ):
    call = builtin(arguments=[literal(value, typ)])
    result = builtin_contract(call, MODEL, lambda ref: ref)
    assert result['result'] == 1 and result['argumentEvaluation'] == 'unevaluated'
    assert result['requiredWitness'] == 'source-and-target-compiler-static-assert'


@pytest.mark.parametrize('argument', [variable('x'),
    {'kind': 'CallExpr', 'type': {'qualType': 'int'}},
    {'kind': 'UnaryOperator', 'opcode': '++', 'inner': [variable('x')], 'type': {'qualType': 'int'}}])
def test_general_constant_queries_are_not_guessed(argument):
    with pytest.raises(ValueError, match='LITERAL_CONTRACT_REQUIRED'):
        builtin_contract(builtin(arguments=[argument]), MODEL, lambda ref: ref)


def test_expect_retains_unsigned_comparison_conversion_and_hint():
    comparison = binary('>=', variable('bits'), cast(variable('window', 'int'), 'unsigned long'), 'int')
    first = cast(comparison, 'long')
    call = builtin('__builtin_expect', [first, cast(literal(0), 'long')])
    call['type'] = {'qualType': 'long'}
    result = builtin_contract(call, MODEL, lambda ref: ref)
    assert result['arguments'][0]['argument']['arguments'][1]['op'] == 'integer-conversion'
    assert result['targetDisposition'] == 'preserve-original-builtin-call'
    assert not result['physicalBranchPredictionEquivalenceClaimed']


@pytest.mark.parametrize('mutation', ['volatile', 'call', 'increment', 'cast', 'signed-overflow'])
def test_unproved_integer_effects_and_conversions_are_rejected(mutation):
    node = variable('x')
    if mutation == 'volatile': node['type']['qualType'] = 'volatile unsigned long'
    if mutation == 'call': node['kind'] = 'CallExpr'
    if mutation == 'increment': node = {'kind': 'UnaryOperator', 'opcode': '++', 'inner': [node], 'type': node['type']}
    if mutation == 'cast': node = dict(cast(node, 'unsigned long'), castKind='BitCast')
    if mutation == 'signed-overflow': node = cast(node, 'long')
    with pytest.raises(ValueError): term(node, MODEL, lambda ref: ref)


@pytest.mark.parametrize('mutation', ['opcode', 'signed-high', 'word-high', 'wrong-register', 'extra-instruction'])
def test_decoding_rejects_similar_mnemonics_wrong_operands_or_extra_code(mutation):
    word = (1 << 25) | (12 << 20) | (11 << 15) | (3 << 12) | (10 << 7) | 0x33
    if mutation == 'opcode': word ^= 1
    elif mutation == 'signed-high': word ^= 2 << 12
    elif mutation == 'word-high': word ^= 8
    elif mutation == 'wrong-register': word ^= 1 << 7
    code = word.to_bytes(4, 'little')
    if mutation == 'extra-instruction': code += code
    with pytest.raises(ValueError): decode_mulhu(code, {0: 10, 1: 11, 2: 12})


def test_decoded_instruction_and_typed_target_have_identical_normal_form():
    word = (1 << 25) | (12 << 20) | (11 << 15) | (3 << 12) | (10 << 7) | 0x33
    assert decode_mulhu(word.to_bytes(4, 'little'), {0: 10, 1: 11, 2: 12})['widthBits'] == 64
    target = cast(binary('>>', binary('*', cast(variable('a'), 'unsigned __int128'),
        cast(variable('b'), 'unsigned __int128'), 'unsigned __int128'), literal(64), 'unsigned __int128'), 'unsigned long')
    expected = multiply_high_term(term(variable('a'), MODEL, str), term(variable('b'), MODEL, str))
    assert term(target, MODEL, str) == expected
    target['inner'][0]['inner'][1]['value'] = '63'
    assert term(target, MODEL, str) != expected


def planned():
    ast, report, raw = example()
    row = derive(ast, report, raw, 'input')['records'][0]
    return raw, row, route.plan_operand(row, MODEL, str)


@pytest.mark.parametrize('mutation', ['volatile', 'signed', 'memory', 'computed-input', 'goto', 'clobber'])
def test_materialization_requires_complete_pure_register_domain(mutation):
    _, row, _ = planned()
    if mutation == 'volatile': row['frontendFragment']['isVolatile'] = True
    elif mutation == 'signed': row['operands'][1]['compilerExport']['compilerType']['isSigned'] = True
    elif mutation == 'memory': row['frontendFragment']['outputs'][0]['constraint'] = '=m'; row['constraintRelation']['outputs'] = ['=m']
    elif mutation == 'computed-input': row['operands'][1]['expressionAst'] = literal(4, 'unsigned long')
    elif mutation == 'goto': row['frontendFragment']['hasAsmGoto'] = True
    else: row['frontendFragment']['clobbers'] = ['memory']
    with pytest.raises(ValueError): route.plan_operand(row, MODEL, str)


def test_edits_preserve_every_unauthorized_byte_and_reject_overlap():
    raw, row, edit = planned()
    output = route.preserve_edits(raw, [edit]); start, stop = edit['sourceRange']
    assert output[:start] == raw[:start]
    assert output[start+len(edit['replacement'].encode()):] == raw[stop:]
    with pytest.raises(ValueError): route.preserve_edits(raw, [edit, edit])
    with pytest.raises(ValueError): route.preserve_edits(raw[:start]+b'X'+raw[start+1:], [edit])
    with pytest.raises(ValueError): route.map_offset(start, [edit])
    for offset in (0, stop, len(raw)):
        assert route.map_offset(route.map_offset(offset, [edit]), [edit], inverse=True) == offset


def test_multi_declarators_do_not_collapse_to_the_shared_type_location():
    ast = {'kind': 'TranslationUnitDecl', 'inner': [
        {'kind': 'VarDecl', 'id': 'a', 'loc': {'offset': 14}, 'range': {'begin': {'offset': 0}}},
        {'kind': 'VarDecl', 'id': 'b', 'loc': {'offset': 16}, 'range': {'begin': {'offset': 0}}}]}
    key = route.declaration_key(ast)
    assert key('a') != key('b')


def test_retargeting_preserves_source_options_and_explicit_char_model():
    receipt = {'context': {'inspectionArguments': ['-O2', '-march=rv64im', '-mabi=lp64',
        '-fwrapv', '-fno-strict-aliasing', '-DVALUE=2']}, 'analysisInput': {'dataModels': {'native': MODEL}}}
    assert '-march=rv64im' in route.c_flags(receipt, 'source')
    flags = route.c_flags(receipt, 'target')
    assert '-march=rv64im' not in flags and '-mabi=lp64' not in flags
    assert '-fwrapv' in flags and '-fno-strict-aliasing' in flags and '-fsigned-char' in flags
    assert '-DVALUE=2' not in flags


def test_generated_expression_executes_without_losing_high_or_low_output(tmp_path):
    gcc = shutil.which('gcc')
    if not gcc: pytest.skip('native GCC required')
    _, _, edit = planned()
    source = tmp_path/'wide.c'
    source.write_text('unsigned long compute(unsigned long left,unsigned long right) {'
        'unsigned long hi; unsigned long low=left*right; '+edit['replacement']+'return hi^low;}')
    library = tmp_path/'wide.so'
    subprocess.run([gcc, '-O2', '-shared', '-fPIC', str(source), '-o', str(library)], check=True, capture_output=True)
    dll = ctypes.CDLL(str(library)); function = dll.compute
    function.argtypes = [ctypes.c_uint64, ctypes.c_uint64]; function.restype = ctypes.c_uint64
    rng = random.Random(384109)
    values = [0, 1, 2**32-1, 2**32, 2**63, 2**64-1]
    pairs = [(a,b) for a in values for b in values]+[(rng.getrandbits(64),rng.getrandbits(64)) for _ in range(400)]
    for left, right in pairs:
        product = left*right
        assert function(left,right) == ((product >> 64) ^ (product & (2**64-1)))


@pytest.mark.parametrize('mutate', [None, 'width', 'signedness', 'value'])
def test_actual_compiler_witness_checks_literal_type_and_value(tmp_path, mutate):
    gcc = shutil.which('gcc')
    if not gcc: pytest.skip('native GCC required')
    checks = []
    for value, typ, spelling in [(193, 'int', '193'), (2**63-1, 'long', '0x7fffffffffffffffL'),
            (2**64-1, 'unsigned long long', '0xffffffffffffffffULL')]:
        contract = builtin_contract(builtin(arguments=[literal(value,typ)]), MODEL, str)
        if mutate == 'width': contract['argument']['type']['bits'] = 32 if typ != 'int' else 64
        if mutate == 'signedness': contract['argument']['type']['signed'] = not contract['argument']['type']['signed']
        if mutate == 'value': contract['argument']['value'] += 1
        checks.extend(route.literal_witness(contract, spelling))
    source = tmp_path/'probe.c'; source.write_text('\n'.join(checks))
    result = subprocess.run([gcc, '-std=gnu11', '-O2', '-Werror', '-c', str(source), '-o', str(tmp_path/'probe.o')], capture_output=True)
    assert (result.returncode == 0) is (mutate is None)


def test_real_native_candidate_and_independent_audit(tmp_path):
    from riscv2x86_py.project_build_records import record
    from riscv2x86_py.project_compile_context import derive as context
    from riscv2x86_py import project_native_input as native
    from riscv2x86_py import project_native_binding as binding
    clang = os.environ.get('RV2X86_SYSTEM_CLANG') or shutil.which('clang')
    gcc = os.environ.get('RV2X86_TEST_RISCV_CC') or shutil.which('riscv64-linux-gnu-gcc')
    frontend = os.environ.get('RISCV2X86_TEST_FRONTEND'); target = shutil.which('gcc')
    if not all((clang, gcc, frontend, target)):
        pytest.skip('real Clang, RV64 GCC, frontend and x86 GCC required')
    source = tmp_path/'case.c'
    source.write_text('unsigned long calculate(unsigned long a,unsigned long b) {'
        'unsigned long hi;unsigned long lo=a*b;__asm__("mulhu %0,%1,%2":"=r"(hi):"%r"(a),"r"(b));'
        'return __builtin_expect(hi!=lo,0)+__builtin_constant_p(193);}')
    action = record([gcc, '-O2', '-std=gnu11', '-march=rv64gc', '-mabi=lp64d', '-c', str(source), '-o', 'case.o'],
        tmp_path, {'kind': 'explicit-test-profile'})
    native.acquire(context(action), clang, tmp_path/'input')
    binding.acquire(tmp_path/'input/native-input.json', frontend, tmp_path/'binding')
    value = route.acquire(tmp_path/'binding/binding-bundle.json', target, tmp_path/'candidate')
    assert value['localIntegerProofComplete'] and value['objectBuildsComplete']
    assert len(value['builtinProofs']) == 2 and not value['productionAcceptanceComplete']
    assert route.audit(value, tmp_path/'audit')['nativeCandidateIndependentAuditComplete']
    altered = deepcopy(value); altered['localProofs'][0]['localIntegerStatementEquivalenceVerified'] = False
    altered['candidateIdentity'] = identity({k:v for k,v in altered.items() if k != 'candidateIdentity'})
    with pytest.raises(ValueError, match='AUDIT_MISMATCH'):
        route.audit(altered, tmp_path/'negative-audit')


def orchestration_fixture(tmp_path, monkeypatch, *, wrong_target=False):
    """Protocol test only: synthesized target AST/cross ELF, real x86 codegen.

    This does not substitute for the explicitly skipped cross-tool integration.
    """
    from types import SimpleNamespace
    import sys
    gcc = shutil.which('gcc')
    if not gcc: pytest.skip('native GCC required')
    real_run = subprocess.run
    ast, report, raw = example()
    function = ast['inner'][0]; body = function['inner'][0]
    for index, name in ((11, 'left'), (12, 'right'), (10, 'hi')):
        offset = raw.index(name.encode())
        declaration = {'kind': 'VarDecl', 'id': 'node:'+str(index), 'name': name,
            'type': {'qualType': 'unsigned long'}, 'loc': {'offset': offset},
            'range': {'begin': {'offset': offset}, 'end': {'offset': offset, 'tokLen': len(name)}}}
        body['inner'].insert(0, declaration)
    bindings = derive(ast, report, raw, 'input')
    model = {key: MODEL[key] for key in route.native.MODEL_KEYS}
    receipt = {'context': {'inspectionArguments': ['-O2', '-march=rv64gc', '-mabi=lp64d'],
        'nativeCompiler': sys.executable, 'workingDirectory': str(tmp_path)}, 'analysisInput': {'dataModels': {'native': model}},
        'inspectionCompiler': sys.executable, 'analysisInputIdentity': 'input', 'target': 'riscv64'}
    receipt_path = tmp_path/'native.json'; receipt_path.write_text(json.dumps(receipt))
    bundle = {'nativeInputReceiptPath': str(receipt_path), 'bindingBundleIdentity': 'bundle',
        'analysisInputIdentity': 'input'}
    bundle_path = tmp_path/'bundle.json'; bundle_path.write_text(json.dumps(bundle))
    monkeypatch.setattr(route.binding, 'validate_artifacts', lambda value: (bindings, {}))
    monkeypatch.setattr(route.native, 'validate_artifacts', lambda value: {'inputBytes': raw, 'canonicalAst': ast})
    def replay(value, output, **kwargs):
        output = Path(output); output.mkdir()
        fresh = {'bindingBundleIdentity': identity(str(output)), 'bindingInventoryIdentity': bindings['bindingInventoryIdentity']}
        (output/'binding-bundle.json').write_text(json.dumps(fresh))
        result = {'originalBindingBundleIdentity': 'bundle', 'freshBindingBundleIdentity': fresh['bindingBundleIdentity'],
            'bindingInventoryIdentity': bindings['bindingInventoryIdentity'], 'analysisInputIdentity': 'input',
            'nativeBindingReplayComplete': True, 'semanticApproval': False, 'productionAcceptanceComplete': False}
        return dict(result, replayIdentity=identity(result))
    monkeypatch.setattr(route.binding, 'replay', replay)
    def as_raw(node):
        if isinstance(node, dict):
            return {k: ('0x'+format(int(v[5:]), 'x') if k in {'id', 'previousDecl'} and isinstance(v,str) and v.startswith('node:')
                else as_raw(v)) for k,v in node.items()}
        if isinstance(node, list): return [as_raw(x) for x in node]
        return node
    def run(argv, **kwargs):
        argv = list(argv)
        if '-dM' in argv:
            return SimpleNamespace(returncode=0, stdout='\n'.join('#define '+k+' '+v for k,v in model.items() if v is not None).encode(), stderr=b'')
        if '-ast-dump=json' in argv:
            key = route.declaration_key(ast)
            edit = route.plan_operand(bindings['records'][0], model, key)
            start = edit['sourceRange'][0]; stop = start+len(edit['replacement'])
            rhs = cast(binary('>>', binary('*', cast(variable('node:11'), 'unsigned __int128'),
                cast(variable('node:12'), 'unsigned __int128'), 'unsigned __int128'),
                literal(63 if wrong_target else 64), 'unsigned __int128'), 'unsigned long')
            assignment = binary('=', variable('node:10'), rhs, 'unsigned long')
            assignment['range'] = {'begin': {'offset': start}, 'end': {'offset': stop-2, 'tokLen': 1}}
            target = deepcopy(ast); target['inner'][0]['inner'][0]['inner'][-1] = assignment
            return SimpleNamespace(returncode=0, stdout=json.dumps(as_raw(target)).encode(), stderr=b'')
        output = Path(argv[argv.index('-o')+1])
        if output.name.startswith('fragment-'):
            word = (1<<25)|(12<<20)|(11<<15)|(3<<12)|(10<<7)|0x33
            assembly = '.text\n.globl rv2x86_native_fragment\n.type rv2x86_native_fragment,@function\nrv2x86_native_fragment:\n.byte '+','.join(str(b) for b in word.to_bytes(4,'little'))+'\n.size rv2x86_native_fragment,.-rv2x86_native_fragment\n'
            result = real_run([gcc, '-c', '-x', 'assembler', '-', '-o', str(output)], input=assembly.encode(), capture_output=True)
        elif argv[0] == sys.executable:
            flags = [a for a in argv[1:] if not a.startswith(('-march=', '-mabi='))]
            data = kwargs.get('input')
            if output.name in {'source.o', 'source-type-witness.o'}: data = b'void original_object_fixture(void) {}'
            result = real_run([gcc, *flags], input=data, capture_output=True)
        else:
            result = real_run(argv, **kwargs)
        if argv[0] == sys.executable and output.is_file():
            content = bytearray(output.read_bytes()); content[18:20] = (243).to_bytes(2,'little'); output.write_bytes(content)
        return result
    monkeypatch.setattr(route.subprocess, 'run', run)
    return bundle_path, gcc


def test_candidate_orchestration_rebuilds_and_audits_all_artifacts(tmp_path, monkeypatch):
    path, gcc = orchestration_fixture(tmp_path, monkeypatch)
    value = route.acquire(path, gcc, tmp_path/'candidate')
    assert value['derivedTargetMaterializationComplete'] and value['localIntegerProofComplete']
    assert not value['wholeFunctionCompositionVerified'] and not value['productionAcceptanceComplete']
    assert route.audit(value, tmp_path/'audit')['nativeCandidateIndependentAuditComplete']
    Path(value['candidatePath']).with_name('target.o').write_bytes(b'changed')
    with pytest.raises(ValueError, match='PROOF_ARTIFACT_CHANGED'):
        route.audit(value, tmp_path/'negative-audit')


def test_changed_target_ast_cannot_authorize_generation(tmp_path, monkeypatch):
    path, gcc = orchestration_fixture(tmp_path, monkeypatch, wrong_target=True)
    with pytest.raises(ValueError, match='TARGET_PRODUCT_MISMATCH'):
        route.acquire(path, gcc, tmp_path/'failed')
    assert not (tmp_path/'failed/candidate.json').exists()
    state = json.loads((tmp_path/'failed/run-status.json').read_text())
    assert state['status'] == 'failed' and not state['productionAcceptanceComplete']


@pytest.mark.parametrize('flag', ['semanticApproval', 'productionAcceptanceComplete', 'wholeFunctionCompositionVerified'])
def test_rehashed_program_acceptance_claim_fails_independent_rebuild(tmp_path, monkeypatch, flag):
    path, gcc = orchestration_fixture(tmp_path, monkeypatch)
    value = route.acquire(path, gcc, tmp_path/'candidate'); value[flag] = True
    value['candidateIdentity'] = identity({k:v for k,v in value.items() if k != 'candidateIdentity'})
    with pytest.raises(ValueError, match='INDEPENDENT_AUDIT_MISMATCH'):
        route.audit(value, tmp_path/'audit')
