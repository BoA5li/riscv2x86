from copy import deepcopy
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from riscv2x86_py import compiler_native_instance_binding as module
from riscv2x86_py import project_native_binding as acquisition
from riscv2x86_py.project_build_records import identity
from riscv2x86_py.project_compile_context import digest
from riscv2x86_py.project_acquisition import StageFailure


def example(prefix='// different-name\n', name='entry'):
    raw = (prefix + 'unsigned long ' + name + '(unsigned long left, unsigned long right) {'
        ' unsigned long hi; unsigned long low = left * right; '
        '__asm__("mulhu %0, %1, %2" : "=r"(hi) : "%r"(left), "r"(right)); return hi; }').encode()
    start = raw.index(b'__asm__'); stop = raw.index(b';', start)+1
    def span(begin, end):
        return {'begin': {'offset': begin, 'tokLen': 1}, 'end': {'offset': end-1, 'tokLen': 1}}
    expressions = []; operands = []
    for index, (constraint, text) in enumerate((('=r', 'hi'), ('%r', 'left'), ('r', 'right'))):
        begin = raw.index(('(' + text + ')').encode(), start)+1; end = begin+len(text)
        expression = {'kind': 'DeclRefExpr', 'range': span(begin, end),
            'type': {'qualType': 'unsigned long'}, 'referencedDecl': {
                'id': 'node:' + str(index+10), 'kind': 'VarDecl', 'name': text,
                'type': {'qualType': 'unsigned long'}}}
        expressions.append(expression)
        operands.append({'constraint': constraint, 'exprText': text, 'isOutput': index == 0,
            'symbolicName': '', 'isTied': False, 'isEarlyClobber': False,
            'compilerType': {'schemaVersion': 'riscv2x86.clang-operand-type.v1',
                'canonicalType': 'unsigned long', 'widthBits': 64, 'alignmentBytes': 8,
                'isInteger': True, 'isPointer': False, 'isSigned': False,
                'sideEffectFree': True, 'modifiableLvalue': True, 'expressionRepeatable': True,
                'qualifiers': '', 'pointeeQualifiers': '', 'pointeeType': '',
                'pointeeWidthBits': 0, 'pointeeAlignmentBytes': 0, 'pointeeIsInteger': False}})
    asm = {'kind': 'GCCAsmStmt', 'range': span(start, stop-1), 'inner': expressions}
    ast = {'kind': 'TranslationUnitDecl', 'id': 'node:0', 'inner': [
        {'kind': 'FunctionDecl', 'id': 'node:1', 'name': name,
         'type': {'qualType': 'unsigned long (unsigned long, unsigned long)'},
         'inner': [{'kind': 'CompoundStmt', 'inner': [asm]}]}]}
    fragment = {'rawAsmText': 'mulhu %0, %1, %2', 'asmText': 'mulhu %0, %1, %2',
        'astBeginOffset': start, 'astEndOffset': stop-1,
        'beginOffset': start, 'endOffset': stop, 'outputs': operands[:1], 'inputs': operands[1:],
        'clobbers': [], 'isVolatile': False}
    report = {'findings': [{'subjectKind': 'AsmFragment', 'fragment': fragment,
        'fromMacroExpansion': False, 'rewriteBeginOffset': start, 'rewriteEndOffset': stop,
        'rawSourceText': raw[start:stop].decode()}]}
    return ast, report, raw


@pytest.mark.parametrize('prefix,name', [('', 'one'), ('// 中文\n', 'renamed')])
def test_compiler_export_binds_exact_byte_domain_and_keeps_relations(prefix, name):
    ast, report, raw = example(prefix, name)
    result = module.derive(ast, report, raw, 'input')
    assert result['occurrenceCount'] == 1 and result['allEmittedAstAsmOccurrencesBound']
    row = result['records'][0]
    assert row['derivedInputInstanceBindingComplete']
    assert row['typedOperandContractsComplete']
    assert not row['originalSourceInstanceBindingComplete'] and not row['editAuthorizationComplete']
    assert row['constraintRelation']['commutativePairs'] == [[1, 2]]
    assert any(b['detail'] == 'OPERAND_PERMUTATION_PROOF_REQUIRED' for b in row['blockers'])
    assert row['operands'][1]['declarationReferences'][0]['declaration']['name'] == 'left'
    contexts = module.call_contexts(ast, result, 'input')
    assert len(contexts['asmOwningFunctionContexts']) == 1
    assert not contexts['asmOwningFunctionContexts'][0]['formalEvaluationEntrySelected']


@pytest.mark.parametrize('mutation,reason', [
    ('missing', 'COVERAGE_MISMATCH'), ('duplicate', 'COVERAGE_MISMATCH'),
    ('range', 'FRONTEND_AST_RANGE_MISMATCH'), ('arity', 'OPERAND_AST_ARITY_MISMATCH'),
    ('expression', 'OPERAND_BYTES_MISMATCH'), ('statement', 'STATEMENT_BYTES_MISMATCH'),
    ('role', 'OPERAND_ROLE_MISMATCH'), ('macro', 'FRONTEND_DOMAIN_MISMATCH'),
    ('boolean', 'FRONTEND_AST_RANGE_MISMATCH'), ('clobber', 'CLOBBER_EXPORT_REQUIRED')])
def test_incomplete_or_conflicting_export_is_rejected(mutation, reason):
    ast, report, raw = example(); finding = report['findings'][0]; f = finding['fragment']
    if mutation == 'missing': report['findings'].clear()
    elif mutation == 'duplicate': report['findings'].append(deepcopy(finding))
    elif mutation == 'range': f['astEndOffset'] += 1
    elif mutation == 'arity': f['inputs'].pop()
    elif mutation == 'expression': f['inputs'][0]['exprText'] = 'right'
    elif mutation == 'statement': finding['rawSourceText'] += ';'
    elif mutation == 'role': f['outputs'][0]['isOutput'] = False
    elif mutation == 'macro': finding['fromMacroExpansion'] = True
    elif mutation == 'boolean': f['astBeginOffset'] = True
    elif mutation == 'clobber': f['clobbers'] = 'memory'
    with pytest.raises(ValueError, match=reason):
        module.derive(ast, report, raw, 'input')


def test_unsupported_constraint_stays_in_denominator_and_unapproved():
    ast, report, raw = example()
    report['findings'][0]['fragment']['inputs'][0]['constraint'] = 'r,m'
    result = module.derive(ast, report, raw, 'input')
    assert result['occurrenceCount'] == 1
    assert result['records'][0]['constraintRelation'] is None
    assert result['records'][0]['blockers'][0]['stage'] == 'constraint-semantics'
    assert not result['semanticApproval']


def test_extra_statement_cannot_become_an_asm_replacement_range():
    ast, report, raw = example(); f = report['findings'][0]
    f['rewriteEndOffset'] = len(raw); f['fragment']['endOffset'] = len(raw)
    f['rawSourceText'] = raw[f['rewriteBeginOffset']:].decode()
    with pytest.raises(ValueError, match='STATEMENT_SUFFIX_INVALID'):
        module.derive(ast, report, raw, 'input')


def test_unsupported_asm_kind_is_not_treated_as_zero_occurrences():
    ast, report, raw = example()
    ast['inner'][0]['inner'][0]['inner'][0]['kind'] = 'MSAsmStmt'
    with pytest.raises(ValueError, match='ASM_KIND_EXPORT_REQUIRED'):
        module.derive(ast, report, raw, 'input')


def test_call_graph_follows_declaration_identity_and_does_not_approve_effects():
    ast, report, raw = example(); binding = module.derive(ast, report, raw, 'input')
    def call(ref):
        return {'kind': 'CallExpr', 'inner': [{'kind': 'ImplicitCastExpr',
            'castKind': 'FunctionToPointerDecay', 'inner': [{'kind': 'DeclRefExpr',
                'referencedDecl': {'kind': 'FunctionDecl', 'id': ref, 'name': 'same_name'}}]}]}
    entry = ast['inner'][0]; entry['inner'][0]['inner'].append(call('node:20'))
    prototype = {'kind': 'FunctionDecl', 'id': 'node:20', 'name': 'helper'}
    definition = {'kind': 'FunctionDecl', 'id': 'node:21', 'previousDecl': 'node:20',
        'name': 'helper', 'inner': [{'kind': 'CompoundStmt', 'inner': [call('node:1')]}]}
    ast['inner'].extend([prototype, definition])
    value = module.call_contexts(ast, binding, 'input')
    root = value['asmOwningFunctionContexts'][0]
    assert len(root['reachableFunctionContexts']) == 2
    assert any(r['reason'] == 'RECURSIVE_EFFECT_SUMMARY_REQUIRED' for r in root['unresolvedCalls'])
    assert not root['effectClosureVerified'] and not value['buildLinkClosureVerified']


def protocol(tmp_path, monkeypatch, failure=0):
    ast, report, raw = example()
    input_path = tmp_path/'input.stdout'; input_path.write_bytes(raw)
    receipt_path = tmp_path/'native-input.json'
    receipt = {'nativeInputIdentity': 'native', 'analysisInputIdentity': 'input',
        'context': {'workingDirectory': str(tmp_path)}, 'target': 'riscv64',
        'commands': [],
        'analysisInput': {'inspectionArguments': ['-O2', '-march=rv64gc', '-mabi=lp64d']}}
    receipt_path.write_text(json.dumps(receipt))
    monkeypatch.setattr(acquisition, 'validate_context', lambda _: None)
    def replay_input(value, output, **kwargs):
        output = Path(output); output.mkdir()
        fresh = dict(value, nativeInputIdentity='fresh')
        (output/'native-input.json').write_text(json.dumps(fresh))
        body = {'schemaVersion': 'riscv2x86.native-analysis-input-replay.v1',
            'originalNativeInputIdentity': value['nativeInputIdentity'],
            'freshNativeInputIdentity': fresh['nativeInputIdentity'],
            'analysisInputIdentity': value['analysisInputIdentity'],
            'nativeInputReplayComplete': True, 'compilerEquivalenceVerified': False,
            'sourceInstanceBindingComplete': False, 'semanticApproval': False,
            'productionAcceptanceComplete': False}
        return dict(body, replayIdentity=identity(body))
    monkeypatch.setattr(acquisition.native_input, 'replay', replay_input)
    monkeypatch.setattr(acquisition.native_input, 'validate_artifacts', lambda _: {
        'inputBytes': raw, 'canonicalAst': ast, 'stages': {'native-expanded': {'stdoutPath': str(input_path)}}})
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        Path(command[command.index('--report-json')+1]).write_text(json.dumps(report))
        return SimpleNamespace(returncode=failure, stdout=b'frontend', stderr=b'failed' if failure else b'')
    monkeypatch.setattr(acquisition.subprocess, 'run', run)
    return receipt_path, calls, report


def test_bundle_and_independent_compiler_export_replay(tmp_path, monkeypatch):
    path, calls, _ = protocol(tmp_path, monkeypatch)
    value = acquisition.acquire(path, sys.executable, tmp_path/'capture')
    assert value['occurrenceCount'] == 1 and value['derivedInputInstanceBindingComplete']
    assert not value['originalSourceInstanceBindingComplete']
    assert '--analysis-only' in calls[0] and '--no-builtin-rules' in calls[0]
    assert calls[0][-2:] == ['-x', 'cpp-output']
    assert acquisition.replay(value, tmp_path/'replay')['nativeBindingReplayComplete']


def test_frontend_failure_keeps_actual_exit_and_no_complete_bundle(tmp_path, monkeypatch):
    path, _, _ = protocol(tmp_path, monkeypatch, failure=9)
    with pytest.raises(StageFailure) as exc:
        acquisition.acquire(path, sys.executable, tmp_path/'capture')
    assert exc.value.code == 9
    state = json.loads((tmp_path/'capture/run-status.json').read_text())
    assert state['primaryFailure']['returnCode'] == 9
    assert not (tmp_path/'capture/binding-bundle.json').exists()


def test_rehashed_binding_change_is_rejected_by_rederivation(tmp_path, monkeypatch):
    path, _, _ = protocol(tmp_path, monkeypatch)
    value = acquisition.acquire(path, sys.executable, tmp_path/'capture')
    bindings_path = Path(value['bindingsPath']); bindings = json.loads(bindings_path.read_text())
    bindings['records'][0]['operands'][0]['compilerExport']['compilerType']['widthBits'] = 32
    bindings['bindingInventoryIdentity'] = identity({k: v for k, v in bindings.items() if k != 'bindingInventoryIdentity'})
    bindings_path.write_text(json.dumps(bindings)); value['bindingsDigest'] = digest(bindings_path)
    value['bindingInventoryIdentity'] = bindings['bindingInventoryIdentity']
    value['bindingBundleIdentity'] = identity({k: v for k, v in value.items() if k != 'bindingBundleIdentity'})
    with pytest.raises(ValueError, match='DERIVATION_MISMATCH'):
        acquisition.validate_artifacts(value)


def test_rehashed_edit_approval_never_becomes_authority(tmp_path, monkeypatch):
    path, _, _ = protocol(tmp_path, monkeypatch)
    value = acquisition.acquire(path, sys.executable, tmp_path/'capture')
    value['editAuthorizationComplete'] = True
    value['bindingBundleIdentity'] = identity({k: v for k, v in value.items() if k != 'bindingBundleIdentity'})
    with pytest.raises(ValueError, match='DERIVATION_MISMATCH'):
        acquisition.validate_artifacts(value)


def test_frontend_changed_semantics_are_detected_in_replay(tmp_path, monkeypatch):
    path, _, report = protocol(tmp_path, monkeypatch)
    value = acquisition.acquire(path, sys.executable, tmp_path/'capture')
    report['findings'][0]['fragment']['rawAsmText'] = 'different operation'
    with pytest.raises(ValueError, match='INDEPENDENT_REPLAY_MISMATCH'):
        acquisition.replay(value, tmp_path/'replay')


def test_unknown_type_contract_is_retained_as_a_blocker():
    ast, report, raw = example()
    report['findings'][0]['fragment']['outputs'][0]['compilerType']['widthBits'] = -1
    result = module.derive(ast, report, raw, 'input')
    assert result['occurrenceCount'] == 1
    row = result['records'][0]
    assert not row['typedOperandContractsComplete']
    assert row['blockers'][0]['stage'] == 'compiler-type-contract'


def test_command_rebinding_is_rejected_even_after_rehash(tmp_path, monkeypatch):
    path, _, _ = protocol(tmp_path, monkeypatch)
    value = acquisition.acquire(path, sys.executable, tmp_path/'capture')
    value['command']['command'][-1] = 'c'
    value['bindingBundleIdentity'] = identity({k: v for k, v in value.items() if k != 'bindingBundleIdentity'})
    with pytest.raises(ValueError, match='EXPORT_COMMAND_MISMATCH'):
        acquisition.validate_artifacts(value)


def test_stored_native_replay_claim_cannot_be_changed(tmp_path, monkeypatch):
    path, _, _ = protocol(tmp_path, monkeypatch)
    value = acquisition.acquire(path, sys.executable, tmp_path/'capture')
    value['nativeInputReplay']['semanticApproval'] = True
    value['nativeInputReplay']['replayIdentity'] = identity({
        k: v for k, v in value['nativeInputReplay'].items() if k != 'replayIdentity'})
    value['bindingBundleIdentity'] = identity({k: v for k, v in value.items() if k != 'bindingBundleIdentity'})
    with pytest.raises(ValueError, match='INPUT_REPLAY_RECEIPT_INVALID'):
        acquisition.validate_artifacts(value)


def test_empty_shell_prefix_cannot_write_a_top_level_result():
    with pytest.raises(ValueError, match='RESULT_PARENT_REQUIRED'):
        acquisition.acquire('missing.json', sys.executable, '/unintended-result')


def test_build_records_are_bound_without_inventing_an_entry(tmp_path, monkeypatch):
    from riscv2x86_py.project_build_records import document, record
    path, _, _ = protocol(tmp_path, monkeypatch)
    action = record(['gcc', '-c', str(tmp_path/'unit.c'), '-o', 'unit.o'], tmp_path, {'kind': 'unit-test'})
    receipt = json.loads(path.read_text())
    receipt['context'].update(actionIdentity=action['actionIdentity'], originalAction=action)
    path.write_text(json.dumps(receipt))
    value = acquisition.acquire(path, sys.executable, tmp_path/'capture')
    records = document([action], [], [], 'source')
    record_path = tmp_path/'records.json'; record_path.write_text(json.dumps(records))
    result = acquisition.build_basis(value, record_path)
    assert result['selectedNativeCompileActionPresent']
    assert result['observedSuccessfulActions'] == 0
    assert not result['formalEvaluationEntrySelected'] and not result['buildLinkClosureVerified']
    records['actionCounts']['link'] = 1
    records['inventoryIdentity'] = identity({k: v for k, v in records.items() if k != 'inventoryIdentity'})
    record_path.write_text(json.dumps(records))
    with pytest.raises(ValueError, match='BUILD_COUNTS_MISMATCH'):
        acquisition.build_basis(value, record_path)


def test_cli_binds_inspects_and_replays_without_translation_authority(tmp_path, monkeypatch, capsys):
    import importlib.util
    path, _, _ = protocol(tmp_path, monkeypatch)
    spec = importlib.util.spec_from_file_location('native_binding_cli',
        Path(__file__).parents[2]/'experiment/preflight_project_macros.py')
    cli = importlib.util.module_from_spec(spec); spec.loader.exec_module(cli)
    assert cli.main(['bind-native', '--native-input-receipt', str(path), '--frontend', sys.executable,
        '--output', str(tmp_path/'capture')]) == 0
    bundle = tmp_path/'capture/binding-bundle.json'
    assert cli.main(['inspect-bindings', '--bundle', str(bundle), '--include-context']) == 0
    assert cli.main(['replay-bindings', '--bundle', str(bundle), '--output', str(tmp_path/'replay')]) == 0
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert lines[0]['derivedInputInstanceBindingComplete']
    assert lines[-1]['nativeBindingReplayComplete'] and not lines[-1]['productionAcceptanceComplete']


def test_real_riscv_compiler_api_binding_and_replay(tmp_path):
    import os
    import shutil
    from riscv2x86_py.project_build_records import record
    from riscv2x86_py.project_compile_context import derive
    clang = os.environ.get('RV2X86_SYSTEM_CLANG') or shutil.which('clang')
    gcc = os.environ.get('RV2X86_TEST_RISCV_CC') or shutil.which('riscv64-linux-gnu-gcc')
    frontend = os.environ.get('RISCV2X86_TEST_FRONTEND')
    if not clang or not gcc or not frontend:
        pytest.skip('real RISC-V GCC, Clang and built riscv2x86 frontend required')
    header = tmp_path/'renamed.h'
    header.write_text('#define PRODUCT(h,l,a,b) do { unsigned long u=(a),v=(b); '
        '(l)=u*v; __asm__("mulhu %0, %1, %2":"=r"(h):"%r"(u),"r"(v)); } while(0)\n')
    source = tmp_path/'program.c'
    source.write_text('#include "renamed.h"\nunsigned long calculate(unsigned long a,unsigned long b)'
        '{unsigned long hi,lo;PRODUCT(hi,lo,a,b);return hi^lo;}\n')
    action = record([gcc, '-std=gnu11', '-O2', '-march=rv64gc', '-mabi=lp64d',
        '-c', str(source), '-o', str(tmp_path/'program.o')], tmp_path, {'kind': 'explicit-test-profile'})
    context = derive(action)
    acquisition.native_input.acquire(context, clang, tmp_path/'native-input')
    bundle = acquisition.acquire(tmp_path/'native-input/native-input.json', frontend, tmp_path/'binding')
    bindings, contexts = acquisition.validate_artifacts(bundle)
    assert bindings['occurrenceCount'] == 1
    assert bindings['records'][0]['typedOperandContractsComplete']
    assert bindings['records'][0]['constraintRelation']['commutativePairs'] == [[1, 2]]
    assert bindings['records'][0]['enclosingCompound']['physicalRange'] is not None
    assert len(contexts['asmOwningFunctionContexts']) == 1
    assert acquisition.replay(bundle, tmp_path/'replay')['nativeBindingReplayComplete']
