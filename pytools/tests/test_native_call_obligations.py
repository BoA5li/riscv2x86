from copy import deepcopy
import json
import shutil
import subprocess
import sys

import pytest

from riscv2x86_py.compiler_native_calls import resolve, CONTEXT_V1, CONTEXT_V2
from riscv2x86_py.compiler_native_instance_binding import call_contexts, derive
from riscv2x86_py import project_native_binding as binding
from riscv2x86_py import project_native_requirements as requirements
from riscv2x86_py.project_build_records import identity, record, document
from .test_native_instance_binding import example, protocol


def builtin(name='__builtin_constant_p', arguments=None):
    if arguments is None:
        arguments = [{'kind': 'IntegerLiteral', 'value': '3', 'type': {'qualType': 'int'}}]
    return {'kind': 'CallExpr', 'type': {'qualType': 'int'}, 'inner': [
        {'kind': 'ImplicitCastExpr', 'castKind': 'BuiltinFnToFnPtr',
         'type': {'qualType': 'int (*)()'}, 'inner': [
            {'kind': 'DeclRefExpr', 'type': {'qualType': '<builtin fn type>'},
             'referencedDecl': {'id': 'node:90', 'kind': 'FunctionDecl',
                                'name': name, 'type': {'qualType': 'int ()'}}}]}, *arguments]}


@pytest.mark.parametrize('name,arity,operation', [
    ('__builtin_constant_p', 1, 'compile-time-constant-query'),
    ('__builtin_expect', 2, 'value-with-branch-expectation')])
def test_builtin_recognized_but_not_approved(name, arity, operation):
    call = builtin(name, [{'kind': 'CallExpr', 'id': 'arg:'+str(i)} for i in range(arity)])
    result = resolve(call)
    assert result['classification'] == 'compiler-builtin'
    assert result['semanticContract']['operation'] == operation
    assert result['semanticContract']['argumentCountMatches']
    assert result['argumentAsts'] == call['inner'][1:]
    assert not result['semanticContractVerified']
    assert result['semanticObligations']
    assert resolve(call, schema=CONTEXT_V1)['declaration'] is None


def test_builtin_name_alone_does_not_authorize_intrinsic_classification():
    call = builtin(); call['inner'][0]['castKind'] = 'FunctionToPointerDecay'
    result = resolve(call)
    assert result['classification'] == 'direct'
    assert result['semanticContract'] is None


@pytest.mark.parametrize('cast', ['LValueToRValue', 'BitCast', 'IntegralToPointer', 'UnknownCast'])
def test_other_conversions_do_not_become_direct_calls(cast):
    call = builtin(); call['inner'][0]['castKind'] = cast
    assert resolve(call)['classification'] == 'unresolved'


def test_function_pointer_and_malformed_cast_are_not_builtins():
    call = builtin(); call['inner'][0]['inner'][0]['referencedDecl']['kind'] = 'VarDecl'
    assert resolve(call)['classification'] == 'unresolved'
    call = builtin(); call['inner'][0]['inner'].append({})
    assert resolve(call)['classification'] == 'unresolved'


def test_unknown_builtin_and_wrong_arity_stay_blocked():
    result = resolve(builtin('__builtin_unmodelled'))
    assert result['classification'] == 'compiler-builtin'
    assert result['semanticObligations'] == ['COMPILER_BUILTIN_SEMANTICS_REQUIRED']
    result = resolve(builtin('__builtin_expect'))
    assert 'BUILTIN_ARGUMENT_ARITY_MISMATCH' in result['semanticObligations']


def test_parentheses_and_noop_keep_compiler_builtin_evidence():
    call = builtin()
    call['inner'][0] = {'kind': 'ParenExpr', 'inner': [
        {'kind': 'ImplicitCastExpr', 'castKind': 'NoOp', 'inner': [call['inner'][0]]}]}
    assert resolve(call)['classification'] == 'compiler-builtin'


def test_builtin_no_external_or_emitted_definition_shortcut():
    ast, report, raw = example(); bound = derive(ast, report, raw, 'input')
    ast['inner'][0]['inner'][0]['inner'].append(builtin())
    # Even an apparent definition with the same ID cannot discharge a builtin.
    ast['inner'].append({'kind': 'FunctionDecl', 'id': 'node:90',
        'inner': [{'kind': 'CompoundStmt'}]})
    result = call_contexts(ast, bound, 'input')
    call = result['functions'][0]['calls'][0]
    assert result['schemaVersion'] == CONTEXT_V2
    assert call['resolution'] == 'builtin-contract-required'
    assert call['targetFunctionAstPath'] is None
    assert not result['asmOwningFunctionContexts'][0]['callTargetGraphResolved']
    assert not result['callEffectClosureVerified']


def test_old_bundle_validates_and_replays_without_migrating_identities(tmp_path, monkeypatch):
    path, _, _ = protocol(tmp_path, monkeypatch)
    ast = binding.native_input.validate_artifacts({})['canonicalAst']
    ast['inner'][0]['inner'][0]['inner'].append(builtin())
    old = binding.acquire(path, sys.executable, tmp_path/'old', context_schema=CONTEXT_V1)
    _, contexts = binding.validate_artifacts(old)
    assert contexts['schemaVersion'] == CONTEXT_V1
    assert 'compilerCallEvidence' not in contexts['functions'][0]['calls'][0]
    assert binding.replay(old, tmp_path/'old-replay')['nativeBindingReplayComplete']
    new = binding.acquire(path, sys.executable, tmp_path/'new')
    _, contexts = binding.validate_artifacts(new)
    assert contexts['functions'][0]['calls'][0]['resolution'] == 'builtin-contract-required'


def development_example(tmp_path, monkeypatch, context_schema=CONTEXT_V2):
    path, _, _ = protocol(tmp_path, monkeypatch)
    ast = binding.native_input.validate_artifacts({})['canonicalAst']
    ast['inner'][0]['inner'][0]['inner'].append(builtin())
    action = record(['gcc', '-c', 'unit.c', '-o', 'unit.o'], tmp_path, {'kind': 'test'})
    receipt = json.loads(path.read_text())
    receipt['context'].update(actionIdentity=action['actionIdentity'], originalAction=action)
    path.write_text(json.dumps(receipt))
    binding.acquire(path, sys.executable, tmp_path/'capture', context_schema=context_schema)
    link = record(['gcc', '-shared', '-o', 'missing.so', 'unit.o'], tmp_path, {'kind': 'test'})
    records_path = tmp_path/'records.json'
    records_path.write_text(json.dumps(document([action, link], [], [], 'record')))
    bundle_path = tmp_path/'capture/binding-bundle.json'
    return bundle_path, records_path


@pytest.mark.parametrize('schema', [CONTEXT_V1, CONTEXT_V2])
def test_development_export_rederives_calls_including_old_bundles(tmp_path, monkeypatch, schema):
    bundle, records = development_example(tmp_path, monkeypatch, schema)
    result = requirements.acquire(bundle, records)
    assert result['callResolutionCounts'] == {'builtin-contract-required': 1}
    assert result['callObligations'][0]['compilerCallEvidence']['argumentAsts'][0]['value'] == '3'
    assert result['callObligations'][0]['immediateParentAst']['kind'] == 'CompoundStmt'
    assert result['syntaxCounts']['CallExpr'] == 1
    assert result['selectedNativeCompileActionPresent']
    assert not result['compositionProofComplete']
    assert not result['formalEvaluationEntrySelected']
    assert requirements.replay(result)['nativeDevelopmentBasisReplayComplete']


@pytest.mark.parametrize('mutation', ['argument', 'approval', 'entry', 'required-work', 'omitted-call'])
def test_rehashed_reports_cannot_erase_or_discharge_obligations(tmp_path, monkeypatch, mutation):
    bundle, records = development_example(tmp_path, monkeypatch)
    result = requirements.acquire(bundle, records)
    if mutation == 'argument':
        result['callObligations'][0]['compilerCallEvidence']['argumentAsts'][0]['value'] = '4'
    elif mutation == 'approval': result['semanticApproval'] = True
    elif mutation == 'entry': result['formalEvaluationEntrySelected'] = True
    elif mutation == 'required-work': result['requiredWork'].clear()
    else: result['callObligations'].clear()
    result['developmentBasisIdentity'] = identity({k: v for k, v in result.items() if k != 'developmentBasisIdentity'})
    with pytest.raises(ValueError, match='REPLAY_MISMATCH'):
        requirements.replay(result)


@pytest.mark.parametrize('args,reason', [
    (['gcc', 'a.o'], 'EXPLICIT_OUTPUT_REQUIRED'),
    (['gcc', '-o'], 'ARGUMENT_INVALID'),
    (['gcc', '-o', 'a', '-ob'], 'AMBIGUOUS'),
    (['gcc', '-o', 'a', '@args'], 'RESPONSE_FILE')])
def test_uncertain_link_outputs_do_not_become_entries(tmp_path, args, reason):
    result = requirements.inspect_link(record(args, tmp_path, {'kind': 'test'}))
    assert any(reason in blocker for blocker in result['blockers'])
    assert result['currentArtifact'] is None
    assert not result['testEntryVerified']


def test_elf_machine_uses_artifact_not_compiler_name_and_does_not_approve_entry(tmp_path):
    gcc = shutil.which('gcc')
    if not gcc: pytest.skip('native GCC required')
    source = tmp_path/'arbitrary.c'; source.write_text('int main(void) { return 0; }')
    output = tmp_path/'binary'
    subprocess.run([gcc, str(source), '-o', str(output)], check=True, capture_output=True)
    action = record(['riscv64-linux-gnu-gcc-7', '-o', str(output), 'arbitrary.c'], tmp_path, {'kind': 'test'})
    result = requirements.inspect_link(action)
    assert result['currentArtifact']['elfMachine'] == 62
    assert result['currentArtifact']['hasDefinedMainSymbol']
    assert not result['currentArtifact']['historicalOutputBindingVerified']
    assert not result['testEntryVerified']


def test_cli_development_export_and_replay(tmp_path, monkeypatch, capsys):
    import importlib.util
    from pathlib import Path
    bundle, records = development_example(tmp_path, monkeypatch)
    spec = importlib.util.spec_from_file_location('development_cli',
        Path(__file__).parents[2]/'experiment/preflight_project_macros.py')
    cli = importlib.util.module_from_spec(spec); spec.loader.exec_module(cli)
    output = tmp_path/'development.json'
    assert cli.main(['development-basis', '--bundle', str(bundle), '--records', str(records),
                     '--output', str(output)]) == 0
    assert cli.main(['replay-development-basis', '--input', str(output)]) == 0
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert rows[-1]['nativeDevelopmentBasisReplayComplete']
    assert not rows[-1]['freshCompilerReplayPerformed']
