"""Native compiler integration plus adversarial protocol/replay tests."""
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from riscv2x86_py import project_native_input as module
from riscv2x86_py.project_build_records import identity, record
from riscv2x86_py.project_compile_context import derive
from riscv2x86_py.project_acquisition import StageFailure


def ast(ids=('0x111', '0x222'), value='0x1234'):
    return {'kind': 'TranslationUnitDecl', 'id': ids[0], 'inner': [
        {'kind': 'FunctionDecl', 'id': ids[1], 'name': 'renamable',
         'type': {'qualType': 'unsigned long (unsigned long)'}, 'inner': [
            {'kind': 'LeafAttr'}, {'kind': 'WarnUnusedResultAttr'},
            {'kind': 'StringLiteral', 'value': value},
            {'kind': 'DeclRefExpr', 'referencedDecl': {'id': ids[1],
                'kind': 'FunctionDecl', 'name': 'renamable'}},
            {'kind': 'GCCAsmStmt', 'range': {'begin': {'offset': 10, 'tokLen': 7},
                'end': {'offset': 30, 'tokLen': 1}}}]}]}


def native_context(tmp_path, compiler=None, architecture=()):
    gcc = compiler or shutil.which('gcc')
    if not gcc:
        pytest.skip('native GCC required')
    header = tmp_path / 'renamed-header.h'
    header.write_text('#define PROJECT_NUMBER 0x7fffffff\n'
        '#if __GNUC__ >= 5\n#define PROJECT_ATTR __attribute__((warn_unused_result))\n'
        '#else\n#define PROJECT_ATTR\n#endif\n')
    source = tmp_path / 'renamed-unit.c'
    source.write_text('#include "renamed-header.h"\n'
        'PROJECT_ATTR unsigned long renamable(unsigned long x) {'
        '__asm__("" : "+r"(x)); return x + PROJECT_NUMBER;}\n')
    action = record([gcc, '-std=gnu11', '-O2', *architecture, '-DPROJECT_FROM_ARG=1',
        '-I', str(tmp_path), '-c', str(source), '-o', str(tmp_path/'unit.o')],
        tmp_path, {'kind': 'explicit-project-profile'})
    context = derive(action)
    assert context['inspectionReady']
    return context, header


def fixture(tmp_path, monkeypatch):
    context, header = native_context(tmp_path)
    real = subprocess.run
    gcc = context['nativeCompiler']
    model = real([gcc, '-std=gnu11', '-E', '-dM', '-x', 'c', '-'],
        input=b'', capture_output=True, check=True).stdout
    calls = []; control = {'iteration': 0, 'attribute': False, 'failed': None,
                          'model': False, 'mutate': False, 'literal': False}
    def run(command, **kwargs):
        calls.append((command, kwargs.get('input')))
        if Path(command[0]).resolve() == Path(sys.executable).resolve():
            if '-dM' in command:
                value = model.replace(b'__SIZEOF_LONG__ 8', b'__SIZEOF_LONG__ 4') if control['model'] else model
                return SimpleNamespace(returncode=0, stdout=value, stderr=b'')
            if control['failed']:
                return SimpleNamespace(returncode=control['failed'], stdout=b'{}', stderr=b'ignored attribute')
            control['iteration'] += 1
            value = ast((hex(100*control['iteration']), hex(100*control['iteration']+1)))
            if control['attribute']:
                value['inner'][0]['inner'][0]['kind'] = 'ConstAttr'
            if control['literal']:
                value['inner'][0]['inner'][2]['value'] = '0xabcd'
            return SimpleNamespace(returncode=0, stdout=json.dumps(value).encode(), stderr=b'')
        result = real(command, **kwargs)
        if control['mutate'] and '-dD' in command:
            header.write_text(header.read_text() + '\n#define CHANGED 1\n')
        return result
    monkeypatch.setattr(module.subprocess, 'run', run)
    return context, calls, control


def test_native_bytes_are_consumed_without_second_preprocessing(tmp_path, monkeypatch):
    context, calls, _ = fixture(tmp_path, monkeypatch)
    value = module.acquire(context, sys.executable, tmp_path/'capture', target='x86_64')
    parsed = next((c, data) for c, data in calls if '-ast-dump=json' in c)
    command, raw = parsed
    assert command[-1] == '-' and command[command.index('-x')+1] == 'cpp-output'
    assert b'warn_unused_result' in raw and b'0x7fffffff' in raw
    assert all(not c.startswith(('-D', '-I')) for c in command)
    assert str(Path(context['sourcePath'])) not in command
    assert value['nativeInputConsumed'] and not value['compilerEquivalenceVerified']
    inventory = json.loads(Path(value['inventoryPath']).read_text())
    assert len(inventory['instances']) == 1
    assert inventory['instances'][0]['locationDomain'] == 'native-preprocessed-input'
    assert not inventory['sourceInstanceBindingComplete']
    result = module.replay(value, tmp_path/'replay')
    assert result['nativeInputReplayComplete'] and not result['semanticApproval']


def test_ast_alpha_renaming_preserves_aliases_literals_and_types():
    assert module.canonical_ast(ast()) == module.canonical_ast(ast(('0xab', '0xcd')))
    changed = ast(); changed['inner'][0]['inner'][3]['referencedDecl']['id'] = '0x111'
    assert module.canonical_ast(ast()) != module.canonical_ast(changed)
    assert module.canonical_ast(ast()) != module.canonical_ast(ast(value='0xabcd'))
    changed = ast(); changed['inner'][0]['type']['qualType'] = 'long (long)'
    assert module.canonical_ast(ast()) != module.canonical_ast(changed)


@pytest.mark.parametrize('change', ['attribute', 'literal'])
def test_changed_ast_semantics_rejected_despite_fresh_ids(tmp_path, monkeypatch, change):
    context, _, control = fixture(tmp_path, monkeypatch)
    value = module.acquire(context, sys.executable, tmp_path/'capture', target='x86_64')
    control[change] = True
    with pytest.raises(ValueError, match='INDEPENDENT_REPLAY_MISMATCH'):
        module.replay(value, tmp_path/'replay')


def test_ignored_or_unsupported_attribute_cannot_be_accepted(tmp_path, monkeypatch):
    context, calls, control = fixture(tmp_path, monkeypatch)
    control['failed'] = 7
    with pytest.raises(StageFailure) as exc:
        module.acquire(context, sys.executable, tmp_path/'capture', target='x86_64')
    assert exc.value.code == 7
    command = next(c for c, _ in calls if '-ast-dump=json' in c)
    assert '-Werror=unknown-attributes' in command and '-Werror=ignored-attributes' in command
    state = json.loads((tmp_path/'capture/run-status.json').read_text())
    assert state['primaryFailure']['stage'] == 'inspection-native-input'
    assert state['primaryFailure']['returnCode'] == 7
    assert not (tmp_path/'capture/native-input.json').exists()


def test_data_model_mismatch_rejected_before_ast(tmp_path, monkeypatch):
    context, calls, control = fixture(tmp_path, monkeypatch)
    control['model'] = True
    with pytest.raises(ValueError, match='DATA_MODEL_MISMATCH'):
        module.acquire(context, sys.executable, tmp_path/'capture', target='x86_64')
    assert not any('-ast-dump=json' in c for c, _ in calls)


def test_dependency_changed_during_capture_rejected(tmp_path, monkeypatch):
    context, _, control = fixture(tmp_path, monkeypatch)
    control['mutate'] = True
    with pytest.raises(ValueError, match='DEPENDENCIES_CHANGED'):
        module.acquire(context, sys.executable, tmp_path/'capture', target='x86_64')


def test_artifact_and_rehashed_approval_cannot_pass(tmp_path, monkeypatch):
    context, _, _ = fixture(tmp_path, monkeypatch)
    value = module.acquire(context, sys.executable, tmp_path/'capture', target='x86_64')
    forged = deepcopy(value); forged['semanticApproval'] = True
    forged['nativeInputIdentity'] = identity({k: v for k, v in forged.items() if k != 'nativeInputIdentity'})
    with pytest.raises(ValueError, match='INDEPENDENT_REPLAY_MISMATCH'):
        module.replay(forged, tmp_path/'forged')
    Path(value['canonicalAstPath']).write_text('{}')
    with pytest.raises(ValueError, match='ARTIFACT_CHANGED'):
        module.replay(value, tmp_path/'replay')


def test_existing_outputs_not_overwritten(tmp_path, monkeypatch):
    context, _, _ = fixture(tmp_path, monkeypatch)
    module.acquire(context, sys.executable, tmp_path/'capture', target='x86_64')
    with pytest.raises(FileExistsError):
        module.acquire(context, sys.executable, tmp_path/'capture', target='x86_64')


def test_rehashed_raw_ast_cannot_disagree_with_canonical_evidence(tmp_path, monkeypatch):
    from riscv2x86_py.project_compile_context import digest
    context, _, _ = fixture(tmp_path, monkeypatch)
    value = module.acquire(context, sys.executable, tmp_path/'capture', target='x86_64')
    row = next(r for r in value['commands'] if r['stage'] == 'inspection-native-input')
    path = Path(row['stdoutPath']); changed = json.loads(path.read_text())
    changed['inner'][0]['inner'][0]['kind'] = 'ConstAttr'
    path.write_text(json.dumps(changed)); row['stdoutDigest'] = digest(path)
    value['nativeInputIdentity'] = identity({k: v for k, v in value.items() if k != 'nativeInputIdentity'})
    with pytest.raises(ValueError, match='ARTIFACT_BINDING_INVALID'):
        module.replay(value, tmp_path/'replay')


def test_cpp_argument_projection_preserves_semantic_order():
    assert module.analysis_arguments(['-I', 'a', '-include', 'forced.h', '-DX=1',
        '-U', 'Y', '-std=c99', '-fwrapv', '-fno-wrapv', '-O2', '-fPIC']) == [
            '-std=c99', '-fwrapv', '-fno-wrapv', '-O2', '-fPIC']


def test_source_and_frontend_changes_invalidate_existing_receipt(tmp_path, monkeypatch):
    context, _, _ = fixture(tmp_path, monkeypatch)
    value = module.acquire(context, sys.executable, tmp_path/'capture', target='x86_64')
    assert len(value['analysisInput']['tools']) == 3
    Path(context['sourcePath']).write_text('int changed;\n')
    with pytest.raises(ValueError, match='PROJECT_CONTEXT_CONTENT_CHANGED'):
        module.replay(value, tmp_path/'replay')


def test_compiler_timeout_records_real_failure(tmp_path, monkeypatch):
    context, _, _ = fixture(tmp_path, monkeypatch)
    def fail(*args, **kwargs):
        raise subprocess.TimeoutExpired('compiler', 1)
    monkeypatch.setattr(module.subprocess, 'run', fail)
    with pytest.raises(subprocess.TimeoutExpired):
        module.acquire(context, sys.executable, tmp_path/'capture', target='x86_64')
    state = json.loads((tmp_path/'capture/run-status.json').read_text())
    assert state['status'] == 'failed' and not state['acquisitionComplete']


def test_preflight_native_mode_binds_discovery_and_rejects_rehashed_claim(tmp_path, monkeypatch):
    from riscv2x86_py import project_native_macro_preflight as preflight
    from riscv2x86_py.project_compile_context import digest
    context, _, _ = fixture(tmp_path, monkeypatch)
    report = {'records': [{'context': context, 'inspection': {'snapshot': {
        'dependencyManifest': {'compilerCommand': [sys.executable]}}}}]}
    path = tmp_path/'contexts.json'; path.write_text(json.dumps(report))
    eligibility = {'eligibilityInventoryIdentity': 'eligibility', 'records': [{
        'contextIdentity': context['contextIdentity'], 'inspectionReportPath': str(path),
        'inspectionReportDigest': digest(path)}]}
    monkeypatch.setattr(preflight, 'validate_eligibility', lambda _: None)
    monkeypatch.setattr(preflight, 'validate_dependencies', lambda _: None)
    # Only the native compiler runs here; inspector/model output is simulated.
    value = preflight.acquire(eligibility, context['contextIdentity'],
        tmp_path/'capture', mode='native-input')
    assert value['nativeInputConsumed'] and not value['originalDiscoveryRebound']
    assert 'sourcePreprocessingMatched' not in value
    result = preflight.replay(value, eligibility, tmp_path/'replay')
    assert result['nativeInputReplayComplete'] and not result['productionAcceptanceComplete']
    forged = deepcopy(value); forged['editAuthorizationComplete'] = True
    forged['preflightIdentity'] = identity({k: v for k, v in forged.items() if k != 'preflightIdentity'})
    with pytest.raises(ValueError, match='NATIVE_RECEIPT_MISMATCH'):
        preflight.replay(forged, eligibility, tmp_path/'forged')


def test_real_native_cpp_and_clang_independent_replay(tmp_path):
    clang = os.environ.get('RV2X86_SYSTEM_CLANG') or shutil.which('clang')
    if not clang:
        pytest.skip('real Clang required; mock protocol tests do not replace this integration')
    context, _ = native_context(tmp_path)
    value = module.acquire(context, clang, tmp_path/'capture', target='x86_64')
    assert module.replay(value, tmp_path/'replay')['nativeInputReplayComplete']


def test_real_riscv_native_cpp_and_clang_independent_replay(tmp_path):
    clang = os.environ.get('RV2X86_SYSTEM_CLANG') or shutil.which('clang')
    gcc = os.environ.get('RV2X86_TEST_RISCV_CC') or shutil.which('riscv64-linux-gnu-gcc')
    if not clang or not gcc:
        pytest.skip('real RISC-V GCC and Clang required for source-toolchain integration')
    context, _ = native_context(tmp_path, gcc, ('-march=rv64gc', '-mabi=lp64d'))
    value = module.acquire(context, clang, tmp_path/'capture', target='riscv64')
    assert module.replay(value, tmp_path/'replay')['nativeInputReplayComplete']
