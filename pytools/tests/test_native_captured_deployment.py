"""Actual capture/compiler/DSO/loader integration; fixtures are not translation proofs."""
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py.native_deployment_observation import observe, check_observation, loader_paths
from riscv2x86_py.project_build_capture import create, run, inventory
from riscv2x86_py.native_reference_inspection import constants


def write_json(path, value):
    path.write_text(json.dumps(value)); return path


@pytest.fixture
def captured(tmp_path):
    cc = shutil.which('gcc')
    if not cc: pytest.skip('native GCC required')
    p = tmp_path/'build'; p.mkdir()
    (p/'original.c').write_text('int value(void){return 3;}\n')
    (p/'replacement.c').write_text('int value(void){return 7;}\n')
    (p/'main.c').write_text('extern int value(void);int main(void){return value();}\n')
    ar = shutil.which('ar')
    if not ar: pytest.skip('GNU ar required for invocation interval capture')
    cap = create(tmp_path/'capture', {'cc': cc, 'ar': ar}, archive_tools={'ar': 'gnu-ar'})
    config = tmp_path/'capture/capture.json'; wrapper = cap['wrappers']['cc']['path']
    def invoke(stage, args):
        _, code = run(config, stage, [wrapper, *args], cwd=p)
        assert code == 0
    invoke('build', ['-O2', '-fPIC', '-c', 'original.c', '-o', 'original.o'])
    invoke('build', ['-shared', 'original.o', '-Wl,-soname', '-Wl,libprobe.so.1', '-o', 'libprobe.so.1'])
    (p/'libprobe.so').symlink_to('libprobe.so.1')
    invoke('test', ['-O2', '-c', 'main.c', '-o', 'main.o'])
    invoke('test', ['-O2', '-o', 'test-program', 'main.o', str(p/'libprobe.so'), './libprobe.so.1',
                    '-Wl,-rpath', '-Wl,'+str(p)])
    library = write_json(tmp_path/'library.json', inventory(config, stage='build'))
    tests = write_json(tmp_path/'tests.json', inventory(config, stage='test'))
    subprocess.run([cc, '-O2', '-fPIC', '-c', str(p/'replacement.c'), '-o', str(p/'target.o')], check=True)
    (p/'candidate.i').write_text('fixture only, not a cross-ISA translation proof\n')
    c = {'schemaVersion': 'riscv2x86.native-integer-candidate.v1', 'candidatePath': str(p/'candidate.i'),
         'targetObjectDigest': d.digest(p/'target.o'), 'artifactDigests': {
             n: d.digest(p/n) for n in ('candidate.i', 'target.o')},
         'semanticApproval': False, 'productionAcceptanceComplete': False}
    candidate = write_json(tmp_path/'candidate.json', d.seal(c, 'candidateIdentity'))
    req = write_json(tmp_path/'requirements.json', d.seal({
        'schemaVersion': 'riscv2x86.native-external-requirements.v1', 'requirements': []}, 'requirementsIdentity'))
    env = {'PATH': os.environ['PATH'], 'LC_ALL': 'C'}
    plan = d.prepare(candidate, library, tests, req, environment=env)
    return tmp_path, p, plan


def test_real_substitution_relinks_both_alias_operands_without_original_mutation(captured):
    root, p, plan = captured
    original = d.digest(p/'original.o'); lib = d.digest(p/'libprobe.so.1')
    assert len(plan['entryLibraryPositions']) == 2
    assert subprocess.run([str(p/'test-program')]).returncode == 3
    value = d.execute(plan, root/'deployment')
    assert value['capturedInputReplacementVerified'] and value['candidateDefinitionAttributionVerified']
    assert value['capturedBaselineBytesReproduced']
    assert subprocess.run([str(root/'deployment/program')]).returncode == 7
    assert d.digest(p/'original.o') == original and d.digest(p/'libprobe.so.1') == lib
    assert d.check_result(root/'deployment/result.json') == value
    assert not value['externalContractClosureComplete'] and not value['targetDependencyLinkClosureComplete']
    replay = d.replay(root/'deployment/result.json', root/'replay')
    # An explicit $ORIGIN route keeps the staged deployment relocatable. The
    # independent replay compares full output bytes, without dropping build IDs.
    assert replay['independentDeploymentRebuildComplete']


def test_loader_selection_and_execution_are_not_binding_or_semantic_proofs(captured):
    root, _, plan = captured
    d.execute(plan, root/'deployment')
    value = observe(root/'deployment/result.json', root/'observed', diagnostic=True)
    assert value['loaderListSelectionVerified'] and value['testExecutionPerformed']
    assert value['observedReturnCode'] == 7
    assert value['diagnosticBindings']
    assert not value['runtimeLibrarySelectionVerified'] and not value['semanticApproval']
    assert check_observation(root/'observed/result.json') == value


def test_same_bytes_at_different_build_role_do_not_select_another_object(captured):
    root, p, plan = captured
    wrong = deepcopy(plan)
    wrong['originalObject']['argumentIndex'] += 1
    wrong = d.seal({k:v for k,v in wrong.items() if k!='deploymentPlanIdentity'}, 'deploymentPlanIdentity')
    with pytest.raises(ValueError, match='REDERIVATION_MISMATCH'):
        d.execute(wrong, root/'wrong')
    assert not (root/'wrong').exists()


@pytest.mark.parametrize('option', ['@untracked.rsp', '-Wl,--allow-multiple-definition', '-fplugin=unknown.so', '-Wl,-T,script.ld'])
def test_unknown_link_semantics_are_rejected_not_dropped(captured, option):
    _, _, plan = captured
    action = deepcopy(plan['library']['action']); action['arguments'].insert(1, option)
    action = d.seal({k:v for k,v in action.items() if k!='actionIdentity'}, 'actionIdentity')
    with pytest.raises(ValueError, match='UNSUPPORTED'):
        d.captured_link(action)


def test_alias_retarget_and_rehashed_claim_are_rejected(captured):
    root, p, plan = captured
    d.execute(plan, root/'deployment')
    path = root/'deployment/result.json'; v = d.read(path)
    v['runtimeLibrarySelectionVerified'] = True
    write_json(path, d.seal({k:x for k,x in v.items() if k!='deploymentIdentity'}, 'deploymentIdentity'))
    with pytest.raises(ValueError, match='UNSUPPORTED_APPROVAL'):
        d.check_result(path)
    (p/'libprobe.so').unlink(); (p/'libprobe.so').symlink_to('target.o')
    with pytest.raises(ValueError):
        d.validate(plan)


def test_changed_parent_object_blocks_replay(captured):
    root, p, plan = captured
    (p/'original.o').write_bytes((p/'original.o').read_bytes()+b'changed')
    with pytest.raises(ValueError):
        d.execute(plan, root/'out')


def test_constant_witnesses_follow_relocations_not_local_label_names(tmp_path):
    cc = shutil.which('gcc')
    if not cc: pytest.skip('native GCC required')
    (tmp_path/'x.c').write_text('extern void sink(const char*);void x(void){sink("alpha:%d");}\n')
    subprocess.run([cc, '-O2', '-fno-pic', '-c', str(tmp_path/'x.c'), '-o', str(tmp_path/'x.o')], check=True)
    rows = constants((tmp_path/'x.o').read_bytes())
    assert any(bytes.fromhex(r['nulTerminatedBytes']) == b'alpha:%d\0' for r in rows)


def test_loader_parser_preserves_unknown_and_missing_dependencies():
    rows, _, unknown = loader_paths('libmissing.so => not found\n')
    assert not rows and unknown


def test_link_failure_keeps_successor_stages_not_run(captured):
    root, p, plan = captured
    # Same public definition signature, but the definition now depends on an
    # unresolved function. Recreate the integrity receipt, not an approval.
    (p/'replacement.c').write_text('extern int absent(void);int value(void){return absent();}')
    subprocess.run([shutil.which('gcc'), '-fPIC', '-c', str(p/'replacement.c'), '-o', str(p/'target.o')], check=True)
    cpath = Path(plan['candidatePath']); c = d.read(cpath)
    c['artifactDigests']['target.o'] = d.digest(p/'target.o'); c['targetObjectDigest'] = d.digest(p/'target.o')
    c = d.seal({k:v for k,v in c.items() if k!='candidateIdentity'}, 'candidateIdentity'); write_json(cpath, c)
    fresh = d.prepare(cpath, plan['libraryRecords']['path'], plan['testRecords']['path'],
                      plan['requirements']['path'], environment=plan['environment'])
    with pytest.raises(ValueError, match='LINK_FAILED:derived-entry'):
        d.execute(fresh, root/'failed')
    state = d.read(root/'failed/run-status.json')
    assert state['primaryFailure'] and state['stages'][-1]['status'] == 'failed'
    assert not (root/'failed/result.json').exists()


def test_overriding_loader_library_is_not_executed(captured):
    root, p, plan = captured
    plan = d.prepare(plan['candidatePath'], plan['libraryRecords']['path'], plan['testRecords']['path'],
                     plan['requirements']['path'], environment=dict(plan['environment'], LD_LIBRARY_PATH=str(p)))
    d.execute(plan, root/'deployment')
    with pytest.raises(ValueError, match='EXPECTED_LIBRARY_NOT_SELECTED'):
        observe(root/'deployment/result.json', root/'observed')
    assert not (root/'observed/natural').exists()


def test_automatic_reference_inspection_uses_captured_paths(tmp_path, captured, monkeypatch):
    from riscv2x86_py import native_reference_inspection as inspection
    root, p, plan = captured
    actions = d.read(plan['libraryRecords']['path'])['actions']
    producer = next(a for a in actions if a['kind'] == 'compile')
    dep = d.seal({'recordsPath': plan['libraryRecords']['path']}, 'inventoryIdentity')
    dep_path = write_json(root/'dependency.json', dep)
    provider = d.seal({'dependencyPath': str(dep_path)}, 'inventoryIdentity')
    provider_path = write_json(root/'provider.json', provider)
    req = d.seal({'schemaVersion': 'riscv2x86.native-external-requirements.v1',
        'providerPath': str(provider_path), 'providerDigest': d.digest(provider_path),
        'requirements': [{'obligationIdentity': 'fixture-obligation',
                          'references': {'objectDigest': d.digest(p/'original.o')},
                          'selectedBuildActions': [{'actionIdentity': producer['actionIdentity']}]}]}, 'requirementsIdentity')
    req_path = write_json(root/'inspection-requirements.json', req)
    # Only the legacy cross-ISA ledger boundary is stubbed in this native
    # integration test. GCC, objdump, preprocessing and dependency probes run.
    monkeypatch.setattr(inspection, 'ledger_acquire', lambda *a: {
        'ledgerIdentity': 'fixture-ledger', 'parentObligationCount': 1, 'referenceCount': 1})
    tool = shutil.which('objdump')
    if not tool: pytest.skip('objdump required')
    result = inspection.acquire(req_path, root/'inspection', tool)
    assert result['objects'][0]['object']['path'] == str(p/'original.o')
    assert len(result['objects'][0]['commands']) == 4
    assert not result['externalContractClosureComplete']
