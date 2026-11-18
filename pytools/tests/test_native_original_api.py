"""Real host GCC execution of the adapter, not a RISC-V or GMP proof.

Only the upstream compiler AST/project ingress is fixture-owned. We exercise
actual eight-argument calls, duplicate library operands, typed object mutation,
command reconstruction and independent receipt checks with live ELF artifacts.
"""
from copy import deepcopy
import os
from pathlib import Path
import shutil
import subprocess

import pytest
from riscv2x86_py import native_original_api as a
from riscv2x86_py import native_api_contract as api
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py import native_project_evaluation as p
from riscv2x86_py.verification_session import record_file_read, session

TYPES = ['unsigned long *'] + ['unsigned long'] * 7
PARAMS = ['out'] + ['p' + str(i) for i in range(1, 8)]
PROTO = ','.join(t + ' ' + n for t, n in zip(TYPES, PARAMS))
BODY = 'void exercise(' + PROTO + '){out[0]+=' + '+'.join(PARAMS[1:]) + ';}\n'


def selected(body=BODY):
    fn = {'kind': 'FunctionDecl', 'name': 'exercise', 'id': 'declaration-17',
          'type': {'qualType': 'void (' + ','.join(TYPES) + ')'},
          'inner': [{'kind': 'ParmVarDecl', 'type': {'qualType': t}} for t in TYPES] +
                   [{'kind': 'CompoundStmt'}]}
    ast = {'kind': 'TranslationUnitDecl', 'inner': [fn]}
    records = [{'functionAstPath': [0], 'instanceBindingIdentity': 'instance-1'}]
    return a.selection(ast, records, body.encode(), a.MODEL, [0]), ast, records


def domain():
    return {'schemaVersion': api.SCHEMA, 'claimScope': 'bounded-api-under-declared-preconditions',
            'preconditions': [{'ge': [{'remainingElements': 0}, {'constant': 1}]}],
            'cases': [{'objects': [{'id': 'buffer', 'type': 'unsigned long', 'alignment': 16, 'values': [3]}],
                       'arguments': [{'object': 'buffer', 'offsetElements': 0}] +
                                    [{'integer': i} for i in range(1, 8)]}]}


@pytest.fixture
def native_pair(tmp_path, monkeypatch):
    cc = shutil.which('gcc')
    if cc is None: pytest.skip('native GCC required')
    def gcc(*args):
        subprocess.run([cc, *map(str, args)], check=True, capture_output=True)
    main = tmp_path / 'main.c'; main.write_text('int main(void){return 0;}\n')
    mainobj = tmp_path / 'main.o'; gcc('-c', main, '-o', mainobj)
    launcher = tmp_path / 'fixture-launcher'
    launcher.write_text('#!/bin/sh\nshift 2\nexec "$@"\n'); launcher.chmod(0o755)
    spec = {'projectEvaluationIdentity': 'fixture-project', 'profiles': {}, 'qemu': d.snapshot(launcher),
            'runtimePrefix': str(tmp_path), 'timeoutSeconds': 10,
            'gaps': ['THREE_COMPILE_CONTEXT_REFINEMENT_REQUIRED', *p.GAPS]}
    records = {}; paths = {}
    for side in a.SIDES:
        root = tmp_path / side; root.mkdir()
        inp = root / 'body.i'; inp.write_text(BODY)
        obj = root / 'body.o'; gcc('-fPIC', '-x', 'cpp-output', '-c', inp, '-o', obj)
        lib = root / 'libexercise.so.1'; gcc('-shared', obj, '-Wl,-soname,libexercise.so.1', '-o', lib)
        program = root / 'baseline'; gcc(mainobj, lib, '-Wl,-rpath,' + str(root), '-o', program)
        inputs = [{**d.snapshot(mainobj), 'argumentIndex': 3},
                  {**d.snapshot(lib), 'argumentIndex': 4}, {**d.snapshot(lib), 'argumentIndex': 5}]
        entry = {'action': {'arguments': [cc, '-o', str(program), str(mainobj), str(lib), str(lib),
                                         '-Wl,-rpath', '-Wl,' + str(root)]},
                 'compiler': d.snapshot(cc), 'inputs': inputs, 'outputIndex': 2,
                 'searchPathArguments': [{'argumentIndex': 7, 'directories': [str(root)]}],
                 'directory': str(tmp_path)}
        spec['profiles'][side] = {'compile': {'compiler': d.snapshot(cc), 'flags': ['-x', 'cpp-output', '-O2', '-fPIC'],
                        'directory': str(tmp_path), 'environment': {'PATH': os.environ['PATH']}},
                    'entry': entry, 'entryLibraryPositions': [4, 5],
                    'environment': {'PATH': os.environ['PATH']}, 'machine': 62}
        record = {'side': side, 'input': d.snapshot(inp), 'object': d.snapshot(obj),
                  'library': d.snapshot(lib), 'program': d.snapshot(program)}
        path = root / 'build.json'; p.write(path, record); paths[side] = str(path); records[side] = record
    selection, _, _ = selected()
    specpath = tmp_path / 'project.json'; p.write(specpath, spec)
    monkeypatch.setattr(a, 'context', lambda path: (deepcopy(spec), [deepcopy(selection)], []))
    def checked_build(program, expected, side):
        row = records[side]
        assert program.artifact_path == row['program']['path']
        assert expected == spec
        for ref in row.values():
            if isinstance(ref, dict): d.verify_snapshot(ref)
        return deepcopy(row)
    monkeypatch.setattr(p, 'build_record', checked_build)
    request = {'schemaVersion': a.REQUEST, 'projectEvaluationIdentity': spec['projectEvaluationIdentity'],
               'functionBindingIdentity': selection['functionBindingIdentity'], 'domain': domain(),
               'assumptionSources': [d.snapshot(main)]}
    requestpath = tmp_path / 'request.json'; p.write(requestpath, request)
    return specpath, requestpath, paths, tmp_path, spec


def test_eight_argument_object_execution_and_independent_check(native_pair):
    spec, request, builds, root, _ = native_pair
    value = a.acquire(spec, request, root / 'execution', builds=builds)
    assert value['caseCount'] == 1
    assert len(value['function']['interface']['parameters']) == 8
    assert value['processObservationStatus'] == 'observed-agreement'
    assert value['protocolComplete'] == {'source': True, 'target': True}
    assert b'object:0:0:31\n' in (root / 'execution/run-source/stdout.log').read_bytes()
    assert all(rows[0]['verified'] for rows in value['bodyLinkAttribution'].values())
    assert a.check(root / 'execution/result.json') == value
    assert not value['semanticApproval'] and not value['machineAbiProofComplete']
    assert not value['canonicalInstructionExecutionVerified']
    assert value['gaps']
    command = d.read(root / 'execution/link-target/execution.json')['arguments']
    assert command.count(builds['target'].replace('build.json', 'libexercise.so.1')) == 2
    assert command[1] == builds['target'].replace('build.json', 'body.o')


@pytest.mark.parametrize('change', ['driver', 'command', 'approval', 'log', 'source'])
def test_independent_check_rejects_tampering_even_with_resealed_outer_result(native_pair, change):
    spec, request, builds, root, _ = native_pair
    out = root / 'execution'; a.acquire(spec, request, out, builds=builds)
    if change == 'driver': (out / 'driver.c').write_text('int main(){return 0;}')
    elif change == 'command':
        path = out / 'run-target/execution.json'; row = d.read(path)
        row['arguments'] = ['/bin/true']; p.write(path, row)
    elif change == 'log': (out / 'run-target/stdout.log').write_bytes(b'')
    elif change == 'source': Path(builds['source']).with_name('body.i').write_text('changed')
    else:
        path = out / 'result.json'; row = d.read(path); row['semanticApproval'] = True
        p.write(path, d.seal({k: v for k, v in row.items() if k != 'apiExecutionIdentity'}, 'apiExecutionIdentity'))
    with pytest.raises(ValueError): a.check(out / 'result.json')


@pytest.mark.parametrize('change', ['domain', 'binding', 'assumptions', 'project'])
def test_bad_requests_rejected_before_creating_execution_directory(native_pair, change):
    spec, request, builds, root, _ = native_pair
    row = d.read(request)
    if change == 'domain': row['domain']['cases'][0]['arguments'][0]['offsetElements'] = 1
    elif change == 'binding': row['functionBindingIdentity'] = 'another-function'
    elif change == 'project': row['projectEvaluationIdentity'] = 'another-project'
    else: row['assumptionSources'] = []
    p.write(request, row)
    with pytest.raises(ValueError): a.acquire(spec, request, root / 'bad', builds=builds)
    assert not (root / 'bad').exists()


def test_empty_process_agreement_is_not_a_completed_api_case(tmp_path):
    rows = {}
    for side in a.SIDES:
        folder = tmp_path / ('run-' + side); folder.mkdir()
        (folder / 'stdout.log').write_bytes(b''); (folder / 'stderr.log').write_bytes(b'')
        rows['run-' + side] = {'returnCode': 0, 'failureReason': None}
    value = a.compare_runs(rows, tmp_path, selected()[0], domain())
    assert value['processObservationStatus'] == 'inconclusive'
    rows['run-source']['failureReason'] = 'TIMEOUT'
    assert a.compare_runs(rows, tmp_path, selected()[0], domain())['processObservationStatus'] == 'failed'


@pytest.mark.parametrize('change', ['static', 'variadic', 'attribute', 'not-edited', 'path'])
def test_declaration_identity_and_finite_signature_scope(change):
    _, ast, records = selected(); fn = ast['inner'][0]; path = [0]
    if change == 'static': fn['storageClass'] = 'static'
    elif change == 'variadic': fn['variadic'] = True
    elif change == 'attribute': fn['inner'].append({'kind': 'MSABIAttr'})
    elif change == 'not-edited': records = []
    else: path = [True]
    with pytest.raises(ValueError): a.selection(ast, records, BODY.encode(), a.MODEL, path)


def test_binding_tracks_exact_source_bytes_and_declaration_path():
    first, ast, records = selected()
    assert first['functionBindingIdentity'] != a.selection(ast, records, (BODY + '\n').encode(), a.MODEL, [0])['functionBindingIdentity']
    ast['inner'].insert(0, {'kind': 'EmptyDecl'})
    records[0]['functionAstPath'] = [1]
    assert first['functionBindingIdentity'] != a.selection(ast, records, BODY.encode(), a.MODEL, [1])['functionBindingIdentity']


def test_file_totals_include_reads_after_path_budget():
    with session() as active:
        for i in range(2050): record_file_read(str(i), 2, 0.01, i == 2049)
        value = active.profile()['fileReads']
    assert value['trackedPathCount'] == 2048 and value['untrackedReadCount'] == 2
    assert value['totals']['reads'] == 2050 and value['totals']['bytes'] == 4100
    assert value['totals']['failedReads'] == 1


def test_wrong_compiler_declaration_is_rejected_by_real_witness(native_pair):
    spec, request, builds, root, _ = native_pair
    # Keep valid upstream fixture receipts, but challenge the actual compiler
    # witness with a different prototype. No successful receipt is published.
    original = a.witness
    from unittest.mock import patch
    def wrong(selected):
        changed = deepcopy(selected)
        changed['interface']['parameters'][1]['cType'] = 'unsigned int'
        return original(changed)
    with patch.object(a, 'witness', wrong), pytest.raises(Exception, match='api-witness-source'):
        a.acquire(spec, request, root / 'bad-type', builds=builds)
    assert d.read(root / 'bad-type/acquisition-status.json')['status'] == 'failed'
    assert not (root / 'bad-type/result.json').exists()


def test_real_target_value_difference_is_a_failure(native_pair):
    spec, request, builds, root, _ = native_pair
    # The fixture ingress owns this changed target, representing a bad candidate.
    # Running actual machine code must expose its different object value.
    target = Path(builds['target']).parent
    inp = target / 'body.i'; inp.write_text(BODY.replace('out[0]+=', 'out[0]+=1+'))
    cc = shutil.which('gcc')
    subprocess.run([cc, '-fPIC', '-x', 'cpp-output', '-c', str(inp), '-o', str(target / 'body.o')], check=True)
    # The fixture's build checker deliberately keeps the old digests, so even
    # before execution this unbound change must be rejected.
    with pytest.raises(ValueError, match='INPUT_CHANGED'):
        a.acquire(spec, request, root / 'bad-candidate', builds=builds)


def test_original_comparator_reports_finite_output_difference(tmp_path):
    selection = selected()[0]
    rows = {}
    for side, value in [('source', 31), ('target', 32)]:
        folder = tmp_path / ('run-' + side); folder.mkdir()
        (folder / 'stdout.log').write_text(f'case:0:object:0:0:{value}\ncase:0:complete:1\n')
        (folder / 'stderr.log').write_bytes(b'')
        rows['run-' + side] = {'returnCode': 0, 'failureReason': None}
    value = a.compare_runs(rows, tmp_path, selection, domain())
    assert value['processObservationStatus'] == 'failed' and value['mismatches']
    assert all(value['protocolComplete'].values())


def test_cli_inspect_and_api_run_exit_codes(native_pair, monkeypatch, capsys):
    import importlib.util
    spec, request, builds, root, _ = native_pair
    module_spec = importlib.util.spec_from_file_location('original_api_cli',
        Path(__file__).resolve().parents[2] / 'experiment/automate_native_project.py')
    cli = importlib.util.module_from_spec(module_spec); module_spec.loader.exec_module(cli)
    assert cli.main(['api-inspect', '--spec', str(spec)]) == 0
    assert 'functionBindingIdentity' in capsys.readouterr().out
    assert cli.main(['api-run', '--spec', str(spec), '--request', str(request), '--output', str(root / 'cli'),
                     '--source-build', builds['source'], '--target-build', builds['target']]) == 0
    assert 'observed-agreement' in capsys.readouterr().out
    assert cli.main(['check', '--input', str(root / 'cli/result.json')]) == 0
    assert '"semanticApproval": false' in capsys.readouterr().out


def test_request_builder_binds_domain_and_sources_without_inventing_cases(native_pair):
    spec, _, _, root, _ = native_pair
    dom = root / 'domain.json'; p.write(dom, domain())
    basis = root / 'main.c'
    output = root / 'bound.json'
    value = a.create_request(spec, dom, [0], [basis], output)
    assert a.request_context(spec, output)[1] == value
    assert value['domain'] == domain()
    assert value['assumptionSources'] == [d.snapshot(basis)]
    invalid = domain(); invalid['cases'] = []; p.write(dom, invalid)
    with pytest.raises(ValueError): a.create_request(spec, dom, [0], [basis], root / 'unbound.json')
    assert not (root / 'unbound.json').exists()
