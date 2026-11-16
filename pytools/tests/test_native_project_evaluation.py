"""Actual native capture/relink/comparison; no claim of real cross-ISA GMP proof."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest
from riscv2x86_py import native_project_evaluation as p
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py import native_original_evaluation as evaluation
from riscv2x86_py.project_compile_context import derive
from riscv2x86_py.translation_validation import ProgramArtifact, ValidationLevel
from riscv2x86_py.validation_status import ValidationStatus
from .test_native_captured_deployment import captured


def test_replay_compile_context_uses_explicit_environment_without_shell_changes(captured, monkeypatch):
    _, _, plan = captured
    action = plan['originalObjectProducer']
    env = action['observedCompileInputs']['searchEnvironment']
    monkeypatch.setenv('CPATH', '/unrelated-current-shell')
    assert not derive(action)['inspectionReady']
    ctx = derive(action, environment=env)
    assert ctx['inspectionReady']
    assert os.environ['CPATH'] == '/unrelated-current-shell'
    prof = p.compile_profile(action)
    assert '-fPIC' in prof['flags'] and prof['flags'][:2] == ['-x', 'cpp-output']
    assert not any(a.startswith('-I') for a in prof['flags'])


@pytest.mark.parametrize('seed', [0, 1, -1, 2**64, True])
def test_gmp_entropy_and_invalid_seed_not_treated_as_fixed(seed):
    with pytest.raises(ValueError): p.gmp_cases([seed], 1000)


def test_explicit_gmp_seed_and_repetition_contract():
    cases = p.gmp_cases([42, 43], 1000)
    assert cases[0]['environmentOverrides']['GMP_CHECK_RANDOMIZE'] == '42'
    assert cases[0]['environmentOverrides']['GMP_CHECK_REPFACTOR'] == '1'
    assert cases[0]['arguments'] == ['1000']
    with pytest.raises(ValueError): p.gmp_cases([42, 42], 1)


@pytest.mark.parametrize('key', ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'QEMU_LD_PREFIX', 'PATH', 'GLIBC_TUNABLES'])
def test_cases_cannot_override_runtime_identity(key):
    with pytest.raises(ValueError):
        p.validate_cases([{'caseId': 'case', 'arguments': [], 'expectedExitCodes': [0], 'environmentOverrides': {key: 'changed'}}])


@pytest.fixture
def toy_project(captured, monkeypatch):
    root, build, plan = captured
    source = build / 'frozen.i'; source.write_text('int value(void){return 0;}\n')
    # Original-candidate ingress is a fixture. Real compiler, ELF and linking
    # below exercise the adapter only, not RISC-V semantics or proof approval.
    inp = root / 'prepared.json'; p.write(inp, {'source': d.snapshot(source)})
    manifest = root / 'manifest.json'; p.write(manifest, {'edits': [{'relativePath': 'input.i', 'afterFileDigest': d.digest(source)}]})
    translated = root / 'translated.json'; p.write(translated, {'candidateManifest': d.snapshot(manifest)})
    run = root / 'run.json'; p.write(run, {'input': d.snapshot(inp), 'translation': d.snapshot(translated)})
    prof = {'library': plan['library'], 'entry': plan['entry'], 'object': plan['originalObject'],
            'compile': p.compile_profile(plan['originalObjectProducer']),
            'entryLibraryPositions': plan['entryLibraryPositions'], 'environment': plan['environment'], 'machine': 62}
    spec = {'projectEvaluationIdentity': 'fixture-project', 'run': d.snapshot(run),
            'profiles': {'source': deepcopy(prof), 'target': deepcopy(prof)},
            'qemu': {'path': '/usr/bin/env'}, 'runtimePrefix': str(root),
            'sourceLoader': d.snapshot(d.parse((build / 'test-program').read_bytes())['interpreter']),
            'targetLoader': d.snapshot(d.parse((build / 'test-program').read_bytes())['interpreter']),
            'cases': [{'caseId': 'default', 'arguments': [], 'expectedExitCodes': [0], 'environmentOverrides': {}}],
            'timeoutSeconds': 30, 'gaps': ['THREE_COMPILE_CONTEXT_REFINEMENT_REQUIRED', *p.GAPS]}
    monkeypatch.setattr(p, 'check', lambda path: spec)
    output = root / 'artifacts'; output.mkdir()
    records = {}
    for side in ('source', 'target'):
        records[side] = p.build_side('fixture', side, source, output / side)
    programs = {side: ProgramArtifact(side, row['program']['path'], 'executable', row['program']['digest'])
                for side, row in records.items()}
    return root, build, spec, programs


def test_real_rebuild_preserves_duplicate_library_operands_and_historical_artifacts(toy_project):
    root, build, spec, programs = toy_project
    record = p.build_record(programs['target'], spec, 'target')
    command = d.read(root / 'artifacts/target.project/entry/execution.json')['arguments']
    assert len(spec['profiles']['target']['entryLibraryPositions']) == 2
    for pos in spec['profiles']['target']['entryLibraryPositions']:
        assert command[pos] == record['library']['path']
    assert subprocess.run([programs['target'].artifact_path]).returncode == 0
    assert subprocess.run([str(build / 'test-program')]).returncode == 3
    assert not any('fixture-project' in str(a) for a in command)


def test_build_record_rejects_current_artifact_mutation(toy_project):
    _, _, spec, programs = toy_project
    Path(programs['target'].artifact_path).write_bytes(b'changed')
    with pytest.raises(ValueError): p.build_record(programs['target'], spec, 'target')


def test_l1_collects_both_processes_with_original_comparator_and_cannot_approve(toy_project, monkeypatch):
    root, _, spec, programs = toy_project
    # Exercise real native commands for both sides; QEMU route itself is not
    # available here. Do not change production source launcher requirements.
    from riscv2x86_py import native_experiment_driver as driver
    original_command = driver.command
    def command(argv, *args):
        if argv[:2] == ['/usr/bin/env', '-L']: argv = argv[3:]
        return original_command(argv, *args)
    monkeypatch.setattr(driver, 'command', command)
    f = p.factory({'specPath': 'fixture', 'workDirectory': str(root / 'observed'), 'level': 'L1'})
    result = f(level=ValidationLevel.L1, source_program_artifact=programs['source'],
               target_program_artifact=programs['target'])
    assert result.status is ValidationStatus.INCONCLUSIVE
    detail = json.loads(result.detail)
    assert not detail['observations']['mismatches']
    assert set(detail['reasonCodes']) == set(spec['gaps']) - {'CANONICAL_INSTANCE_INSTRUCTION_COVERAGE_REQUIRED', 'PROGRAM_L2_AUTHORITY_REQUIRED', 'INDEPENDENT_PROGRAM_AUDIT_REQUIRED'}
    assert detail['obligationAssessment']['boundedProcessObservableStatus'] == 'observed-match'
    assert len(detail['obligationAssessment']['obligations']) == len(spec['gaps'])
    assert not detail['observations']['semanticApproval']
    assert (root / 'observed/case-000000/source/stdout.log').is_file()
    assert (root / 'observed/case-000000/target/stderr.log').is_file()


def test_request_producer_uses_original_schema_and_keeps_l2_missing(toy_project, monkeypatch):
    root, _, spec, _ = toy_project
    run = d.read(spec['run']['path']); translation = d.read(run['translation']['path'])
    translation.update(report={'path': '/fixture/report.json'}, attemptArchive={'path': '/fixture/archive.json'})
    p.write(run['translation']['path'], translation)
    spec['profiles']['source']['compile']['flags'] += ['-march=rv64gc', '-mabi=lp64d']
    spec['python'] = d.snapshot(__import__('sys').executable)
    spec['sourceLoader'] = {'digest': 'fixture-loader'}; spec['qemu']['digest'] = 'fixture-qemu'
    monkeypatch.setattr(p.route, 'check_run', lambda path: run)
    specfile = root / 'project.json'; p.write(specfile, spec)
    request = p.request(specfile, root / 'contracts')
    parsed = evaluation.original.load_evaluation_request(request)
    assert parsed.validation_unit == 'program'
    assert set(parsed.runtime_registry_template['validators']) == {'L0', 'L1'}
    assert '${SOURCE_PATH}' in parsed.source_build.command
    assert parsed.runtime_registry_template['validators']['L0']['type'] == 'original-captured-project'
    assert '${WORK_DIR}' in parsed.runtime_registry_template['validators']['L1']['config']['workDirectory']
    refs, plan = evaluation.contracts(request)
    assert plan.required_levels[-1] is ValidationLevel.L2
    assert refs['projectSpec:L0'] == refs['projectSpec:L1'] == d.snapshot(specfile)
    specfile.write_text(specfile.read_text() + ' ')
    with pytest.raises(ValueError): d.verify_snapshot(refs['projectSpec:L0'])


@pytest.mark.parametrize('path', ['', '.'])
def test_missing_request_reports_contract_error_instead_of_reading_directory(path):
    with pytest.raises(ValueError, match='REGULAR_FILE_REQUIRED'): evaluation.contracts(path)


def test_l0_adapter_delegates_full_positional_matrix_without_its_own_pass_rule(toy_project, monkeypatch):
    from riscv2x86_py import l0_manifest_builder, l0_build_matrix
    from riscv2x86_py.translation_validation import ValidationLayerResult
    root, _, spec, programs = toy_project
    seen = {}
    marker = object()
    original_result = ValidationLayerResult(ValidationLevel.L0, ValidationStatus.FAILED, 'original-matrix-evidence')
    def reference(**kwargs):
        seen.update(kwargs)
        assert kwargs['target_link_arguments'].count('{object}') == 1
        assert kwargs['target_link_arguments'].count('{output}') == 1
        assert '-O2' not in kwargs['target_flags_override']
        assert kwargs['target_flags_override'][:2] == ['-x', 'cpp-output']
        assert kwargs['link_kind'] == 'shared_library'
        return marker, programs['source'], programs['target']
    def matrix(value, translation, source, target, **kwargs):
        assert value is marker and translation is marker
        return original_result
    monkeypatch.setattr(l0_manifest_builder, 'build_l0_reference_manifest', reference)
    monkeypatch.setattr(l0_build_matrix, 'run_l0_build_matrix', matrix)
    f = p.factory({'specPath': 'fixture', 'workDirectory': str(root / 'matrix'), 'level': 'L0'})
    result = f(level=ValidationLevel.L0, translation_artifact=marker,
               source_program_artifact=programs['source'], target_program_artifact=programs['target'])
    assert result is original_result
    assert l0_manifest_builder.COMPILERS == ('gcc', 'clang')
    assert l0_manifest_builder.OPTIMIZATIONS == ('-O0', '-O2', '-O3')
    assert l0_manifest_builder.SANITIZERS == ('none', 'asan', 'ubsan')


def test_compile_producer_ambiguity_does_not_choose_by_source_text(captured):
    _, _, plan = captured
    action = plan['originalObjectProducer']
    chosen, profile = p.producer(plan['library'], [action], action['observedCompileInputs']['sourceDigest'])
    assert chosen == plan['originalObject']
    with pytest.raises(ValueError, match='PRODUCER_AMBIGUOUS'):
        p.producer(plan['library'], [action, deepcopy(action)], profile['sourceDigest'])
    with pytest.raises(ValueError, match='OBJECT_AMBIGUOUS:0'):
        p.producer(plan['library'], [action], 'sha256:' + '0' * 64)


def test_discovery_metadata_cannot_relabel_actual_x86_executable_as_riscv(captured, monkeypatch):
    root, _, plan = captured
    receipt = root / 'receipt.json'
    p.write(receipt, {'context': {'sourceDigest': plan['originalObjectProducer']['observedCompileInputs']['sourceDigest']}})
    bundle = root / 'bundle.json'; p.write(bundle, {'nativeInputReceiptPath': str(receipt)})
    monkeypatch.setattr(p.route, 'check_run', lambda path: {'bundle': d.snapshot(bundle)})
    target = root / 'target-plan.json'; p.write(target, plan)
    record = d.read(plan['testRecords']['path'])
    for i, action in enumerate(record['actions']):
        if action['kind'] == 'link':
            action['observedOutput']['elfHeader']['machine'] = 243
            record['actions'][i] = d.seal({k: v for k, v in action.items() if k != 'actionIdentity'}, 'actionIdentity')
    source_records = root / 'spoofed-records.json'; p.write(source_records, record)
    with pytest.raises(ValueError, match='SOURCE_ENTRY_AMBIGUOUS:0'):
        p.freeze('fixture-run', target, [source_records], root / 'not-published.json',
                 qemu='/usr/bin/env', runtime_prefix=root, cases=p.gmp_cases([42], 1))
    assert not (root / 'not-published.json').exists()


def test_cli_rejects_entropy_seed_before_launching_translation(tmp_path, capsys):
    import importlib.util
    import sys
    file = Path(__file__).resolve().parents[2] / 'experiment/automate_native_project.py'
    spec = importlib.util.spec_from_file_location('automate_project_cli', file)
    cli = importlib.util.module_from_spec(spec); spec.loader.exec_module(cli)
    output = tmp_path / 'must-not-exist'
    assert cli.main(['run', '--bundle', 'missing', '--target-plan', 'missing',
        '--source-records', 'missing', '--runtime-prefix', 'missing', '--qemu', sys.executable,
        '--gmp-seeds', '0', '--output', str(output)]) == 2
    assert 'GMP_FIXED_SEEDS' in capsys.readouterr().out
    assert not output.exists()


def test_exit_domain_is_explicit_not_inferred_from_successful_execution():
    value = [{'caseId': 'explicit-seven', 'arguments': [], 'expectedExitCodes': [7], 'environmentOverrides': {}}]
    assert p.validate_cases(value) == value
    for invalid in ([], [True], [256]):
        broken = deepcopy(value); broken[0]['expectedExitCodes'] = invalid
        with pytest.raises(ValueError): p.validate_cases(broken)
    missing = deepcopy(value); del missing[0]['expectedExitCodes']
    with pytest.raises(ValueError): p.validate_cases(missing)


def test_resealed_receipt_cannot_bind_an_unrelated_input_or_command(toy_project):
    root, build, spec, programs = toy_project
    file = root / 'artifacts/target.project/result.json'
    value = d.read(file)
    value['input'] = d.snapshot(build / 'main.c')
    p.write(file, d.seal({k: v for k, v in value.items() if k != 'projectBuildIdentity'}, 'projectBuildIdentity'))
    with pytest.raises(ValueError, match='BUILD_BINDING_MISMATCH'):
        p.build_record(programs['target'], spec, 'target')


def test_record_checker_rederives_ordered_commands_not_only_program_hash(toy_project):
    root, _, spec, programs = toy_project
    log = root / 'artifacts/target.project/entry/execution.json'
    value = d.read(log); value['arguments'].append('-unexpected-link-option')
    p.write(log, value)
    with pytest.raises(ValueError, match='BUILD_EXECUTION_MISMATCH:entry'):
        p.build_record(programs['target'], spec, 'target')


def test_declared_nonzero_exit_is_not_a_budget_failure(toy_project, monkeypatch):
    root, build, spec, _ = toy_project
    # Identical native baseline programs are a process-comparator fixture only.
    artifact = ProgramArtifact('baseline', str(build / 'test-program'), 'executable', d.digest(build / 'test-program'))
    spec['cases'][0]['expectedExitCodes'] = [3]
    from riscv2x86_py import native_experiment_driver as driver
    execute = driver.command
    def native(argv, *args):
        return execute(argv[3:] if argv[:2] == ['/usr/bin/env', '-L'] else argv, *args)
    monkeypatch.setattr(driver, 'command', native)
    output = root / 'nonzero'; output.mkdir()
    value = p.observe(spec, artifact, artifact, output)
    assert value['cases'][0]['sourceReturnCode'] == value['cases'][0]['targetReturnCode'] == 3
    assert not value['executionBudgetFailed'] and not value['exitOutsideDeclaredDomain']
    assert not value['mismatches'] and not value['semanticApproval']


def test_project_contract_roundtrip_rederives_recipes_and_rejects_resealed_environment(captured, monkeypatch):
    """Real captures/ELFs; ONLY source ISA metadata and original ingress mocked.

    This checks selection/pinning, not executable RISC-V code or a GMP proof.
    """
    import shutil
    import sys
    from .test_native_captured_deployment import captured_project
    root, _, target_plan = captured
    source_root = root / 'source-fixture'; source_root.mkdir()
    _, source_build, source_plan = captured_project(source_root, language_flags=('-fno-asynchronous-unwind-tables',))
    parse = d.parse
    source_bytes = {path.read_bytes() for path in source_build.iterdir()
                    if path.is_file() and path.read_bytes().startswith(b'\x7fELF')}
    # Confirm no target object/library is accidentally in the mocked boundary.
    assert Path(target_plan['originalObject']['path']).read_bytes() not in source_bytes
    monkeypatch.setattr(d, 'parse', lambda raw: dict(parse(raw), machine=243) if raw in source_bytes else parse(raw))
    record_paths = []
    for role in ('libraryRecords', 'testRecords'):
        record = d.read(source_plan[role]['path'])
        for i, action in enumerate(record['actions']):
            if (action.get('observedOutput') or {}).get('elfHeader'):
                action['observedOutput']['elfHeader']['machine'] = 243
                record['actions'][i] = d.seal({k: v for k, v in action.items() if k != 'actionIdentity'}, 'actionIdentity')
        path = source_root / (role + '.json'); p.write(path, record); record_paths.append(path)
    receipt = root / 'receipt.json'
    context = {'sourceDigest': target_plan['originalObjectProducer']['observedCompileInputs']['sourceDigest'],
               'searchEnvironment': source_plan['originalObjectProducer']['observedCompileInputs']['searchEnvironment']}
    p.write(receipt, {'context': context})
    bundle = root / 'bundle.json'; p.write(bundle, {'nativeInputReceiptPath': str(receipt)})
    run = root / 'run.json'; p.write(run, {})
    monkeypatch.setattr(p.route, 'check_run', lambda path: {'bundle': d.snapshot(bundle)})
    prefix = root / 'guest'; loader = prefix / parse(Path(source_plan['entry']['originalOutput']['path']).read_bytes())['interpreter'].lstrip('/')
    loader.parent.mkdir(parents=True); loader.write_bytes(Path(source_plan['library']['originalOutput']['path']).read_bytes())
    which = shutil.which
    monkeypatch.setattr(shutil, 'which', lambda name, **kw: which('gcc' if name == 'clang' else name, **kw))
    plan = root / 'target-plan.json'; p.write(plan, target_plan)
    output = root / 'project.json'
    value = p.freeze(run, plan, record_paths, output, qemu=sys.executable,
                     runtime_prefix=prefix, cases=p.gmp_cases([42], 1))
    assert p.check(output) == value
    assert value['profiles']['target']['entryLibraryPositions'] == target_plan['entryLibraryPositions']
    assert not value['semanticApproval']
    value['profiles']['target']['environment']['LC_ALL'] = 'changed'
    p.write(output, d.seal({k: v for k, v in value.items() if k != 'projectEvaluationIdentity'}, 'projectEvaluationIdentity'))
    with pytest.raises(ValueError, match='REDERIVATION_MISMATCH'): p.check(output)


def test_build_output_does_not_follow_a_broken_symlink(toy_project):
    root, _, _, _ = toy_project
    alias = root / 'output-alias'; target = root / 'unexpected-output'
    alias.symlink_to(target)
    with pytest.raises(FileExistsError): p.build_side('fixture', 'target', root / 'unused', alias)
    assert alias.is_symlink() and not target.exists()


def test_request_companion_is_checked_without_rewriting_it(toy_project, monkeypatch):
    root, _, spec, _ = toy_project
    run = d.read(spec['run']['path']); translated = d.read(run['translation']['path'])
    translated.update(report={'path': '/fixture/report.json'}, attemptArchive={'path': '/fixture/archive.json'})
    p.write(run['translation']['path'], translated)
    spec['profiles']['source']['compile']['flags'] += ['-march=rv64gc', '-mabi=lp64d']
    spec['python'] = d.snapshot(__import__('sys').executable)
    specfile = root / 'spec.json'; p.write(specfile, spec)
    monkeypatch.setattr(p.route, 'check_run', lambda path: run)
    request = p.request(specfile, root / 'request-contracts')
    files = p.check_request(request, specfile)
    assert len(files) == 3
    companion = request.parent / 'environment.json'
    companion.write_bytes(companion.read_bytes() + b' ')
    changed = companion.read_bytes()
    with pytest.raises(ValueError, match='REQUEST_REDERIVATION_MISMATCH'):
        p.check_request(request, specfile)
    assert companion.read_bytes() == changed


def test_selected_observation_replays_original_comparator_and_rejects_changed_context(toy_project, monkeypatch):
    from riscv2x86_py import native_experiment_driver as driver
    root, _, spec, programs = toy_project
    spec['cases'] = p.gmp_cases([42, 43], 10)
    execute = driver.command
    def native(argv, *args):
        return execute(argv[3:] if argv[:2] == ['/usr/bin/env', '-L'] else argv, *args)
    monkeypatch.setattr(driver, 'command', native)
    output = root / 'selected'; output.mkdir()
    result = p.observe(spec, programs['source'], programs['target'], output, case_indices=[1])
    assert result['caseIndices'] == [1] and len(result['cases']) == 1 and not result['mismatches']
    assert not (output / 'case-000000').exists()
    assert p.rederive_observations(spec, programs['source'], programs['target'], output, [1]) == result
    file = output / 'case-000001/source/execution.json'; row = d.read(file)
    row['environment']['GMP_CHECK_RANDOMIZE'] = 'unrelated'; p.write(file, row)
    with pytest.raises(ValueError, match='COMMAND_CONTEXT_MISMATCH'):
        p.rederive_observations(spec, programs['source'], programs['target'], output, [1])
    with pytest.raises(ValueError): p.observation_recipe(spec, programs['source'], programs['target'], [])
