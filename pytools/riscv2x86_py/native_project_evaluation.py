"""Captured-project adapters to the ORIGINAL evaluator, matrix and comparator.

No translation rules or alternative approval path. Replays frozen CPP artifacts
at their recorded object positions. Process equality remains a bounded diagnostic
until ABI, input relation, object legality and canonical coverage are discharged.
"""
import base64
import json
import math
import time
from pathlib import Path
import shutil
import sys

from .verification_session import measured, pure, ContentBytes
from . import native_captured_deployment as d
from . import native_original_pipeline as route
from .native_external_providers import checked
from .native_verifier_manifest import current, compare
from .project_acquisition import StageFailure, publish_checked
from .project_compile_context import derive
from .project_build_contract import source_arguments
from .project_native_input import analysis_arguments, execution_environment
from .translation_validation import ValidationLayerResult, ValidationLevel
from .validation_status import ValidationStatus

SCHEMA = 'riscv2x86.original-project-evaluation.v1'
GAPS = ('ACTUAL_MACHINE_ABI_REQUIRED', 'INTERNAL_OBJECT_ACCESS_PROOF_REQUIRED',
        'DEPENDENCY_CALL_AND_EFFECT_CLOSURE_REQUIRED',
        'SOURCE_TARGET_TEST_INPUT_RELATION_REQUIRED', 'NATURAL_RUN_IMAGE_IDENTITY_REQUIRED',
        'CANONICAL_INSTANCE_INSTRUCTION_COVERAGE_REQUIRED', 'OUTPUT_AND_TERMINATION_RELATION_REQUIRED',
        'PROGRAM_L2_AUTHORITY_REQUIRED', 'INDEPENDENT_PROGRAM_AUDIT_REQUIRED')


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def unique(rows, reason):
    if len(rows) != 1:
        raise ValueError(reason + ':' + str(len(rows)))
    return rows[0]


def compile_profile(action):
    observed = action.get('observedCompileInputs') or {}
    env = dict(observed.get('searchEnvironment') or {})
    ctx = derive(action, environment=env)
    if not ctx['inspectionReady']:
        raise ValueError('PROJECT_COMPILE_PROFILE_UNSUPPORTED:' + repr(ctx['blockers']))
    if not env.get('PATH'):
        raise ValueError('PROJECT_CAPTURED_PATH_REQUIRED')
    # CPP inputs already select their macros/headers. Retain all semantic flags;
    # changing a producer's macro selection is NOT proved by this projection.
    return {'action': action, 'compiler': d.snapshot(ctx['nativeCompiler']),
            'flags': ['-x', 'cpp-output', *analysis_arguments(source_arguments(ctx))],
            'directory': ctx['workingDirectory'],
            'environment': {k: v for k, v in env.items() if v},
            'sourceDigest': ctx['sourceDigest']}


def inputs_equal(a, b):
    return all(a[k] == b[k] for k in ('resolvedPath', 'digest'))


def producer(link, actions, source_digest):
    matches = []
    for item in link['inputs']:
        rows = [a for a in actions if a.get('kind') == 'compile'
                and (a.get('observedCompileInputs') or {}).get('sourceDigest') == source_digest
                and all((a.get('observedOutput') or {}).get(k) == item[k]
                        for k in ('resolvedPath', 'digest'))]
        if rows:
            matches.append((item, unique(rows, 'PROJECT_OBJECT_PRODUCER_AMBIGUOUS')))
    item, action = unique(matches, 'PROJECT_REPLACEMENT_OBJECT_AMBIGUOUS')
    return item, compile_profile(action)


def validate_cases(cases):
    if not isinstance(cases, list) or not cases:
        raise ValueError('PROJECT_NONEMPTY_CASES_REQUIRED')
    ids = set()
    for case in cases:
        if (not isinstance(case, dict) or set(case) != {'caseId', 'arguments', 'environmentOverrides', 'expectedExitCodes'}
                or not isinstance(case['caseId'], str) or not case['caseId'] or case['caseId'] in ids
                or not isinstance(case['arguments'], list)
                or any(not isinstance(v, str) or '\0' in v for v in case['arguments'])
                or not isinstance(case['environmentOverrides'], dict)
                or not isinstance(case['expectedExitCodes'], list) or not case['expectedExitCodes']
                or any(type(v) is not int or not -64 <= v <= 255 for v in case['expectedExitCodes'])):
            raise ValueError('PROJECT_CASE_INVALID')
        ids.add(case['caseId'])
        for k, v in case['environmentOverrides'].items():
            # Runtime path/loader selection cannot be changed by a test case.
            if (not isinstance(k, str) or not k or '=' in k or k.startswith(('LD_', 'QEMU_'))
                    or k in ('PATH', 'GCONV_PATH', 'GLIBC_TUNABLES')
                    or not isinstance(v, str) or '\0' in k + v):
                raise ValueError('PROJECT_CASE_ENVIRONMENT_INVALID')
    return cases


def gmp_cases(seeds, repetitions):
    """Explicit GMP tests/misc.c profile: seeds 0 and 1 request entropy!"""
    if type(repetitions) is not int or not 1 <= repetitions <= 1000000:
        raise ValueError('GMP_REPETITIONS_INVALID')
    if not seeds or any(type(s) is not int or not 2 <= s < 2**64 for s in seeds) or len(set(seeds)) != len(seeds):
        raise ValueError('GMP_FIXED_SEEDS_MUST_BE_DISTINCT_INTEGERS_GE_2')
    return validate_cases([{'caseId': 'gmp-seed-' + str(s), 'arguments': [str(repetitions)], 'expectedExitCodes': [0],
                           'environmentOverrides': {'GMP_CHECK_RANDOMIZE': str(s),
                                                    'GMP_CHECK_REPFACTOR': '1', 'LC_ALL': 'C'}} for s in seeds])


@measured('native-project.source-action-identities')
def checked_source_actions(path):
    """Reuse only canonical hash calculations keyed by freshly read bytes.

    File availability, schema, claimed identities and all live compiler/link
    inputs are checked again. No receipt validity or file digest is cached.
    """
    raw = ContentBytes(Path(path).read_bytes())
    record = d.strict_json(raw.raw)
    if record.get('schemaVersion') != 'riscv2x86.project-build-records.v1':
        raise ValueError('PROJECT_SOURCE_RECORD_SCHEMA_INVALID')
    actions = record['actions']
    if not isinstance(actions, list) or any(not isinstance(a, dict) for a in actions):
        raise ValueError('PROJECT_SOURCE_ACTION_ARRAY_REQUIRED')
    hashes = pure('project-source-action-canonical-identities.v1', (raw,),
        lambda: [d.identity({k: v for k, v in a.items() if k != 'actionIdentity'}) for a in actions], readonly=True)
    for action, computed in zip(actions, hashes):
        if action.get('actionIdentity') != computed:
            raise ValueError('EXTERNAL_EVIDENCE_IDENTITY_INVALID:actionIdentity')
    return actions


def freeze(run_path, target_plan_path, source_records, output, *, qemu,
           runtime_prefix, cases, source_entry_action=None, timeout=600):
    run = route.check_run(run_path)
    bundle = d.read(run['bundle']['path']); receipt = d.read(bundle['nativeInputReceiptPath'])
    source_digest = receipt['context']['sourceDigest']
    target_plan = d.read(target_plan_path); checked(target_plan, 'deploymentPlanIdentity')
    actions = {}
    records = list(dict.fromkeys(str(Path(p).resolve(strict=True)) for p in source_records))
    for path in records:
        for action in checked_source_actions(path):
            actions[action['actionIdentity']] = action
    actions = list(actions.values())
    entries = []
    for a in actions:
        header = (a.get('observedOutput') or {}).get('elfHeader') or {}
        if (a.get('kind') == 'link' and header.get('machine') == 243
                and (source_entry_action is None or a['actionIdentity'] == source_entry_action)):
            link = d.captured_link(a); elf = d.parse(Path(link['originalOutput']['path']).read_bytes())
            if elf['machine'] == 243 and elf['elfType'] in (2, 3) and elf['interpreter'] and not elf['soname']:
                entries.append(link)
    entry = unique(entries, 'PROJECT_SOURCE_ENTRY_AMBIGUOUS')
    libraries = []
    for a in actions:
        observed = a.get('observedOutput') or {}
        if a.get('kind') == 'link' and any(inputs_equal(i, observed) for i in entry['inputs']
                                                       if all(k in observed for k in ('resolvedPath', 'digest'))):
            link = d.captured_link(a); elf = d.parse(Path(link['originalOutput']['path']).read_bytes())
            if elf['machine'] == 243 and elf['soname'] == target_plan['soname']:
                libraries.append(link)
    library = unique(libraries, 'PROJECT_SOURCE_LIBRARY_AMBIGUOUS')
    source_object, source_profile = producer(library, actions, source_digest)
    target_records = [target_plan['libraryRecords']['path'], target_plan['testRecords']['path']]
    target_actions = {}
    for path in target_records:
        for a in d.read(path)['actions']:
            target_actions[a['actionIdentity']] = a
    target_library = d.captured_link(target_plan['library']['action'])
    target_entry = d.captured_link(target_plan['entry']['action'])
    if target_library != target_plan['library'] or target_entry != target_plan['entry']:
        raise ValueError('PROJECT_TARGET_RECIPE_CHANGED')
    target_object, target_profile = producer(target_library, list(target_actions.values()), source_digest)
    if target_object != target_plan['originalObject']:
        raise ValueError('PROJECT_TARGET_OBJECT_POSITION_MISMATCH')
    for obj, machine in ((source_object, 243), (target_object, 62)):
        elf = d.parse(Path(obj['path']).read_bytes())
        if elf['machine'] != machine or elf['elfType'] != 1:
            raise ValueError('PROJECT_BASELINE_OBJECT_ARCHITECTURE_MISMATCH')
    source_env = execution_environment(receipt['context'])
    qemu = str(Path(qemu).resolve(strict=True)); prefix = Path(runtime_prefix).resolve(strict=True)
    source_elf = d.parse(Path(entry['originalOutput']['path']).read_bytes())
    interpreter = source_elf['interpreter']
    if not Path(interpreter).is_absolute():
        raise ValueError('PROJECT_ABSOLUTE_INTERPRETER_REQUIRED')
    loader = prefix / interpreter.lstrip('/')
    if d.parse(loader.read_bytes())['machine'] != 243:
        raise ValueError('PROJECT_RV64_LOADER_REQUIRED')
    target_loader = Path(d.parse(Path(target_entry['originalOutput']['path']).read_bytes())['interpreter'])
    if not target_loader.is_absolute() or d.parse(target_loader.read_bytes())['machine'] != 62:
        raise ValueError('PROJECT_AMD64_LOADER_REQUIRED')
    if type(timeout) is not int or not 1 <= timeout <= 86400:
        raise ValueError('PROJECT_TIMEOUT_INVALID')
    profiles = {}
    for side, lib, ent, obj, prof, env in (
            ('source', library, entry, source_object, source_profile, source_env),
            ('target', target_library, target_entry, target_object, target_profile, target_plan['environment'])):
        positions = [i['argumentIndex'] for i in ent['inputs'] if inputs_equal(i, lib['originalOutput'])]
        if not positions:
            raise ValueError('PROJECT_ENTRY_LIBRARY_POSITION_REQUIRED')
        for key in ('LD_PRELOAD', 'LD_AUDIT', 'LD_DEBUG', 'LD_DEBUG_OUTPUT', 'LD_BIND_NOW'):
            if env.get(key): raise ValueError('PROJECT_DIAGNOSTIC_ENVIRONMENT_FORBIDDEN:' + key)
        profiles[side] = {'library': lib, 'entry': ent, 'object': obj, 'compile': prof,
                          'entryLibraryPositions': positions, 'environment': env,
                          'machine': 243 if side == 'source' else 62}
    matrix_tools = [shutil.which(name, path=target_plan['environment']['PATH']) for name in ('gcc', 'clang')]
    if any(p is None for p in matrix_tools): raise ValueError('PROJECT_FULL_GCC_CLANG_MATRIX_TOOLS_REQUIRED')
    cli = Path(__file__).resolve().parents[2] / 'experiment/automate_native_project.py'
    refs = [d.snapshot(p) for p in [run_path, target_plan_path, bundle['nativeInputReceiptPath'],
                                   *records, *target_records, *matrix_tools, qemu, loader, target_loader, sys.executable, cli]]
    value = d.seal({'schemaVersion': SCHEMA, 'run': d.snapshot(run_path), 'verifier': current(),
                    'references': refs, 'profiles': profiles, 'qemu': d.snapshot(qemu),
                    'runtimePrefix': str(prefix), 'sourceLoader': d.snapshot(loader),
                    'targetLoader': d.snapshot(target_loader),
                    'python': d.snapshot(sys.executable), 'cases': validate_cases(cases),
                    'timeoutSeconds': timeout,
                    'scope': 'frozen-cpp-object-replacement-and-bounded-process-observations',
                    'gaps': ['THREE_COMPILE_CONTEXT_REFINEMENT_REQUIRED', *GAPS],
                    'semanticApproval': False, 'productionAcceptanceComplete': False}, 'projectEvaluationIdentity')
    value['configuration'] = {'run_path': str(Path(run_path).resolve()), 'target_plan_path': str(Path(target_plan_path).resolve()),
        'source_records': records, 'qemu': qemu, 'runtime_prefix': str(prefix), 'cases': cases,
        'source_entry_action': source_entry_action, 'timeout': timeout}
    value = d.seal({k: v for k, v in value.items() if k != 'projectEvaluationIdentity'}, 'projectEvaluationIdentity')
    if output is None: return value
    output = Path(output); output.parent.mkdir(parents=True, exist_ok=True)
    publish_checked(output, value, check)
    return value


@measured('native_project_evaluation.check')
def check(path):
    value = d.read(path); checked(value, 'projectEvaluationIdentity'); compare(value['verifier'], current())
    if value['schemaVersion'] != SCHEMA or value['gaps'] != ['THREE_COMPILE_CONTEXT_REFINEMENT_REQUIRED', *GAPS]:
        raise ValueError('PROJECT_EVALUATION_SCHEMA_OR_CLAIM_INVALID')
    if value['semanticApproval'] is not False or value['productionAcceptanceComplete'] is not False:
        raise ValueError('PROJECT_EVALUATION_SCOPE_ESCALATION')
    if freeze(output=None, **value['configuration']) != value:
        raise ValueError('PROJECT_EVALUATION_REDERIVATION_MISMATCH')
    validate_cases(value['cases'])
    for ref in value['references']: d.verify_snapshot(ref)
    # freeze(output=None) above already checks the original run, captures all
    # ordered link inputs/compile profiles and rederives library positions.
    # Equality with the entire stored value closes those same obligations;
    # repeating the complete run graph here supplied no independent evidence.
    # Reference snapshots stay live after rederivation. No validator result is
    # cached and a new public check or audit starts from current inputs again.
    return value


@measured('native_project_evaluation.command')
def command(argv, cwd, env, root, timeout):
    from .native_experiment_driver import command as execute
    root.mkdir()
    started = time.monotonic()
    code, failure = execute(list(argv), cwd, env, root, timeout, 16 * 1024 * 1024)
    write(root / 'execution.json', {'arguments': list(argv), 'directory': str(cwd),
          'environment': env, 'returnCode': code, 'failureReason': failure, 'elapsedSeconds': time.monotonic() - started})
    return code, failure


def validate_execution_record(row):
    if (set(row) != {'arguments', 'directory', 'environment', 'returnCode', 'failureReason', 'elapsedSeconds'}
            or type(row['returnCode']) is not int
            or row['failureReason'] not in (None, 'TIMEOUT', 'LOG_BUDGET_EXCEEDED')
            or type(row['elapsedSeconds']) not in (int, float)
            or not math.isfinite(row['elapsedSeconds']) or row['elapsedSeconds'] < 0):
        raise ValueError('PROJECT_EXECUTION_RECORD_INVALID')
    return row


def expected_input_digest(spec, side):
    run = d.read(spec['run']['path']); prepared = d.read(run['input']['path'])
    if side == 'source': expected = prepared['source']['digest']
    else:
        translation = d.read(run['translation']['path'])
        manifest = d.read(translation['candidateManifest']['path'])
        expected = unique(list({e['afterFileDigest'] for e in manifest['edits'] if e['relativePath'] == 'input.i'}), 'PROJECT_SINGLE_TU_DIGEST_REQUIRED')
    return expected


def build_side(spec_path, side, input_path, output):
    spec = check(spec_path); profile = spec['profiles'][side]
    output = Path(output).absolute()
    if output.exists() or output.is_symlink(): raise FileExistsError(str(output))
    output = output.resolve(); root = output.parent / (output.name + '.project')
    root.mkdir(); inp = d.snapshot(input_path)
    expected = expected_input_digest(spec, side)
    if inp['digest'] != expected: raise ValueError('PROJECT_CURRENT_INPUT_BINDING_MISMATCH')
    prof = profile['compile']; obj = root / 'input.o'
    steps = [('compile', [prof['compiler']['path'], *prof['flags'], '-c', inp['path'], '-o', str(obj)],
              prof['directory'], prof['environment'])]
    lib = root / Path(profile['library']['originalOutput']['path']).name
    steps.append(('library', d._argv(profile['library'], lib, {profile['object']['argumentIndex']: obj}),
                  profile['library']['directory'], profile['environment']))
    for name, argv, cwd, env in steps:
        code, failure = command(argv, cwd, env, root / name, spec['timeoutSeconds'])
        if code != 0 or failure: raise StageFailure('project-' + name, code or 2)
    elf = d.parse(lib.read_bytes()); soname = elf['soname']
    if (elf['machine'] != profile['machine'] or not soname or Path(soname).name != soname
            or elf['elfType'] != 3): raise ValueError('PROJECT_LIBRARY_INTERFACE_INVALID')
    if d.definitions(d.parse(obj.read_bytes())) != d.definitions(d.parse(Path(profile['object']['path']).read_bytes())):
        raise ValueError('PROJECT_DEFINED_INTERFACE_CHANGED')
    alias = lib.parent / soname
    if alias != lib: alias.symlink_to(lib.name)
    argv = d._argv(profile['entry'], output,
                   {i: lib for i in profile['entryLibraryPositions']}, str(root))
    code, failure = command(argv, profile['entry']['directory'], profile['environment'], root / 'entry', spec['timeoutSeconds'])
    if code != 0 or failure: raise StageFailure('project-entry', code or 2)
    elf = d.parse(output.read_bytes())
    if elf['machine'] != profile['machine'] or not elf['interpreter']:
        raise ValueError('PROJECT_EXECUTABLE_INTERFACE_INVALID')
    d.verify_snapshot(inp); check(spec_path)
    value = d.seal({'schemaVersion': 'riscv2x86.original-project-build.v1',
                    'input': inp, 'program': d.snapshot(output), 'library': d.snapshot(lib),
                    'object': d.snapshot(obj), 'side': side,
                    'projectEvaluationIdentity': spec['projectEvaluationIdentity'],
                    'scope': 'captured-project-rebuild-not-abi-proof'}, 'projectBuildIdentity')
    write(root / 'result.json', value)
    return value


@measured('native_project_evaluation.build_record')
def build_record(program, spec, side):
    root = Path(program.artifact_path).parent / (Path(program.artifact_path).name + '.project')
    value = d.read(root / 'result.json'); checked(value, 'projectBuildIdentity')
    if (set(value) != {'schemaVersion', 'input', 'program', 'library', 'object', 'side',
                      'projectEvaluationIdentity', 'scope', 'projectBuildIdentity'}
            or value['schemaVersion'] != 'riscv2x86.original-project-build.v1'
            or value['scope'] != 'captured-project-rebuild-not-abi-proof'
            or value['input']['digest'] != expected_input_digest(spec, side)
            or value['side'] != side or value['projectEvaluationIdentity'] != spec['projectEvaluationIdentity']
            or value['program']['digest'] != program.artifact_digest
            or value['program']['path'] != program.artifact_path):
        raise ValueError('PROJECT_BUILD_BINDING_MISMATCH')
    for k in ('input', 'program', 'library', 'object'): d.verify_snapshot(value[k])
    profile = spec['profiles'][side]; prof = profile['compile']
    for key, types in (('object', (1,)), ('library', (3,)), ('program', (2, 3))):
        elf = d.parse(Path(value[key]['path']).read_bytes())
        if elf['machine'] != profile['machine'] or elf['elfType'] not in types:
            raise ValueError('PROJECT_BUILD_ELF_ROLE_MISMATCH:' + key)
    if d.definitions(d.parse(Path(value['object']['path']).read_bytes())) != d.definitions(d.parse(Path(profile['object']['path']).read_bytes())):
        raise ValueError('PROJECT_BUILD_DEFINITION_INTERFACE_CHANGED')
    expected_commands = {
        'compile': ([prof['compiler']['path'], *prof['flags'], '-c', value['input']['path'], '-o', value['object']['path']],
                    prof['directory'], prof['environment']),
        'library': (d._argv(profile['library'], value['library']['path'],
                           {profile['object']['argumentIndex']: value['object']['path']}),
                    profile['library']['directory'], profile['environment']),
        'entry': (d._argv(profile['entry'], value['program']['path'],
                         {i: value['library']['path'] for i in profile['entryLibraryPositions']}, str(root)),
                  profile['entry']['directory'], profile['environment']),
    }
    for stage, (argv, cwd, env) in expected_commands.items():
        recorded = d.read(root / stage / 'execution.json')
        validate_execution_record(recorded)
        if {k: v for k, v in recorded.items() if k != 'elapsedSeconds'} != {'arguments': argv, 'directory': cwd, 'environment': env,
                        'returnCode': 0, 'failureReason': None}:
            raise ValueError('PROJECT_BUILD_EXECUTION_MISMATCH:' + stage)
    return value


def observation_recipe(spec, source, target, case_indices=None):
    indices = list(range(len(spec['cases']))) if case_indices is None else case_indices
    if (not isinstance(indices, list) or not indices or any(type(i) is not int or not 0 <= i < len(spec['cases']) for i in indices)
            or indices != sorted(set(indices))):
        raise ValueError('PROJECT_OBSERVATION_CASE_SELECTION_INVALID')
    rows = []
    for side, artifact in (('source', source), ('target', target)):
        profile = spec['profiles'][side]
        prefix = [spec['qemu']['path'], '-L', spec['runtimePrefix']] if side == 'source' else []
        rows.append({'path': 'loader-list-' + side, 'arguments': [*prefix, spec[side + 'Loader']['path'], '--list', artifact.artifact_path],
                     'directory': profile['entry']['directory'], 'environment': profile['environment']})
    for index in indices:
        case = spec['cases'][index]
        for side, artifact in (('source', source), ('target', target)):
            profile = spec['profiles'][side]
            prefix = [spec['qemu']['path'], '-L', spec['runtimePrefix']] if side == 'source' else []
            rows.append({'path': 'case-%06d/%s' % (index, side),
                         'arguments': [*prefix, artifact.artifact_path, *case['arguments']],
                         'directory': profile['entry']['directory'],
                         'environment': {**profile['environment'], **case['environmentOverrides']}})
    return indices, rows


@measured('native_project_evaluation.rederive_observations')
def rederive_observations(spec, source, target, root, case_indices=None):
    """Recompute the ORIGINAL comparator from pinned command records and logs."""
    from .l1_differential import HarnessObservation, ProcessObservation, compare_l1_observations
    from .validation_case import ComparisonContract
    root = Path(root); indices, recipe = observation_recipe(spec, source, target, case_indices)
    records = {}
    for item in recipe:
        folder = root / item['path']; row = d.read(folder / 'execution.json'); validate_execution_record(row)
        if any(row[k] != item[k] for k in ('arguments', 'directory', 'environment')):
            raise ValueError('PROJECT_OBSERVATION_COMMAND_CONTEXT_MISMATCH')
        records[item['path']] = row
        for name in ('stdout.log', 'stderr.log'):
            if not (folder / name).is_file(): raise ValueError('PROJECT_OBSERVATION_LOG_REQUIRED')
        if sum((folder / name).stat().st_size for name in ('stdout.log', 'stderr.log')) > 16 * 1024 * 1024:
            raise ValueError('PROJECT_OBSERVATION_RETAINED_LOG_BUDGET_INVALID')
    loaders = {side: {k: records['loader-list-' + side][k] for k in ('returnCode', 'failureReason', 'elapsedSeconds')}
               for side in ('source', 'target')}
    unavailable = any(r['failureReason'] is not None for r in records.values())
    observations = []; mismatches = []; outside = False
    for index in indices:
        case = spec['cases'][index]; pair = {}; durations = {}
        for side in ('source', 'target'):
            key = 'case-%06d/%s' % (index, side); row = records[key]
            logs = [(root / key / name).read_bytes() for name in ('stdout.log', 'stderr.log')]
            pair[side] = ProcessObservation(HarnessObservation(None, (), (), (), ()), row['returnCode'],
                *(base64.b64encode(raw).decode('ascii') for raw in logs), ())
            durations[side] = row['elapsedSeconds']; outside |= row['returnCode'] not in case['expectedExitCodes']
        mismatch = compare_l1_observations(pair['source'], pair['target'],
            ComparisonContract(False, True, True, True, False, (), (), (), ()))
        mismatches.extend(mismatch)
        observations.append({'case': case, 'mismatches': list(mismatch), 'elapsedSeconds': durations,
                             'sourceReturnCode': pair['source'].exit_code, 'targetReturnCode': pair['target'].exit_code})
    return {'cases': observations, 'caseIndices': indices, 'mismatches': list(mismatches),
            'executionBudgetFailed': unavailable, 'exitOutsideDeclaredDomain': outside,
            'loaderListFailed': any(r['returnCode'] != 0 for r in loaders.values()),
            'loaderListDiagnostics': loaders, 'naturalRunImageIdentityVerified': False,
            'scope': 'exact-process-output-and-exit-only', 'gaps': spec['gaps'],
            'semanticApproval': False, 'productionAcceptanceComplete': False}


def observe(spec, source, target, root, *, case_indices=None):
    """Execute selected cases; the formal default still executes ALL cases."""
    root = Path(root); _, recipe = observation_recipe(spec, source, target, case_indices)
    for item in recipe:
        folder = root / item['path']; folder.parent.mkdir(parents=True, exist_ok=True)
        command(item['arguments'], item['directory'], item['environment'], folder, spec['timeoutSeconds'])
    value = rederive_observations(spec, source, target, root, case_indices)
    write(root / 'observations.json', value)
    return value


def factory(config):
    if set(config) not in ({'specPath', 'workDirectory', 'level'}, {'specPath', 'workDirectory', 'level', 'applicabilityPath'}): raise ValueError('PROJECT_VALIDATOR_CONFIG_INVALID')
    level = ValidationLevel(config['level'])
    def validator(**kwargs):
        if kwargs.get('level') is not level: raise ValueError('PROJECT_VALIDATOR_LEVEL_MISMATCH')
        started = time.monotonic()
        spec = check(config['specPath']); root = Path(config['workDirectory']); root.mkdir(parents=True, exist_ok=True)
        source = kwargs['source_program_artifact']; target = kwargs['target_program_artifact']
        src = build_record(source, spec, 'source'); tgt = build_record(target, spec, 'target')
        if level is ValidationLevel.L0:
            from .l0_manifest_builder import build_l0_reference_manifest
            from .l0_build_matrix import run_l0_build_matrix
            from .native_toolchain_environment import operation
            profile = spec['profiles']['target']; lib = profile['library']
            replacements = {i['argumentIndex']: Path(i['path']) for i in lib['inputs']}
            replacements[profile['object']['argumentIndex']] = Path('{object}')
            args = d._argv(lib, '{output}', replacements)[1:]
            # Full mandatory original 2 x 3 x 3 matrix; no SDK fallback.
            with operation(profile['environment'], {spec['profiles']['source']['compile']['compiler']['path']:
                                                    spec['profiles']['source']['compile']['environment']}):
                reference_started = time.monotonic()
                matrix, refsource, reftarget = build_l0_reference_manifest(
                    source_path=Path(src['input']['path']), target_path=Path(tgt['input']['path']),
                    output_directory=root / 'reference', translation=kwargs['translation_artifact'],
                    link_kind='shared_library', timeout=spec['timeoutSeconds'],
                    source_compiler=spec['profiles']['source']['compile']['compiler']['path'],
                    source_flags_override=spec['profiles']['source']['compile']['flags'],
                    target_flags_override=[a for a in profile['compile']['flags'] if not a.startswith('-O')],
                    target_link_arguments=args)
                reference_seconds = time.monotonic() - reference_started
                verify_started = time.monotonic()
                result = run_l0_build_matrix(matrix, kwargs['translation_artifact'], refsource, reftarget,
                                             target_environment=kwargs.get('target_environment'),
                                             tool_available=lambda name: bool(shutil.which(name, path=profile['environment']['PATH'])))
                verify_seconds = time.monotonic() - verify_started
            check(config['specPath'])
            write(root / 'phase-timings.json', {'schemaVersion': 'riscv2x86.project-layer-timing.v1',
                'level': 'L0', 'referenceBuildSeconds': reference_seconds, 'matrixVerificationSeconds': verify_seconds,
                'layerElapsedSeconds': time.monotonic() - started})
            return result
        if level is not ValidationLevel.L1: raise ValueError('PROJECT_VALIDATOR_UNSUPPORTED_LEVEL')
        observation_started = time.monotonic()
        value = observe(spec, source, target, root)
        observation_seconds = time.monotonic() - observation_started
        build_record(source, spec, 'source'); build_record(target, spec, 'target'); check(config['specPath'])
        from .program_validation_obligations import project_assessment
        applicability = None
        if config.get('applicabilityPath'):
            from .native_original_applicability import check as check_applicability
            applicability = check_applicability(config['applicabilityPath'])
            if applicability['project'] != d.snapshot(config['specPath']):
                raise ValueError('PROJECT_APPLICABILITY_BINDING_MISMATCH')
        machine_inventory = None; machine_seconds = 0.0
        if applicability is not None:
            from . import program_machine_inventory as machines
            machine_started = time.monotonic()
            machines.acquire(config['specPath'], {'source': src, 'target': tgt}, root / 'machine-inventory.json')
            machine_seconds = time.monotonic() - machine_started
            machine_inventory = d.snapshot(root / 'machine-inventory.json')
        assessment = project_assessment(spec, value, applicability)
        write(root / 'obligation-assessment.json', assessment)
        write(root / 'phase-timings.json', {'schemaVersion': 'riscv2x86.project-layer-timing.v1',
            'level': 'L1', 'observationSeconds': observation_seconds, 'machineInventorySeconds': machine_seconds,
            'layerElapsedSeconds': time.monotonic() - started})
        return ValidationLayerResult(level, ValidationStatus(assessment['l1Status']),
            d.digest(root / 'obligation-assessment.json'), json.dumps({'reasonCodes': assessment['l1ReasonCodes'],
                'observations': value, 'obligationAssessment': assessment, 'machineInventory': machine_inventory}))
    return validator


def request_payload(spec_path, output, applicability_path=None, *, api_l2_result=None):
    """Produce a real ORIGINAL EvaluationRequest; no manually fabricated template."""
    from .evaluation import EVALUATION_REQUEST_SCHEMA, evaluation_request_from_dict
    from .translation_validation import validation_plan_from_dict, target_environment_from_dict
    from .validation_runtime_registry import VALIDATION_RUNTIME_REGISTRY_SCHEMA
    spec = check(spec_path); run = route.check_run(spec['run']['path'])
    root = Path(output).resolve()
    plan = root / 'validation-plan.json'; env = root / 'environment.json'
    plan_value = {'schemaVersion': 'riscv2x86.validation-plan.v1', 'planId': spec['projectEvaluationIdentity'],
        'profile': 'architectural', 'sourceRunner': 'qemu', 'targetRunner': 'native', 'seed': 0,
        'timeoutSeconds': spec['timeoutSeconds'], 'runtimeRegistryVersion': 'original-project.v1',
        'experimentContractId': ''}
    flags = spec['profiles']['source']['compile']['flags']
    source_isa = unique([a.split('=', 1)[1] for a in flags if a.startswith('-march=')], 'PROJECT_EXPLICIT_SOURCE_ISA_REQUIRED')
    source_abi = unique([a.split('=', 1)[1] for a in flags if a.startswith('-mabi=')], 'PROJECT_EXPLICIT_SOURCE_ABI_REQUIRED')
    env_value = {'schemaVersion': 'riscv2x86.target-environment.v1', 'environmentId': spec['projectEvaluationIdentity'],
        'sourceIsa': source_isa, 'sourceAbi': source_abi, 'targetIsa': 'x86_64', 'targetAbi': 'sysv_amd64',
        'sourceRunnerCapabilities': ['qemu'], 'targetRunnerCapabilities': ['native'],
        'sanitizerCapabilities': ['asan', 'none', 'ubsan'],
        # TargetEnvironment's loader belongs to the target. Source QEMU and
        # guest loader are separately pinned in the project context; their
        # identities must not be relabeled as the native target runtime.
        'runtimeIdentity': spec['projectEvaluationIdentity'],
        'loaderIdentity': spec['targetLoader']['digest']}
    cli = Path(__file__).resolve().parents[2] / 'experiment' / 'automate_native_project.py'
    builders = {}
    for side in ('source', 'target'):
        builders[side + 'Build'] = {'artifactId': side, 'artifactKind': 'executable',
            'outputRelativePath': 'build/' + side,
            'command': [spec['python']['path'], str(cli), 'build-side', '--spec', str(Path(spec_path).resolve()),
                        '--side', side, '--input', '${' + side.upper() + '_PATH}', '--output', '${OUTPUT}']}
    runinput = d.read(run['input']['path']); translation = d.read(run['translation']['path'])
    raw = {'schemaVersion': EVALUATION_REQUEST_SCHEMA, 'sourceRoot': str(Path(runinput['source']['path']).parent),
           'sourceRelativePath': 'input.i', 'targetRelativePath': 'input.i',
           'translatedReport': translation['report']['path'], 'attemptArchive': translation['attemptArchive']['path'],
           'validationPlan': str(plan), 'targetEnvironment': str(env),
           'runtimeRegistryTemplate': {'schemaVersion': VALIDATION_RUNTIME_REGISTRY_SCHEMA,
               'version': 'original-project.v1', 'validators': {level: {'type': 'original-captured-project',
                   'config': {'specPath': str(Path(spec_path).resolve()), 'level': level,
                              'workDirectory': '${WORK_DIR}/project-${ATTEMPT_ID}-' + level}} for level in ('L0', 'L1')}},
           'translationArtifacts': {}, **builders, 'translationCommand': [],
           'comparisonPolicy': 'exit-code-stdout-stderr-exact-bytes.v1',
           'validationUnit': 'program', 'validationGroupId': '', 'selectedAttemptIds': []}
    if applicability_path is not None:
        from .native_original_applicability import check as check_applicability
        app = check_applicability(applicability_path)
        if app['project'] != d.snapshot(spec_path): raise ValueError('PROJECT_APPLICABILITY_BINDING_MISMATCH')
        for descriptor in raw['runtimeRegistryTemplate']['validators'].values():
            descriptor['config']['applicabilityPath'] = str(Path(applicability_path).resolve())
    if api_l2_result is not None:
        from . import native_project_l2 as typed_l2
        l2 = typed_l2.check(api_l2_result)
        l2_inputs = d.read(Path(api_l2_result).resolve().parent / 'inputs.json')
        api_inputs = d.read(Path(l2_inputs['apiResult']['path']).parent / 'inputs.json')
        if api_inputs['spec'] != d.snapshot(spec_path):
            raise ValueError('PROJECT_L2_SPEC_BINDING_MISMATCH')
        if applicability_path is None or l2_inputs['applicability'] != d.snapshot(applicability_path):
            raise ValueError('PROJECT_L2_APPLICABILITY_BINDING_MISMATCH')
        # An ordinary requirement-driven original registry. Other dimensions
        # remain required and cannot be replaced by finite API observations.
        raw['runtimeRegistryTemplate']['validators']['L2'] = d.read(l2['registryDescriptor']['path'])
    evaluation_request_from_dict(raw); validation_plan_from_dict(plan_value); target_environment_from_dict(env_value)
    return {'validation-plan.json': plan_value, 'environment.json': env_value, 'request.json': raw}


def request(spec_path, output, applicability_path=None, *, api_l2_result=None):
    payload = request_payload(spec_path, output, applicability_path, api_l2_result=api_l2_result)
    root = Path(output).resolve(); root.mkdir()
    for name, value in payload.items(): write(root / name, value)
    check_request(root / 'request.json', spec_path, applicability_path, api_l2_result=api_l2_result)
    return root / 'request.json'


def check_request(path, spec_path, applicability_path=None, *, api_l2_result=None):
    """Rederive all contracts without overwriting or executing anything."""
    path = Path(path).resolve(strict=True)
    if path.name != 'request.json': raise ValueError('PROJECT_REQUEST_NAME_INVALID')
    expected = request_payload(spec_path, path.parent, applicability_path, api_l2_result=api_l2_result)
    for name, value in expected.items():
        # These are exclusively generated contracts, so their original byte
        # representation is known. Do not lose companion-file mutations when
        # only request.json is the scheduler's main checkpoint reference.
        expected_bytes = (json.dumps(value, indent=2) + '\n').encode('utf-8')
        if d.read(path.parent / name) != value or (path.parent / name).read_bytes() != expected_bytes:
            raise ValueError('PROJECT_REQUEST_REDERIVATION_MISMATCH:' + name)
    return [d.snapshot(path.parent / name) for name in expected]
