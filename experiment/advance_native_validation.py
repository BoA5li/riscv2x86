#!/usr/bin/env python3
"""Prepare/run prerequisite acquisition without skipping the target build.

No command in this entry point grants external behavior or L0--L3 approval.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'pytools'))
from riscv2x86_py import native_experiment_driver as driver
from riscv2x86_py.native_dependency_inventory import checked_records
from riscv2x86_py.native_external_providers import checked, read
from riscv2x86_py.project_build_records import identity
from riscv2x86_py.project_compile_context import digest, ENV_KEYS
from riscv2x86_py.project_acquisition import Runner


def inspect_build(root, expected_machine):
    from riscv2x86_py.native_test_entry import acquire
    root = Path(root).resolve(strict=True)
    state = read(root/'run-status.json')
    if (state.get('stateIdentity') != identity({k: v for k, v in state.items() if k != 'stateIdentity'})
            or state.get('status') != 'complete' or state.get('acquisitionComplete') is not True
            or state.get('primaryFailure') is not None):
        raise ValueError('NATIVE_ADVANCE_BUILD_NOT_COMPLETE')
    library = checked_records(root/'records.json')
    tests = checked_records(root/'test-records.json')
    support = checked_records(root/'test-records-0.json')
    candidates = []
    for action in tests['actions']:
        if (action['kind'] == 'link' and action.get('exitStatusObserved') is True
                and type(action.get('observedReturnCode')) is int and action['observedReturnCode'] == 0):
            # Do not select by filename. Preserve every successful link action;
            # later deployment needs an explicitly reviewed action identity.
            candidates.append(acquire(root/'test-records.json', action['actionIdentity'],
                                      expected_machine=expected_machine))
    if not candidates:
        raise ValueError('NATIVE_ADVANCE_SUCCESSFUL_TEST_LINK_REQUIRED')
    body = {'schemaVersion': 'riscv2x86.native-build-readiness.v1',
            'buildStateIdentity': state['stateIdentity'],
            'libraryInventoryIdentity': library['inventoryIdentity'],
            'testSupportInventoryIdentity': support['inventoryIdentity'],
            'testInventoryIdentity': tests['inventoryIdentity'], 'entryCandidates': candidates,
            'candidateSelectionRequired': True, 'testExecutionPerformed': False,
            'semanticApproval': False, 'productionAcceptanceComplete': False}
    return dict(body, readinessIdentity=identity(body))


def configuration(requirements, output, timeout):
    from riscv2x86_py.native_compiler_configuration import acquire
    req = read(requirements)
    checked(req, 'requirementsIdentity')
    provider = read(req['providerPath'])
    checked(provider, 'inventoryIdentity')
    if digest(req['providerPath']) != req['providerDigest']:
        raise ValueError('NATIVE_ADVANCE_PROVIDER_CHANGED')
    dependencies = read(provider['dependencyPath'])
    checked(dependencies, 'inventoryIdentity')
    if provider['dependencyInventoryIdentity'] != dependencies['inventoryIdentity']:
        raise ValueError('NATIVE_ADVANCE_DEPENDENCY_CHANGED')
    ids = list(dict.fromkeys(a['actionIdentity'] for r in req['requirements'] for a in r['selectedBuildActions']))
    if not ids:
        raise ValueError('NATIVE_ADVANCE_NO_CAPTURED_COMPILE_ACTIONS')
    value = acquire(dependencies['recordsPath'], ids, output, timeout)
    return value


def plan(tooling, prep, archives, profile, requirements, timeout):
    from riscv2x86_py.project_build_profile import validate
    tooling = Path(tooling).resolve(strict=True)
    prep = Path(prep).resolve(strict=True)
    archives = Path(archives).resolve(strict=True)
    profile = Path(profile).resolve(strict=True)
    requirements = Path(requirements).resolve(strict=True)
    value = validate(read(profile))
    if value['side'] != 'target':
        raise ValueError('NATIVE_ADVANCE_TARGET_PROFILE_REQUIRED')
    req = read(requirements)
    checked(req, 'requirementsIdentity')
    if req['schemaVersion'] != 'riscv2x86.native-external-requirements.v1':
        raise ValueError('NATIVE_ADVANCE_REQUIREMENTS_REQUIRED')
    script = tooling/'experiment/advance_native_validation.py'
    runtime = tooling/'experiment/inspect_native_runtime_contracts.py'
    files = [str(p) for p in sorted((tooling/'pytools/riscv2x86_py').glob('*.py'))]
    files += [str(p) for pattern in ('*.py', '*.sh') for p in sorted((tooling/'experiment').glob(pattern))]
    env = {k: os.environ[k] for k in ENV_KEYS if k in os.environ}
    env.update(PATH=os.environ.get('PATH', '/usr/bin:/bin'), LC_ALL='C',
               PYTHONPATH=str(tooling/'pytools'), PYTHONDONTWRITEBYTECODE='1')
    stages = []
    def add(name, argv, inputs, outputs):
        stages.append({'id': name, 'dependsOn': [] if not stages else [stages[-1]['id']],
            'command': [sys.executable, *argv], 'directory': str(tooling), 'environment': env,
            'inputs': [*files, *map(str, inputs)], 'outputs': outputs,
            'timeoutSeconds': timeout, 'maxLogBytes': 64*1024*1024})
    add('target-build', [str(tooling/'experiment/acquire_real_project_builds.py'),
        str(tooling), str(prep), str(archives), '${STAGE}/gmp-target', 'gmp',
        '--archive-provenance', '--build-profile', str(profile),
        '--test-target', 'tests:libtests.la', '--test-target', 'tests/mpz:t-powm'],
        [profile], ['gmp-target/run-status.json', 'gmp-target/records.json',
                    'gmp-target/test-records-0.json', 'gmp-target/test-records.json'])
    add('target-readiness', [str(script), 'inspect-build', '--root', '${RUN}/target-build/gmp-target',
        '--expected-machine', '62', '--output', '${STAGE}/result.json'],
        ['${RUN}/target-build/gmp-target/run-status.json', '${RUN}/target-build/gmp-target/records.json',
         '${RUN}/target-build/gmp-target/test-records-0.json', '${RUN}/target-build/gmp-target/test-records.json'],
        ['result.json'])
    add('reference-ledger', [str(runtime), 'reference-ledger', '--input', str(requirements),
        '--output', '${STAGE}/evidence'], [requirements], ['evidence/result.json'])
    add('reference-replay', [str(runtime), 'replay-reference-ledger',
        '--input', '${RUN}/reference-ledger/evidence/result.json', '--output', '${STAGE}/evidence'],
        ['${RUN}/reference-ledger/evidence/result.json'], ['evidence/result.json'])
    add('source-compiler-configurations', [str(script), 'compiler-configurations',
        '--requirements', str(requirements), '--output', '${STAGE}/evidence',
        '--timeout-seconds', str(min(timeout, 300))], [requirements], ['evidence/result.json'])
    add('source-compiler-replay', [str(script), 'replay-compiler-configurations',
        '--input', '${RUN}/source-compiler-configurations/evidence/result.json',
        '--output', '${STAGE}/evidence', '--timeout-seconds', str(min(timeout, 300))],
        ['${RUN}/source-compiler-configurations/evidence/result.json'], ['evidence/result.json'])
    body = {'schemaVersion': driver.SCHEMA, 'stages': stages}
    return dict(body, planIdentity=identity(body))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    prepare = sub.add_parser('prepare-target')
    for name in ('tooling', 'prep', 'archives', 'profile', 'requirements', 'output'):
        prepare.add_argument('--'+name, required=True)
    prepare.add_argument('--timeout-seconds', type=int, default=3600)
    run = sub.add_parser('run')
    run.add_argument('--plan', required=True)
    run.add_argument('--output', required=True)
    check = sub.add_parser('check-run')
    check.add_argument('--input', required=True)
    inspect = sub.add_parser('inspect-build')
    inspect.add_argument('--root', required=True)
    inspect.add_argument('--expected-machine', type=int, choices=(62, 243), required=True)
    inspect.add_argument('--output', required=True)
    config = sub.add_parser('compiler-configurations')
    config.add_argument('--requirements', required=True)
    config.add_argument('--output', required=True)
    config.add_argument('--timeout-seconds', type=int, default=120)
    replay = sub.add_parser('replay-compiler-configurations')
    replay.add_argument('--input', required=True)
    replay.add_argument('--output', required=True)
    replay.add_argument('--timeout-seconds', type=int, default=120)
    args = parser.parse_args(argv)
    runner = None
    try:
        if args.operation == 'prepare-target':
            value = plan(args.tooling, args.prep, args.archives, args.profile, args.requirements, args.timeout_seconds)
            driver.validate(value)
        elif args.operation == 'run':
            value = driver.execute(read(args.plan), args.output)
            print(json.dumps({'status': value['status'], 'primaryFailure': value['primaryFailure'],
                'acquisitionComplete': value['acquisitionComplete'], 'semanticApproval': False,
                'productionAcceptanceComplete': False, 'statusPath': str(Path(args.output)/'run-status.json')}))
            return 0 if value['acquisitionComplete'] else 2
        elif args.operation == 'check-run':
            print(json.dumps(driver.check_run(args.input)))
            return 0
        elif args.operation == 'inspect-build':
            value = inspect_build(args.root, args.expected_machine)
        else:
            runner = Runner(args.output, 'native-'+args.operation)
            if args.operation == 'compiler-configurations':
                value = configuration(args.requirements, runner.output, args.timeout_seconds)
            else:
                from riscv2x86_py.native_compiler_configuration import replay as check_configuration
                original = Path(args.input).resolve(strict=True)
                value = check_configuration(read(original), original.parent, runner.output, args.timeout_seconds)
            (runner.output/'result.json').write_text(json.dumps(value, indent=2)+'\n')
            runner.state.update(status='complete', currentStage='complete', acquisitionComplete=True)
            runner.save()
            print(json.dumps({'resultPath': str(runner.output/'result.json'),
                              'semanticApproval': False, 'productionAcceptanceComplete': False}))
            return 0
        with Path(args.output).open('x') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
        print(json.dumps({'resultPath': args.output, 'semanticApproval': False,
                          'productionAcceptanceComplete': False}))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        if runner is not None:
            runner.failure(args.operation, exc)
        print(json.dumps({'error': type(exc).__name__, 'detail': str(exc),
            'semanticApproval': False, 'productionAcceptanceComplete': False}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
