"""Fail-closed orchestration of pinned original-project acquisition recipes.

Stage success is not translation, ABI equivalence or production acceptance.
Failed native actions and partial capture evidence remain available for diagnosis.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from .project_compile_context import digest
from .project_tool_resolution import resolve_executable
from .project_build_records import identity

SCHEMA = 'riscv2x86.project-acquisition-run.v1'
RELEASES = {'gmp': 'gmp-6.3.0', 'linux': 'linux-6.6'}
DEPENDENCIES = {
    'gmp': ('make', 'sh', 'env', 'm4', 'sed', 'awk'),
    'linux': ('make', 'sh', 'bc', 'flex', 'bison', 'perl', 'sed', 'awk'),
}
TOOLS = {'cc': ('RV2X86_TEST_RISCV_CC', '/usr/bin/riscv64-linux-gnu-gcc-7'),
         'hostcc': ('RV2X86_TEST_HOST_CC', '/usr/bin/x86_64-linux-gnu-gcc-7'),
         'ar': ('RV2X86_TEST_RISCV_AR', '/usr/bin/riscv64-linux-gnu-ar'),
         'ld': ('RV2X86_TEST_RISCV_LD', '/usr/bin/riscv64-linux-gnu-ld'),
         'ranlib': ('RV2X86_TEST_RISCV_RANLIB', '/usr/bin/riscv64-linux-gnu-ranlib')}


def publish(path, value):
    """Replace only this run's progress file; never an older result directory."""
    value = dict(value, stateIdentity=identity(value))
    with tempfile.NamedTemporaryFile('w', dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(value, stream, indent=2)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    os.replace(temporary, path)


def preflight(project, tools=None):
    rows = []; missing = []
    selected = ({name: os.environ.get(variable, default) for name, (variable, default) in TOOLS.items()}
                if tools is None else tools)
    for role, name in [(name, name) for name in DEPENDENCIES[project]] + list(selected.items()):
        try:
            executable = resolve_executable(name)
            row = {'role': role, 'requested': name, 'path': str(executable), 'digest': digest(executable)}
            # These selected dependencies have safe version queries. Other
            # utilities are identity-bound without guessing their CLI grammar.
            if role in {'bc', 'make', 'm4', 'flex', 'bison', 'perl', 'cc', 'hostcc', 'ar', 'ld', 'ranlib'}:
                arg = '-v' if role == 'perl' else '--version'
                result = subprocess.run([str(executable), arg], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=15)
                row.update(versionReturnCode=result.returncode, version=(result.stdout + result.stderr)[:4096])
                if digest(executable) != row['digest']:
                    raise ValueError('PROJECT_DEPENDENCY_CHANGED:' + role)
                if result.returncode:
                    raise ValueError('PROJECT_DEPENDENCY_VERSION_PROBE_FAILED:' + role)
            rows.append(row)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            missing.append({'role': role, 'requested': name, 'reason': str(exc)})
    # Availability is not a proof of all headers/libraries or build compatibility.
    return {'project': project, 'tools': rows, 'missing': missing,
            'prerequisitesAvailable': not missing, 'allBuildDependenciesVerified': False,
            'semanticApproval': False, 'productionAcceptanceComplete': False}


class StageFailure(Exception):
    def __init__(self, stage, code):
        self.stage = stage; self.code = code


class Runner:
    def __init__(self, output, project):
        self.output = Path(output).absolute()
        # Deliberately exclusive; never erase or mix old capture sessions.
        self.output.mkdir()
        self.output = self.output.resolve()
        self.state = {'schemaVersion': SCHEMA, 'project': project, 'output': str(self.output),
                      'implementation': {'module': str(Path(__file__).resolve()), 'moduleDigest': digest(__file__),
                                         'python': sys.executable, 'pythonDigest': digest(sys.executable)},
                      'currentStage': 'initialization', 'status': 'running', 'stages': [],
                      'primaryFailure': None, 'diagnostics': [], 'acquisitionComplete': False,
                      'semanticApproval': False, 'productionAcceptanceComplete': False}
        self.save()

    def save(self):
        publish(self.output / 'run-status.json', self.state)

    def step(self, stage, command, *, cwd=None, env=None):
        path = self.output / (stage + '.log')
        row = {'stage': stage, 'command': list(map(str, command)), 'directory': str(Path(cwd or Path.cwd()).resolve()),
               'logPath': str(path), 'status': 'running', 'returnCode': None}
        self.state['currentStage'] = stage; self.state['stages'].append(row); self.save()
        started = time.monotonic()
        try:
            with path.open('xb') as log:
                result = subprocess.run(row['command'], cwd=row['directory'], env=env, stdout=log, stderr=subprocess.STDOUT)
            code = result.returncode
        except OSError as exc:
            row['launchError'] = {'type': type(exc).__name__, 'detail': str(exc)}
            code = 127
        row.update(returnCode=code, status='succeeded' if code == 0 else 'failed', wallSeconds=time.monotonic()-started)
        if code:
            self.state.update(status='failed', primaryFailure={'stage': stage, 'returnCode': code, 'logPath': str(path)})
        self.save()
        if code:
            print(json.dumps({'acquisitionFailure': self.state['primaryFailure'], 'statusPath': str(self.output/'run-status.json')}), file=sys.stderr)
            raise StageFailure(stage, code)
        return path

    def failure(self, stage, exc):
        self.state.update(currentStage=stage, status='failed', primaryFailure={
            'stage': stage, 'type': type(exc).__name__, 'detail': str(exc)})
        self.save()
        print(json.dumps({'acquisitionFailure': self.state['primaryFailure'], 'statusPath': str(self.output/'run-status.json')}), file=sys.stderr)

    def capture_diagnostic(self, tooling, capture, stage):
        """Best effort export; never replaces the original stage return code."""
        if not capture.is_file():
            return
        logpath = self.output / 'failure-capture.log'
        command = [sys.executable, str(tooling/'experiment/prepare_real_project_experiment.py'),
                   'import-capture', '--capture', str(capture), '--stage', stage,
                   '--output', str(self.output/'failure-records.json')]
        try:
            with logpath.open('xb') as log:
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
            self.state['diagnostics'].append({'command': command, 'returnCode': result.returncode, 'logPath': str(logpath)})
        except OSError as exc:
            self.state['diagnostics'].append({'error': str(exc), 'logPath': str(logpath)})
        self.save()


def acquire(tooling, prep, archives, output, project, archive_provenance=False,
            build_profile=None, test_target=()):
    runner = Runner(output, project)
    capture = runner.output/'capture/capture.json'
    native_stage = None
    try:
        tooling = Path(tooling).resolve(strict=True); prep = Path(prep).resolve(strict=True)
        archives = Path(archives).resolve(strict=True)
        release = RELEASES[project]; source = prep/'upstream'/release
        archive = archives/(release+'.tar.xz'); lock = tooling/'experiment/corpora/real-projects-v2/sources.lock.json'
        runner.state['currentStage'] = 'prerequisites'; runner.save()
        from .project_build_profile import validate, targets
        profile = None
        goals = targets(test_target)
        if build_profile is not None:
            if project != 'gmp':
                raise ValueError('PROJECT_BUILD_PROFILE_GMP_ONLY')
            profile = validate(json.loads(Path(build_profile).read_text()))
            publish(runner.output/'build-profile.json', profile)
        check = (preflight(project) if profile is None else
                 preflight(project, {k: v['path'] for k, v in profile['tools'].items()}))
        publish(runner.output/'prerequisites.json', check)
        if not check['prerequisitesAvailable']:
            raise ValueError('PROJECT_BUILD_DEPENDENCIES_MISSING:' + json.dumps(check['missing']))
        proof = runner.output/'source.json'; build = runner.output/'build'; binpath = runner.output/'capture/bin'
        prepare = [sys.executable, str(tooling/'experiment/prepare_real_project_experiment.py')]
        capture_command = [sys.executable, str(tooling/'experiment/capture_project_build.py')]
        runner.step('decoder', [sys.executable, str(tooling/'experiment/check_project_acquisition.py'), '--archive', str(archive)])
        runner.step('source', [*prepare, 'verify-source', '--lock', str(lock), '--project', project,
                              '--archive', str(archive), '--source', str(source), '--output', str(proof)])
        build.mkdir()
        tools = {row['role']: row['path'] for row in check['tools'] if row['role'] in TOOLS}
        argv = [*capture_command, 'create', '--output', str(capture.parent)]
        for name, path in tools.items(): argv += ['--tool', name+'='+path]
        if archive_provenance:
            argv += ['--archive-tool','ar=gnu-ar','--archive-tool','ranlib=gnu-ranlib']
        if build_profile is not None:
            argv += ['--input', str(Path(build_profile).resolve(strict=True))]
        runner.step('create', [*argv, '--input', str(lock)])

        def run(stage, command, inputs=()):
            nonlocal native_stage
            native_stage = stage
            argv = [*capture_command, 'run', '--capture', str(capture), '--cwd', str(build),
                    '--source-proof', str(proof), '--stage', stage]
            for path in inputs: argv += ['--input', str(build/path)]
            return runner.step(stage, [*argv, '--', *map(str, command)])

        if project == 'gmp':
            guessed = runner.step('build-triple', [str(source/'config.guess')])
            triple = guessed.read_text().strip()
            if not triple or any(c.isspace() for c in triple):
                raise ValueError('PROJECT_GMP_BUILD_TRIPLE_INVALID')
            # GMP 6.3.0 riscv64 uses the project's default ABI selector
            # "standard". This is independent of GCC's -mabi=lp64d.
            # env -u also prevents a caller's ABI=64 from leaking back in.
            envtool = str(resolve_executable('env'))
            run('configure', [envtool, '-u', 'ABI', 'CC='+str(binpath/'cc'), 'CC_FOR_BUILD='+str(binpath/'hostcc'),
                'AR='+str(binpath/'ar'), 'RANLIB='+str(binpath/'ranlib'), 'LD='+str(binpath/'ld'),
                'CFLAGS='+('-O2 -march=rv64gc -mabi=lp64d' if profile is None else profile['cflags']),
                str(resolve_executable('sh')), str(source/'configure'),
                '--build='+triple, '--host='+('riscv64-linux-gnu' if profile is None else profile['host']), '--enable-assembly', '--enable-static',
                '--enable-shared', '--prefix='+str(runner.output/'install')])
            run('build', [str(resolve_executable('make')), '-j4', 'V=1'],
                ('config.h', 'gmp.h', 'gmp-mparam.h', 'Makefile', 'config.status', 'libtool'))
        else:
            make = [str(resolve_executable('make')), '-C', str(source), 'O='+str(build), 'ARCH=riscv',
                    'CROSS_COMPILE=riscv64-linux-gnu-', 'V=1', *[k.upper()+'='+str(binpath/v)
                    for k,v in (('cc','cc'),('hostcc','hostcc'),('ar','ar'),('ld','ld'),('ranlib','ranlib'))]]
            run('configure', [*make, 'defconfig'])
            if 'CONFIG_64BIT=y' not in (build/'.config').read_text().splitlines():
                raise ValueError('PROJECT_LINUX_RV64_CONFIG_REQUIRED')
            run('prepare', [*make, 'prepare'], ('.config',))
            run('diagnostic-build', [*make, '-j1', 'init/main.o'],
                ('.config', 'include/config/auto.conf', 'include/generated/autoconf.h'))
        library_stage = native_stage
        if goals:
            if project != 'gmp':
                raise ValueError('PROJECT_TEST_TARGET_GMP_ONLY')
            for index, goal in enumerate(goals):
                directory, target = goal.split(':', 1) if ':' in goal else ('.', goal)
                stage = 'test-build-'+str(index)
                test_inputs = ['config.h', 'gmp.h', 'gmp-mparam.h', 'Makefile', 'config.status', 'libtool']
                if directory != '.':test_inputs.append(str(Path(directory)/'Makefile'))
                run(stage, [str(resolve_executable('make')), '-C', directory, '-j4', 'V=1', target], test_inputs)
                name = 'test-records.json' if index == len(goals)-1 else 'test-records-'+str(index)+'.json'
                runner.step('import-'+stage, [*prepare, 'import-capture', '--capture', str(capture),
                    '--stage', stage, '--output', str(runner.output/name)])
        runner.step('import', [*prepare, 'import-capture', '--capture', str(capture), '--stage', library_stage,
                               '--output', str(runner.output/'records.json')])
        inspection_target = [] if profile is None else ['--target', 'riscv64' if profile['side']=='source' else 'x86_64']
        runner.step('inspect', [*prepare, 'inspect', '--records', str(runner.output/'records.json'),
                                *inspection_target, '--output', str(runner.output/'contexts.json')])
        runner.state.update(currentStage='complete', status='complete', acquisitionComplete=True)
        runner.save()
        print(json.dumps({'acquisitionComplete': True, 'output': str(runner.output), 'semanticApproval': False,
                          'productionAcceptanceComplete': False}))
        return 0
    except StageFailure as exc:
        if native_stage is not None and exc.stage == native_stage:
            runner.capture_diagnostic(tooling, capture, native_stage)
        return exc.code if exc.code >= 0 else 128-exc.code
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        runner.failure(runner.state['currentStage'], exc)
        return 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('tooling', 'prep', 'archives', 'output'): parser.add_argument(name)
    parser.add_argument('project', choices=tuple(RELEASES))
    parser.add_argument('--archive-provenance',action='store_true',
                        help='Observe GNU regular-ar append/index input and output provenance')
    parser.add_argument('--build-profile', help='Explicit identity-bound source or target GMP profile')
    parser.add_argument('--test-target', action='append', default=[], help='Official [build-subdirectory:]make-goal, captured separately in order')
    args = parser.parse_args(argv)
    try:
        return acquire(**vars(args))
    except FileExistsError:
        print(json.dumps({'error': 'PROJECT_ACQUISITION_OUTPUT_EXISTS', 'output': str(Path(args.output).absolute()),
                          'detail': 'Use a new directory; earlier evidence was not changed.', 'semanticApproval': False}), file=sys.stderr)
        return 2
    except OSError as exc:
        print(json.dumps({'error': type(exc).__name__, 'detail': str(exc), 'semanticApproval': False}), file=sys.stderr)
        return 2
