"""Run layered checks without reusing a previous batch path or hiding failures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

MODULES = ('l2_authority', 'automatic_l2_authority', 'automatic_l2_operand',
           'automatic_translation_command', 'batch_evaluation_cli')
TARGETS = ('l2_typed_authority', 'canonical_l2_operand',
           'canonical_observation_materializer', 'l2_operand_join_preconditions',
           'l2_real_production_chain', 'requirement_staging',
           'requirement_artifact_ingress', 'fence_execution_closure',
           'l2_fence_ordering_relations', 'l2_evidence_closure',
           'l2_stage11_contract_matrix', 'l2_stage11_lifecycle')


def collect_records(value, path='$'):
    """Keep complete records and paths; never infer a verdict from key presence."""
    if isinstance(value, dict):
        keys = {'authorityIdentity', 'effectRelationIdentity', 'executionIdentity',
                'sourceObservationIdentity', 'targetObservationIdentity',
                'executionDisposition', 'evidenceProductionDisposition'}
        if keys.intersection(value):
            yield {'jsonPath': path, 'record': value}
        for key, child in value.items():
            yield from collect_records(child, path + '.' + key)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from collect_records(child, f'{path}[{index}]')


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--suite', type=Path, required=True)
    parser.add_argument('--frontend', type=Path, required=True)
    parser.add_argument('--clang10', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ)
    env['PYTHONPATH'] = str(repo / 'pytools') + os.pathsep + env.get('PYTHONPATH', '')
    steps = []

    def run(name, command):
        with (output / (name + '.log')).open('w') as log:
            try:
                code = subprocess.run(command, cwd=repo, env=env, stdout=log,
                                      stderr=subprocess.STDOUT).returncode
            except OSError as error:
                log.write(f'{type(error).__name__}: {error}\n')
                code = 127
        steps.append({'stage': name, 'command': command, 'returnCode': code})
        return code

    clang = args.clang10.resolve()
    env['PATH'] = str(clang.parent) + os.pathsep + env.get('PATH', '')
    run('git-head', ['git', 'rev-parse', 'HEAD'])
    run('git-branch', ['git', 'branch', '--show-current'])
    run('git-status', ['git', 'status', '--porcelain'])
    run('python-module', [sys.executable, '-c',
                         'import riscv2x86_py; print(riscv2x86_py.__file__)'])
    run('clang-version', [str(clang), '--version'])
    version = (output / 'clang-version.log').read_text()
    tools_ok = (shutil.which('clang', path=env['PATH']) == str(clang)
                and re.search(r'clang version 10\.', version) is not None)
    run('static', [sys.executable, '-m', 'py_compile'] +
        [f'pytools/riscv2x86_py/{name}.py' for name in MODULES])
    run('targeted', [sys.executable, '-m', 'pytest', '-q'] +
        [f'pytools/tests/test_{name}.py' for name in TARGETS])
    run('full-python', [sys.executable, '-m', 'pytest', '-q', 'pytools/tests'])
    run('frontend-build', ['cmake', '--build', 'build', '-j2'])
    frontend = args.frontend.resolve()
    provenance = {'python': sys.executable, 'clang': str(clang),
                  'suite': str(args.suite.resolve()), 'frontend': str(frontend)}
    if frontend.is_file():
        provenance.update(frontendSha256=hashlib.sha256(frontend.read_bytes()).hexdigest(),
                          frontendMtimeNs=frontend.stat().st_mtime_ns)
    blockers = [step['stage'] for step in steps if step['returnCode']]
    if not tools_ok:
        blockers.append('clang10-selection')
    if not args.suite.is_dir() or not frontend.is_file():
        blockers.append('suite-or-frontend-missing')
    batch_status = None
    if not blockers:
        batch_status = run('generated-suite', [sys.executable, '-m',
            'riscv2x86_py.automatic_batch_cli', '--input', str(args.suite.resolve()),
            '--frontend', str(frontend), '--output-directory', str(output / 'strict'),
            '--jobs', '1', '--timeout-seconds', '120'])
        batch = output / 'strict/batch-evaluation.json'
        if batch.exists():
            data = json.loads(batch.read_text())
            (output / 'summary.json').write_text(json.dumps({key: data.get(key) for key in
                ('batchIdentity', 'caseCount', 'statusCounts', 'programValidationCounts',
                 'reasonCodeCounts', 'translationOutcomeCounts', 'l2CoverageDiagnostics')}, indent=2))
            with (output / 'evidence-records.jsonl').open('w') as stream:
                for artifact in sorted((output / 'strict/cases').rglob('*.json')):
                    try:
                        records = collect_records(json.loads(artifact.read_text()))
                        for record in records:
                            stream.write(json.dumps({'artifact': str(artifact), **record}) + '\n')
                    except (ValueError, UnicodeError) as error:
                        stream.write(json.dumps({'artifact': str(artifact), 'parseError': str(error)}) + '\n')
        else:
            blockers.append('batch-artifact-missing')
    (output / 'run-status.json').write_text(json.dumps({
        'provenance': provenance, 'steps': steps, 'blockers': blockers,
        'generatedSuiteExecuted': batch_status is not None,
        'generatedSuiteExitCode': batch_status}, indent=2))
    return 1 if blockers else (batch_status or 0)


if __name__ == '__main__':
    sys.exit(main())
