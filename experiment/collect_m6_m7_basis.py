"""Read-only host evidence inventory; never environment or L3 approval.

Only explicitly supplied JSON files are read. No backend is executed, no package
is installed, and no environment variable dump or recursive result scan occurs.
Run from the repository with PYTHONPATH=pytools and retain the original files.
"""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess


def command(argv):
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
        return {'command': argv, 'returnCode': done.returncode,
                'stdout': done.stdout[:8000], 'stderr': done.stderr[:4000]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'command': argv, 'error': type(exc).__name__ + ': ' + str(exc)}


def read_json(path):
    path = Path(path).resolve()
    before = path.read_bytes()
    value = json.loads(before)
    if not isinstance(value, dict):
        raise ValueError('JSON object required: ' + str(path))
    if path.read_bytes() != before:
        raise ValueError('Input changed during collection: ' + str(path))
    return {'path': str(path), 'digest': 'sha256:' + sha256(before).hexdigest()}, value


def backend_record(path):
    record, value = read_json(path)
    keys = ('schemaVersion', 'backendIdentity', 'buildIdentity', 'profile', 'supportDomain',
            'executionProfile', 'semanticApproval', 'productionAcceptanceComplete',
            'sourceCompiler', 'targetCompiler', 'qemuBinary', 'sourceExecutor', 'targetExecutor')
    record['declaredFields'] = {k: value[k] for k in keys if k in value}
    record['formalBackendValidationPerformed'] = False
    return record


def evaluation_record(path):
    record, value = read_json(path)
    record.update(status=value.get('status'), reasonCodes=value.get('reasonCodes'), attempts=[])
    for attempt in value.get('attempts', []):
        layers = []
        for layer in (attempt.get('validation') or {}).get('layers', []):
            detail = layer.get('detail')
            try:
                detail = json.loads(detail) if isinstance(detail, str) else detail
            except ValueError:
                detail = None
            layers.append({'level': layer.get('level'), 'status': layer.get('status'),
                'evidenceIdentity': layer.get('evidenceIdentity'),
                'detailSchema': detail.get('schemaVersion') if isinstance(detail, dict) else None,
                'detailReasonCodes': detail.get('reasonCodes') if isinstance(detail, dict) else None})
        record['attempts'].append({'fragmentId': attempt.get('fragmentId'),
            'translationOutcome': attempt.get('translationOutcome'), 'layers': layers})
    record['independentAuditPerformed'] = False
    return record


def collect(*, repository, backends=(), evaluations=()):
    repository = Path(repository).resolve()
    tools = {}
    for name in ('clang', 'gcc', 'riscv64-linux-gnu-gcc', 'qemu-riscv64', 'qemu-system-riscv64'):
        selected = (os.environ.get('RV2X86_SYSTEM_CLANG') if name == 'clang' else
                    os.environ.get('RV2X86_TEST_RISCV_CC') if name == 'riscv64-linux-gnu-gcc' else None)
        executable = shutil.which(selected or name)
        tools[name] = {'available': executable is not None}
        if executable:
            path = Path(executable).resolve()
            tools[name].update(path=str(path), digest='sha256:' + sha256(path.read_bytes()).hexdigest(),
                               version=command([str(path), '--version']))
    result = {'schemaVersion': 'riscv2x86.m6-m7-host-basis.v1',
        'repository': str(repository), 'system': platform.system(), 'machine': platform.machine(),
        'pythonVersion': platform.python_version(), 'libc': list(platform.libc_ver()),
        'affinity': sorted(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else None,
        'head': command(['git', '-C', str(repository), 'rev-parse', 'HEAD']),
        'sourceChanges': command(['git', '-C', str(repository), 'diff', '--name-only', 'HEAD',
                                  '--', 'src', 'include', 'pytools', 'runtime', 'experiment']),
        'tools': tools, 'backends': [], 'evaluations': [], 'errors': [],
        'semanticApproval': False, 'executionPerformed': False,
        'productionAcceptanceComplete': False,
        'note': 'File/host inventory only. Recorded verified labels are not replayed acceptance.'}
    for category, paths, reader in (('backends', backends, backend_record),
                                     ('evaluations', evaluations, evaluation_record)):
        for path in paths:
            try:
                result[category].append(reader(path))
            except (OSError, ValueError, TypeError, KeyError) as exc:
                result['errors'].append({'category': category, 'path': str(path),
                                         'detail': type(exc).__name__ + ': ' + str(exc)})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument('--backend', action='append', default=[])
    parser.add_argument('--evaluation', action='append', default=[])
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    result = collect(repository=args.repository, backends=args.backend, evaluations=args.evaluation)
    with Path(args.output).open('x', encoding='utf-8') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
    print(json.dumps({'output': args.output, 'backendCount': len(result['backends']),
        'evaluationCount': len(result['evaluations']), 'errors': result['errors'],
        'semanticApproval': False, 'productionAcceptanceComplete': False}))
    return 2 if result['errors'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
