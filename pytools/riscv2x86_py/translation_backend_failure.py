"""Executed-backend diagnostics; never approval or a fabricated attempt archive."""
from hashlib import sha256
import json
from pathlib import Path


def digest(raw):
    return 'sha256:' + sha256(raw).hexdigest()


def write_failure(report, source, command, backend_command, completed):
    report = Path(report).resolve()
    source = Path(source).resolve()
    payload = {
        'schemaVersion': 'riscv2x86.translation-backend-failure.v1',
        'backendExecuted': True, 'semanticApproval': False,
        'sourcePath': str(source), 'sourceDigest': digest(source.read_bytes()),
        'command': list(command), 'backendCommand': list(backend_command),
        'returnCode': completed.returncode, 'failureStage': 'backend_execution',
        'stdoutDigest': digest(completed.stdout.encode('utf-8')),
        'stderrDigest': digest(completed.stderr.encode('utf-8')),
        'stderr': completed.stderr,
        'artifacts': {suffix: Path(str(report) + suffix).is_file()
                      for suffix in ('', '.attempts.json')},
    }
    detail = Path(str(report) + '.pipeline-failure.json')
    payload['pipelineFailure'] = (json.loads(detail.read_text(encoding='utf-8'))
                                  if detail.is_file() else None)
    payload['diagnosticIdentity'] = digest(json.dumps(
        payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode())
    with Path(str(report) + '.backend-failure.json').open('x', encoding='utf-8') as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2)


def read_failure(report, source, command, returncode=None):
    report = Path(report).resolve()
    data = json.loads(Path(str(report) + '.backend-failure.json').read_text(encoding='utf-8'))
    fields = {'schemaVersion', 'backendExecuted', 'semanticApproval', 'sourcePath',
              'sourceDigest', 'command', 'backendCommand', 'returnCode', 'failureStage',
              'stdoutDigest', 'stderrDigest', 'stderr', 'artifacts', 'pipelineFailure',
              'diagnosticIdentity'}
    if (not isinstance(data, dict) or set(data) != fields
            or any(not isinstance(data[k], str) for k in ('sourcePath', 'sourceDigest',
                'stdoutDigest', 'stderrDigest', 'stderr', 'diagnosticIdentity'))
            or any(not isinstance(data[k], list) or not data[k]
                   or any(not isinstance(v, str) for v in data[k]) for k in ('command','backendCommand'))
            or data['artifacts'] != {suffix: Path(str(report)+suffix).is_file()
                                     for suffix in ('', '.attempts.json')}
            or data['failureStage'] != 'backend_execution'
            or (returncode is not None and data['returnCode'] != returncode)):
        raise ValueError('backend failure diagnostic structure is invalid')
    identity = data.pop('diagnosticIdentity')
    if (identity != digest(json.dumps(data, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False).encode())
            or data['schemaVersion'] != 'riscv2x86.translation-backend-failure.v1'
            or data['backendExecuted'] is not True or data['semanticApproval'] is not False
            or data['sourcePath'] != str(Path(source).resolve())
            or data['sourceDigest'] != digest(Path(source).read_bytes())
            or data['command'] != list(command)
            or type(data['returnCode']) is not int or data['returnCode'] == 0
            or data['stdoutDigest'] != digest((report.parent/'backend.stdout').read_bytes())
            or data['stderrDigest'] != digest((report.parent/'backend.stderr').read_bytes())
            or data['stderrDigest'] != digest(data['stderr'].encode('utf-8'))):
        raise ValueError('backend failure diagnostic binding is invalid')
    data['diagnosticIdentity'] = identity
    return data
