"""Content-bound command failures before a backend attempt exists."""
from hashlib import sha256
import json
from pathlib import Path

from .requirement_staging import atomic_json

SCHEMA = 'riscv2x86.translation-preflight-result.v1'



class PreflightToolFailure(ValueError):
    def __init__(self, completed):
        super().__init__(completed.stderr or "preflight tool returned no usable artifact")
        self.diagnostics = {"command": list(completed.args),
                            "returnCode": completed.returncode,
                            "stdout": completed.stdout, "stderr": completed.stderr}

def identity(value):
    return 'sha256:' + sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                       ensure_ascii=False).encode()).hexdigest()


def write_preflight_failure(report, source, command, *, stage, reason_code, exc,
                            returncode=2, backend_executed=False):
    report, source = Path(report).resolve(), Path(source).resolve()
    value = {
        'schemaVersion': SCHEMA, 'translationReportPath': str(report),
        'sourcePath': str(source),
        'sourceDigest': 'sha256:' + sha256(source.read_bytes()).hexdigest() if source.is_file() else '',
        'commandIdentity': identity(list(command)), 'commandDisposition': 'completed',
        'preflightDisposition': 'rejected', 'failureStage': stage,
        'reasonCode': reason_code, 'exceptionType': type(exc).__name__,
        'detail': str(exc) or repr(exc), 'diagnostics': getattr(exc, 'diagnostics', {}),
        'returnCode': returncode, 'backendExecuted': backend_executed, 'complete': True,
    }
    value['failureIdentity'] = identity(value)
    atomic_json(str(report) + '.preflight.json', value)
    return value


def read_preflight_failure(report, source, command, returncode):
    path = Path(str(report) + '.preflight.json')
    value = json.loads(path.read_text(encoding='utf-8'))
    fields = {'schemaVersion', 'translationReportPath', 'sourcePath', 'sourceDigest',
              'commandIdentity', 'commandDisposition', 'preflightDisposition', 'failureStage',
              'reasonCode', 'exceptionType', 'detail', 'diagnostics', 'returnCode',
              'backendExecuted', 'complete', 'failureIdentity'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('preflight fields invalid')
    unsigned = {k:v for k,v in value.items() if k != 'failureIdentity'}
    source = Path(source).resolve()
    source_digest = 'sha256:' + sha256(source.read_bytes()).hexdigest() if source.is_file() else ''
    if (value['schemaVersion'] != SCHEMA or value['failureIdentity'] != identity(unsigned)
            or value['commandIdentity'] != identity(list(command))
            or value['translationReportPath'] != str(Path(report).resolve())
            or value['sourcePath'] != str(source) or value['sourceDigest'] != source_digest
            or value['returnCode'] != returncode or returncode <= 0
            or value['complete'] is not True or value['backendExecuted'] is not False
            or value['commandDisposition'] != 'completed' or value['preflightDisposition'] != 'rejected'
            or not isinstance(value['diagnostics'], dict)
            or any(not isinstance(value[k], str) or not value[k]
                   for k in ('failureStage', 'reasonCode', 'exceptionType', 'detail'))):
        raise ValueError('preflight identity/binding/disposition invalid')
    return {**value, 'artifactPath': str(path)}
