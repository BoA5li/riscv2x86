"""Mutable diagnostic checkpoints, separate from immutable semantic evidence.

One process owns a fresh run directory. Atomic replacement prevents partial JSON;
this is not a concurrent-writer or power-loss recovery protocol.
"""
import json
import os
from pathlib import Path
import sys
import tempfile


def write_status_atomic(path, value):
    path = Path(path)
    payload = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                                         prefix='.' + path.name + '.', suffix='.tmp',
                                         dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError as cleanup_error:
                print('L3_STATUS_TEMP_CLEANUP_FAILED: ' + str(cleanup_error), file=sys.stderr)
    return path


def record_failure(path, status, error, *, stage_key='stage', completion_keys=('complete',)):
    """Best-effort failure checkpoint; caller retains and propagates primary error."""
    status.update(status='failed', failedStage=status.get(stage_key),
                  errorType=type(error).__name__, error=str(error))
    for key in completion_keys:
        status[key] = False
    try:
        write_status_atomic(path, status)
    except Exception as checkpoint_error:
        print('L3_PRIMARY_FAILURE: ' + type(error).__name__ + ': ' + str(error), file=sys.stderr)
        print('L3_STATUS_WRITE_FAILED: ' + type(checkpoint_error).__name__ + ': ' + str(checkpoint_error), file=sys.stderr)
        return False
    return True
