"""Opt-in diagnostic spans. Timing records never participate in acceptance.

Set RV2X86_VALIDATION_TIMING to an absolute JSONL path shared by the child
processes of one experiment. Each process appends one complete record per span.
These inclusive spans overlap; the inspection script reports exclusive time
separately and never calls their sum the experiment's wall time.
"""
from contextvars import ContextVar
from functools import wraps
import json
import os
from pathlib import Path
import sys
import time
from uuid import uuid4

_parent = ContextVar('rv2x86_validation_span', default=None)


def timed(stage):
    def decorate(operation):
        @wraps(operation)
        def wrapped(*args, **kwargs):
            destination = os.environ.get('RV2X86_VALIDATION_TIMING')
            if not destination:
                return operation(*args, **kwargs)
            span = uuid4().hex
            parent = _parent.get()
            token = _parent.set(span)
            start = time.perf_counter_ns()
            success = False
            try:
                result = operation(*args, **kwargs)
                success = True
                return result
            finally:
                end = time.perf_counter_ns()
                _parent.reset(token)
                record = {'schemaVersion': 'riscv2x86.validation-timing.v1',
                          'pid': os.getpid(), 'span': span, 'parent': parent,
                          'stage': stage, 'startNs': start, 'endNs': end,
                          'elapsedSeconds': (end-start)/1e9, 'returned': success}
                # Diagnostics must neither grant approval nor replace an original
                # exception. A failed logger is visible on stderr, not hidden.
                try:
                    path = Path(destination)
                    if not path.is_absolute():
                        raise ValueError('absolute timing path required')
                    data = (json.dumps(record, sort_keys=True)+'\n').encode()
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                    try:
                        if os.write(fd, data) != len(data):
                            raise OSError('short timing write')
                    finally:
                        os.close(fd)
                except (OSError, ValueError) as exc:
                    print('RV2X86_TIMING_WRITE_FAILED: '+str(exc), file=sys.stderr)
        return wrapped
    return decorate
