"""Operation-local backend reuse with mandatory uncached closing validation.

Only successful checks are reused. No session survives a selection load, capture,
or audit. Closing checks replay the original validators (including transitive
file, toolchain and calibration checks); a cache hit never grants lasting trust.
"""
from copy import deepcopy
from pathlib import Path
import json
import time
from hashlib import sha256


class BackendValidationSession:
    def __init__(self, progress=None):
        self._entries = {}
        self._closed = False
        self.progress = progress or (lambda event: None)

    def __enter__(self):
        return self

    def check(self, validator, value, *, nested=False):
        if self._closed:
            raise ValueError('L3_BACKEND_VALIDATION_SESSION_CLOSED')
        if isinstance(value, (str, Path)):
            original = str(Path(value).resolve())
            binding = original + ':' + sha256(Path(original).read_bytes()).hexdigest()
        else:
            original = deepcopy(value)
            binding = json.dumps(original, sort_keys=True, separators=(',', ':'))
        key = (validator, binding)
        if key not in self._entries:
            start = time.monotonic()
            label = validator.__module__ + '.' + validator.__name__
            self.progress({'stage': 'backend-validation', 'validator': label, 'state': 'started'})
            result = validator(original, _context=self) if nested else validator(original)
            self._entries[key] = (validator, original, deepcopy(result))
            self.progress({'stage': 'backend-validation', 'validator': label, 'state': 'complete',
                           'elapsedSeconds': time.monotonic() - start})
        return deepcopy(self._entries[key][2])

    def __exit__(self, kind, value, traceback):
        self._closed = True
        try:
            if kind is None:
                # No context is passed: every closing check is fully uncached.
                for validator, original, expected in self._entries.values():
                    label = validator.__module__ + '.' + validator.__name__
                    self.progress({'stage': 'backend-revalidation', 'validator': label, 'state': 'started'})
                    start = time.monotonic()
                    if validator(original) != expected:
                        raise ValueError("L3_BACKEND_VALIDATION_RESULT_CHANGED:" + label)
                    self.progress({'stage': 'backend-revalidation', 'validator': label, 'state': 'complete',
                                   'elapsedSeconds': time.monotonic() - start})
        finally:
            self._entries.clear()


def checked(context, validator, value, *, nested=False):
    return (context.check(validator, value, nested=nested) if context is not None
            else validator(value))
