"""Successful replay reuse inside one evaluation or independent joint audit.

Every registered computation runs afresh on entry and again, without ANY
operation reuse, before a successful operation returns. Member checks and file
checks remain at their original sites. Nothing is persisted as cached trust.
Set RV2X86_JOINT_OPERATION_REUSE=0 for a same-code, same-domain full-work control.
"""
from contextvars import ContextVar
from copy import deepcopy
from functools import wraps
import json
import os
import threading
from .l3_trace_support import require_json_document,require_json_match
from .validation_timing import timed

_active=ContextVar('rv2x86_joint_validation_operation',default=None)


def current():
    value=_active.get()
    if value is not None and (value.pid!=os.getpid() or value.thread!=threading.get_ident()):return None
    return value


class JointValidationOperation:
    def __init__(self,name):
        self.name=name;self.pid=os.getpid();self.thread=threading.get_ident()
        self.entries={};self.closed=False;self.entered=False

    def __enter__(self):
        if self.entered:raise ValueError('JOINT_OPERATION_ALREADY_ENTERED')
        mode=os.environ.get('RV2X86_JOINT_OPERATION_REUSE','1')
        if mode not in {'0','1'}:raise ValueError('JOINT_OPERATION_REUSE_MODE_INVALID')
        self.entered=True
        self.token=_active.set(self if mode=='1' else None)
        return self

    def check(self,computation,value):
        if self.closed or not self.entered or current() is not self:
            raise ValueError('JOINT_OPERATION_CLOSED_OR_FOREIGN')
        require_json_document(value,'JOINT_OPERATION_INPUT_NOT_JSON')
        key=(computation,json.dumps(value,sort_keys=True,separators=(',',':')))
        if key not in self.entries:
            original=deepcopy(value);result=computation(deepcopy(original))
            require_json_document(result,'JOINT_OPERATION_RESULT_NOT_JSON')
            self.entries[key]=(computation,original,deepcopy(result))
        return deepcopy(self.entries[key][2])

    @timed('joint.operation-closing-replay')
    def close(self):
        # A closing checker must not consume the initial cache or an outer
        # production operation's entries. Nested independent audits stay fresh.
        token=_active.set(None)
        try:
            for computation,value,expected in self.entries.values():
                actual=computation(deepcopy(value))
                require_json_match(expected,actual,'JOINT_OPERATION_CLOSING_REPLAY_CHANGED')
        finally:_active.reset(token)

    def __exit__(self,kind,value,traceback):
        self.closed=True
        try:
            if kind is None:self.close()
        finally:
            self.entries.clear();_active.reset(self.token)


def operation(name):
    def decorate(function):
        @wraps(function)
        def wrapped(*args,**kwargs):
            with JointValidationOperation(name):
                return function(*args,**kwargs)
        return wrapped
    return decorate


def checked(computation,value):
    scope=current()
    return scope.check(computation,value) if scope is not None else computation(value)


def _check_files(files):
    from .l3_trace_support import digest
    for path,sha in files.items():
        if digest(path)!=sha:raise ValueError('JOINT_OPERATION_FILE_CHANGED:'+path)
    return files


def watch_files(files):
    # Immediate checks remain at EVERY ingress, including after a cache hit.
    _check_files(files)
    if current() is not None:checked(_check_files,files)
