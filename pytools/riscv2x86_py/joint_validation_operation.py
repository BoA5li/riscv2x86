"""Successful replay reuse inside one evaluation or independent joint audit.

Every registered computation is checked on first use and before successful
return. Closing has a fresh dependency epoch and cannot consume initial trust.
Member and file checks remain at their original sites. No cached trust persists.
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
_leaf_epoch=ContextVar('rv2x86_joint_validation_leaf_epoch',default=None)


def current():
    value=_active.get()
    if value is not None and (value.pid!=os.getpid() or value.thread!=threading.get_ident()):return None
    return value


class JointValidationOperation:
    def __init__(self,name):
        self.name=name;self.pid=os.getpid();self.thread=threading.get_ident()
        self.entries={};self.leaves={};self.closed=False;self.entered=False

    def __enter__(self):
        if self.entered:raise ValueError('JOINT_OPERATION_ALREADY_ENTERED')
        mode=os.environ.get('RV2X86_JOINT_OPERATION_REUSE','1')
        if mode not in {'0','1'}:raise ValueError('JOINT_OPERATION_REUSE_MODE_INVALID')
        self.entered=True
        self.token=_active.set(self if mode=='1' else None)
        from .joint_performance import enabled
        try:self.leaf_token=_leaf_epoch.set((self,{}) if mode=='1' and enabled() else None)
        except Exception:
            _active.reset(self.token);raise
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
        from .joint_performance import enabled
        leaf_token=_leaf_epoch.set((self,{}) if enabled() else None)
        try:
            for computation,value,expected in self.entries.values():
                actual=computation(deepcopy(value))
                require_json_match(expected,actual,'JOINT_OPERATION_CLOSING_REPLAY_CHANGED')
            # Each initial leaf is checked in the fresh closing epoch even if
            # no root happens to request it on that traversal. No initial hit.
            for computation,value,expected in self.leaves.values():
                actual=leaf_checked(computation,deepcopy(value))
                require_json_match(expected,actual,'JOINT_OPERATION_LEAF_REPLAY_CHANGED')
        finally:
            _leaf_epoch.reset(leaf_token);_active.reset(token)

    def __exit__(self,kind,value,traceback):
        self.closed=True
        try:
            if kind is None:self.close()
        finally:
            self.entries.clear();self.leaves.clear();_leaf_epoch.reset(self.leaf_token);_active.reset(self.token)


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


def leaf_checked(computation,value):
    """Validated dependency result shared only within one initial/final epoch.

    Root checks still execute on closing; only identical dependency nodes in
    THAT fresh traversal share work. Outside an operation no reuse is possible.
    """
    epoch=_leaf_epoch.get()
    if epoch is None:return computation(value)
    owner,memo=epoch
    if owner.pid!=os.getpid() or owner.thread!=threading.get_ident():return computation(value)
    require_json_document(value,'JOINT_OPERATION_LEAF_INPUT_NOT_JSON')
    key=(computation,json.dumps(value,sort_keys=True,separators=(',',':')))
    if key not in memo:
        original=deepcopy(value);result=computation(deepcopy(original))
        require_json_document(result,'JOINT_OPERATION_LEAF_RESULT_NOT_JSON')
        memo[key]=(computation,original,deepcopy(result))
        if not owner.closed:owner.leaves[key]=memo[key]
    return deepcopy(memo[key][2])


def leaf_epoch_active():
    epoch=_leaf_epoch.get()
    return epoch is not None and epoch[0].pid==os.getpid() and epoch[0].thread==threading.get_ident()
