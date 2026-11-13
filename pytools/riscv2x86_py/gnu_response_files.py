"""Bounded, strict-subset GNU/libiberty response-file expansion.

Independent parser for balanced quotes/backslash escaping and ASCII whitespace;
no shell, environment substitution or current-file reads during replay. Nested
paths are relative to the invocation cwd, as expandargv's fopen(arg+1) is.
Malformed quoting/NUL/non-UTF8, missing files, cycles and budgets reject authority.
Capture may still execute the original native command as unsupported evidence.
"""
import os
from pathlib import Path

from .native_dependency_evidence import bytes_digest
from .project_build_records import identity

POLICY='riscv2x86.gnu-response-frozen-argv.v1'
LIMITS={'depth':16,'files':128,'bytes':4*1024*1024,'arguments':65536}


def tokens(raw):
    if b'\0' in raw:raise ValueError('RESPONSE_NUL_UNSUPPORTED')
    try:text=raw.decode('utf-8')
    except UnicodeDecodeError as exc:raise ValueError('RESPONSE_UTF8_REQUIRED') from exc
    result=[];word=[];quote=None;escaped=False;started=False
    for c in text:
        if escaped:
            word.append(c);escaped=False;started=True
        elif c=='\\':escaped=True;started=True
        elif quote:
            if c==quote:quote=None
            else:word.append(c)
        elif c in ('"',"'"):quote=c;started=True
        elif c in ' \t\n\r\v\f':
            if started:result.append(''.join(word));word=[];started=False
        else:word.append(c);started=True
    if quote or escaped:raise ValueError('RESPONSE_BALANCED_QUOTING_REQUIRED')
    if started:result.append(''.join(word))
    return result


def expand(arguments,cwd,reader,*,limits=None):
    limits=dict(LIMITS if limits is None else limits)
    if set(limits)!=set(LIMITS) or any(type(v) is not int or not 1<=v<=LIMITS[k] for k,v in limits.items()):
        raise ValueError('RESPONSE_BUDGET_INVALID')
    if not isinstance(arguments,list) or any(not isinstance(a,str) or '\0' in a for a in arguments):
        raise ValueError('RESPONSE_ARGUMENT_VECTOR_INVALID')
    files=[];total=0;effective=[]
    def visit(args,stack):
        nonlocal total
        for arg in args:
            if not arg.startswith('@'):
                effective.append(arg)
                if len(effective)>limits['arguments']:raise ValueError('RESPONSE_ARGUMENT_BUDGET_EXCEEDED')
                continue
            if not arg[1:]:raise ValueError('RESPONSE_PATH_REQUIRED')
            if len(stack)>=limits['depth']:raise ValueError('RESPONSE_DEPTH_BUDGET_EXCEEDED')
            path=os.path.abspath(os.path.join(cwd,arg[1:]))
            snapshot,raw=reader(path)
            if snapshot['path']!=path or snapshot['status']!='present' or bytes_digest(raw)!=snapshot['digest']:
                raise ValueError('RESPONSE_FILE_BINDING_INVALID')
            key=snapshot['resolvedPath']
            if key in stack:raise ValueError('RESPONSE_INCLUDE_CYCLE')
            total+=len(raw)
            if total>limits['bytes'] or len(files)>=limits['files']:
                raise ValueError('RESPONSE_FILE_BUDGET_EXCEEDED')
            files.append(snapshot)
            visit(tokens(raw),[*stack,key])
    visit(arguments,[])
    body={'schemaVersion':POLICY,'directory':cwd,'originalArguments':arguments,
          'effectiveArguments':effective,'files':files,'limits':limits,
          'executionMode':'frozen-effective-argv'}
    return dict(body,responseExpansionIdentity=identity(body))


def capture(directory,arguments,cwd):
    from .project_archive_provenance import _blob
    import stat
    def reader(path):
        try:
            fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
            with os.fdopen(fd,'rb') as stream:
                first=os.fstat(stream.fileno());resolved=str(Path(path).resolve(strict=True))
                if not stat.S_ISREG(first.st_mode):raise ValueError('RESPONSE_REGULAR_FILE_REQUIRED')
                raw=stream.read(LIMITS['bytes']+1);last=os.fstat(stream.fileno())
            if len(raw)>LIMITS['bytes']:raise ValueError('RESPONSE_FILE_BUDGET_EXCEEDED')
            fields=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
            if (any(getattr(first,k)!=getattr(last,k) for k in fields)
                    or (Path(path).stat().st_dev,Path(path).stat().st_ino)!=(last.st_dev,last.st_ino)
                    or str(Path(path).resolve(strict=True))!=resolved):
                raise ValueError('RESPONSE_FILE_CHANGED')
            row={'path':path,'resolvedPath':resolved,'status':'present','digest':_blob(directory,raw)}
        except OSError as exc:raise ValueError('RESPONSE_FILE_UNAVAILABLE') from exc
        return row,raw
    return expand(list(arguments),cwd,reader)


def replay(directory,evidence,arguments,cwd):
    if (not isinstance(evidence,dict) or evidence.get('schemaVersion')!=POLICY
            or evidence.get('responseExpansionIdentity')!=identity({k:v for k,v in evidence.items() if k!='responseExpansionIdentity'})
            or evidence['originalArguments']!=arguments or evidence['directory']!=cwd):
        raise ValueError('RESPONSE_EXPANSION_BINDING_INVALID')
    pending=iter(evidence['files'])
    def reader(path):
        try:row=next(pending)
        except StopIteration as exc:raise ValueError('RESPONSE_FILE_EVIDENCE_MISSING') from exc
        if row['path']!=path:raise ValueError('RESPONSE_FILE_ORDER_INVALID')
        sha=row.get('digest')
        if (not isinstance(sha,str) or len(sha)!=71 or not sha.startswith('sha256:')
                or any(c not in '0123456789abcdef' for c in sha[7:])):
            raise ValueError('RESPONSE_BLOB_DIGEST_INVALID')
        with (Path(directory)/'archive-blobs'/sha[7:]).open('rb') as stream:
            raw=stream.read(LIMITS['bytes']+1)
        if len(raw)>LIMITS['bytes'] or bytes_digest(raw)!=sha:
            raise ValueError('RESPONSE_BLOB_CHANGED_OR_BUDGET_EXCEEDED')
        return row,raw
    fresh=expand(arguments,cwd,reader,limits=evidence['limits'])
    if next(pending,None) is not None or fresh!=evidence:
        raise ValueError('RESPONSE_EXPANSION_REDERIVATION_MISMATCH')
    return fresh['effectiveArguments']
