"""Native-compiler-derived inspection header search, never compiler equivalence.

Mirror reported search directories explicitly; do not guess a sysroot from GCC
installation names, mix in host multiarch headers or edit the native recipe.
Actual dependency snapshots and exact CPP comparison remain required.
"""
import json
import os
from pathlib import Path
import subprocess

from .project_build_records import identity
from .project_compile_context import digest, ENV_KEYS

SCHEMA = 'riscv2x86.project-native-header-search.v1'
PROFILE_SCHEMA = 'riscv2x86.project-header-contexts.v1'
PROFILE_ENV = 'RV2X86_PROJECT_HEADER_CONTEXTS'


def parse_search(text, cwd):
    quote = '#include "..." search starts here:'
    angle = '#include <...> search starts here:'
    end = 'End of search list.'
    lines = text.splitlines()
    if any(lines.count(marker) != 1 for marker in (quote, angle, end)):
        raise ValueError('PROJECT_HEADER_SEARCH_PROTOCOL_INVALID')
    q, a, e = (lines.index(marker) for marker in (quote, angle, end))
    if not q < a < e:
        raise ValueError('PROJECT_HEADER_SEARCH_PROTOCOL_ORDER_INVALID')
    rows=[]
    for kind, section in (('quote', lines[q+1:a]), ('angle', lines[a+1:e])):
        for line in section:
            if not line.startswith(' ') or not line.strip() or line.endswith('(framework directory)'):
                raise ValueError('PROJECT_HEADER_SEARCH_ENTRY_UNSUPPORTED:'+line)
            value=line.strip(); path=Path(value)
            if not path.is_absolute(): path=Path(cwd)/path
            resolved=path.resolve(strict=True)
            if not resolved.is_dir(): raise ValueError('PROJECT_HEADER_SEARCH_DIRECTORY_REQUIRED:'+value)
            rows.append({'kind':kind,'compilerPath':value,'resolvedPath':str(resolved)})
    return rows


def query(compiler, arguments, cwd, *, timeout=60):
    cwd=Path(cwd).resolve(strict=True); compiler=Path(compiler).resolve(strict=True)
    before=digest(compiler)
    environment={key:os.environ.get(key,'') for key in ENV_KEYS}
    # Fix diagnostic language only, and record that choice explicitly.
    env=dict(os.environ, LC_ALL='C', LANG='C')
    command=[str(compiler),*arguments,'-E','-v','-x','c','-']
    result=subprocess.run(command,cwd=cwd,env=env,input='',capture_output=True,text=True,timeout=timeout,check=False)
    if result.returncode:
        raise ValueError('PROJECT_NATIVE_HEADER_PROBE_FAILED:'+result.stderr[-6000:])
    rows=parse_search(result.stderr,cwd)
    if before!=digest(compiler) or environment!={k:os.environ.get(k,'') for k in ENV_KEYS}:
        raise ValueError('PROJECT_NATIVE_HEADER_PROBE_CHANGED')
    return {'command':command,'compilerDigest':before,'workingDirectory':str(cwd),
            'searchEnvironment':environment,'diagnosticLocale':'C','directories':rows}


def projection(receipt):
    # Explicit original -I/-iquote/-isystem options are retained, preserving
    # their spelling/category and priority. CPATH remains a non-system search
    # path from the unchanged environment. C_INCLUDE_PATH must be mirrored
    # explicitly before builtin paths: its automatic position would otherwise
    # follow the newly supplied -isystem directories.
    args=receipt['inspectionArguments']; cwd=Path(receipt['probe']['workingDirectory'])
    explicit=set(); i=0
    while i<len(args):
        arg=args[i]; value=None
        if arg in ('-I','-isystem','-iquote'):
            i+=1
            if i>=len(args):raise ValueError('PROJECT_HEADER_ARGUMENT_INCOMPLETE')
            value=args[i]
        else:
            for prefix in ('-isystem','-iquote','-I'):
                if arg.startswith(prefix) and len(arg)>len(prefix):value=arg[len(prefix):];break
        if value is not None:
            p=Path(value);explicit.add(('quote' if arg.startswith('-iquote') else 'angle',str((p if p.is_absolute() else cwd/p).resolve())))
        i+=1
    for key in ('CPATH',):
        value=receipt['probe']['searchEnvironment'].get(key,'')
        if value:
            for part in value.split(os.pathsep):
                p=Path(part or '.');explicit.add(('angle',str((p if p.is_absolute() else cwd/p).resolve())))
    result=['-nostdinc'];seen=set()
    for row in receipt['probe']['directories']:
        p=row['resolvedPath']
        if (row['kind'],p) in explicit or (row['kind'],p) in seen:continue
        seen.add((row['kind'],p))
        result.extend(['-iquote' if row['kind']=='quote' else '-isystem',p])
    return result


def acquire(context, *, timeout=60):
    from .project_compile_context import validate
    from .project_build_contract import source_arguments
    validate(context)
    if not context['inspectionReady']:raise ValueError('PROJECT_HEADER_CONTEXT_NOT_READY')
    arguments=source_arguments(context)
    probe=query(context['nativeCompiler'],arguments,context['workingDirectory'],timeout=timeout)
    body={'schemaVersion':SCHEMA,'contextIdentity':context['contextIdentity'],
          'sourcePath':context['sourcePath'],'sourceDigest':context['sourceDigest'],
          'nativeCompiler':context['nativeCompiler'],'nativeArguments':arguments,
          'inspectionArguments':context['inspectionArguments'],'probe':probe,
          'compilerEquivalenceVerified':False,'semanticApproval':False,'productionAcceptanceComplete':False}
    return dict(body,headerSearchIdentity=identity(body))


def validate(receipt, *, context=None, timeout=60):
    fields={'schemaVersion','contextIdentity','sourcePath','sourceDigest','nativeCompiler','nativeArguments',
            'inspectionArguments','probe','compilerEquivalenceVerified','semanticApproval',
            'productionAcceptanceComplete','headerSearchIdentity'}
    if (not isinstance(receipt,dict) or set(receipt)!=fields or receipt['schemaVersion']!=SCHEMA
            or receipt['headerSearchIdentity']!=identity({k:v for k,v in receipt.items() if k!='headerSearchIdentity'})
            or any(receipt[k] is not False for k in ('compilerEquivalenceVerified','semanticApproval','productionAcceptanceComplete'))):
        raise ValueError('PROJECT_HEADER_RECEIPT_INVALID')
    if digest(receipt['sourcePath'])!=receipt['sourceDigest']:
        raise ValueError('PROJECT_HEADER_SOURCE_CHANGED')
    from .project_build_contract import compiler_profile
    # A rehashed receipt cannot inject action outputs, plugins or a second input
    # into the native compiler probe. Reuse the closed project option grammar.
    compiler_profile(receipt['nativeCompiler'],receipt['nativeArguments'],receipt['probe']['workingDirectory'],source=receipt['sourcePath'])
    if context is not None:
        from .project_build_contract import source_arguments
        from .project_compile_context import validate as validate_context
        validate_context(context)
        if (receipt['contextIdentity']!=context['contextIdentity'] or receipt['sourcePath']!=context['sourcePath']
                or receipt['sourceDigest']!=context['sourceDigest'] or receipt['nativeCompiler']!=context['nativeCompiler']
                or receipt['nativeArguments']!=source_arguments(context)
                or receipt['inspectionArguments']!=context['inspectionArguments']
                or receipt['probe']['workingDirectory']!=context['workingDirectory']):
            raise ValueError('PROJECT_HEADER_CONTEXT_BINDING_MISMATCH')
    fresh=query(receipt['nativeCompiler'],receipt['nativeArguments'],receipt['probe']['workingDirectory'],timeout=timeout)
    if identity(fresh)!=identity(receipt['probe']):raise ValueError('PROJECT_HEADER_SEARCH_REPLAY_MISMATCH')
    if context is not None:
        other=acquire(context,timeout=timeout)
        if identity(other)!=identity(receipt):raise ValueError('PROJECT_HEADER_CONTEXT_BINDING_MISMATCH')
    return receipt


def configured_context(source, args, cwd):
    """Explicit opt-in for legacy project consumers without a context argument.

    Exact command/source selection, never a global directory injection. No
    matching entry is an error; it must not fall back to host search paths.
    """
    from .project_validation_operation import active
    contract=active()
    if contract is not None:
        context=contract['sourceContext']
        if (context['sourcePath']!=str(Path(source).resolve()) or context['inspectionArguments']!=list(args)
                or context['workingDirectory']!=str(Path(cwd).resolve())):
            raise ValueError('PROJECT_HEADER_ACTIVE_CONTEXT_MISMATCH')
        return context
    path=os.environ.get(PROFILE_ENV)
    if not path:return None
    value=json.loads(Path(path).read_text())
    if (set(value)!= {'schemaVersion','contexts','profileIdentity'} or value['schemaVersion']!=PROFILE_SCHEMA
            or value['profileIdentity']!=identity({k:v for k,v in value.items() if k!='profileIdentity'})):
        raise ValueError('PROJECT_HEADER_CONTEXT_PROFILE_INVALID')
    matches=[c for c in value['contexts'] if c.get('sourcePath')==str(Path(source).resolve())
             and c.get('inspectionArguments')==list(args) and c.get('workingDirectory')==str(Path(cwd).resolve())]
    if not matches:raise ValueError('PROJECT_HEADER_CONTEXT_PROFILE_MATCH_REQUIRED')
    if len({c['contextIdentity'] for c in matches})!=1:raise ValueError('PROJECT_HEADER_CONTEXT_PROFILE_AMBIGUOUS')
    return matches[0]


def inspect_search(receipt, clang, target, *, timeout=60):
    arguments=['--target='+target+'-linux-gnu','-std=gnu11',*receipt['inspectionArguments'],*projection(receipt)]
    result=query(clang,arguments,receipt['probe']['workingDirectory'],timeout=timeout)
    def keys(probe):return [(row['kind'],row['resolvedPath']) for row in probe['directories']]
    if keys(result)!=keys(receipt['probe']):
        raise ValueError('PROJECT_INSPECTION_HEADER_ORDER_MISMATCH:'+json.dumps({
            'native':keys(receipt['probe']),'inspection':keys(result)}))
    return result
