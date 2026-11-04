"""Compiler-emitted dependency binding for call inventories, never effect proof.

Two dependency scans surround AST acquisition; every declared file must retain
its content. This is an acquisition consistency check, not an immutable build,
link/ABI closure, arbitrary compiler plugin audit or protection from adversarial
concurrent ABA replacement. Preserve these distinctions in downstream consumers.
"""
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess

from .compiler_value_flow import identity
from .l3_trace_support import require_json_match
from .validation_timing import timed

SCHEMA = 'riscv2x86.compiler-call-dependencies.v1'


def parse_dependencies(text):
    """Parse the single fixed -MT rule, including Make escaped spaces/#/$/."""
    text = text.replace('\\\r\n', '').replace('\\\n', '')
    prefix = 'rv2x86_call_inventory:'
    if not text.startswith(prefix):
        raise ValueError('CALL_DEPENDENCY_TARGET_INVALID')
    text = text[len(prefix):]
    tokens = []; word = []; i = 0
    while i < len(text):
        c = text[i]
        if c == '\\':
            i += 1
            if i >= len(text):
                raise ValueError('CALL_DEPENDENCY_ESCAPE_INVALID')
            word.append(text[i])
        elif c == '$':
            if i+1 >= len(text) or text[i+1] != '$':
                raise ValueError('CALL_DEPENDENCY_MAKE_EXPANSION_UNSUPPORTED')
            word.append('$'); i += 1
        elif c.isspace():
            if word: tokens.append(''.join(word)); word = []
        elif c in '#:':
            raise ValueError('CALL_DEPENDENCY_RULE_AMBIGUOUS')
        else:
            word.append(c)
        i += 1
    if word: tokens.append(''.join(word))
    if not tokens:
        raise ValueError('CALL_DEPENDENCY_EMPTY')
    return sorted(set(tokens))


def _snapshot(paths, cwd):
    result = []
    for item in paths:
        lexical = Path(item) if Path(item).is_absolute() else cwd/item
        resolved = lexical.resolve(strict=True)
        if not resolved.is_file():
            raise ValueError('CALL_DEPENDENCY_REGULAR_FILE_REQUIRED')
        result.append({'compilerPath': item, 'resolvedPath': str(resolved),
                       'digest': 'sha256:'+sha256(resolved.read_bytes()).hexdigest()})
    return result


@timed('compiler.call-dependency-acquisition')
def acquire(source, *, clang, target, compile_args=(), timeout=60, working_directory=None, include_type_facts=False, include_ast=False):
    from .compiler_call_inventory import derive
    if target not in {'riscv64', 'x86_64'}:
        raise ValueError('CALL_INVENTORY_TARGET_UNSUPPORTED')
    # Diagnostic compile flags may describe preprocessing/ISA. Do not allow
    # response files, AST/output redirection, plugins or a second input to alter
    # the selected acquisition recipe without an explicit future contract.
    args = list(compile_args)
    prefixes = ('-march=', '-mabi=', '-mcpu=', '-mtune=', '-std=', '-D', '-U', '-I',
                '--sysroot=', '-isystem', '-iquote', '-include', '-imacros', '-fexcess-precision=')
    separated = {'-D','-U','-I','-isystem','-iquote','-include','-imacros'}
    from .project_compile_context import EXACT
    import re
    waiting = False
    for arg in args:
        if not isinstance(arg, str) or not arg:
            raise ValueError('CALL_DEPENDENCY_COMPILE_ARGUMENT_INVALID')
        if waiting:
            if arg.startswith(('@','-')):
                raise ValueError('CALL_DEPENDENCY_COMPILE_ARGUMENT_INVALID')
            waiting = False
        elif arg in EXACT or re.fullmatch(r'-O(?:[0-3sgz]|fast)', arg):
            pass
        elif not arg.startswith(prefixes):
            raise ValueError('CALL_DEPENDENCY_COMPILE_ARGUMENT_UNSUPPORTED:'+arg)
        else:
            waiting = arg in separated
    if waiting:
        raise ValueError('CALL_DEPENDENCY_COMPILE_ARGUMENT_INCOMPLETE')
    source = Path(source).resolve(strict=True)
    from .project_tool_resolution import resolve_executable
    compiler = resolve_executable(clang,working_directory)
    compiler_digest = 'sha256:'+sha256(compiler.read_bytes()).hexdigest()
    cwd = Path(working_directory or Path.cwd()).resolve(strict=True)
    source_bytes = source.read_bytes()
    env_keys = ('CPATH','C_INCLUDE_PATH','CPLUS_INCLUDE_PATH','SDKROOT',
                'GCC_EXEC_PREFIX','COMPILER_PATH','LIBRARY_PATH','LD_LIBRARY_PATH','LD_PRELOAD')
    environment = {key:os.environ.get(key, '') for key in env_keys}
    base = [str(compiler),'--target='+target+'-linux-gnu','-std=gnu11',*args]
    dependency_command = [*base,'-M','-MT','rv2x86_call_inventory',str(source)]
    def run(command):
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                                timeout=timeout, check=False)
        if result.returncode:
            raise ValueError('CALL_DEPENDENCY_COMPILER_FAILED:'+result.stderr[-4000:])
        return result.stdout
    dependencies = parse_dependencies(run(dependency_command))
    before = _snapshot(dependencies, cwd)
    if str(source) not in {r['resolvedPath'] for r in before}:
        raise ValueError('CALL_DEPENDENCY_SOURCE_MISSING')
    command = [*base,'-fsyntax-only','-Xclang','-ast-dump=json',str(source)]
    ast_text = run(command)
    if parse_dependencies(run(dependency_command)) != dependencies:
        raise ValueError('CALL_DEPENDENCY_SET_CHANGED')
    require_json_match(before, _snapshot(dependencies, cwd), 'CALL_DEPENDENCY_CONTENT_CHANGED')
    if (compiler_digest != 'sha256:'+sha256(compiler.read_bytes()).hexdigest()
            or environment != {k:os.environ.get(k, '') for k in env_keys}
            or source.read_bytes() != source_bytes):
        raise ValueError('CALL_DEPENDENCY_ACQUISITION_CHANGED')
    ast = json.loads(ast_text)
    inventory = derive(ast, source_path=source, source_digest='sha256:'+sha256(source_bytes).hexdigest())
    body = {'schemaVersion':SCHEMA, 'inventoryIdentity':inventory['inventoryIdentity'],
        'compilerCommand':command, 'dependencyCommand':dependency_command,
        'compilerDigest':compiler_digest, 'workingDirectory':str(cwd), 'searchEnvironment':environment,
        'dependencies':before, 'acquisitionConsistent':True,
        'linkClosureVerified':False, 'immutableSnapshot':False,
        'semanticApproval':False, 'productionAcceptanceComplete':False}
    manifest = dict(body, dependencyIdentity=identity(body))
    result = {'inventory':inventory, 'compilerCommand':command, 'compilerDigest':compiler_digest,
        'astDigest':identity(ast), 'dependencyClosureVerified':False,
        'dependencyManifest':manifest, 'semanticApproval':False}
    if include_type_facts:
        from .compiler_function_types import derive as derive_types
        result['functionTypeInventory'] = derive_types(ast, source_path=source,
            dependency_identity=manifest['dependencyIdentity'], target=target)
    if include_ast:
        result['ast']=ast
    return result


@timed('compiler.call-dependency-replay')
def validate(manifest):
    """Recheck recorded bytes, paths and compiler; never manufacture approval."""
    fields = {'schemaVersion','inventoryIdentity','compilerCommand','dependencyCommand','compilerDigest',
        'workingDirectory','searchEnvironment','dependencies','acquisitionConsistent','linkClosureVerified',
        'immutableSnapshot','semanticApproval','productionAcceptanceComplete','dependencyIdentity'}
    if (not isinstance(manifest, dict) or set(manifest) != fields or manifest['schemaVersion'] != SCHEMA
            or manifest['acquisitionConsistent'] is not True
            or any(manifest[k] is not False for k in ('linkClosureVerified','immutableSnapshot',
                                                     'semanticApproval','productionAcceptanceComplete'))
            or manifest['dependencyIdentity'] != identity({k:v for k,v in manifest.items() if k != 'dependencyIdentity'})):
        raise ValueError('CALL_DEPENDENCY_MANIFEST_INVALID')
    cwd = Path(manifest['workingDirectory'])
    rows = manifest['dependencies']
    if not isinstance(rows, list) or not rows or any(set(r) != {'compilerPath','resolvedPath','digest'} for r in rows):
        raise ValueError('CALL_DEPENDENCY_RECORD_INVALID')
    if [r['compilerPath'] for r in rows] != sorted(set(r['compilerPath'] for r in rows)):
        raise ValueError('CALL_DEPENDENCY_RECORD_SET_INVALID')
    require_json_match(rows, _snapshot([r['compilerPath'] for r in rows], cwd), 'CALL_DEPENDENCY_CONTENT_CHANGED')
    if ('sha256:'+sha256(Path(manifest['compilerCommand'][0]).read_bytes()).hexdigest() != manifest['compilerDigest']
            or manifest['searchEnvironment'] != {k:os.environ.get(k, '') for k in manifest['searchEnvironment']}):
        raise ValueError('CALL_DEPENDENCY_TOOL_OR_ENVIRONMENT_CHANGED')
    command = manifest['compilerCommand']
    if (not isinstance(command, list) or len(command) < 7 or command[2] != '-std=gnu11'
            or command[-4:-1] != ['-fsyntax-only','-Xclang','-ast-dump=json']
            or command[1] not in {'--target=riscv64-linux-gnu','--target=x86_64-linux-gnu'}):
        raise ValueError('CALL_DEPENDENCY_COMMAND_INVALID')
    target = command[1].removeprefix('--target=').removesuffix('-linux-gnu')
    replayed = acquire(command[-1], clang=command[0], target=target,
        compile_args=command[3:-4], working_directory=cwd)
    require_json_match(manifest, replayed['dependencyManifest'], 'CALL_DEPENDENCY_REPLAY_MISMATCH')
    return manifest


def main():
    import argparse
    from .compiler_call_inventory import closure
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', required=True)
    args = parser.parse_args()
    try:
        result = json.loads(Path(args.inventory).read_text())
        manifest = result['dependencyManifest']
        validate(manifest)
        if result['inventory']['inventoryIdentity'] != manifest['inventoryIdentity']:
            raise ValueError('CALL_DEPENDENCY_INVENTORY_BINDING_MISMATCH')
        if 'closure' in result:
            require_json_match(closure(result['inventory'], result['closure']['rootFunctionIdentity']),
                               result['closure'], 'CALL_DEPENDENCY_CLOSURE_REPLAY_MISMATCH')
        print(json.dumps({'acquisitionReplayed': True, 'dependencyIdentity':manifest['dependencyIdentity'],
                          'semanticApproval':False, 'productionAcceptanceComplete':False}))
        return 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
        print(json.dumps({'acquisitionReplayed':False,'detail':str(exc),'semanticApproval':False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
