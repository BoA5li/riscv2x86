"""Content-bound, opt-in project compile contexts; never semantic authority.

Preserve native argv separately from the explicit Clang inspection projection.
A successful AST scan does not establish GCC/Clang equivalence, a translated
binary, floating-point support, or L0--L3 acceptance.
"""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import re
import shutil

from .project_build_records import identity, classify

SCHEMA = 'riscv2x86.project-compile-context.v1'
PAIRS = {'-I', '-isystem', '-iquote', '-include', '-imacros', '-D', '-U', '-isysroot'}
EXACT = {'-nostdinc', '-ffreestanding', '-frounding-math', '-fno-strict-aliasing',
         '-fno-builtin', '-fsigned-char', '-funsigned-char', '-fshort-enums',
         '-fshort-wchar', '-fwrapv', '-fno-wrapv', '-fno-strict-overflow',
         '-fPIC', '-fpic', '-fPIE', '-fpie', '-pthread', '-mno-relax', '-mrelax',
         '-fno-stack-protector', '-fstack-protector', '-fstack-protector-strong',
         '-fomit-frame-pointer', '-fno-omit-frame-pointer', '-fno-lto',
         '-fno-asynchronous-unwind-tables', '-fno-unwind-tables'}
PREFIXES = ('-std=', '-march=', '-mabi=', '-mcpu=', '-mtune=', '--sysroot=',
            '-D', '-U', '-I', '-isystem', '-iquote', '-include', '-imacros',
            '-fexcess-precision=')
ENV_KEYS = ('PATH', 'CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'SDKROOT',
            'GCC_EXEC_PREFIX', 'COMPILER_PATH', 'LIBRARY_PATH', 'LD_LIBRARY_PATH',
            'LD_PRELOAD', 'SOURCE_DATE_EPOCH')


def digest(path):
    return 'sha256:' + sha256(Path(path).read_bytes()).hexdigest()


def absolute(path, cwd):
    return (Path(path) if Path(path).is_absolute() else cwd / path).resolve()


def derive(action):
    if action.get('actionIdentity') != identity({k:v for k,v in action.items() if k != 'actionIdentity'}):
        raise ValueError('PROJECT_ACTION_IDENTITY_INVALID')
    if action.get('kind') != 'compile' or classify(action.get('arguments', [])) != 'compile':
        raise ValueError('PROJECT_C_COMPILE_ACTION_REQUIRED')
    cwd = Path(action['directory']).resolve(strict=True)
    argv = action['arguments']; args = argv[1:]; projected = []; excluded = []; reasons = []
    sources = []; outputs = []; i = 0; language = None
    while i < len(args):
        arg = args[i]
        if arg in PAIRS:
            if i+1 >= len(args) or args[i+1].startswith('-'):
                reasons.append('PROJECT_COMPILE_ARGUMENT_INCOMPLETE:'+arg); break
            projected.extend(args[i:i+2]); i += 2; continue
        if arg in {'-o', '-MF', '-MT', '-MQ', '-x'}:
            if i+1 >= len(args): reasons.append('PROJECT_COMPILE_ARGUMENT_INCOMPLETE:'+arg); break
            value = args[i+1]
            if arg == '-o': outputs.append(value)
            elif arg == '-x': language = value
            excluded.append({'arguments': [arg, value], 'reason': 'action-output-or-language'})
            i += 2; continue
        if arg == '-c' or arg in {'-MMD', '-MD', '-MP', '-pipe'}:
            excluded.append({'arguments':[arg], 'reason':'action-or-transport-only'})
        elif arg in EXACT or arg.startswith(PREFIXES) or re.fullmatch(r'-O(?:[0-3sgz]|fast)', arg):
            projected.append(arg)
        elif arg.startswith('-W') and not arg.startswith(('-Wa,', '-Wl,', '-Wp,')):
            excluded.append({'arguments':[arg], 'reason':'diagnostic-only'})
        elif arg == '-Wa,--noexecstack':
            excluded.append({'arguments':[arg], 'reason':'assembler-stack-marker-not-AST-input'})
        elif not arg.startswith('-') and not arg.startswith('@'):
            sources.append(arg)
        else:
            # Retain the original command and block inspection. Unknown flags
            # may change language/ABI/semantics and must not simply disappear.
            reasons.append('PROJECT_COMPILE_ARGUMENT_UNSUPPORTED:'+arg)
        i += 1
    if len(sources) != 1: reasons.append('PROJECT_SINGLE_SOURCE_REQUIRED')
    source = absolute(sources[0], cwd) if len(sources) == 1 else None
    if source and source.suffix != '.c' and language != 'c': reasons.append('PROJECT_C_LANGUAGE_REQUIRED')
    if language not in (None, 'c'): reasons.append('PROJECT_C_LANGUAGE_REQUIRED')
    if action.get('file') and source != absolute(action['file'], cwd): reasons.append('PROJECT_DATABASE_SOURCE_MISMATCH')
    if len(outputs) > 1: reasons.append('PROJECT_OUTPUT_AMBIGUOUS')
    if action.get('output') and outputs and absolute(action['output'], cwd) != absolute(outputs[0], cwd):
        reasons.append('PROJECT_DATABASE_OUTPUT_MISMATCH')
    if source is None or not source.is_file(): reasons.append('PROJECT_SOURCE_UNAVAILABLE')
    compiler_name = argv[0]
    if '/' in compiler_name: compiler = absolute(compiler_name, cwd)
    else:
        found = shutil.which(compiler_name)
        compiler = Path(found).resolve() if found else None
    if compiler is None or not compiler.is_file(): reasons.append('PROJECT_COMPILER_UNAVAILABLE')
    body = {'schemaVersion': SCHEMA, 'actionIdentity':action['actionIdentity'], 'originalAction':action,
        'workingDirectory':str(cwd), 'nativeArguments':argv,
        'nativeCompiler': str(compiler) if compiler else None,
        'nativeCompilerDigest':digest(compiler) if compiler and compiler.is_file() else None,
        'sourcePath':str(source) if source else None,
        'sourceDigest':digest(source) if source and source.is_file() else None,
        'outputPath':str(absolute(outputs[0], cwd)) if len(outputs)==1 else None,
        'inspectionArguments':projected, 'projectionExclusions':excluded,
        'searchEnvironment':{k:os.environ.get(k, '') for k in ENV_KEYS},
        'blockers':sorted(set(reasons)), 'inspectionReady':not reasons,
        'compilerEquivalenceVerified':False, 'nativeBuildReplayed':False,
        'semanticApproval':False, 'productionAcceptanceComplete':False}
    return dict(body, contextIdentity=identity(body))


def validate(context):
    if (not isinstance(context, dict) or context.get('schemaVersion') != SCHEMA
            or context.get('contextIdentity') != identity({k:v for k,v in context.items() if k!='contextIdentity'})
            or any(context.get(k) is not False for k in ('compilerEquivalenceVerified',
                'nativeBuildReplayed','semanticApproval','productionAcceptanceComplete'))):
        raise ValueError('PROJECT_CONTEXT_INVALID')
    if context['searchEnvironment'] != {k:os.environ.get(k, '') for k in ENV_KEYS}:
        raise ValueError('PROJECT_CONTEXT_ENVIRONMENT_CHANGED')
    for pathkey, hashkey in (('sourcePath','sourceDigest'), ('nativeCompiler','nativeCompilerDigest')):
        if context[pathkey] is not None and digest(context[pathkey]) != context[hashkey]:
            raise ValueError('PROJECT_CONTEXT_CONTENT_CHANGED:'+pathkey)
    if identity(context) != identity(derive(context['originalAction'])):
        raise ValueError('PROJECT_CONTEXT_DERIVATION_MISMATCH')
    if context['inspectionReady'] != (not context['blockers']):
        raise ValueError('PROJECT_CONTEXT_READINESS_INVALID')
    return context


def acquire(context, *, clang, target='riscv64', timeout=60):
    from .compiler_call_dependencies import acquire as acquire_ast
    validate(context)
    if not context['inspectionReady']: raise ValueError('PROJECT_CONTEXT_NOT_INSPECTABLE')
    snapshot = acquire_ast(context['sourcePath'], clang=clang, target=target,
        compile_args=context['inspectionArguments'], working_directory=context['workingDirectory'],
        timeout=timeout, include_type_facts=True)
    validate(context)
    functions = []
    for fn in snapshot['inventory']['functions']:
        # New identity includes the build variant, dependencies and tool. Never
        # reuse old source-only function identities as project proof identities.
        functions.append(dict(fn, projectFunctionIdentity=identity({
            'contextIdentity':context['contextIdentity'],
            'dependencyIdentity':snapshot['dependencyManifest']['dependencyIdentity'],
            'functionIdentity':fn['functionIdentity']})))
    body = {'schemaVersion':'riscv2x86.project-context-inspection.v1',
        'contextIdentity':context['contextIdentity'], 'snapshot':snapshot,
        'functions':functions, 'contextAcquisitionConsistent':True,
        'compilerEquivalenceVerified':False,
        'semanticApproval':False, 'productionAcceptanceComplete':False}
    return dict(body, inspectionIdentity=identity(body))
