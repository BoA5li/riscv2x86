"""Explicit project source/target/driver build recipes, never semantic approval.

The contract binds recipes; it does not certify cross-compiler equivalence or
approve an ISA lowering. Every consumer must still establish its usual proof,
artifact, executable-mechanism and observation obligations.
"""
from __future__ import annotations
from hashlib import sha256
import json
from pathlib import Path
import re

from .project_build_records import identity
from .project_compile_arguments import action_option
from .project_tool_resolution import resolve_executable
from .project_compile_context import validate as validate_context, derive, absolute, PAIRS

SCHEMA='riscv2x86.project-build-contract.v1'
PROFILE='riscv2x86.project-compiler-profile.v1'


def digest(path):return 'sha256:'+sha256(Path(path).read_bytes()).hexdigest()


def resolve_tool(tool,cwd=None):
    return str(resolve_executable(tool,cwd))


def normalize_paths(args,cwd):
    """Preserve ordering and macro text, resolve only compiler path options."""
    path_pairs={'-I','-isystem','-iquote','-include','-imacros','-isysroot'}
    out=[];i=0
    while i<len(args):
        arg=args[i]
        if arg in PAIRS:
            if i+1>=len(args):raise ValueError('PROJECT_ARGUMENT_INCOMPLETE')
            value=args[i+1]
            out.extend([arg,str(absolute(value,Path(cwd))) if arg in path_pairs else value]);i+=2;continue
        done=False
        for prefix in ('--sysroot=','-isystem','-iquote','-include','-imacros','-I'):
            if arg.startswith(prefix) and len(arg)>len(prefix):
                out.append(prefix+str(absolute(arg[len(prefix):],Path(cwd))));done=True;break
        if not done:out.append(arg)
        i+=1
    return out


def source_arguments(context):
    """Remove only action outputs/inputs, retaining native diagnostic options."""
    args=context['nativeArguments'][1:];out=[];i=0;cwd=Path(context['workingDirectory'])
    while i<len(args):
        arg=args[i]
        option=action_option(args,i)
        if option is not None:i+=option[2];continue
        if arg in {'-c','-MD','-MMD','-MP'}:i+=1;continue
        if not arg.startswith('-') and str(absolute(arg,cwd))==context['sourcePath']:i+=1;continue
        out.append(arg)
        if arg in PAIRS:
            if i+1>=len(args):raise ValueError('PROJECT_ARGUMENT_INCOMPLETE')
            out.append(args[i+1]);i+=2
        else:i+=1
    return normalize_paths(out,cwd)


def compiler_profile(compiler,arguments,working_directory,*,source):
    from .project_build_records import record
    cwd=Path(working_directory).resolve(strict=True);compiler=resolve_tool(compiler,cwd)
    a=record([compiler,*arguments,'-c',str(Path(source).resolve()),'-o','project-profile.o'],cwd,{'kind':'explicit-project-profile'})
    context=derive(a)
    if not context['inspectionReady']:raise ValueError('PROJECT_PROFILE_ARGUMENTS_UNSUPPORTED:'+repr(context['blockers']))
    # Arguments must be options only: no action/input/output injection.
    if context['outputPath']!=str(cwd/'project-profile.o') or context['sourcePath']!=str(Path(source).resolve()):
        raise ValueError('PROJECT_PROFILE_ACTION_INJECTION')
    if (any(a in {'-c','-o','-MF','-MT','-MQ','-MD','-MMD','-MP','-x'} for a in arguments)
            or any(action_option(arguments,i) is not None for i in range(len(arguments)))):
        raise ValueError('PROJECT_PROFILE_ACTION_ARGUMENT_FORBIDDEN')
    body={'schemaVersion':PROFILE,'compiler':compiler,'compilerDigest':digest(compiler),
          'arguments':list(arguments),'inspectionArguments':context['inspectionArguments'],'workingDirectory':str(cwd)}
    return dict(body,profileIdentity=identity(body))


def make(context,*,clang,target_compiler,target_arguments,target_directory,
         source_driver_arguments,target_driver_arguments):
    validate_context(context)
    if not context['inspectionReady']:raise ValueError('PROJECT_CONTEXT_NOT_READY')
    clang=resolve_tool(clang,context['workingDirectory'])
    target=compiler_profile(target_compiler,target_arguments,target_directory,source=context['sourcePath'])
    if any(a.startswith('-mabi=') or a.startswith('-march=rv') for a in list(target_arguments)+list(target_driver_arguments)):
        raise ValueError('PROJECT_TARGET_ISA_ARGUMENT_MISMATCH')
    def semantic_options(args):
        # Relative order of independent option families is irrelevant; preserve
        # order within interacting FP/overflow families instead of sorting argv.
        result={'standard':None,'fp':[],'overflow':[],'alias':False,'freestanding':False,'builtin':False,'common':None}
        for arg in args:
            if arg.startswith('-std='):result['standard']=arg
            elif arg in {'-Ofast','-frounding-math'} or arg.startswith('-fexcess-precision='):result['fp'].append(arg)
            elif arg in {'-fwrapv','-fno-wrapv','-fno-strict-overflow'}:result['overflow'].append(arg)
            elif arg=='-fno-strict-aliasing':result['alias']=True
            elif arg=='-ffreestanding':result['freestanding']=True
            elif arg=='-fno-builtin':result['builtin']=True
            elif arg in {'-fcommon','-fno-common'}:result['common']=arg
        return result
    if semantic_options(context['inspectionArguments'])!=semantic_options(target['inspectionArguments']):
        raise ValueError('PROJECT_PROGRAM_SEMANTIC_ARGUMENTS_MISMATCH')
    source_driver=compiler_profile(context['nativeCompiler'],source_driver_arguments,context['workingDirectory'],source=context['sourcePath'])
    target_driver=compiler_profile(target_compiler,target_driver_arguments,target_directory,source=context['sourcePath'])
    for driver in (source_driver,target_driver):
        if any(a.startswith(('-D','-U','-I','-isystem','-iquote','-include','-imacros')) for a in driver['arguments']):
            raise ValueError('PROJECT_DRIVER_PREPROCESSOR_ADAPTER_REQUIRED')
    body={'schemaVersion':SCHEMA,'sourceContext':context,'inspectionCompiler':clang,
          'inspectionCompilerDigest':digest(clang),'targetProfile':target,
          'sourceDriverProfile':source_driver,'targetDriverProfile':target_driver,
          'compilerCompatibilityVerified':False,'semanticApproval':False,
          'productionAcceptanceComplete':False}
    return dict(body,contractIdentity=identity(body))


def validate(contract,*,source=None):
    fields={'schemaVersion','sourceContext','inspectionCompiler','inspectionCompilerDigest','targetProfile',
        'sourceDriverProfile','targetDriverProfile','compilerCompatibilityVerified','semanticApproval',
        'productionAcceptanceComplete','contractIdentity'}
    if (not isinstance(contract,dict) or set(contract)!=fields or contract['schemaVersion']!=SCHEMA
            or contract['contractIdentity']!=identity({k:v for k,v in contract.items() if k!='contractIdentity'})
            or any(contract[k] is not False for k in ('compilerCompatibilityVerified','semanticApproval','productionAcceptanceComplete'))):
        raise ValueError('PROJECT_BUILD_CONTRACT_INVALID')
    context=contract['sourceContext'];validate_context(context)
    if source is not None and (str(Path(source).resolve())!=context['sourcePath'] or digest(source)!=context['sourceDigest']):
        raise ValueError('PROJECT_BUILD_SOURCE_BINDING_MISMATCH')
    if digest(contract['inspectionCompiler'])!=contract['inspectionCompilerDigest']:
        raise ValueError('PROJECT_INSPECTION_COMPILER_CHANGED')
    fresh=make(context,clang=contract['inspectionCompiler'],target_compiler=contract['targetProfile']['compiler'],
        target_arguments=contract['targetProfile']['arguments'],target_directory=contract['targetProfile']['workingDirectory'],
        source_driver_arguments=contract['sourceDriverProfile']['arguments'],target_driver_arguments=contract['targetDriverProfile']['arguments'])
    if identity(fresh)!=identity(contract):raise ValueError('PROJECT_BUILD_CONTRACT_DERIVATION_CHANGED')
    return contract


def load(path,*,source=None):return validate(json.loads(Path(path).read_text()),source=source)


def profile(contract,side,*,driver=False,compiler=None):
    validate(contract)
    if side not in {'source','target'}:raise ValueError('PROJECT_BUILD_SIDE_INVALID')
    if driver:
        p=contract[side+'DriverProfile'];cc=p['compiler'];args=normalize_paths(p['arguments'],p['workingDirectory'])
    elif side=='source':
        cc=contract['sourceContext']['nativeCompiler'];args=source_arguments(contract['sourceContext'])
    else:
        p=contract['targetProfile'];cc=p['compiler'];args=normalize_paths(p['arguments'],p['workingDirectory'])
    if compiler is not None and resolve_tool(compiler)!=cc:raise ValueError('PROJECT_EXECUTION_COMPILER_MISMATCH:'+side)
    if not driver:
        args=['-iquote',str(Path(contract['sourceContext']['sourcePath']).parent),*args]
    return cc,args


def report_contract(report,*,source=None):
    value=json.loads(Path(report).read_text()) if not isinstance(report,dict) else report
    contract=value.get('projectBuildContract')
    return validate(contract,source=source) if contract is not None else None


def deployment_arguments(contract,side,compiler,*,driver=False):
    return profile(contract,side,driver=driver,compiler=compiler)[1]
