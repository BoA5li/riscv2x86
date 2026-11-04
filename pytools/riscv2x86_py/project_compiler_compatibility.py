"""Conservative source preprocessing compatibility with actual native compiler.

Exact token equality is sufficient for this acquisition prerequisite, not proof
of compiler equivalence. Differences are retained and block project authority;
normalizing attributes, macro branches or literal values would be unsound.
"""
from pathlib import Path
import re
import subprocess
from .project_build_contract import validate, source_arguments, digest
from .project_build_records import identity
from .compiler_call_dependencies import parse_dependencies, _snapshot

# String/character tokens stay indivisible. Keep whitespace so token adjacency
# ('a b' versus 'ab') cannot be changed by deleting whitespace wholesale.
TOKEN=re.compile(r"""(?:u8|u|U|L)?"(?:\\.|[^"\\])*"|(?:u|U|L)?'(?:\\.|[^'\\])*'|[A-Za-z_][A-Za-z_0-9]*|(?:[0-9]|\.[0-9])(?:[eEpP][+-]|[A-Za-z_0-9.])*|%:%:|>>=|<<=|\.\.\.|->|\+\+|--|<<|>>|<=|>=|==|!=|&&|\|\||\*=|/=|%=|\+=|-=|&=|\^=|\|=|\#\#|<:|:>|<%|%>|%:|[{}\[\]().&*+~!/%<>^|?:;=,\#-]""",re.S)


def tokens(text):
    result=[];position=0
    while position<len(text):
        if text[position].isspace():position+=1;continue
        match=TOKEN.match(text,position)
        if match is None:raise ValueError('PROJECT_PREPROCESSING_TOKEN_UNSUPPORTED:'+repr(text[position:position+16]))
        result.append(match[0]);position=match.end()
    return result


def acquire(contract,*,timeout=120):
    validate(contract);ctx=contract['sourceContext'];source=ctx['sourcePath'];cwd=Path(ctx['workingDirectory'])
    native=[ctx['nativeCompiler'],*source_arguments(ctx)]
    clang=[contract['inspectionCompiler'],'--target=riscv64-linux-gnu',*ctx['inspectionArguments']]
    all_rows={};streams={};commands={}
    for name,base in (('native',native),('inspection',clang)):
        def run(options):
            command=[*base,*options,source]
            result=subprocess.run(command,cwd=cwd,capture_output=True,text=True,timeout=timeout,check=False)
            if result.returncode:raise ValueError('PROJECT_COMPATIBILITY_COMPILER_FAILED:'+name+':'+result.stderr[-5000:])
            return command,result.stdout
        _,deps=run(['-M','-MT','rv2x86_call_inventory']);paths=parse_dependencies(deps);before=_snapshot(paths,cwd)
        command,text=run(['-E','-P']);commands[name]=command;streams[name]=tokens(text)
        _,after=run(['-M','-MT','rv2x86_call_inventory'])
        if paths!=parse_dependencies(after) or identity(before)!=identity(_snapshot(paths,cwd)):
            raise ValueError('PROJECT_COMPATIBILITY_DEPENDENCIES_CHANGED')
        all_rows[name]=before
    validate(contract)
    from .project_build_contract import profile
    target_cc,target_args=profile(contract,'target')
    source_driver_cc,source_driver_args=profile(contract,'source',driver=True)
    target_driver_cc,target_driver_args=profile(contract,'target',driver=True)
    macro_keys=('__CHAR_BIT__','__SIZEOF_SHORT__','__SIZEOF_INT__','__SIZEOF_LONG__',
        '__SIZEOF_LONG_LONG__','__SIZEOF_POINTER__','__BYTE_ORDER__','__CHAR_UNSIGNED__',
        '__WCHAR_TYPE__','__SIZEOF_WCHAR_T__','__STDC_VERSION__')
    models={}
    protected=set(macro_keys)|{'__ORDER_LITTLE_ENDIAN__','__ORDER_BIG_ENDIAN__','__ORDER_PDP_ENDIAN__'}
    for args in (native[1:],target_args,source_driver_args,target_driver_args):
        i=0
        while i<len(args):
            arg=args[i]
            if arg in {'-D','-U'}:
                i+=1;name=args[i].split('=',1)[0] if i<len(args) else ''
            elif arg.startswith(('-D','-U')):name=arg[2:].split('=',1)[0]
            else:name=''
            if name in protected:raise ValueError('PROJECT_DATA_MODEL_BUILTIN_OVERRIDE_UNSUPPORTED:'+name)
            i+=1
    for name,base in (('source',native),('target',[target_cc,*target_args]),
            ('sourceDriver',[source_driver_cc,*source_driver_args]),('targetDriver',[target_driver_cc,*target_driver_args])):
        command=[*base,'-dM','-E','-x','c','-']
        result=subprocess.run(command,cwd=cwd,capture_output=True,text=True,input='',timeout=timeout,check=False)
        if result.returncode:raise ValueError('PROJECT_DATA_MODEL_COMPILER_FAILED:'+name+':'+result.stderr[-4000:])
        macros={m[1]:m[2].strip() for line in result.stdout.splitlines()
                if (m:=re.fullmatch(r'#define ([A-Za-z_][A-Za-z_0-9]*) (.*)',line))}
        if any(key not in macros for key in macro_keys if key not in {'__CHAR_UNSIGNED__','__STDC_VERSION__'}):
            raise ValueError('PROJECT_DATA_MODEL_FACTS_INCOMPLETE:'+name)
        models[name]={key:macros.get(key) for key in macro_keys}
        # Resolve the standard endian aliases; their textual macro names alone
        # are not numerical data-model evidence.
        order=models[name]['__BYTE_ORDER__']
        models[name]['__BYTE_ORDER__']=macros.get(order,order)
        commands[name+'DataModel']=command
    abi=lambda row:{k:v for k,v in row.items() if k!='__STDC_VERSION__'}
    model_equal=(models['source']==models['target'] and all(abi(row)==abi(models['source']) for row in models.values()))
    enum_flags=[('-fshort-enums' in args) for args in (native[1:],target_args,source_driver_args,target_driver_args)]
    model_equal=model_equal and len(set(enum_flags))==1
    a,b=streams['native'],streams['inspection'];count=min(len(a),len(b));first=next((i for i in range(count) if a[i]!=b[i]),count)
    equal=a==b
    body={'schemaVersion':'riscv2x86.project-preprocessing-compatibility.v1','contractIdentity':contract['contractIdentity'],
          'commands':commands,'dependencies':all_rows,'tokenDigests':{k:identity(v) for k,v in streams.items()},
          'tokenCounts':{k:len(v) for k,v in streams.items()},'sourcePreprocessingMatched':equal,
          'integerDataModels':models,'integerDataModelMatched':model_equal,
          'firstDifference':None if equal else {'tokenIndex':first,'native':a[max(0,first-4):first+5],
              'inspection':b[max(0,first-4):first+5]},
          'compilerEquivalenceVerified':False,'semanticApproval':False,'productionAcceptanceComplete':False}
    return dict(body,compatibilityIdentity=identity(body))


def require(contract,receipt):
    if receipt.get('compatibilityIdentity')!=identity({k:v for k,v in receipt.items() if k!='compatibilityIdentity'}):
        raise ValueError('PROJECT_COMPATIBILITY_IDENTITY_INVALID')
    fresh=acquire(contract)
    if identity(fresh)!=identity(receipt):raise ValueError('PROJECT_COMPATIBILITY_REPLAY_MISMATCH')
    if fresh['integerDataModelMatched'] is not True:raise ValueError('PROJECT_INTEGER_DATA_MODEL_MISMATCH')
    if fresh['sourcePreprocessingMatched'] is not True:raise ValueError('PROJECT_COMPILER_PREPROCESSING_MISMATCH')
    return fresh


def target_acquire(contract,target,*,timeout=120,include_directories=()):
    """Check the materialized target TU under original and migrated CPP recipes.

    Comparing original-source CPP alone would miss target-only macro branches.
    This conservative check can reject legitimate target runtime headers; those
    need a separate proved adaptation, not deletion of differing tokens.
    """
    from .project_build_contract import profile
    validate(contract);target=str(Path(target).resolve(strict=True));cwd=Path(contract['sourceContext']['workingDirectory'])
    source_cc,source_args=profile(contract,'source');target_cc,target_args=profile(contract,'target')
    streams={};dependencies={};commands={}
    for side,cc,args in (('source',source_cc,source_args),('target',target_cc,target_args)):
        def run(options):
            cmd=[cc,*args,*['-I'+str(Path(p).resolve()) for p in include_directories],*options,target]
            result=subprocess.run(cmd,cwd=cwd,capture_output=True,text=True,timeout=timeout,check=False)
            if result.returncode:raise ValueError('PROJECT_TARGET_CPP_COMPILER_FAILED:'+side+':'+result.stderr[-5000:])
            return cmd,result.stdout
        _,dep=run(['-M','-MT','rv2x86_call_inventory']);paths=parse_dependencies(dep);before=_snapshot(paths,cwd)
        cmd,text=run(['-E','-P']);commands[side]=cmd;streams[side]=tokens(text)
        _,dep=run(['-M','-MT','rv2x86_call_inventory'])
        if paths!=parse_dependencies(dep) or identity(before)!=identity(_snapshot(paths,cwd)):
            raise ValueError('PROJECT_TARGET_CPP_DEPENDENCIES_CHANGED')
        dependencies[side]=before
    a,b=streams['source'],streams['target'];n=min(len(a),len(b));first=next((i for i in range(n) if a[i]!=b[i]),n)
    body={'schemaVersion':'riscv2x86.project-target-preprocessing.v1','contractIdentity':contract['contractIdentity'],
          'targetPath':target,'targetDigest':digest(target),'commands':commands,'dependencies':dependencies,
          'tokenDigests':{k:identity(v) for k,v in streams.items()},'targetPreprocessingMatched':a==b,
          'firstDifference':None if a==b else {'index':first,'source':a[max(0,first-4):first+5],'target':b[max(0,first-4):first+5]},
          'semanticApproval':False,'productionAcceptanceComplete':False}
    return dict(body,compatibilityIdentity=identity(body))
