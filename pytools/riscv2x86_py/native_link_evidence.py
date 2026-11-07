"""Controlled GNU/bfd link build and independent rebuild, never program approval.

Explicit candidate and dependency bytes are bound. Implicit runtime selection,
dynamic interposition, typed effects and actual translated execution stay open.
"""
import os
from pathlib import Path
import re
import subprocess

from .native_elf_runtime import parse
from .native_external_providers import read, checked
from .native_dependency_evidence import archive_members, bytes_digest
from .project_build_records import identity
from .project_compile_context import digest
from .project_tool_resolution import resolve_executable

REQUEST='riscv2x86.native-link-request.v1'
SCHEMA='riscv2x86.native-link-build.v1'
REQUEST_V2='riscv2x86.native-link-request.v2'
SCHEMA_V2='riscv2x86.native-link-build.v2'


def ordered_plan(items):
    if not isinstance(items, list):raise ValueError('NATIVE_LINK_ORDERED_PLAN_REQUIRED')
    result=[];depth=0
    for item in items:
        if not isinstance(item,dict) or len(item)!=1:raise ValueError('NATIVE_LINK_PLAN_ITEM_INVALID')
        if 'file' in item:
            result.append({'file':str(Path(item['file']).resolve(strict=True))})
        elif item=={'group':'start'}:
            depth+=1;result.append(item)
        elif item=={'group':'end'} and depth:
            depth-=1;result.append(item)
        else:raise ValueError('NATIVE_LINK_PLAN_OPTION_UNSUPPORTED')
    if depth:raise ValueError('NATIVE_LINK_PLAN_GROUP_UNCLOSED')
    return result


def request(candidate,side,compiler,inputs,mode='executable',static=False,pie=None,abi_options=(),
            *, ordered_inputs=None):
    if side not in ('source','target') or mode not in ('executable','shared'):
        raise ValueError('NATIVE_LINK_SIDE_OR_MODE_INVALID')
    if type(static) is not bool or pie is not None and type(pie) is not bool:
        raise ValueError('NATIVE_LINK_OPTIONS_INVALID')
    if mode=='shared' and (static or pie is not None):raise ValueError('NATIVE_LINK_SHARED_OPTIONS_INVALID')
    options=list(abi_options)
    for option in options:
        if not re.fullmatch(r'-(?:mabi|march)=[a-zA-Z0-9_+.-]+',option):
            raise ValueError('NATIVE_LINK_ABI_OPTION_UNSUPPORTED')
    if ordered_inputs is not None and inputs:raise ValueError('NATIVE_LINK_MIXED_INPUT_FORMS')
    plan=None if ordered_inputs is None else ordered_plan(ordered_inputs)
    paths=([str(Path(p).resolve(strict=True)) for p in inputs] if plan is None else
           [item['file'] for item in plan if 'file' in item])
    if plan is None and len(paths)!=len(set(paths)):raise ValueError('NATIVE_LINK_DUPLICATE_INPUT')
    body={'schemaVersion':REQUEST,'candidatePath':str(Path(candidate).resolve(strict=True)),
        'side':side,'compiler':str(resolve_executable(compiler)),'inputs':paths,
        'mode':mode,'static':static,'pie':pie,'abiOptions':options}
    if plan is not None:body.update(schemaVersion=REQUEST_V2,orderedInputs=plan)
    return dict(body,linkRequestIdentity=identity(body))


def build(value,output,timeout=300):
    checked(value,'linkRequestIdentity')
    if value['schemaVersion'] not in (REQUEST,REQUEST_V2):raise ValueError('NATIVE_LINK_REQUEST_SCHEMA_INVALID')
    v2=value['schemaVersion']==REQUEST_V2
    reconstructed=request(value['candidatePath'],value['side'],value['compiler'],[] if v2 else value['inputs'],
                          value['mode'],value['static'],value['pie'],value['abiOptions'],
                          ordered_inputs=value['orderedInputs'] if v2 else None)
    if reconstructed!=value:raise ValueError('NATIVE_LINK_REQUEST_NONCANONICAL')
    out=Path(output).resolve(strict=True)
    if any(out.iterdir()):
        # Runner's run-status.json is the only allowed preexisting artifact.
        if {p.name for p in out.iterdir()}!={'run-status.json'}:
            raise ValueError('NATIVE_LINK_OUTPUT_NOT_EMPTY')
    bound={};aliases={};commands=[]
    environment=({'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C'} if v2 else dict(os.environ,LC_ALL='C'))
    def bind(path):
        path=Path(path);lexical=str(path.absolute());resolved=str(path.resolve(strict=True));sha=digest(resolved)
        if lexical in aliases and aliases[lexical]!=resolved:raise ValueError('NATIVE_LINK_ALIAS_CHANGED')
        if resolved in bound and bound[resolved]!=sha:raise ValueError('NATIVE_LINK_INPUT_CHANGED')
        aliases[lexical]=resolved;bound[resolved]=sha
        return resolved
    def run(stage,argv):
        bind(argv[0]);result=subprocess.run(argv,cwd=out,env=environment,
                capture_output=True,timeout=timeout)
        row={'stage':stage,'arguments':argv,'returnCode':result.returncode}
        for stream in ('stdout','stderr'):
            path=out/(stage+'.'+stream);raw=getattr(result,stream);path.write_bytes(raw)
            row[stream+'Digest']=bytes_digest(raw);row[stream+'Path']=str(path)
        commands.append(row)
        (out/'commands.json').write_text(__import__('json').dumps(commands,indent=2)+'\n')
        if result.returncode:raise ValueError('NATIVE_LINK_COMMAND_FAILED:'+stage+':'+str(result.returncode))
        return result.stdout.decode('utf-8')
    candidate=read(value['candidatePath']);checked(candidate,'candidateIdentity');bind(value['candidatePath'])
    if (candidate['schemaVersion']!='riscv2x86.native-integer-candidate.v1'
            or candidate['semanticApproval'] is not False or candidate['productionAcceptanceComplete'] is not False):
        raise ValueError('NATIVE_LINK_CANDIDATE_SCOPE_INVALID')
    directory=Path(candidate['candidatePath']).parent
    for name,expected in candidate['artifactDigests'].items():
        if Path(name).name!=name:raise ValueError('NATIVE_LINK_CANDIDATE_ARTIFACT_INVALID')
        path=bind(directory/name)
        if bound[path]!=expected:raise ValueError('NATIVE_LINK_CANDIDATE_ARTIFACT_CHANGED')
    root=bind(directory/(value['side']+'.o'));root_elf=parse(Path(root).read_bytes())
    machine=243 if value['side']=='source' else 62
    if root_elf['machine']!=machine or root_elf['elfType']!=1:
        raise ValueError('NATIVE_LINK_CANDIDATE_ARCHITECTURE_INVALID')
    if bound[root]!=candidate[value['side']+'ObjectDigest']:
        raise ValueError('NATIVE_LINK_CANDIDATE_OBJECT_CHANGED')
    definitions=[s for s in root_elf['staticSymbols'] if s['name'] and s['defined'] and s['binding']!=0]
    if any(s['binding']!=1 or s['sectionIndex']>=0xff00 for s in definitions):
        raise ValueError('NATIVE_LINK_SPECIAL_CANDIDATE_DEFINITION_UNSUPPORTED')
    for name in value['inputs']:
        path=bind(name)
        if path==root:raise ValueError('NATIVE_LINK_CANDIDATE_DUPLICATED')
        raw=Path(path).read_bytes()
        raws=[m['bytes'] for m in archive_members(raw)] if raw.startswith(b'!<arch>\n') else [raw]
        for obj in raws:
            elf=parse(obj)
            if elf['machine']!=machine:raise ValueError('NATIVE_LINK_DEPENDENCY_ARCHITECTURE_INVALID')
            if elf['elfType']==1 and elf['abiFlags']!=root_elf['abiFlags']:
                raise ValueError('NATIVE_LINK_DEPENDENCY_ABI_FLAGS_DIFFER')
    cc=bind(value['compiler'])
    run('compiler-version',[cc,'--version'])
    linker=run('linker-query',[cc,*value['abiOptions'],'-print-prog-name=ld.bfd']).strip()
    linker=bind(resolve_executable(linker))
    version=run('linker-version',[linker,'--version'])
    if not version.startswith('GNU ld '):raise ValueError('NATIVE_LINK_GNU_BFD_REQUIRED')
    implicit=[]
    for n,name in enumerate(('crt1.o','Scrt1.o','crti.o','crtn.o','libgcc.a','libgcc_s.so.1','libc.so')):
        found=run('runtime-query-'+str(n),[cc,*value['abiOptions'],'-print-file-name='+name]).strip()
        row={'query':name,'result':found,'actualSelectionVerified':False}
        if Path(found).is_absolute() and Path(found).is_file():
            row['resolvedPath']=bind(found);row['digest']=bound[row['resolvedPath']]
        implicit.append(row)
    program=out/'program';linkmap=out/'link.map'
    argv=[cc,*value['abiOptions'],'-fuse-ld=bfd']
    if value['mode']=='shared':argv.append('-shared')
    if value['static']:argv.append('-static')
    if value['pie'] is not None:argv.append('-pie' if value['pie'] else '-no-pie')
    inputs=value['inputs']
    if v2:
        inputs=[item['file'] if 'file' in item else '-Wl,--'+item['group']+'-group'
                for item in value['orderedInputs']]
        for symbol in definitions:
            if not re.fullmatch(r'[A-Za-z_.$][A-Za-z0-9_.$]*',symbol['name']):
                raise ValueError('NATIVE_LINK_TRACE_SYMBOL_UNSUPPORTED')
            argv.extend(['-Xlinker','--trace-symbol','-Xlinker',symbol['name']])
    argv.extend([root,*inputs,'-Wl,-z,defs','-Wl,-t',
                 '-Xlinker','-Map','-Xlinker',str(linkmap),'-o',str(program)])
    run('link',argv)
    output_raw=program.read_bytes();elf=parse(output_raw)
    if elf['machine']!=machine or elf['elfType'] not in (2,3):raise ValueError('NATIVE_LINK_OUTPUT_ARCHITECTURE_INVALID')
    symbols=elf['staticSymbols'] or elf['dynamicSymbols']
    exports=[]
    for expected in definitions:
        matches=[s for s in symbols if s['name']==expected['name'] and s['defined']
                 and s['binding']==1 and s['type']==expected['type']]
        if len(matches)!=1:raise ValueError('NATIVE_LINK_CANDIDATE_EXPORT_MISSING_OR_AMBIGUOUS:'+expected['name'])
        exports.append(matches[0])
    if not linkmap.is_file():raise ValueError('NATIVE_LINK_MAP_REQUIRED')
    artifacts={p.name:digest(p) for p in out.iterdir() if p.is_file() and p.name!='run-status.json'}
    for path,expected in bound.items():
        if digest(path)!=expected:raise ValueError('NATIVE_LINK_CLOSING_INPUT_CHANGED')
    for path,expected in aliases.items():
        if str(Path(path).resolve(strict=True))!=expected:raise ValueError('NATIVE_LINK_ALIAS_CHANGED')
    body={'schemaVersion':SCHEMA,'request':value,'candidateIdentity':candidate['candidateIdentity'],
        'boundInputDigests':bound,'aliases':aliases,'commands':commands,'implicitRuntimeCandidates':implicit,
        'artifactDigests':artifacts,'outputElf':elf,'candidateExports':exports,
        'candidateObjectExplicitInputVerified':True,'candidateExportsPresent':True,'linkBuildComplete':True,
        'actualLinkSelectionVerified':False,'candidateDefinitionAttributionVerified':False,
        'runtimeLibrarySelectionVerified':False,'translatedInstanceExecutionVerified':False,
        'typedCallContractVerified':False,'semanticApproval':False,'productionAcceptanceComplete':False,
        'pendingWork':['LINK_MAP_AND_RELOCATION_ATTRIBUTION','IMPLICIT_RUNTIME_SELECTION',
                       'TYPED_CALL_OBJECT_EFFECT_CONTRACT','ACTUAL_TRANSLATED_EXECUTION','PROGRAM_L0_L3_AUDIT']}
    if v2:
        body.update(schemaVersion=SCHEMA_V2,linkEnvironment=environment)
    return dict(body,linkBuildIdentity=identity(body))


def audit(value,original_output,new_output,timeout=300):
    checked(value,'linkBuildIdentity')
    if value['schemaVersion'] not in (SCHEMA,SCHEMA_V2):raise ValueError('NATIVE_LINK_BUILD_SCHEMA_INVALID')
    old=Path(original_output).resolve(strict=True)
    for name,expected in value['artifactDigests'].items():
        if Path(name).name!=name:raise ValueError('NATIVE_LINK_ARTIFACT_NAME_INVALID')
        if digest(old/name)!=expected:raise ValueError('NATIVE_LINK_ARTIFACT_CHANGED')
    if read(old/'commands.json')!=value['commands']:
        raise ValueError('NATIVE_LINK_COMMAND_RECEIPT_MISMATCH')
    fresh=build(value['request'],new_output,timeout)
    if set(value['artifactDigests'])!=set(fresh['artifactDigests']):
        raise ValueError('NATIVE_LINK_REBUILD_ARTIFACT_SET_MISMATCH')
    for name in value['artifactDigests']:
        if name in ('program','commands.json'):continue
        old_raw=(old/name).read_bytes().replace((str(old)+'/').encode(),b'$OUTPUT/')
        new_raw=(Path(new_output)/name).read_bytes().replace((str(Path(new_output).resolve())+'/').encode(),b'$OUTPUT/')
        if old_raw!=new_raw:raise ValueError('NATIVE_LINK_REBUILD_STREAM_MISMATCH:'+name)
    for key in ('candidateIdentity','boundInputDigests','aliases','outputElf','candidateExports'):
        if value[key]!=fresh[key]:raise ValueError('NATIVE_LINK_REBUILD_MISMATCH:'+key)
    if fresh['artifactDigests']['program']!=value['artifactDigests']['program']:
        raise ValueError('NATIVE_LINK_REBUILD_BYTES_DIFFER')
    # Validate every field/flag against independent recomputation. Output-root
    # paths are the only permitted projection, never arbitrary source paths.
    def projection(v,root):
        if isinstance(v,str):
            if v.startswith(root+'/'):return '$OUTPUT/'+v[len(root)+1:]
            return v
        if isinstance(v,list):return [projection(x,root) for x in v]
        if isinstance(v,dict):return {k:projection(x,root) for k,x in v.items() if k not in ('linkBuildIdentity','artifactDigests')}
        return v
    left=projection(value,str(old));right=projection(fresh,str(Path(new_output).resolve()))
    # Raw map/stream digests can include the output path; raw integrity above
    # is mandatory, whereas these streams are not semantic-comparison evidence.
    for doc in (left,right):
        for command in doc['commands']:
            command.pop('stdoutDigest');command.pop('stderrDigest')
    if left!=right:raise ValueError('NATIVE_LINK_REBUILD_RECEIPT_MISMATCH')
    return {'nativeLinkIndependentRebuildComplete':True,'linkBuildIdentity':value['linkBuildIdentity'],
        'candidateObjectExplicitInputVerified':True,'candidateExportsPresent':True,
        'actualLinkSelectionVerified':False,'typedCallContractVerified':False,
        'translatedInstanceExecutionVerified':False,'semanticApproval':False,'productionAcceptanceComplete':False}
