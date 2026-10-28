"""Byte-identical local-control deployment, including compiler-bound asm-goto exits."""
import json
from pathlib import Path
import subprocess
import tempfile
from .l3_trace_support import Elf,digest,identity,run,save
from .l3_control_spec import spec as control_spec,signature,samples,harness
from .l3_control_machine import graph

SCHEMA='riscv2x86.control-execution-deployment.v1'
BEGIN='__rv2x86_control_begin';END='__rv2x86_control_end'
TAKEN='__rv2x86_control_taken';FALL='__rv2x86_control_fall'


from .l3_trace_support import require_json_document,require_json_match

def marker(name):return '.globl '+name+'\n.hidden '+name+'\n'+name+':\n'


def instrument(source,sites):
    if sites['siteFactsIdentity']!=identity({k:v for k,v in sites.items() if k!='siteFactsIdentity'}):raise ValueError('L3_CONTROL_CONTINUATION_SITES_INVALID')
    labels=sites['labels']
    if len(labels)!=1:raise ValueError('L3_CONTROL_GOTO_LABEL_DOMAIN_UNSUPPORTED')
    offsets=[(sites['fallthroughBegin'],FALL),(labels[0]['statementBegin'],TAKEN)]
    if len({x[0] for x in offsets})!=2:raise ValueError('L3_CONTROL_CONTINUATION_SITES_AMBIGUOUS')
    for offset,name in sorted(offsets,reverse=True):
        if type(offset) is not int or not 0<=offset<len(source):raise ValueError('L3_CONTROL_CONTINUATION_OFFSET_INVALID')
        text='__asm__ volatile ('+json.dumps(marker(name))+');\n'
        source=source[:offset]+text.encode()+source[offset:]
    return source


def label_assembly(text,goto):
    lines=text.splitlines(keepends=True);starts=[i for i,s in enumerate(lines) if s.strip()=='#APP'];ends=[i for i,s in enumerate(lines) if s.strip()=='#NO_APP']
    if len(starts)!=len(ends) or not 1<=len(starts)<=(3 if goto else 1) or any(a>=b for a,b in zip(starts,ends)):
        raise ValueError('L3_CONTROL_ASSEMBLER_BOUNDARY_UNSUPPORTED')
    metadata=set();locations={}
    for name in ((FALL,TAKEN) if goto else ()):
        matches=[i for i,line in enumerate(lines) if line.strip()=='.globl '+name]
        if len(matches)!=1:raise ValueError('L3_CONTROL_MARKER_NOT_UNIQUE')
        pos=matches[0];nonempty=[i for i in range(pos,len(lines)) if lines[i].strip() and not lines[i].lstrip().startswith('#')][:3]
        if [lines[i].strip() for i in nonempty]!=marker(name).strip().splitlines():raise ValueError('L3_CONTROL_MARKER_NOT_METADATA')
        if not any(a<pos<b for a,b in zip(starts,ends)):raise ValueError('L3_CONTROL_MARKER_OUTSIDE_ASM')
        locations[name]=pos;metadata.update(nonempty)
    originals=[]
    for a,b in zip(starts,ends):
        code=[i for i in range(a+1,b) if i not in metadata and lines[i].strip() and not lines[i].lstrip().startswith('#')]
        if code:originals.append((a,b))
    if len(originals)!=1:raise ValueError('L3_CONTROL_ASSEMBLER_REGION_AMBIGUOUS')
    a,b=originals[0]
    # GCC may coalesce adjacent volatile asm statements into one APP block.
    # The independently inserted zero-byte fallthrough marker still fixes the
    # exact original region's end; no instruction text selects the boundary.
    end=locations[FALL] if goto and a<locations[FALL]<b else b
    if goto and a<locations[TAKEN]<end:raise ValueError('L3_CONTROL_MARKER_ORDER_INVALID')
    return ''.join(lines[:a+1])+marker(BEGIN)+''.join(lines[a+1:end])+marker(END)+''.join(lines[end:])


def bound_inputs(source,target,report,finding,clang):
    from .mechanism_route_checks import compiler_bound_finding
    from .approved_replacement import approved_replacement
    bound,snapshot=compiler_bound_finding(source,report,finding['fragment']['id'])
    if bound!=finding:raise ValueError('L3_CONTROL_FINDING_CHANGED')
    if len(snapshot['functions'])!=1:raise ValueError('L3_CONTROL_SINGLE_FUNCTION_DOMAIN_REQUIRED')
    function=snapshot['functions'][0];control=control_spec(finding,snapshot['functions']);call=signature(function);plan=samples(control,call)
    from .automatic_batch_cli import inspect_entry_points
    _,fresh=inspect_entry_points(Path(source),clang=clang)
    used=('functionId','sourceDigest','parameterTypes','returnType','l2OperandBoundary',
          'compilerIntegerCallSignature','compilerAtomicFunctionScope','compilerContinuationSites')
    if len(fresh)!=1 or any(fresh[0].get(k)!=function.get(k) for k in used):raise ValueError('L3_CONTROL_COMPILER_FACT_REBUILD_MISMATCH')
    if function['functionId']!=control['functionId']:raise ValueError('L3_CONTROL_FUNCTION_IDENTITY_MISMATCH')
    data=Path(source).read_bytes();a=finding['rewriteBeginOffset'];b=finding['rewriteEndOffset']
    if data[a:b].decode()!=finding['rawSourceText'] or data[:a]+approved_replacement(finding).encode()+data[b:]!=Path(target).read_bytes():raise ValueError('L3_CONTROL_TARGET_MATERIALIZATION_MISMATCH')
    return control,call,plan,function


def side_source(path,side,control,function,clang):
    data=Path(path).read_bytes()
    if control['kind']!='asm_goto':return data,None
    if side=='source':sites=function['compilerContinuationSites']
    else:
        from .automatic_batch_cli import inspect_entry_points
        _,functions=inspect_entry_points(Path(path),clang=clang,target_isa='x86_64')
        matches=[f for f in functions if f['name']==function['name']]
        if len(matches)!=1:raise ValueError('L3_CONTROL_TARGET_COMPILER_FUNCTION_AMBIGUOUS')
        sites=matches[0].get('compilerContinuationSites')
    if not sites or sites['sourceDigest']!=digest(path):raise ValueError('L3_CONTROL_CONTINUATION_SOURCE_CHANGED')
    return instrument(data,sites),sites


def region_of(elf,name,goto):
    start,size,idx,_=elf.symbol(name);first=elf.symbol(BEGIN);last=elf.symbol(END)
    if first[2]!=idx or last[2]!=idx or not start<=first[0]<last[0]<start+size:raise ValueError('L3_CONTROL_REGION_OUTSIDE_FUNCTION')
    roles={'fallthrough':last[0]}
    if goto:
        fall=elf.symbol(FALL);taken=elf.symbol(TAKEN)
        if fall[0]!=last[0] or any(s[2]!=idx or not last[0]<=s[0]<start+size for s in (fall,taken)) or taken[0]==fall[0]:raise ValueError('L3_CONTROL_GOTO_EXIT_MAPPING_AMBIGUOUS')
        roles['taken']=taken[0]
    return {'start':first[0],'end':last[0],'exits':sorted(roles.values()),'exitRoles':roles}


def flags(side):return ['-O0','-std=gnu11','-fno-lto']+(['-march=rv64gc','-mabi=lp64d'] if side=='source' else ['-fPIC'])


def build_side(path,side,control,call,plan,function,backend,artifact,work,clang):
    work.mkdir(parents=True);data,sites=side_source(path,side,control,function,clang)
    c=work/'input.c';c.write_bytes(data);assembly=work/'compiler.s';marked=work/'region.s';obj=work/'region.o';wrapper=work/'harness.c';binary=work/'program';cc=backend[side+'Compiler']
    run([cc,*flags(side),'-S',c,'-o',assembly],work,'compile')
    marked.write_text(label_assembly(assembly.read_text(),control['kind']=='asm_goto'))
    run([cc,*flags(side),'-c',marked,'-o',obj],work,'assemble')
    original=Elf(artifact.artifact_path)
    if digest(artifact.artifact_path)!=artifact.artifact_digest or original.machine!=(243 if side=='source' else 62) or Elf(obj).code(function['name'])!=original.code(function['name']):raise ValueError('L3_CONTROL_SEMANTIC_FUNCTION_BYTES_CHANGED:'+side)
    wrapper.write_text(harness(function['name'],call,plan))
    linker=['-Wl,--build-id=none']+(['-Wl,--no-relax'] if side=='source' else [])
    run([cc,*flags(side),'-no-pie',wrapper,obj,*linker,'-o',binary],work,'link')
    final=Elf(binary)
    if final.type!=2 or final.machine!=original.machine or final.code(function['name'])!=original.code(function['name']):raise ValueError('L3_CONTROL_LINKED_FUNCTION_BYTES_CHANGED:'+side)
    region=region_of(final,function['name'],control['kind']=='asm_goto')
    machine=graph(final.code(function['name']),final.symbol(function['name'])[0],region,final.machine)
    files={str(p):digest(p) for p in (c,assembly,marked,obj,wrapper,binary,Path(artifact.artifact_path),*work.glob('*.command.json'))}
    return {'semanticArtifact':{'artifactId':artifact.artifact_id,'artifactPath':str(Path(artifact.artifact_path).resolve()),'artifactDigest':artifact.artifact_digest,'buildIdentity':artifact.build_identity},
        'executionArtifact':{'artifactPath':str(binary),'artifactDigest':digest(binary),'buildIdentity':identity([json.loads(p.read_text()) for p in sorted(work.glob('*.command.json'))])},
        'region':region,'machineGraph':machine,'compilerContinuationSites':sites,'files':files}


def prepare(source,target,report,finding,backend,source_artifact,target_artifact,directory,clang):
    source,target,report=map(lambda p:Path(p).resolve(),(source,target,report));directory=Path(directory).resolve();directory.mkdir(parents=True,exist_ok=False)
    control,call,plan,function=bound_inputs(source,target,report,finding,clang)
    sides={}
    for side,path,artifact in (('source',source,source_artifact),('target',target,target_artifact)):
        sides[side]=build_side(path,side,control,call,plan,function,backend,artifact,directory/side,clang)
    body={'schemaVersion':SCHEMA,'backendIdentity':backend['backendIdentity'],'spec':control,'callSignature':call,'samplePlan':plan,
          'functionName':function['name'],'inputs':{'source':str(source),'target':str(target),'report':str(report)},
          'inputDigests':{str(p):digest(p) for p in (source,target,report)},'clang':clang,'clangDigest':digest(clang),'sides':sides,
          'outsideFragmentEffectsClaimed':False,'physicalMicroarchitectureClaimed':False}
    require_json_document(body,'L3_CONTROL_DEPLOYMENT_JSON_INVALID')
    value=dict(body,deploymentIdentity=identity(body));save(directory/'deployment.json',value);return value


def validate(value,backend,source_artifact,target_artifact):
    require_json_document(value,'L3_CONTROL_DEPLOYMENT_JSON_INVALID')
    if value.get('schemaVersion')!=SCHEMA or value.get('deploymentIdentity')!=identity({k:v for k,v in value.items() if k!='deploymentIdentity'}) or value['backendIdentity']!=backend['backendIdentity'] or value['outsideFragmentEffectsClaimed'] is not False or value['physicalMicroarchitectureClaimed'] is not False:raise ValueError('L3_CONTROL_DEPLOYMENT_IDENTITY_INVALID')
    for p,sha in value['inputDigests'].items():
        if digest(p)!=sha:raise ValueError('L3_CONTROL_DEPLOYMENT_INPUT_CHANGED')
    if digest(value['clang'])!=value['clangDigest']:raise ValueError('L3_CONTROL_COMPILER_CHANGED')
    paths=value['inputs'];data=json.loads(Path(paths['report']).read_text());matches=[f for f in data['findings'] if f['fragment']['id']==value['spec']['fragmentId']]
    if len(matches)!=1:raise ValueError('L3_CONTROL_DEPLOYMENT_FRAGMENT_AMBIGUOUS')
    control,call,plan,function=bound_inputs(paths['source'],paths['target'],paths['report'],matches[0],value['clang'])
    require_json_match([control,call,plan,function['name']],
        [value['spec'],value['callSignature'],value['samplePlan'],value['functionName']],
        'L3_CONTROL_DEPLOYMENT_FACT_REPLAY_MISMATCH')
    for side,artifact in (('source',source_artifact),('target',target_artifact)):
        item=value['sides'][side]
        if item['semanticArtifact']!={'artifactId':artifact.artifact_id,'artifactPath':str(Path(artifact.artifact_path).resolve()),'artifactDigest':artifact.artifact_digest,'buildIdentity':artifact.build_identity}:raise ValueError('L3_CONTROL_SEMANTIC_ARTIFACT_MISMATCH')
        for p,sha in item['files'].items():
            if digest(p)!=sha:raise ValueError('L3_CONTROL_DEPLOYMENT_FILE_CHANGED:'+p)
        with tempfile.TemporaryDirectory(prefix='rv2x86-control-replay-') as temp:
            fresh=build_side(paths[side],side,control,call,plan,function,backend,artifact,Path(temp)/side,value['clang'])
            actual=Elf(item['executionArtifact']['artifactPath']);rebuilt=Elf(fresh['executionArtifact']['artifactPath'])
            for key in ('region','machineGraph','compilerContinuationSites'):
                require_json_match(fresh[key],item[key],'L3_CONTROL_DEPLOYMENT_REBUILD_MISMATCH:'+key)
            if (actual.execution_image()!=rebuilt.execution_image() or item['region']!=fresh['region']
                    or item['machineGraph']!=fresh['machineGraph'] or item['compilerContinuationSites']!=fresh['compilerContinuationSites']):raise ValueError('L3_CONTROL_DEPLOYMENT_REBUILD_MISMATCH')
            # Addresses and graph are rebuilt, not trusted merely by content hash.
            if actual.code(function['name'])!=Elf(artifact.artifact_path).code(function['name']) or digest(item['executionArtifact']['artifactPath'])!=item['executionArtifact']['artifactDigest']:raise ValueError('L3_CONTROL_DEPLOYMENT_CODE_CHANGED')
    return value
