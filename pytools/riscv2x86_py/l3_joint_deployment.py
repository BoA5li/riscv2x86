"""All region labels are zero-byte compiler metadata; C dataflow is unchanged."""
import json
from pathlib import Path
import tempfile
from .l3_trace_support import Elf,digest,identity,run,save
from .l3_joint_spec import spec
from .l3_joint_spec import sample_plan
from .l3_joint_observation import harness

SCHEMA='riscv2x86.joint-program-deployment.v1'


from .l3_trace_support import require_json_document,require_json_match

def marker(i,side):return '__asm__ volatile ('+json.dumps('.globl __rv2x86_r'+str(i)+'_'+side+'\n.hidden __rv2x86_r'+str(i)+'_'+side+'\n__rv2x86_r'+str(i)+'_'+side+':\n')+');\n'


def instrument(data,sites):
    edits=[];last=-1
    for i,site in enumerate(sites):
        a,b=site['begin'],site['end']
        if type(a) is not int or type(b) is not int or not last<=a<b<=len(data):raise ValueError('L3_JOINT_SITE_RANGE_INVALID')
        if data[b:b+1]==b';':b+=1
        elif data[b-1:b]!=b';':raise ValueError('L3_JOINT_STATEMENT_END_REQUIRED')
        edits.extend([(a,marker(i,'begin').encode()),(b,marker(i,'end').encode())]);last=b
    for _,(pos,text) in sorted(enumerate(edits),key=lambda x:(x[1][0],x[0]),reverse=True):data=data[:pos]+text+data[pos:]
    return data


def label_assembly(text,count):
    """Move metadata labels onto original APP code, excluding operand spills.

    A C-level marker alone is insufficient: the compiler may evaluate inputs
    after it or spill outputs before the end marker. Only the original APP
    code between compiler-bound marker pairs is the observed asm region.
    Coalesced APP blocks are supported; no instruction mnemonic is matched.
    """
    lines=text.splitlines(keepends=True);starts=[i for i,s in enumerate(lines) if s.strip()=='#APP'];ends=[i for i,s in enumerate(lines) if s.strip()=='#NO_APP']
    if len(starts)!=len(ends) or any(a>=b for a,b in zip(starts,ends)):raise ValueError('L3_JOINT_APP_LAYOUT_INVALID')
    metadata=set();locations={}
    for i in range(count):
        for edge in ('begin','end'):
            name='__rv2x86_r'+str(i)+'_'+edge;matches=[n for n,s in enumerate(lines) if s.strip()=='.globl '+name]
            if len(matches)!=1:raise ValueError('L3_JOINT_MARKER_NOT_UNIQUE')
            pos=matches[0];parts=[n for n in range(pos,len(lines)) if lines[n].strip() and not lines[n].lstrip().startswith('#')][:3]
            if [lines[n].strip() for n in parts]!=['.globl '+name,'.hidden '+name,name+':'] or not any(a<pos<b for a,b in zip(starts,ends)):raise ValueError('L3_JOINT_MARKER_NOT_METADATA')
            metadata.update(parts);locations[i,edge]=pos
    app_code={n for a,b in zip(starts,ends) for n in range(a+1,b) if n not in metadata and lines[n].strip() and not lines[n].lstrip().startswith('#')}
    claimed=set();insert={}
    for i in range(count):
        selected=sorted(n for n in app_code if locations[i,'begin']<n<locations[i,'end'])
        owners=[(a,b) for a,b in zip(starts,ends) if any(a<n<b for n in selected)]
        if not selected or len(owners)!=1 or claimed&set(selected):raise ValueError('L3_JOINT_ORIGINAL_ASM_BOUNDARY_AMBIGUOUS')
        claimed.update(selected)
        for pos,edge in ((selected[0],'begin'),(selected[-1]+1,'end')):
            name='__rv2x86_r'+str(i)+'_'+edge
            insert.setdefault(pos,[]).append('.globl '+name+'\n.hidden '+name+'\n'+name+':\n')
    if claimed!=app_code:raise ValueError('L3_JOINT_UNBOUND_ASSEMBLY_CODE')
    return ''.join(''.join(insert.get(i,[]))+('' if i in metadata else line) for i,line in enumerate(lines))+''.join(insert.get(len(lines),[]))


def bound(source,target,report,clang):
    from .mechanism_route_checks import compiler_bound_finding
    from .approved_replacement import approved_replacement
    from .automatic_batch_cli import inspect_entry_points
    findings=json.loads(Path(report).read_text())['findings'];functions=None
    for f in findings:
        same,snapshot=compiler_bound_finding(source,report,f['fragment']['id'])
        if same!=f:raise ValueError('L3_JOINT_FINDING_CHANGED')
        if functions is not None and functions!=snapshot['functions']:raise ValueError('L3_JOINT_SNAPSHOT_CONFLICT')
        functions=snapshot['functions']
    program=spec(findings,functions);_,fresh=inspect_entry_points(Path(source),clang=clang)
    if list(fresh)!=functions:raise ValueError('L3_JOINT_COMPILER_SNAPSHOT_REBUILD_MISMATCH')
    original=Path(source).read_bytes();edits=[]
    for f in findings:
        a,b=f['rewriteBeginOffset'],f['rewriteEndOffset']
        if type(a) is not int or type(b) is not int or not 0<=a<b<=len(original) or original[a:b].decode()!=f['rawSourceText']:raise ValueError('L3_JOINT_REPLACEMENT_RANGE_CHANGED')
        edits.append((a,b,approved_replacement(f).encode()))
    ordered=sorted(edits)
    if any(a[1]>b[0] for a,b in zip(ordered,ordered[1:])):raise ValueError('L3_JOINT_REPLACEMENTS_OVERLAP')
    for a,b,text in sorted(edits,reverse=True):original=original[:a]+text+original[b:]
    if original!=Path(target).read_bytes():raise ValueError('L3_JOINT_TARGET_MATERIALIZATION_MISMATCH')
    from .l3_entry_binding import entry
    return program,entry(functions,program['functionIdentity'])


def flags(side):return ['-O0','-std=gnu11','-fno-lto']+(['-march=rv64gc','-mabi=lp64d'] if side=='source' else ['-fPIC'])


def build_side(path,side,program,function,backend,artifact,work,clang,count):
    from .automatic_batch_cli import inspect_entry_points
    work.mkdir(parents=True);data=Path(path).read_bytes()
    if side=='source':scope=program['scope']
    else:
        _,functions=inspect_entry_points(Path(path),clang=clang,target_isa='x86_64')
        matches=[f for f in functions if f['name']==function['name']]
        if len(matches)!=1:raise ValueError('L3_JOINT_TARGET_FUNCTION_CHANGED')
        scope=matches[0].get('compilerJointScope')
    if not scope or len(scope['sites'])!=len(program['members']) or scope['sourceDigest']!=digest(path):raise ValueError('L3_JOINT_TARGET_REGIONS_MISSING')
    c=work/'input.c';c.write_bytes(instrument(data,scope['sites']));asm=work/'compiler.s';marked=work/'regions.s';obj=work/'regions.o';h=work/'harness.c';binary=work/'program';cc=backend[side+'Compiler']
    run([cc,*flags(side),'-S',c,'-o',asm],work,'compile');marked.write_text(label_assembly(asm.read_text(),len(program['members'])))
    run([cc,*flags(side),'-c',marked,'-o',obj],work,'assemble')
    original=Elf(artifact.artifact_path);name=function['name']
    if digest(artifact.artifact_path)!=artifact.artifact_digest or original.machine!=(243 if side=='source' else 62) or Elf(obj).code(name)!=original.code(name):raise ValueError('L3_JOINT_INSTRUMENTATION_CHANGED_FUNCTION:'+side)
    h.write_text(harness(program,sample_plan(program,count)))
    run([cc,*flags(side),'-no-pie',h,obj,'-Wl,--build-id=none',*(['-Wl,--no-relax'] if side=='source' else []),'-o',binary],work,'link')
    elf=Elf(binary);start,size,section,_=elf.symbol(name);regions=[]
    if elf.type!=2 or elf.machine!=original.machine or elf.code(name)!=original.code(name):raise ValueError('L3_JOINT_LINK_CHANGED_FUNCTION:'+side)
    for i in range(len(program['members'])):
        a=elf.symbol('__rv2x86_r'+str(i)+'_begin');b=elf.symbol('__rv2x86_r'+str(i)+'_end')
        if a[2]!=section or b[2]!=section or not start<=a[0]<b[0]<start+size or regions and a[0]<regions[-1]['end']:raise ValueError('L3_JOINT_BINARY_REGIONS_INVALID')
        regions.append({'start':a[0],'end':b[0]})
    return {'semanticArtifact':{'artifactId':artifact.artifact_id,'artifactPath':str(Path(artifact.artifact_path).resolve()),'artifactDigest':artifact.artifact_digest,'buildIdentity':artifact.build_identity},
        'executionArtifact':{'artifactPath':str(binary),'artifactDigest':digest(binary)},'regions':regions,'compilerSites':scope,
        'files':{str(p):digest(p) for p in (c,asm,marked,obj,h,binary,Path(artifact.artifact_path),*work.glob('*.command.json'))}}


def prepare(source,target,report,backend,source_artifact,target_artifact,work,clang,count):
    source,target,report=map(lambda p:Path(p).resolve(),(source,target,report));program,function=bound(source,target,report,clang);work=Path(work).resolve();work.mkdir(parents=True,exist_ok=False)
    body={'schemaVersion':SCHEMA,'spec':program,'samplePlan':sample_plan(program,count),
        'backendIdentity':backend['backendIdentity'],'clang':clang,'clangDigest':digest(clang),
        'inputs':{'source':str(source),'target':str(target),'report':str(report)},'inputDigests':{str(p):digest(p) for p in (source,target,report)},
        'sides':{s:build_side(p,s,program,function,backend,a,work/s,clang,count) for s,p,a in (('source',source,source_artifact),('target',target,target_artifact))},
        'physicalMicroarchitectureClaimed':False,'executionUnit':'whole-function-all-ordered-regions'}
    require_json_document(body,'L3_JOINT_DEPLOYMENT_JSON_INVALID')
    value=dict(body,deploymentIdentity=identity(body));save(work/'deployment.json',value);return value


def validate(value,backend,source,target):
    require_json_document(value,'L3_JOINT_DEPLOYMENT_JSON_INVALID')
    if value.get('schemaVersion')!=SCHEMA or value['deploymentIdentity']!=identity({k:v for k,v in value.items() if k!='deploymentIdentity'}) or value['backendIdentity']!=backend['backendIdentity'] or value['physicalMicroarchitectureClaimed'] is not False or value['executionUnit']!='whole-function-all-ordered-regions':raise ValueError('L3_JOINT_DEPLOYMENT_INVALID')
    for p,sha in value['inputDigests'].items():
        if digest(p)!=sha:raise ValueError('L3_JOINT_INPUT_CHANGED')
    if digest(value['clang'])!=value['clangDigest']:raise ValueError('L3_JOINT_AST_COMPILER_CHANGED')
    with tempfile.TemporaryDirectory(prefix='rv2x86-program-replay-') as temp:
        fresh=prepare(**{k:value['inputs'][k] for k in ('source','target','report')},backend=backend,source_artifact=source,target_artifact=target,work=Path(temp)/'deployment',clang=value['clang'],count=len(value['samplePlan']['inputs']))
        require_json_match({'spec':fresh['spec'],'samplePlan':fresh['samplePlan']},
            {'spec':value['spec'],'samplePlan':value['samplePlan']},'L3_JOINT_FACT_REPLAY_MISMATCH')
        for side in ('source','target'):
            a=value['sides'][side];b=fresh['sides'][side]
            for p,sha in a['files'].items():
                if digest(p)!=sha:raise ValueError('L3_JOINT_DEPLOYMENT_FILE_CHANGED:'+p)
            if (a['semanticArtifact']!=b['semanticArtifact'] or a['regions']!=b['regions'] or a['compilerSites']!=b['compilerSites']
                    or digest(a['executionArtifact']['artifactPath'])!=a['executionArtifact']['artifactDigest']
                    or Elf(a['executionArtifact']['artifactPath']).execution_image()!=Elf(b['executionArtifact']['artifactPath']).execution_image()):raise ValueError('L3_JOINT_INDEPENDENT_REBUILD_MISMATCH')
    return value
