"""Deploy unchanged source and approved builtin; locate RMW in actual function bytes."""
import json
from pathlib import Path
import tempfile
from .l3_trace_support import Elf,digest,identity,run,save,require_json_document,require_json_match
from .l3_lrsc_spec import spec,samples,harness
from .l3_lrsc_machine import function_mechanism
from .l3_control_deployment import flags

SCHEMA='riscv2x86.lrsc-execution-deployment.v1'


def bound_inputs(source,target,report,finding,clang):
    from .mechanism_route_checks import compiler_bound_finding
    from .approved_replacement import approved_replacement
    from .automatic_batch_cli import inspect_entry_points
    bound,snapshot=compiler_bound_finding(source,report,finding['fragment']['id'])
    if bound!=finding or len(snapshot['functions'])!=1:raise ValueError('L3_LRSC_COMPILER_FINDING_MISMATCH')
    function=snapshot['functions'][0];atomic=spec(finding,snapshot['functions'])
    _,fresh=inspect_entry_points(Path(source),clang=clang)
    used=('functionId','sourceDigest','parameterTypes','returnType','l2OperandBoundary','compilerAtomicFunctionScope')
    if len(fresh)!=1 or any(fresh[0].get(k)!=function.get(k) for k in used):raise ValueError('L3_LRSC_COMPILER_REBUILD_MISMATCH')
    data=Path(source).read_bytes();a=finding['rewriteBeginOffset'];b=finding['rewriteEndOffset']
    if data[a:b].decode()!=finding['rawSourceText'] or data[:a]+approved_replacement(finding).encode()+data[b:]!=Path(target).read_bytes():
        raise ValueError('L3_LRSC_TARGET_MATERIALIZATION_MISMATCH')
    return atomic,samples(atomic),function


def build_side(path,side,plan,function,backend,artifact,work,atomic):
    work.mkdir(parents=True);c=work/'input.c';c.write_bytes(Path(path).read_bytes())
    obj=work/'region.o';wrapper=work/'harness.c';binary=work/'program';cc=backend[side+'Compiler']
    run([cc,*flags(side),'-c',c,'-o',obj],work,'compile')
    original=Elf(artifact.artifact_path)
    if digest(artifact.artifact_path)!=artifact.artifact_digest or original.machine!=(243 if side=='source' else 62) or Elf(obj).code(function['name'])!=original.code(function['name']):
        raise ValueError('L3_LRSC_SEMANTIC_FUNCTION_BYTES_CHANGED:'+side)
    wrapper.write_text(harness(function['name'],atomic,plan))
    linker=['-Wl,--build-id=none']+(['-Wl,--no-relax'] if side=='source' else [])
    run([cc,*flags(side),'-no-pie',wrapper,obj,*linker,'-o',binary],work,'link')
    final=Elf(binary)
    if final.type!=2 or final.machine!=original.machine or final.code(function['name'])!=original.code(function['name']):
        raise ValueError('L3_LRSC_LINKED_FUNCTION_BYTES_CHANGED:'+side)
    machine=function_mechanism(final,function['name'],atomic);region=machine['region']
    return {'semanticArtifact':{'artifactId':artifact.artifact_id,'artifactPath':str(Path(artifact.artifact_path).resolve()),'artifactDigest':artifact.artifact_digest,'buildIdentity':artifact.build_identity},
            'executionArtifact':{'artifactPath':str(binary),'artifactDigest':digest(binary)},
            'region':region,'machineMechanism':machine,
            'files':{str(p):digest(p) for p in (c,obj,wrapper,binary,Path(artifact.artifact_path),*work.glob('*.command.json'))}}


def prepare(source,target,report,finding,backend,source_artifact,target_artifact,directory,clang):
    source,target,report=map(lambda p:Path(p).resolve(),(source,target,report));work=Path(directory).resolve();work.mkdir(parents=True,exist_ok=False)
    atomic,plan,function=bound_inputs(source,target,report,finding,clang)
    body={'schemaVersion':SCHEMA,'backendIdentity':backend['backendIdentity'],'spec':atomic,'samplePlan':plan,
          'functionName':function['name'],'inputs':{'source':str(source),'target':str(target),'report':str(report)},
          'inputDigests':{str(p):digest(p) for p in (source,target,report)},'clang':clang,'clangDigest':digest(clang),
          'sides':{side:build_side(p,side,plan,function,backend,a,work/side,atomic) for side,p,a in
                   (('source',source,source_artifact),('target',target,target_artifact))},
          'outsideFragmentEffectsClaimed':False,'physicalMicroarchitectureClaimed':False}
    require_json_document(body,'L3_LRSC_DEPLOYMENT_JSON_INVALID')
    value=dict(body,deploymentIdentity=identity(body));save(work/'deployment.json',value);return value


def validate(value,backend,source_artifact,target_artifact):
    require_json_document(value,'L3_LRSC_DEPLOYMENT_JSON_INVALID')
    fields={'schemaVersion','backendIdentity','spec','samplePlan','functionName','inputs',
        'inputDigests','clang','clangDigest','sides','outsideFragmentEffectsClaimed',
        'physicalMicroarchitectureClaimed','deploymentIdentity'}
    if (type(value) is not dict or set(value)!=fields
            or value.get('schemaVersion')!=SCHEMA or value.get('deploymentIdentity')!=identity({k:v for k,v in value.items() if k!='deploymentIdentity'})
            or value['backendIdentity']!=backend['backendIdentity'] or value['physicalMicroarchitectureClaimed'] is not False
            or value['outsideFragmentEffectsClaimed'] is not False):raise ValueError('L3_LRSC_DEPLOYMENT_INVALID')
    paths=value['inputs']
    if (type(paths) is not dict or set(paths)!={'source','target','report'}
            or any(type(p) is not str for p in paths.values())
            or type(value['inputDigests']) is not dict or set(value['inputDigests'])!=set(paths.values())
            or type(value['sides']) is not dict or set(value['sides'])!={'source','target'}):
        raise ValueError('L3_LRSC_DEPLOYMENT_BINDINGS_INVALID')
    for p,sha in value['inputDigests'].items():
        if digest(p)!=sha:raise ValueError('L3_LRSC_INPUT_CHANGED')
    if digest(value['clang'])!=value['clangDigest']:raise ValueError('L3_LRSC_COMPILER_CHANGED')
    data=json.loads(Path(paths['report']).read_text());findings=data['findings']
    if len(findings)!=1:raise ValueError('L3_LRSC_SINGLE_FRAGMENT_REQUIRED')
    atomic,plan,function=bound_inputs(paths['source'],paths['target'],paths['report'],findings[0],value['clang'])
    require_json_match({'spec':atomic,'samplePlan':plan,'functionName':function['name']},
        {key:value[key] for key in ('spec','samplePlan','functionName')},
        'L3_LRSC_SPEC_REPLAY_MISMATCH')
    for side,artifact in (('source',source_artifact),('target',target_artifact)):
        item=value['sides'][side]
        expected={'artifactId':artifact.artifact_id,'artifactPath':str(Path(artifact.artifact_path).resolve()),'artifactDigest':artifact.artifact_digest,'buildIdentity':artifact.build_identity}
        require_json_match(expected,item['semanticArtifact'],'L3_LRSC_SEMANTIC_ARTIFACT_MISMATCH')
        for p,sha in item['files'].items():
            if digest(p)!=sha:raise ValueError('L3_LRSC_DEPLOYMENT_FILE_CHANGED')
        with tempfile.TemporaryDirectory(prefix='rv2x86-lrsc-replay-') as temp:
            fresh=build_side(paths[side],side,plan,function,backend,artifact,Path(temp)/side,atomic)
            actual=Elf(item['executionArtifact']['artifactPath']);rebuilt=Elf(fresh['executionArtifact']['artifactPath'])
            require_json_match(
                {'executionImage':rebuilt.execution_image(),'region':fresh['region'],'machineMechanism':fresh['machineMechanism']},
                {'executionImage':actual.execution_image(),'region':item['region'],'machineMechanism':item['machineMechanism']},
                'L3_LRSC_INDEPENDENT_REBUILD_MISMATCH')
            if (digest(item['executionArtifact']['artifactPath'])!=item['executionArtifact']['artifactDigest']
                    or actual.code(function['name'])!=Elf(artifact.artifact_path).code(function['name'])):
                raise ValueError('L3_LRSC_INDEPENDENT_REBUILD_MISMATCH')
    return value
