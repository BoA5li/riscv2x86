"""Deploy approved bounded single-asm ordinary accesses using zero-instruction compiler labels.

The observer scope is exactly the compiler APP region, not the whole function.
Both object and final executable function bytes must equal the actual approved
code artifact. Any compiler/linker change rejects this route rather than being
normalized away. Existing native L0-L2 executions remain separately identified.
"""
import json
from pathlib import Path
import re
import subprocess
import tempfile

from .l3_trace_support import Elf, digest, identity, run, save
from .l3_memory_intent import memory_spec

SCHEMA='riscv2x86.compiler-region-execution-deployment.v1'
_INTEGER=r'(?:u?int(?:8|16|32|64)_t|unsigned(?: (?:char|short|int|long|long long))?|signed(?: (?:char|short|int|long|long long))?|char|short|int|long|long long)'


def label_assembly(text):
    lines=text.splitlines(keepends=True)
    starts=[i for i,line in enumerate(lines) if line.strip()=='#APP']
    ends=[i for i,line in enumerate(lines) if line.strip()=='#NO_APP']
    if len(starts)!=1 or len(ends)!=1 or starts[0]>=ends[0]:
        raise ValueError('L3_TRACE_COMPILER_ASM_BOUNDARY_UNSUPPORTED')
    begin='.globl __rv2x86_fragment_begin\n.hidden __rv2x86_fragment_begin\n__rv2x86_fragment_begin:\n'
    end='.globl __rv2x86_fragment_end\n.hidden __rv2x86_fragment_end\n__rv2x86_fragment_end:\n'
    return ''.join(lines[:starts[0]+1])+begin+''.join(lines[starts[0]+1:ends[0]])+end+''.join(lines[ends[0]:])


def function_scope(source, report, finding):
    from .mechanism_route_checks import compiler_bound_finding
    fid=finding['fragment']['id']; bound,snapshot=compiler_bound_finding(source,report,fid)
    if bound!=finding: raise ValueError('L3_TRACE_FINDING_CHANGED')
    functions=snapshot['functions']; boundary=finding['approvalArtifact']['l2FragmentOperandBoundary']
    if len(functions)!=1: raise ValueError('L3_TRACE_SINGLE_FUNCTION_SCOPE_REQUIRED')
    function=functions[0]; scope=function.get('compilerAtomicFunctionScope') or {}
    name=function.get('name'); result=function.get('returnType'); parameters=function.get('parameterTypes')
    spec=memory_spec(finding)
    if spec['access']=='write':
        store=function.get('compilerStoreFunctionScope') or {}
        normalized=[re.sub(r'\s+',' ',p.strip()) for p in parameters or []]
        if (not isinstance(name,str) or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',name) is None
                or name!=finding['fragment'].get('enclosingFunction')
                or function.get('functionId')!=boundary.get('functionId')
                or normalized not in [['uint64_t *','uint64_t'],['unsigned long *','unsigned long']]
                or result not in {'uint64_t','unsigned long'} or spec['width']!=8
                or store.get('scope')!='single_asm_and_bound_object_return'
                or store.get('sourceDigest')!=digest(source)
                or store.get('functionIdentity')!=function['functionId']
                or type(store.get('returnElementIndex')) is not int
                or store['returnElementIndex']*8!=spec['offset']):
            raise ValueError('L3_TRACE_COMPILER_STORE_SCOPE_UNSUPPORTED')
        return {'name':name,'returnType':result,'parameterType':parameters[0],
                'valueParameterType':parameters[1],'functionIdentity':function['functionId'],
                'scopeIdentity':store['scopeIdentity']}
    if (not isinstance(name,str) or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',name) is None or
            name!=finding['fragment'].get('enclosingFunction') or function.get('functionId')!=boundary.get('functionId') or
            scope.get('scope')!='single_asm_no_other_memory_or_control_effects' or scope.get('sourceDigest')!=digest(source) or
            not isinstance(result,str) or re.fullmatch(_INTEGER,result) is None or not isinstance(parameters,list) or
            len(parameters)!=1 or not isinstance(parameters[0],str) or
            re.fullmatch(r'(?:const )?'+_INTEGER+r' \*',parameters[0]) is None):
        raise ValueError('L3_TRACE_COMPILER_FUNCTION_SCOPE_UNSUPPORTED')
    return {'name':name,'returnType':result,'parameterType':parameters[0],
            'functionIdentity':function['functionId'],'scopeIdentity':scope['scopeIdentity']}


def harness(scope, spec, samples):
    if spec['access']=='write': return store_harness(scope,spec,samples)
    # Metadata is emitted outside the observed asm region. The object is real,
    # initialized and private. No timing/non-interference claim is made for it.
    return '''#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
extern %s %s(%s);
int main(int argc,char **argv){
 if(argc!=2 || strlen(argv[1])!=64) return 2;
 _Alignas(64) uint64_t object[%d];
 for(unsigned sample=0;sample<%d;++sample){
  unsigned char *bytes=(unsigned char *)object;
  for(unsigned i=0;i<sizeof object;++i) bytes[i]=(unsigned char)(0x31u+17u*i+sample);
  uint64_t value=(uint64_t)%s((%s)object);
  printf("{\\"token\\":\\"%%s\\",\\"sample\\":%%u,\\"objectBase\\":\\"%%" PRIxPTR "\\",\\"objectSize\\":%%zu,\\"value\\":\\"%%016" PRIx64 "\\"}\\n",argv[1],sample,(uintptr_t)object,sizeof object,value);
 }
 return 0;
}
''' % (scope['returnType'],scope['name'],scope['parameterType'],(spec['size']+7)//8,samples,scope['name'],scope['parameterType'])


def prepare(source, target, report, finding, backend, source_artifact, target_artifact, directory, samples):
    from .l3_qemu_backend import validate_backend
    backend=validate_backend(backend)
    directory=Path(directory).resolve(); directory.mkdir(parents=True,exist_ok=False)
    spec=memory_spec(finding); scope=function_scope(source,report,finding)
    source=Path(source).resolve(); target=Path(target).resolve()
    if digest(source)!=finding['sourceDigest']: raise ValueError('L3_TRACE_SOURCE_CHANGED')
    from .approved_replacement import approved_replacement
    # Candidate materialization is checked by the evaluator. Recheck its asm
    # replacement digest through the original approved finding, not C matching.
    replacement=approved_replacement(finding)
    if not replacement: raise ValueError('L3_TRACE_APPROVED_REPLACEMENT_MISSING')
    original=source.read_bytes(); begin=finding.get('rewriteBeginOffset'); end=finding.get('rewriteEndOffset')
    if (type(begin) is not int or type(end) is not int or not 0<=begin<end<=len(original) or
            original[begin:end].decode()!=finding.get('rawSourceText') or
            original[:begin]+replacement.encode()+original[end:]!=target.read_bytes()):
        raise ValueError('L3_TRACE_TARGET_MATERIALIZATION_MISMATCH')
    code_files={str(source):digest(source),str(target):digest(target),str(Path(report).resolve()):digest(report)}
    deployments={}
    for side,path,original,expected_machine in (
            ('source',source,source_artifact,243),('target',target,target_artifact,62)):
        work=directory/side; work.mkdir()
        compiler=backend[side+'Compiler']
        original_elf=Elf(original.artifact_path)
        if original_elf.machine!=expected_machine or digest(original.artifact_path)!=original.artifact_digest:
            raise ValueError('L3_TRACE_SEMANTIC_ARTIFACT_INVALID:'+side)
        flags=['-O0','-std=gnu11','-fno-lto']
        if side=='source': flags+=['-march=rv64gc','-mabi=lp64d']
        else: flags+=['-fPIC']
        assembly=work/'compiler.s'
        run([compiler,*flags,'-S',path,'-o',assembly],work,'compiler-assembly')
        marked=work/'region.s'; marked.write_text(label_assembly(assembly.read_text()))
        obj=work/'region.o'
        run([compiler,*flags,'-c',marked,'-o',obj],work,'assemble-region')
        if Elf(obj).code(scope['name'])!=original_elf.code(scope['name']):
            raise ValueError('L3_TRACE_COMPILER_FUNCTION_BYTES_CHANGED:'+side)
        wrapper=work/'harness.c'; wrapper.write_text(harness(scope,spec,samples))
        executable=work/'program'
        linker_flags=['-Wl,--build-id=none']+(['-Wl,--no-relax'] if side=='source' else [])
        run([compiler,*flags,'-no-pie',wrapper,obj,*linker_flags,'-o',executable],work,'link-harness')
        final=Elf(executable)
        if final.type!=2 or final.machine!=expected_machine or final.code(scope['name'])!=original_elf.code(scope['name']):
            raise ValueError('L3_TRACE_LINKED_FUNCTION_BYTES_CHANGED:'+side)
        region=final.region(scope['name'])
        files={str(p):digest(p) for p in (assembly,marked,obj,wrapper,executable,Path(original.artifact_path))}
        commands=sorted(work.glob('*.command.json'))
        files.update({str(p):digest(p) for p in commands})
        body={'semanticArtifact':{'artifactId':original.artifact_id,'artifactPath':str(Path(original.artifact_path).resolve()),
                'artifactDigest':original.artifact_digest,'buildIdentity':original.build_identity},
              'executionArtifact':{'artifactPath':str(executable),'artifactDigest':digest(executable),
                'buildIdentity':identity([json.loads(p.read_text()) for p in commands])},
              'region':region,'functionCodeDigest':'sha256:'+__import__('hashlib').sha256(final.code(scope['name'])).hexdigest(),
              'files':files,'executor':backend[side+'Executor'],'executorDigest':digest(backend[side+'Executor']),
              'runnerArguments':backend[side+'RunnerArguments']}
        deployments[side]=body
    value={'schemaVersion':SCHEMA,'backendIdentity':backend['backendIdentity'],'spec':spec,'functionScope':scope,
           'sampleCount':samples,'sourceAndTargetFiles':code_files,'inputs':{'source':str(source),'target':str(target),'report':str(Path(report).resolve())},'sides':deployments,
           'captureBoundary':'compiler-asm-region-only','compilerRegionWitness':'zero-byte-labels-and-exact-function-bytes',
           'outsideFragmentEffectsClaimed':False}
    value['deploymentIdentity']=identity(value)
    save(directory/'deployment.json',value)
    return value


def validate(value, backend, source_artifact, target_artifact):
    fields={'schemaVersion','backendIdentity','spec','functionScope','sampleCount','sourceAndTargetFiles','sides',
            'captureBoundary','compilerRegionWitness','outsideFragmentEffectsClaimed','deploymentIdentity','inputs'}
    if not isinstance(value,dict) or set(value)!=fields or value['schemaVersion']!=SCHEMA or value['deploymentIdentity']!=identity({k:v for k,v in value.items() if k!='deploymentIdentity'}):
        raise ValueError('L3_TRACE_DEPLOYMENT_IDENTITY_INVALID')
    if (value['backendIdentity']!=backend['backendIdentity'] or value['captureBoundary']!='compiler-asm-region-only' or
            value['compilerRegionWitness']!='zero-byte-labels-and-exact-function-bytes' or value['outsideFragmentEffectsClaimed'] is not False):
        raise ValueError('L3_TRACE_DEPLOYMENT_SCOPE_INVALID')
    for path,expected in value['sourceAndTargetFiles'].items():
        if digest(path)!=expected: raise ValueError('L3_TRACE_DEPLOYMENT_SOURCE_CHANGED')
    inputs=value['inputs']; data=json.loads(Path(inputs['report']).read_text())
    findings=[f for f in data['findings'] if (f.get('fragment') or {}).get('id')==value['spec']['fragmentId']]
    if len(findings)!=1 or memory_spec(findings[0])!=value['spec'] or function_scope(inputs['source'],inputs['report'],findings[0])!=value['functionScope']:
        raise ValueError('L3_TRACE_DEPLOYMENT_PROOF_REPLAY_MISMATCH')
    from .approved_replacement import approved_replacement
    finding=findings[0]; original=Path(inputs['source']).read_bytes()
    begin=finding['rewriteBeginOffset']; end=finding['rewriteEndOffset']
    if original[:begin]+approved_replacement(finding).encode()+original[end:]!=Path(inputs['target']).read_bytes():
        raise ValueError('L3_TRACE_DEPLOYMENT_TARGET_REPLAY_MISMATCH')
    for side,artifact in (('source',source_artifact),('target',target_artifact)):
        item=value['sides'][side]; semantic=item['semanticArtifact']
        if semantic!={'artifactId':artifact.artifact_id,'artifactPath':str(Path(artifact.artifact_path).resolve()),
                      'artifactDigest':artifact.artifact_digest,'buildIdentity':artifact.build_identity}:
            raise ValueError('L3_TRACE_DEPLOYMENT_SEMANTIC_BINDING_MISMATCH')
        for path,expected in item['files'].items():
            if digest(path)!=expected: raise ValueError('L3_TRACE_DEPLOYMENT_FILE_CHANGED:'+path)
        binary=Elf(item['executionArtifact']['artifactPath']); original=Elf(artifact.artifact_path)
        if (binary.type!=2 or binary.machine!=(243 if side=='source' else 62) or
                binary.code(value['functionScope']['name'])!=original.code(value['functionScope']['name']) or
                binary.region(value['functionScope']['name'])!=item['region'] or
                digest(item['executionArtifact']['artifactPath'])!=item['executionArtifact']['artifactDigest'] or
                item['executor']!=backend[side+'Executor'] or item['executorDigest']!=digest(backend[side+'Executor']) or
                item['runnerArguments']!=backend[side+'RunnerArguments']):
            raise ValueError('L3_TRACE_DEPLOYMENT_REGION_OR_EXECUTION_MISMATCH')
        work=Path(item['executionArtifact']['artifactPath']).parent
        flags=['-O0','-std=gnu11','-fno-lto']+(['-march=rv64gc','-mabi=lp64d'] if side=='source' else ['-fPIC'])
        assembly=work/'compiler.s'; marked=work/'region.s'
        if (work/'harness.c').read_text()!=harness(value['functionScope'],value['spec'],value['sampleCount']):
            raise ValueError('L3_TRACE_REGISTERED_HARNESS_CHANGED')
        if marked.read_text()!=label_assembly(assembly.read_text()):
            raise ValueError('L3_TRACE_COMPILER_LABEL_WITNESS_MISMATCH')
        # Recompute the boundary witness from the actual bound C input and
        # pinned compiler, not a file-owned verified=true or a content hash.
        with tempfile.TemporaryDirectory(prefix='rv2x86-l3-region-replay-') as tmp:
            fresh=Path(tmp)/'compiler.s'; fresh_obj=Path(tmp)/'region.o'; fresh_marked=Path(tmp)/'region.s'
            result=subprocess.run([backend[side+'Compiler'],*flags,'-S',inputs[side],'-o',str(fresh)],capture_output=True,text=True,timeout=120,check=False)
            if result.returncode or fresh.read_bytes()!=assembly.read_bytes():
                raise ValueError('L3_TRACE_COMPILER_BOUNDARY_REPLAY_MISMATCH')
            fresh_marked.write_text(label_assembly(fresh.read_text()))
            result=subprocess.run([backend[side+'Compiler'],*flags,'-c',str(fresh_marked),'-o',str(fresh_obj)],capture_output=True,text=True,timeout=120,check=False)
            if result.returncode: raise ValueError('L3_TRACE_COMPILER_REGION_REPLAY_FAILED')
            rebuilt=Elf(fresh_obj); rebuilt_region=rebuilt.region(value['functionScope']['name'])
            if (rebuilt.code(value['functionScope']['name'])!=original.code(value['functionScope']['name']) or
                    [rebuilt_region[k]-rebuilt_region['functionStart'] for k in ('start','end')] !=
                    [item['region'][k]-item['region']['functionStart'] for k in ('start','end')]):
                raise ValueError('L3_TRACE_COMPILER_REGION_ATTRIBUTION_MISMATCH')
            fresh_wrapper=Path(tmp)/'harness.c'; fresh_binary=Path(tmp)/'program'
            fresh_wrapper.write_text(harness(value['functionScope'],value['spec'],value['sampleCount']))
            linker_flags=['-Wl,--build-id=none']+(['-Wl,--no-relax'] if side=='source' else [])
            result=subprocess.run([backend[side+'Compiler'],*flags,'-no-pie',str(fresh_wrapper),str(fresh_obj),
                *linker_flags,'-o',str(fresh_binary)],capture_output=True,text=True,timeout=120,check=False)
            if result.returncode or Elf(fresh_binary).execution_image()!=binary.execution_image():
                raise ValueError('L3_TRACE_EXECUTION_IMAGE_REBUILD_MISMATCH')

    return value


def store_harness(scope, spec, samples):
    """Observe object post-state outside the compiler asm trace boundary."""
    return r'''#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
extern %s %s(%s,%s);
int main(int argc,char **argv){
 if(argc!=2 || strlen(argv[1])!=64) return 2;
 _Alignas(64) uint64_t object[%d];
 for(unsigned sample=0;sample<%d;++sample){
  unsigned char *bytes=(unsigned char *)object;
  for(unsigned i=0;i<sizeof object;++i) bytes[i]=(unsigned char)(0x31u+17u*i+sample);
  uint64_t written=UINT64_C(0x1020304050607080)+sample;
  uint64_t value=(uint64_t)%s((%s)object,(%s)written);
  printf("{\"token\":\"%%s\",\"sample\":%%u,\"objectBase\":\"%%" PRIxPTR "\",\"objectSize\":%%zu,\"value\":\"%%016" PRIx64 "\",\"objectHex\":\"",argv[1],sample,(uintptr_t)object,sizeof object,value);
  for(unsigned i=0;i<sizeof object;++i) printf("%%02x",bytes[i]);
  puts("\"}");
 }
 return 0;
}
''' % (scope['returnType'],scope['name'],scope['parameterType'],scope['valueParameterType'],
       (spec['size']+7)//8,samples,scope['name'],scope['parameterType'],scope['valueParameterType'])
