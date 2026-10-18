"""Actual bounded asm-goto input/exit observation provider.

The trace hooks live outside the asm region. They record executed statement
sites, never a predicted branch or an inferred function-return template.
"""
import json
import re
import subprocess
from pathlib import Path
from .compiler_value_flow import identity
from .l2_dimensions import L2Dimension
from .l2_evidence_closure import (provider_precondition_detail, provider_evidence_fields,
    L2ProviderExecutionDisposition)
from .translation_validation import ValidationLayerResult, ValidationLevel
from .validation_status import ValidationStatus

VALUES=(0,1,2,0x7fffffff,0x80000000,0xffffffff,0x7fffffffffffffff,0x8000000000000000,0xffffffffffffffff)
DIMENSIONS=(L2Dimension.CONTROL_FLOW,L2Dimension.LOGICAL_OPERANDS,L2Dimension.SHELL_SEMANTICS)


def instrument_continuations(data, sites, *, label, prefix):
    required={'schemaVersion','sourceDigest','functionIdentity','asmBegin','fallthroughBegin',
        'inputParameterIndex','inputIdentifier','labels','scope','siteFactsIdentity'}
    from hashlib import sha256
    if (not isinstance(sites,dict) or set(sites)!=required
            or sites['schemaVersion']!='riscv2x86.compiler-continuation-sites.v1'
            or sites['scope']!='single_parameter_single_asm_direct_compound'
            or sites['sourceDigest']!='sha256:'+sha256(data).hexdigest()
            or sites['siteFactsIdentity']!=identity({k:v for k,v in sites.items() if k!='siteFactsIdentity'})
            or sites['inputParameterIndex']!=0
            or not isinstance(sites['inputIdentifier'],str)
            or re.fullmatch(r'[A-Za-z_]\w*',sites['inputIdentifier']) is None
            or re.fullmatch(r'r2x_[0-9a-f]{16}',prefix) is None
            or prefix.encode() in data):
        raise ValueError('L2_ASM_GOTO_INSTRUMENTATION_SITE_INVALID')
    labels=[x for x in sites['labels'] if x.get('label')==label]
    if len(labels)!=1:
        raise ValueError('L2_ASM_GOTO_INSTRUMENTATION_LABEL_UNBOUND')
    edits=[(sites['asmBegin'],f'{prefix}_in((unsigned long long)({sites["inputIdentifier"]}));\n'),
        (sites['fallthroughBegin'],f'{prefix}_out(0);\n'),
        (labels[0]['statementBegin'],f'{prefix}_out(1);\n')]
    offsets=[x[0] for x in edits]
    if (any(type(x) is not int or x<0 or x>=len(data) for x in offsets)
            or len(set(offsets))!=len(offsets)
            or sites['fallthroughBegin']<=sites['asmBegin']):
        raise ValueError('L2_ASM_GOTO_INSTRUMENTATION_EXTENT_INVALID')
    patched=data
    for offset,text in sorted(edits,reverse=True):
        patched=patched[:offset]+text.encode()+patched[offset:]
    header=(f'unsigned long long {prefix}_arg; unsigned {prefix}_ni,{prefix}_no,{prefix}_exit,{prefix}_active;\n'
        f'void {prefix}_in(unsigned long long v){{ {prefix}_arg=v; ++{prefix}_ni; {prefix}_active=1; }}\n'
        f'void {prefix}_out(unsigned v){{ if({prefix}_active){{ {prefix}_exit=v; ++{prefix}_no; {prefix}_active=0; }} }}\n')
    manifest={'schemaVersion':'riscv2x86.continuation-instrumentation.v1',
        'siteFactsIdentity':sites['siteFactsIdentity'],'sourceDigest':sites['sourceDigest'],
        'edits':[{'offset':n,'insertedText':s} for n,s in sorted(edits)],'helperPrefix':prefix,
        'scope':'architectural_predicate_observation_only'}
    manifest['instrumentedDigest']='sha256:'+sha256(header.encode()+patched).hexdigest()
    manifest['instrumentationIdentity']=identity(manifest)
    return header.encode()+patched,manifest


def wrapper(function,prefix):
    from .automatic_batch_cli import _INTEGER_TYPE
    if (function.get('arity')!=1 or len(function.get('parameterTypes',[]))!=1
            or _INTEGER_TYPE.fullmatch(function['parameterTypes'][0]) is None
            or _INTEGER_TYPE.fullmatch(function.get('returnType','')) is None
            or re.fullmatch(r'[A-Za-z_]\w*',function.get('name','')) is None):
        raise ValueError('L2_ASM_GOTO_FUNCTION_SIGNATURE_UNSUPPORTED')
    typ=function['parameterTypes'][0]; name=function['name']
    return ('#include <stdio.h>\n#include <stdint.h>\n'
        +f'{function["returnType"]} {name}({typ});\n'
        +f'extern unsigned long long {prefix}_arg; extern unsigned {prefix}_ni,{prefix}_no,{prefix}_exit,{prefix}_active;\n'
        +'int main(void){\n unsigned long long values[]={'+','.join(hex(v)+'ULL' for v in VALUES)+'};\n'
        +' for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);++i){\n'
        +f'{prefix}_ni={prefix}_no={prefix}_active=0; {prefix}_exit=99;\n'
        +f'(void){name}(({typ})values[i]);\n'
        +f'printf("goto_trace;%u;%016llx;%u;%u;%u\\n",i,{prefix}_arg,{prefix}_ni,{prefix}_no,{prefix}_exit);\n'
        +' } return 0; }\n')


def actual_events(stdout,control,width):
    found={}
    for line in stdout.splitlines():
        match=re.fullmatch(r'goto_trace;([0-9]+);([0-9a-f]{16});([0-9]+);([0-9]+);([0-9]+)',line)
        if match is None:
            raise ValueError('L2_ASM_GOTO_TRACE_RECORD_INVALID')
        sample,value,inputs,exits,exit_id=(int(match[1]),int(match[2],16),int(match[3]),int(match[4]),int(match[5]))
        if sample in found or sample>=len(VALUES) or inputs!=1 or exits!=1 or exit_id not in {0,1}:
            raise ValueError('L2_ASM_GOTO_TRACE_ARITY_MISMATCH')
        found[sample]={'sampleId':str(sample),'inputValue':f'{value & ((1<<width)-1):0{width//4}x}',
            'continuationId':control.target_continuation if exit_id else control.source_continuation,
            'inputCount':inputs,'exitCount':exits,'termination':'normal_return'}
    if set(found)!=set(range(len(VALUES))):
        raise ValueError('L2_ASM_GOTO_TRACE_SAMPLE_MISSING')
    return [found[i] for i in range(len(VALUES))]


def build_continuation_validator(config):
    def validate(**kwargs):
        artifact=kwargs.get("translation_artifact")
        from .automatic_l2_effect import (_digest,_run,_finding,_function_for,_approved_relations,
                                        _effect_dimension_evidence,_build_failure_detail)
        from .automatic_batch_cli import inspect_entry_points
        from .l2_authority import l2_authority_sidecar_from_dict
        from .l2_asm_goto import validate_asm_goto_proof_facts
        stage='authority_join'; executed=False
        def reject(code,**details):
            return ValidationLayerResult(ValidationLevel.L2,ValidationStatus.INCONCLUSIVE,
                detail=json.dumps(provider_precondition_detail(code,failureStage=stage,**details),sort_keys=True))
        from .l1_differential import ARCHITECTURAL_COMPARISON_POLICY
        from .validation_status import PreservationMode
        if kwargs.get('level') is not ValidationLevel.L2:
            return reject('L2_ASM_GOTO_LEVEL_MISMATCH')
        if kwargs.get('comparison_policy')!=ARCHITECTURAL_COMPARISON_POLICY:
            return reject('L2_ASM_GOTO_COMPARISON_POLICY_MISMATCH')
        if getattr(artifact,'preservation_mode',None) is not PreservationMode.ARCHITECTURE_EQUIVALENT:
            return reject('L2_ASM_GOTO_ARCHITECTURAL_APPROVAL_REQUIRED')
        try:
            source,target=Path(config['sourcePath']),Path(config['targetPath'])
            if (_digest(source)!=config['sourceDigest'] or _digest(target)!=config['targetDigest']):
                return reject('L2_ASM_GOTO_ARTIFACT_DIGEST_MISMATCH')
            report=json.loads(Path(config['translatedReport']).read_text())
            finding=_finding(report,artifact.fragment_id)
            if finding is None:return reject('L2_ASM_GOTO_FINDING_MISSING')
            approval=finding['approvalArtifact']; fragment=finding['fragment']
            validate_asm_goto_proof_facts(approval.get('l2AsmGotoProofFacts'),fragment,approval)
            authority=l2_authority_sidecar_from_dict(approval['l2AuthoritySidecar'])
            relation_authority,reason=_approved_relations(finding,artifact)
            if relation_authority is None:return reject(reason)
            if (len(authority.control_flow)!=1 or authority.control_flow[0].transfer_kind!='asm_goto'
                    or len(authority.operands)!=1 or authority.operands[0].parameter_index!=0
                    or authority.operands[0].width_bits not in {32,64}
                    or any(r.relation_kind!='exact' for r in authority.approved_effect_relations)):
                return reject('L2_ASM_GOTO_OBSERVER_SCOPE_UNSUPPORTED')
            function=_function_for(finding,config['functions'])
            if function is None:return reject('L2_ASM_GOTO_FUNCTION_BINDING_MISSING')
            _,source_functions=inspect_entry_points(source)
            _,target_functions=inspect_entry_points(target,target_isa='x86_64')
            left_functions=[x for x in source_functions if x['name']==function['name']]
            right_functions=[x for x in target_functions if x['name']==function['name']]
            if len(left_functions)!=1 or len(right_functions)!=1:
                return reject('L2_ASM_GOTO_OBSERVER_FUNCTION_AMBIGUOUS')
            left_function,right_function=left_functions[0],right_functions[0]
            if any(left_function[k]!=right_function[k] for k in ('arity','parameterTypes','returnType')):
                return reject('L2_ASM_GOTO_OBSERVER_ABI_MISMATCH')
            sites=[f.get('compilerContinuationSites') for f in (left_function,right_function)]
            if any(s is None for s in sites):return reject('L2_ASM_GOTO_COMPILER_SITES_UNAVAILABLE')
            key=fragment['compilerFragmentAuthority']['fragmentBindingKey']
            if (sites[0]['asmBegin']!=key['beginOffset']
                    or sites[0]['functionIdentity']!=fragment['compilerFragmentAuthority']['functionIdentity']):
                return reject('L2_ASM_GOTO_SOURCE_SITE_IDENTITY_MISMATCH')
            stage='instrumentation'
            prefix='r2x_'+identity({'fragment':artifact.fragment_id,'authority':authority.authority_identity})[-16:]
            label=fragment['gotoEdges'][0]['cLabel']
            left_data,left_map=instrument_continuations(source.read_bytes(),sites[0],label=label,prefix=prefix)
            right_data,right_map=instrument_continuations(target.read_bytes(),sites[1],label=label,prefix=prefix)
            harness=wrapper(function,prefix)
            work,replay=Path(config['workDirectory']),Path(config['replayDirectory'])
            work.mkdir(parents=True,exist_ok=True);replay.mkdir(parents=True,exist_ok=True)
            (work/'source-instrumented.c').write_bytes(left_data);(work/'target-instrumented.c').write_bytes(right_data)
            (work/'continuation-harness.c').write_text(harness)
            stage='harness_build';timeout=int(config['timeoutSeconds'])
            source_exe,target_exe=work/'source.rv64',work/'target.x86_64'
            left_build=_run(('riscv64-linux-gnu-gcc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',
                '-march=rv64gc','-mabi=lp64d','-static','-I'+str(source.parent),str(work/'continuation-harness.c'),
                str(work/'source-instrumented.c'),'-o',str(source_exe)),work,timeout)
            right_build=_run(('gcc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',
                '-I'+str(target.parent),str(work/'continuation-harness.c'),str(work/'target-instrumented.c'),'-o',str(target_exe)),work,timeout)
            if left_build.returncode or right_build.returncode:
                return reject('L2_ASM_GOTO_HARNESS_BUILD_FAILED',commands=_build_failure_detail(left_build,right_build))
            stage='execution'
            executed=True
            left=_run((config['qemuBinary'],str(source_exe)),work,timeout)
            right=_run((str(target_exe),),work,timeout)
            execution={'schemaVersion':'riscv2x86.continuation-execution.v1',
                'source':{'binaryDigest':_digest(source_exe),'stdout':left.stdout,'stderr':left.stderr,'returnCode':left.returncode},
                'target':{'binaryDigest':_digest(target_exe),'stdout':right.stdout,'stderr':right.stderr,'returnCode':right.returncode}}
            execution['executionArtifactIdentity']=identity(execution)
            (replay/'continuation-execution.json').write_text(json.dumps(execution,indent=2,sort_keys=True)+'\n')
            stage='observation_materialization'
            control=authority.control_flow[0];width=authority.operands[0].width_bits
            source_events=actual_events(left.stdout,control,width)
            target_events=actual_events(right.stdout,control,width)
            success=not(left.returncode or right.returncode or left.stderr or right.stderr) and source_events==target_events
            status=ValidationStatus.VERIFIED if success else ValidationStatus.FAILED
            reason='' if success else 'L2_ASM_GOTO_ACTUAL_CONTINUATION_MISMATCH'
            observation={'schemaVersion':'riscv2x86.auto-l2-effect-observation.v1',
                'mode':'asm-goto-continuations','fragmentId':artifact.fragment_id,
                'approvedRelationAuthority':relation_authority,
                'instrumentation':{'source':left_map,'target':right_map},
                'source':{'events':source_events,'exitCode':left.returncode,'stderr':left.stderr,'execution':execution['source']},
                'target':{'events':target_events,'exitCode':right.returncode,'stderr':right.stderr,'execution':execution['target']},'reasonCode':reason}
            closure=provider_evidence_fields(artifact,provider_id=kwargs.get('l2_provider_id',''),
                harness_identity=identity({'harness':harness,'maps':observation['instrumentation']}),
                execution_nonce={'work':str(work),'mode':'actual-continuations','executionArtifactIdentity':execution['executionArtifactIdentity']},dimensions=DIMENSIONS,
                dimension_evidence=_effect_dimension_evidence(observation,DIMENSIONS),
                execution_disposition=L2ProviderExecutionDisposition.EXECUTED_VERIFIED if success else L2ProviderExecutionDisposition.EXECUTED_FAILED)
            (replay/'effect-observation.json').write_text(json.dumps(observation,indent=2,sort_keys=True)+'\n')
            (replay/'continuation-instrumentation.json').write_text(json.dumps(observation['instrumentation'],indent=2,sort_keys=True)+'\n')
            detail={'schemaVersion':'riscv2x86.auto-l2-effect-result.v2','status':status.value,
                'reasonCode':reason,'fragmentId':artifact.fragment_id,
                'replayArtifact':'effect-observation.json','observationEvidenceIdentity':identity(observation),**closure}
            return ValidationLayerResult(ValidationLevel.L2,status,identity(observation),json.dumps(detail,sort_keys=True))
        except (ValueError,TypeError,KeyError,OSError,subprocess.TimeoutExpired) as exc:
            if executed:
                return ValidationLayerResult(ValidationLevel.L2,ValidationStatus.INCONCLUSIVE,
                    detail=json.dumps({'reasonCode':'L2_ASM_GOTO_'+stage.upper()+'_FAILED',
                        'failureStage':stage,'exceptionType':type(exc).__name__,'detail':str(exc),
                        'artifactPath':str(Path(config['replayDirectory'])/'continuation-execution.json'),
                        'executionDisposition':'executed_inconclusive','evidenceProductionDisposition':'not_produced'}))
            return reject('L2_ASM_GOTO_'+stage.upper()+'_REJECTED',exceptionType=type(exc).__name__,detail=str(exc))
    return validate
