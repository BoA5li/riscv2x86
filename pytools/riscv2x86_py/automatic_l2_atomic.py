"""Atomic RMW execution observations plus independently approved static proof.

Atomicity/order is attributed to Phase 6D, not inferred from absence of a
forbidden outcome in a finite single-thread experiment.
"""
import json
import re
import subprocess
from pathlib import Path
from .compiler_value_flow import identity
from .l2_dimensions import L2Dimension
from .l2_evidence_closure import (L2DimensionEvidence,provider_evidence_fields,
    provider_precondition_detail,L2ProviderExecutionDisposition)
from .translation_validation import ValidationLayerResult,ValidationLevel
from .validation_status import ValidationStatus,PreservationMode

DIMENSIONS=(L2Dimension.ATOMIC_MEMORY_ORDER,L2Dimension.LOGICAL_OPERANDS,
            L2Dimension.MEMORY_EFFECTS,L2Dimension.SHELL_SEMANTICS)
VALUES=(0,1,0xffffffffffffffff,0x7fffffff,0x80000000,0xffffffff,0x7fffffffffffffff,0x8000000000000000)
BUILTINS={'fetch_add':'c.builtin.atomic-fetch-add.u32-u64.v2',
    'fetch_and':'c.builtin.atomic-fetch-and.u32-u64.v2','fetch_or':'c.builtin.atomic-fetch-or.u32-u64.v2',
    'fetch_xor':'c.builtin.atomic-fetch-xor.u32-u64.v2','exchange':'c.builtin.atomic-exchange.u32-u64.v2'}


def atomic_wrapper(function,atom,sidecar):
    from .automatic_batch_cli import _INTEGER_TYPE,_INTEGER_POINTER_TYPE
    types=function['parameterTypes'];pointers=function['pointerParameters']
    by_index={x.operand_index:x for x in sidecar.operands}
    address=by_index[atom['address_operand_index']];value=by_index[atom['value_operand_index']]
    address_parameter=address.parameter_index
    if atom.get('address_projection'):
        base=atom['address_projection']['baseDeclarationIdentity']
        parameters=function['l2OperandBoundary']['parameterDeclarationIds']
        if base not in parameters:raise ValueError('L2_ATOMIC_ADDRESS_PARAMETER_UNBOUND')
        address_parameter=parameters.index(base)
    if (function.get('arity')!=2 or len(types)!=2 or len(pointers)!=1
            or address_parameter!=pointers[0] or value.parameter_index is None
            or value.parameter_index==address_parameter
            or _INTEGER_POINTER_TYPE.fullmatch(types[pointers[0]]) is None
            or _INTEGER_TYPE.fullmatch(types[value.parameter_index]) is None
            or (function['returnType']!='void' and _INTEGER_TYPE.fullmatch(function['returnType']) is None)
            or re.fullmatch(r'[A-Za-z_]\w*',function['name']) is None):
        raise ValueError('L2_ATOMIC_HARNESS_SIGNATURE_UNSUPPORTED')
    if atom['result_semantics']=='old_value' and function['returnType']=='void':
        raise ValueError('L2_ATOMIC_RETURN_OBSERVATION_CONTRACT_REQUIRED')
    pointee=' '.join(x for x in types[pointers[0]][:-1].split() if x not in {'const','volatile'})
    scalar=types[value.parameter_index];name=function['name'];width=atom['width_bits']
    args=['',''];args[pointers[0]]='object';args[value.parameter_index]='input'
    return '\n'.join([
        '#include <stdint.h>','#include <stdio.h>','#include <string.h>',
        f'{function["returnType"]} {name}({",".join(types)});',
        f'typedef {pointee} element;',f'_Static_assert(sizeof(element)=={width//8},"atomic object width");',
        f'_Static_assert(sizeof({scalar})=={value.width_bits//8},"atomic input width");',
        '_Static_assert(__atomic_always_lock_free(sizeof(element),0),"atomic lock-free contract");',
        'int main(void){const unsigned long long values[]={'+','.join(hex(x)+'ULL' for x in VALUES)+'};',
        'for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);++i){',
        'element object[32/sizeof(element)] __attribute__((aligned(16)));',
        'uint64_t initial[4]={UINT64_C(0x1122334455667788),UINT64_C(0x8877665544332211),UINT64_C(0x0123456789abcdef),UINT64_C(0xfedcba9876543210)};',
        ('initial[0]=(UINT64_C(0x1122334400000000)|(uint32_t)values[(i+5)%8]);' if width==32 else 'initial[0]=values[(i+3)%8];'),
        'uint64_t before[4],after[4];memcpy(object,initial,32);memcpy(before,object,32);',
        f'{scalar} input=({scalar})values[i];',
        (f'{name}({",".join(args)});unsigned long long result=0;' if function['returnType']=='void' else
         f'{function["returnType"]} returned={name}({",".join(args)});unsigned long long result=(unsigned long long)returned;'),
        'memcpy(after,object,32);',
        'printf("atomic_trace;%u;%016llx;%016llx;%016llx,%016llx,%016llx,%016llx;%016llx,%016llx,%016llx,%016llx\\n",i,(unsigned long long)input,result,',
        '(unsigned long long)before[0],(unsigned long long)before[1],(unsigned long long)before[2],(unsigned long long)before[3],',
        '(unsigned long long)after[0],(unsigned long long)after[1],(unsigned long long)after[2],(unsigned long long)after[3]);',
        '}return 0;}'])+'\n'


def atomic_events(stdout,atom):
    records={};width=atom['width_bits'];mask=(1<<width)-1;operation=atom['rmw_operation']
    for line in stdout.splitlines():
        match=re.fullmatch(r'atomic_trace;([0-9]+);([0-9a-f]{16});([0-9a-f]{16});([0-9a-f]{16}(?:,[0-9a-f]{16}){3});([0-9a-f]{16}(?:,[0-9a-f]{16}){3})',line)
        if match is None:raise ValueError('L2_ATOMIC_TRACE_RECORD_INVALID')
        sample=int(match[1]);input_value=int(match[2],16)&mask;returned=int(match[3],16)
        before=[int(x,16) for x in match[4].split(',')];after=[int(x,16) for x in match[5].split(',')]
        if sample in records or sample>=len(VALUES):raise ValueError('L2_ATOMIC_TRACE_ARITY_MISMATCH')
        old=before[0]&mask
        expected={'fetch_add':lambda:(old+input_value)&mask,'fetch_and':lambda:old&input_value,
            'fetch_or':lambda:old|input_value,'fetch_xor':lambda:old^input_value,'exchange':lambda:input_value}[operation]()
        relation_holds=not ((after[0]&mask)!=expected or after[1:]!=before[1:]
                or (width==32 and (after[0]>>32)!=(before[0]>>32))
                or (atom['result_semantics']=='old_value' and (returned&mask)!=old))
        records[sample]={'sampleId':str(sample),'objectId':atom['memory_object_identity'],
            'offsetBytes':0,'widthBits':width,'inputValue':input_value,'oldValue':old,
            'newValue':after[0]&mask,'returnedValue':returned,'beforeObject':before,'afterObject':after,
            'approvedValueRelationHolds':relation_holds,
            'effectKind':'AtomicReadModifyWrite','relationEvidence':'measured-values-with-approved-rmw-contract'}
    if set(records)!=set(range(len(VALUES))):raise ValueError('L2_ATOMIC_TRACE_SAMPLE_MISSING')
    return [records[i] for i in range(len(VALUES))]


def build_atomic_validator(config):
    def validate(**kwargs):
        from .l1_differential import ARCHITECTURAL_COMPARISON_POLICY
        from .automatic_l2_effect import _digest,_run,_finding,_function_for,_approved_relations,_build_failure_detail
        from .l2_atomic_authority import validate_atomic_proof_facts,materialize_atomic_authority
        from .l2_authority import l2_authority_sidecar_from_dict
        from .automatic_batch_cli import inspect_entry_points
        artifact=kwargs.get('translation_artifact');stage='authority_join';executed=False
        def reject(code,**details):
            return ValidationLayerResult(ValidationLevel.L2,ValidationStatus.INCONCLUSIVE,
                detail=json.dumps(provider_precondition_detail(code,failureStage=stage,**details),sort_keys=True))
        if kwargs.get('level') is not ValidationLevel.L2 or kwargs.get('comparison_policy')!=ARCHITECTURAL_COMPARISON_POLICY:
            return reject('L2_ATOMIC_PROVIDER_INVOCATION_INVALID')
        if getattr(artifact,'preservation_mode',None) is not PreservationMode.ARCHITECTURE_EQUIVALENT:
            return reject('L2_ATOMIC_ARCHITECTURAL_PROOF_REQUIRED')
        try:
            source,target=Path(config['sourcePath']),Path(config['targetPath'])
            if (_digest(source)!=config['sourceDigest'] or _digest(target)!=config['targetDigest']):
                return reject('L2_ATOMIC_ARTIFACT_DIGEST_MISMATCH')
            finding=_finding(json.loads(Path(config['translatedReport']).read_text()),artifact.fragment_id)
            if finding is None:return reject('L2_ATOMIC_FINDING_MISSING')
            approval=finding['approvalArtifact'];fragment=finding['fragment']
            is_lrsc = approval.get('l2LrscProofFacts') is not None
            if is_lrsc:
                from .l2_lrsc_authority import validate as validate_lrsc, materialize as materialize_lrsc, require_observable_scope
                atom,width,lrsc_source=validate_lrsc(finding)
            else:
                atom,width=validate_atomic_proof_facts(approval.get('l2AtomicProofFacts'),approval,artifact.fragment_id)
            if (approval.get('rendererSemanticContractId')!=('x86.gnu-att.lrsc.locked-cas.multi-output.v1' if is_lrsc else BUILTINS[atom['rmw_operation']])
                    or getattr(artifact,'renderer_semantic_contract_id','')!=approval['rendererSemanticContractId']):
                return reject('L2_ATOMIC_STATIC_TARGET_CONTRACT_UNSUPPORTED')
            function=_function_for(finding,config['functions'])
            if function is None:return reject('L2_ATOMIC_FUNCTION_BINDING_MISSING')
            _,fresh=inspect_entry_points(source)
            functions=[f for f in fresh if f['functionId']==function['functionId']]
            if len(functions)!=1:return reject('L2_ATOMIC_COMPILER_FUNCTION_IDENTITY_MISMATCH')
            function=functions[0]
            scope=function.get('compilerAtomicFunctionScope')
            compiler=fragment['compilerFragmentAuthority']
            if compiler.get('sourceDigest')!=config['sourceDigest']:
                return reject('L2_ATOMIC_COMPILER_SOURCE_IDENTITY_MISMATCH')
            key=compiler['fragmentBindingKey']
            if (not isinstance(scope,dict) or scope.get('sourceDigest')!=config['sourceDigest']
                    or scope.get('scopeIdentity')!=identity({k:v for k,v in scope.items() if k!='scopeIdentity'})
                    or scope.get('asmBegin')!=key['beginOffset'] or scope.get('asmEnd')!=key['endOffset']):
                return reject('L2_ATOMIC_FUNCTION_EFFECT_SCOPE_UNPROVEN')
            sidecar=l2_authority_sidecar_from_dict(approval['l2AuthoritySidecar'])
            if is_lrsc:require_observable_scope(finding,function,lrsc_source)
            rebuilt=(materialize_lrsc if is_lrsc else materialize_atomic_authority)(finding,fresh,sidecar.producer.producer_binary_digest)
            if rebuilt is None or rebuilt.authority_identity!=sidecar.authority_identity:
                return reject('L2_ATOMIC_COMPILER_PROOF_JOIN_MISMATCH')
            relations,reason=_approved_relations(finding,artifact,function)
            if relations is None:return reject(reason)
            if any(r.relation_kind!='exact' for r in sidecar.approved_effect_relations):
                return reject('L2_ATOMIC_EXPLICIT_REFINEMENT_OBSERVATION_REQUIRED')
            by_index={x.operand_index:x for x in sidecar.operands}
            if atom['result_semantics']=='old_value':
                output=by_index[atom['result_operand_index']]
                if function['l2OperandBoundary'].get('returnDeclarationId')!=output.declaration_id:
                    return reject('L2_ATOMIC_OUTPUT_SINK_INSTRUMENTATION_REQUIRED')
            stage='harness_build';harness=atomic_wrapper(function,atom,sidecar)
            work,replay=Path(config['workDirectory']),Path(config['replayDirectory'])
            work.mkdir(parents=True,exist_ok=True);replay.mkdir(parents=True,exist_ok=True)
            driver=work/'atomic-harness.c';driver.write_text(harness)
            source_exe,target_exe=work/'atomic.rv64',work/'atomic.x86_64';timeout=int(config['timeoutSeconds'])
            left_build=_run(('riscv64-linux-gnu-gcc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',
                '-march=rv64gc','-mabi=lp64d','-static',str(driver),str(source),'-o',str(source_exe)),work,timeout)
            right_build=_run(('gcc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',str(driver),str(target),'-o',str(target_exe)),work,timeout)
            if left_build.returncode or right_build.returncode:
                return reject('L2_ATOMIC_HARNESS_BUILD_FAILED',commands=_build_failure_detail(left_build,right_build))
            stage='execution';executed=True
            left=_run((config['qemuBinary'],str(source_exe)),work,timeout)
            right=_run((str(target_exe),),work,timeout)
            execution={'schemaVersion':'riscv2x86.atomic-execution.v1',
                'source':{'binaryDigest':_digest(source_exe),'returnCode':left.returncode,'stdout':left.stdout,'stderr':left.stderr},
                'target':{'binaryDigest':_digest(target_exe),'returnCode':right.returncode,'stdout':right.stdout,'stderr':right.stderr}}
            (replay/'atomic-execution.json').write_text(json.dumps(execution,indent=2,sort_keys=True)+'\n')
            stage='observation_materialization'
            source_events=atomic_events(left.stdout,atom);target_events=atomic_events(right.stdout,atom)
            values_valid=all(e['approvedValueRelationHolds'] for e in source_events+target_events)
            success=not(left.returncode or right.returncode or left.stderr or right.stderr) and source_events==target_events and values_valid
            status=ValidationStatus.VERIFIED if success else ValidationStatus.FAILED
            reason='' if success else 'L2_ATOMIC_RMW_VALUE_RELATION_FAILED' if not values_valid else 'L2_ATOMIC_EXECUTION_OBSERVATION_MISMATCH'
            observation={'schemaVersion':'riscv2x86.atomic-observation.v1','fragmentId':artifact.fragment_id,
                'approvedRelationAuthority':relations,'atomicProofFacts':approval['l2LrscProofFacts'] if is_lrsc else approval['l2AtomicProofFacts'],
                'source':{'events':source_events,**execution['source']},'target':{'events':target_events,**execution['target']},
                'atomicityEvidenceKind':('approved-phase6d-locked-cas-sequence-contract' if is_lrsc
                    else 'approved-phase6d-compiler-builtin-contract'),
                'orderingEvidenceKind':'approved-phase6d-contract-not-litmus-inference','reasonCode':reason}
            properties={L2Dimension.LOGICAL_OPERANDS:('operand_binding','operand_value','operand_width'),
                L2Dimension.MEMORY_EFFECTS:('object','offset','width','old_value','new_value'),
                L2Dimension.ATOMIC_MEMORY_ORDER:('approved_atomicity_contract','approved_ordering_contract','single_thread_execution_witness'),
                L2Dimension.SHELL_SEMANTICS:('constraints','compiler_visibility','approved_shell_relation')}
            per_dimension={d:L2DimensionEvidence(identity({'dimension':d.value,'side':'source','authority':relations,'observation':observation['source']}),
                identity({'dimension':d.value,'side':'target','authority':relations,'observation':observation['target']}),properties[d]) for d in DIMENSIONS}
            closure=provider_evidence_fields(artifact,provider_id=kwargs.get('l2_provider_id',''),harness_identity=identity(harness),
                execution_nonce=execution,dimensions=DIMENSIONS,dimension_evidence=per_dimension,
                execution_disposition=L2ProviderExecutionDisposition.EXECUTED_VERIFIED if success else L2ProviderExecutionDisposition.EXECUTED_FAILED)
            (replay/'atomic-observation.json').write_text(json.dumps(observation,indent=2,sort_keys=True)+'\n')
            detail={'schemaVersion':'riscv2x86.auto-l2-atomic-result.v1','status':status.value,'reasonCode':reason,
                'replayArtifact':'atomic-observation.json','observationEvidenceIdentity':identity(observation),**closure}
            return ValidationLayerResult(ValidationLevel.L2,status,identity(observation),json.dumps(detail,sort_keys=True))
        except (ValueError,TypeError,KeyError,OSError,IndexError,subprocess.TimeoutExpired) as exc:
            detail={'reasonCode':'L2_ATOMIC_'+stage.upper()+'_FAILED','failureStage':stage,
                'exceptionType':type(exc).__name__,'detail':str(exc),
                'artifactPath':str(Path(config['replayDirectory'])/'atomic-execution.json'),
                'executionDisposition':'executed_inconclusive' if executed else 'precondition_rejected',
                'evidenceProductionDisposition':'not_produced'}
            return ValidationLayerResult(ValidationLevel.L2,ValidationStatus.INCONCLUSIVE,detail=json.dumps(detail,sort_keys=True))
    return validate
