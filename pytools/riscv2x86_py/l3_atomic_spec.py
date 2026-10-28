"""Compiler/proof-bound direct atomic RMW invocation and observation contract."""
import json
import re
from .l3_trace_support import identity
from .l3_property_obligations import analyze
from .l2_atomic_authority import validate_atomic_proof_facts,materialize_atomic_authority
from .l2_authority import l2_authority_sidecar_from_dict

CAPABILITY='qemu-attributed-atomic-rmw-v2'
LIMITS=['single-thread-successful-region-execution','bounded-cas-retry-paths-not-concurrent-progress-proof','boundary-value-samples-not-exhaustive-input-proof','ordinary-aligned-memory-only',
        'atomicity-and-order-from-approved-contract-and-attributed-machine-mechanism',
        'raw-callbacks-not-expanded-into-synthetic-read-write-pairs',
        'failed-cas-callbacks-may-be-absent-only-when-explicitly-calibrated;failed-values-not-observed',
        'concurrent-linearizability-and-physical-memory-order-not-measured',
        'outside-fragment-effects-not-compared','physical-cache-timing-prediction-speculation-not-claimed']
from .l3_atomic_semantics import OPERATIONS
UNSIGNED=re.compile(r'(?:uint(32|64)_t|unsigned (int|long|long long)(?: int)?)')


def unsigned_width(typ):
    m=UNSIGNED.fullmatch(typ)
    if m is None:raise ValueError('L3_ATOMIC_UNSIGNED_CARRIER_REQUIRED')
    return int(m[1]) if m[1] else 32 if m[2]=='int' else 64


def spec(finding,functions,*,_sequence=False):
    if not _sequence and (finding.get("approvalArtifact") or {}).get("l2LrscProofFacts") is not None:
        raise ValueError("L3_LRSC_SOURCE_OBSERVATION_BACKEND_REQUIRED")
    ob=analyze(finding,functions);a=finding['approvalArtifact'];f=finding['fragment'];sync=ob.get('synchronizationObligations') or {}
    if (not sync.get('basisComplete') or sync.get('mechanismFamily')!='atomic-rmw'
            or {p['propertyId'] for p in sync['requiredSubproperties']}!={'sync.compiler-contract','sync.atomic-mechanism','sync.atomic-outcome','sync.ordering-contract'}
            or [p['dimension'] for p in ob['requiredProperties']]!=(['control_flow','access_pattern','synchronization'] if _sequence else ['access_pattern','synchronization'])):
        raise ValueError('L3_ATOMIC_OBLIGATION_DOMAIN_UNSUPPORTED')
    sequence=None
    if _sequence:
        from .l2_lrsc_authority import validate as validate_sequence,materialize as sequence_materialize,require_observable_scope
        atom,width,source=validate_sequence(finding);sequence=source.lrsc_sequence.to_dict()
        bits=source.lrsc_sequence.lr_ordering_bits+source.lrsc_sequence.sc_ordering_bits
        atom=dict(atom,success_ordering='acq_rel' if bits[0] and bits[3] else 'acquire' if bits[0] else 'release' if bits[3] else 'relaxed',atomicity_scope='system')
    else:
        atom,width=validate_atomic_proof_facts(a['l2AtomicProofFacts'],a,f['id'])
    if (width['sourceXlen']!=64 or atom['rmw_operation'] not in OPERATIONS or a.get('rendererSemanticContractId')!=('x86.gnu-att.lrsc.locked-cas.multi-output.v1' if _sequence else OPERATIONS[atom['rmw_operation']])
            or atom['success_ordering'] not in {'relaxed','acquire','release','acq_rel'}
            or atom['alignment_bytes']<atom['width_bits']//8 or atom['alignment_bytes']>4096
            or atom['alignment_bytes']&(atom['alignment_bytes']-1) or atom['atomicity_scope']!='system'):
        raise ValueError('L3_ATOMIC_DIRECT_OPERATION_CONTRACT_UNSUPPORTED')
    matches=[fn for fn in functions if fn.get('functionId')==f['compilerFragmentAuthority']['functionIdentity']]
    if len(matches)!=1:raise ValueError('L3_ATOMIC_FUNCTION_BINDING_AMBIGUOUS')
    fn=matches[0];scope=fn.get('compilerAtomicFunctionScope') or {};key=f['compilerFragmentAuthority']['fragmentBindingKey']
    if (scope.get('scope')!='single_asm_no_other_memory_or_control_effects'
            or scope.get('scopeIdentity')!=identity({k:v for k,v in scope.items() if k!='scopeIdentity'})
            or scope.get('sourceDigest')!=fn['sourceDigest'] or scope.get('functionIdentity')!=fn['functionId']
            or (scope.get('asmBegin'),scope.get('asmEnd'))!=(key['beginOffset'],key['endOffset'])):
        raise ValueError('L3_ATOMIC_FUNCTION_SCOPE_REQUIRED')
    sidecar=l2_authority_sidecar_from_dict(a['l2AuthoritySidecar'])
    if _sequence:require_observable_scope(finding,fn,source)
    rebuilt=(sequence_materialize if _sequence else materialize_atomic_authority)(finding,functions,sidecar.producer.producer_binary_digest)
    if rebuilt is None or rebuilt.to_dict()!=sidecar.to_dict():raise ValueError('L3_ATOMIC_AUTHORITY_REPLAY_MISMATCH')
    if (len(sidecar.memory_objects)!=1 or not sidecar.memory_objects[0].complete
            or sidecar.memory_objects[0].object_id!=atom['memory_object_identity']
            or sidecar.memory_objects[0].minimum_alignment<atom['width_bits']//8
            or sidecar.memory_objects[0].size_bytes>4096
            or sidecar.memory_objects[0].size_bytes%(atom['width_bits']//8)
            or sidecar.runtime_contracts or sidecar.ignored_state):
        raise ValueError('L3_ATOMIC_OBJECT_DOMAIN_UNSUPPORTED')
    by_index={o.operand_index:o for o in sidecar.operands};address=by_index[atom['address_operand_index']];value=by_index[atom['value_operand_index']]
    parameters=fn['l2OperandBoundary']['parameterDeclarationIds'];projection=atom.get('address_projection')
    pointer=parameters.index(projection['baseDeclarationIdentity']) if projection else address.parameter_index
    offset=projection['offsetBytes'] if projection else 0
    types=fn['parameterTypes'];pointee=types[pointer].strip()[:-1].strip() if pointer in (0,1) and types[pointer].strip().endswith('*') else ''
    if (fn.get('arity')!=2 or len(types)!=2 or fn.get('pointerParameters')!=[pointer] or value.parameter_index!=1-pointer
            or value.signedness!='unsigned' or unsigned_width(pointee)!=atom['width_bits']
            or unsigned_width(types[1-pointer])!=width['inputCarrierWidth'] or offset!=0
            or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',fn.get('name','')) is None):
        raise ValueError('L3_ATOMIC_INVOCATION_DOMAIN_UNSUPPORTED')
    if atom['result_semantics']=='none':
        if fn['returnType']!='void':raise ValueError('L3_ATOMIC_DISCARDED_RESULT_VOID_REQUIRED')
    else:
        result=by_index[atom['result_operand_index']]
        if (result.signedness!='unsigned' or fn['l2OperandBoundary'].get('returnDeclarationId')!=result.declaration_id
                or unsigned_width(fn['returnType'])!=width['resultCarrierWidth']):raise ValueError('L3_ATOMIC_RETURN_BINDING_REQUIRED')
    body={'schemaVersion':'riscv2x86.atomic-observation-spec.v1','fragmentId':f['id'],'programId':ob['programId'],
          'functionId':fn['functionId'],'sourceDigest':fn['sourceDigest'],'kind':'atomic-rmw','operation':atom,'widthRoles':width,
          'pointerParameter':pointer,'valueParameter':1-pointer,'parameterTypes':types,'returnType':fn['returnType'],
          'objectSizeBytes':sidecar.memory_objects[0].size_bytes,'obligations':ob,'authorityIdentity':sidecar.authority_identity,
          'physicalMicroarchitectureClaimed':False}
    if _sequence:body.update(sourceMechanism='lrsc-sequence',sourceSequence=sequence)
    return dict(body,specIdentity=identity(body))


def samples(spec):
    values=[0,1,0xffffffffffffffff,0x7fffffff,0x80000000,0xffffffff,0x7fffffffffffffff,0x8000000000000000]
    mask=(1<<spec['operation']['width_bits'])-1;carrier=(1<<spec['widthRoles']['inputCarrierWidth'])-1
    pairs=sorted({(old&mask,value&carrier) for old in values for value in values})
    body={'schemaVersion':'riscv2x86.atomic-sample-plan.v1','inputs':[{'old':f'{a:016x}','input':f'{b:016x}'} for a,b in pairs],
          'inputDomain':'cartesian-boundary-values-v1','distinctInputCount':len(pairs),
          'objectCellCount':max(4,spec.get('objectSizeBytes',4*(spec['operation']['width_bits']//8))//(spec['operation']['width_bits']//8))}
    return dict(body,planIdentity=identity(body))


def harness(name,spec,plan):
    types=spec['parameterTypes'];bits=spec['operation']['width_bits'];args=['input','input'];args[spec['pointerParameter']]='object'
    rows=','.join('{0x'+r['old']+'ULL,0x'+r['input']+'ULL}' for r in plan['inputs'])
    call=name+'('+','.join(args)+')'
    returned=call+';unsigned long long result=0;' if spec['returnType']=='void' else spec['returnType']+' returned='+call+';unsigned long long result=(unsigned long long)returned;'
    return ('#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n'
            +spec['returnType']+' '+name+'('+','.join(types)+');\n'
            +'int main(int argc,char **argv){if(argc!=2||strlen(argv[1])!=64)return 2;'
            +'const unsigned long long pairs[][2]={'+rows+'};'
            +'for(unsigned i=0;i<sizeof(pairs)/sizeof(pairs[0]);i++){'
            +'uint'+str(bits)+'_t object['+str(plan['objectCellCount'])+'] __attribute__((aligned('+str(max(16,spec['operation']['alignment_bytes']))+')))={0,0x31,0x72,0x53};'
            +'object[0]=(uint'+str(bits)+'_t)pairs[i][0];unsigned long long before=(unsigned long long)object[0];'
            +types[spec['valueParameter']]+' input=('+types[spec['valueParameter']]+')pairs[i][1];'
            +returned
            +'printf("{\\"sample\\":%u,\\"token\\":\\"%s\\",\\"objectBase\\":\\"%016llx\\",\\"old\\":\\"%016llx\\",\\"input\\":\\"%016llx\\",\\"result\\":\\"%016llx\\",\\"after\\":[",'
            +'i,argv[1],(unsigned long long)(uintptr_t)object,before,(unsigned long long)input,result);'
            +'for(unsigned j=0;j<'+str(plan['objectCellCount'])+';j++)printf("%s\\"%016llx\\"",j?",":"",(unsigned long long)object[j]);puts("]}");'
            +'}return 0;}\n')


def parse_samples(stdout,token,plan):
    rows=[json.loads(line) for line in stdout.splitlines()]
    if len(rows)!=len(plan['inputs']):raise ValueError('L3_ATOMIC_SAMPLE_COUNT_MISMATCH')
    for i,(row,wanted) in enumerate(zip(rows,plan['inputs'])):
        if (set(row)!={'sample','token','objectBase','old','input','result','after'} or type(row['sample']) is not int
                or row['sample']!=i or row['token']!=token or row['old']!=wanted['old'] or row['input']!=wanted['input']
                or not isinstance(row['after'],list) or len(row['after'])!=plan['objectCellCount']
                or any(not isinstance(x,str) or re.fullmatch('[0-9a-f]{16}',x) is None for x in [row['objectBase'],row['old'],row['input'],row['result'],*row['after']])):
            raise ValueError('L3_ATOMIC_SAMPLE_BINDING_MISMATCH')
    return rows
