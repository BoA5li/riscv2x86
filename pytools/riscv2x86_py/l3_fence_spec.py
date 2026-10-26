"""Proof/compiler-bound standalone hardware-fence execution domain."""
import json
import re
from .l3_trace_support import identity
from .l3_property_obligations import analyze

CAPABILITY='qemu-executed-ordinary-rw-fence-v1'
LIMITS=['ordinary-coherent-memory-only','single-thread-successful-region-execution',
        'ordering-guarantees-from-approved-contract-not-measured-reordering',
        'proof-context-anchors-not-dynamic-memory-events',
        'physical-cache-timing-prediction-and-speculation-not-claimed',
        'outside-fragment-effects-not-compared']


def spec(finding,functions):
    from .l2_authority import l2_authority_sidecar_from_dict
    from .automatic_l2_authority import _fence_authority
    from .l2_materialization import assess_fragment_l2_materializability
    ob=analyze(finding,functions);a=finding['approvalArtifact'];f=finding['fragment']
    sync=ob.get('synchronizationObligations') or {}
    expected={'sync.compiler-contract','sync.fence-mechanism','sync.ordering-contract'}
    if (finding['l2SemanticProfile']['patternKind']!='fence' or not sync.get('basisComplete')
            or sync.get('mechanismFamily')!='memory-fence'
            or {p['propertyId'] for p in sync.get('requiredSubproperties',[])}!=expected
            or [p['dimension'] for p in ob['requiredProperties']]!=['access_pattern','synchronization']):
        raise ValueError('L3_FENCE_OBLIGATION_DOMAIN_UNSUPPORTED')
    basis=sync['basis']
    if any(basis[k]['ordering']!='rw_rw' or basis[k]['memoryDomain']!='ordinary-coherent-memory'
           for k in ('sourceOrderingContract','targetOrderingContract')):
        raise ValueError('L3_FENCE_ORDINARY_RW_DOMAIN_REQUIRED')
    if a.get('rendererSemanticContractId')!='x86.gnu-att.mfence.ordinary-rw.v2':
        raise ValueError('L3_FENCE_TARGET_CONTRACT_UNSUPPORTED')
    sidecar=l2_authority_sidecar_from_dict(a['l2AuthoritySidecar'])
    rebuilt=_fence_authority(finding,functions,sidecar.producer.producer_binary_digest)
    if rebuilt is None or rebuilt.to_dict()!=sidecar.to_dict():raise ValueError('L3_FENCE_AUTHORITY_REPLAY_MISMATCH')
    if not assess_fragment_l2_materializability(finding,sidecar=sidecar).executable:
        raise ValueError('L3_FENCE_MATERIALIZATION_INCOMPLETE')
    matches=[x for x in functions if x.get('name')==f.get('enclosingFunction')]
    if len(matches)!=1:raise ValueError('L3_FENCE_FUNCTION_AMBIGUOUS')
    function=matches[0];scope=function.get('compilerAtomicFunctionScope') or {}
    if (function.get('arity')!=0 or function.get('parameterTypes')!=[] or function.get('returnType')!='void'
            or scope.get('scope')!='single_asm_no_other_memory_or_control_effects'
            or scope.get('scopeIdentity')!=identity({k:v for k,v in scope.items() if k!='scopeIdentity'})
            or scope.get('functionIdentity')!=function['functionId'] or scope.get('sourceDigest')!=function['sourceDigest']):
        raise ValueError('L3_FENCE_COMPILER_SCOPE_UNSUPPORTED')
    compiler=f.get('compilerFragmentAuthority') or {}
    if (compiler.get('functionIdentity')!=function['functionId'] or compiler.get('sourceDigest')!=function['sourceDigest']
            or compiler.get('fragmentId')!=f['id'] or finding.get('sourceDigest')!=function['sourceDigest']
            or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',function.get('name','')) is None):
        raise ValueError('L3_FENCE_COMPILER_BINDING_REQUIRED')
    if sidecar.operands or sidecar.memory_objects or sidecar.runtime_contracts or sidecar.ignored_state:
        raise ValueError('L3_FENCE_STANDALONE_DOMAIN_REQUIRED')
    body={'schemaVersion':'riscv2x86.l3-fence-spec.v1','fragmentId':f['id'],'programId':ob['programId'],
          'functionId':function['functionId'],'sourceDigest':function['sourceDigest'],'kind':'memory-fence',
          'authorityIdentity':sidecar.authority_identity,'obligations':ob,'fenceFactsIdentity':basis['fenceFactsIdentity'],
          'claimScope':'bounded-successful-architectural-fence-intent','physicalMicroarchitectureClaimed':False}
    return dict(body,specIdentity=identity(body))


def samples(control,call=None):
    # Three invocations check protocol completion, not input-domain diversity.
    body={'schemaVersion':'riscv2x86.fence-invocation-plan.v1','inputs':[[],[],[]],
          'inputDomain':'no-arguments','distinctInputCount':1}
    return dict(body,planIdentity=identity(body))


def harness(name,call,plan):
    return ('#include <stdio.h>\n#include <string.h>\nextern void '+name+'(void);\n'
            'int main(int argc,char **argv){if(argc!=2||strlen(argv[1])!=64)return 2;'
            'for(unsigned i=0;i<'+str(len(plan['inputs']))+';i++){'+name+'();'
            'printf("{\\"sample\\":%u,\\"token\\":\\"%s\\",\\"completed\\":true}\\n",i,argv[1]);}return 0;}\n')


def parse_samples(stdout,token,plan):
    rows=[json.loads(s) for s in stdout.splitlines()]
    if len(rows)!=len(plan['inputs']):raise ValueError('L3_FENCE_SAMPLE_COUNT_MISMATCH')
    for i,r in enumerate(rows):
        if r!={'sample':i,'token':token,'completed':True} or type(r['sample']) is not int or r['completed'] is not True:
            raise ValueError('L3_FENCE_SAMPLE_BINDING_MISMATCH')
    return rows
