"""Bounded register-scalar data-access absence, with actual entry/exit capture."""
from .l3_property_obligations import analyze


def scalar_spec(finding):
    obligations=analyze(finding); a=finding['approvalArtifact']
    from .l2_authority import l2_authority_sidecar_from_dict
    sidecar=l2_authority_sidecar_from_dict(a['l2AuthoritySidecar'])
    raw=finding['l2SemanticProfile']; mem=raw['memoryShape']; state=raw['internalStateShape']
    if (raw['patternKind']!='scalar' or mem['reads'] or mem['writes'] or mem['atomic']
            or state['hasMultipleOperations'] or state['hasInternalValues']
            or obligations['requiredProperties']!=[{'propertyId':'memory.fragment-access','dimension':'access_pattern','unit':'fragment'}]
            or sidecar.memory_objects or sidecar.runtime_contracts or sidecar.ignored_state
            or sidecar.control_flow or sidecar.ordering
            or any(x.effect_kind!='ScalarResult' or not x.complete for x in sidecar.source_effects)
            or not sidecar.source_effects
            or any(x.relation_kind!='exact' or not x.complete for x in sidecar.approved_effect_relations)):
        raise ValueError('L3_SCALAR_STRAIGHT_LINE_REGISTER_DOMAIN_REQUIRED')
    return {'fragmentId':obligations['fragmentId'],'programId':obligations['programId'],
        'objectId':'','sourceEffectId':'','offset':0,'width':0,'size':0,'alignment':0,
        'access':'none','observationUnit':'compiler-asm-region','authorityIdentity':sidecar.authority_identity}


def trace_spec(finding):
    # Dispatch on typed source shape, never mnemonic or filename.
    if (finding.get('l2SemanticProfile') or {}).get('patternKind')=='scalar':
        return scalar_spec(finding)
    from .l3_memory_intent import memory_spec
    return memory_spec(finding)


def scalar_harness(scope, samples):
    return r'''#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
extern %s %s(%s);
int main(int argc,char **argv){
 if(argc!=2 || strlen(argv[1])!=64) return 2;
 for(unsigned sample=0;sample<%d;++sample){
  uint64_t input=UINT64_C(0x1020304050607080)+sample;
  uint64_t value=(uint64_t)%s((%s)input);
  printf("{\"token\":\"%%s\",\"sample\":%%u,\"input\":\"%%016" PRIx64 "\",\"value\":\"%%016" PRIx64 "\"}\n",argv[1],sample,input,value);
 }
 return 0;
}
''' % (scope['returnType'],scope['name'],scope['parameterType'],samples,scope['name'],scope['parameterType'])


def parse_samples(stdout,token,samples):
    import json,re
    rows=[]
    for line in stdout.splitlines():
        row=json.loads(line)
        if (not isinstance(row,dict) or set(row)!={'token','sample','input','value'}
                or row['token']!=token or type(row['sample']) is not int or row['sample']!=len(rows)
                or any(not isinstance(row[k],str) or re.fullmatch('[0-9a-f]{16}',row[k]) is None for k in ('input','value'))
                or int(row['input'],16)!=0x1020304050607080+len(rows)):
            raise ValueError('L3_SCALAR_RUNTIME_SAMPLE_INVALID')
        rows.append(row)
    if len(rows)!=samples:raise ValueError('L3_SCALAR_RUNTIME_SAMPLES_MISSING')
    return rows
