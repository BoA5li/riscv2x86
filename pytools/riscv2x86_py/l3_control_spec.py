"""Proof-bound, typed local control experiments; no source-text classifier."""
from .l3_trace_support import identity
from .l3_property_obligations import analyze

CAPABILITY='qemu-compiler-control-path-trace-v1'
LIMITS=['bounded-acyclic-integer64-control-regions-only','listed-input-vectors-only',
        'physical-cache-timing-prediction-and-speculation-not-claimed',
        'outside-fragment-effects-not-compared']


def spec(finding,functions):
    from .l2_authority import l2_authority_sidecar_from_dict
    from .compiler_provenance import bind_compiler_provenance
    from .l2_materialization import assess_fragment_l2_materializability
    from .automatic_l2_authority import _scalar_authority,_asm_goto_authority
    from copy import deepcopy
    ob=analyze(finding);a=finding['approvalArtifact'];fragment=finding['fragment']
    kind=finding['l2SemanticProfile']['patternKind']
    if kind not in {'branch','jump','asm_goto'}:raise ValueError('L3_CONTROL_SEMANTIC_FAMILY_UNSUPPORTED')
    if [p['dimension'] for p in ob['requiredProperties']]!=['control_flow','access_pattern']:
        raise ValueError('L3_CONTROL_OBLIGATION_SET_UNSUPPORTED')
    sidecar=l2_authority_sidecar_from_dict(a['l2AuthoritySidecar'])
    rebuilt=(_asm_goto_authority if kind=='asm_goto' else _scalar_authority)(deepcopy(finding),functions,sidecar.producer.producer_binary_digest)
    if rebuilt is None or rebuilt.to_dict()!=sidecar.to_dict():raise ValueError('L3_CONTROL_AUTHORITY_REPLAY_MISMATCH')
    bind_compiler_provenance(fragment,sidecar)
    if not assess_fragment_l2_materializability(finding,sidecar=sidecar).executable:
        raise ValueError('L3_CONTROL_MATERIALIZATION_INCOMPLETE')
    matches=[f for f in functions if f.get('functionId')==fragment['compilerFragmentAuthority']['functionIdentity']]
    if len(matches)!=1:raise ValueError('L3_CONTROL_FUNCTION_BINDING_AMBIGUOUS')
    function=matches[0]
    if sidecar.memory_objects or sidecar.runtime_contracts or sidecar.ignored_state or sidecar.ordering:
        raise ValueError('L3_CONTROL_REGISTER_ONLY_DOMAIN_REQUIRED')
    if len(sidecar.control_flow)!=1:raise ValueError('L3_CONTROL_SINGLE_TRANSFER_AUTHORITY_REQUIRED')
    by_index={o.operand_index:o for o in sidecar.operands}
    def parameter(index):
        o=by_index[index]
        if o.parameter_index is None or o.width_bits!=64 or o.type_kind!='integer':raise ValueError('L3_CONTROL_PARAMETER_BINDING_UNSUPPORTED')
        return o.parameter_index
    if kind=='asm_goto':
        from .l2_asm_goto import validate_asm_goto_proof_facts
        facts=validate_asm_goto_proof_facts(a['l2AsmGotoProofFacts'],fragment,a)
        if facts.condition_kind not in {'zero','nonzero'}:raise ValueError('L3_CONTROL_GOTO_PREDICATE_UNSUPPORTED')
        conditions={'kind':'equal' if facts.condition_kind=='zero' else 'not_equal',
                    'left':'parameter:'+str(parameter(int(facts.lhs_binding.split(':')[-1]))),'right':0}
        arms=None
        sites=function.get('compilerContinuationSites')
        if not isinstance(sites,dict) or sites['sourceDigest']!=function['sourceDigest'] or sites['functionIdentity']!=function['functionId'] or sites['siteFactsIdentity']!=identity({k:v for k,v in sites.items() if k!='siteFactsIdentity'}):
            raise ValueError('L3_CONTROL_COMPILER_CONTINUATION_SITES_REQUIRED')
        if len(sites['labels'])!=1 or sites['labels'][0]['label']!=facts.taken_label_identity:
            raise ValueError('L3_CONTROL_GOTO_EXIT_DOMAIN_UNSUPPORTED')
        proof_identity=a['l2AsmGotoProofFacts']['factsIdentity']
    else:
        from .l2_control_flow import control_flow_proof_facts_from_dict
        facts=control_flow_proof_facts_from_dict(a['l2ControlFlowProofFacts'])
        if not facts.complete or facts.fragment_id!=fragment['id'] or facts.pattern_kind!=kind:raise ValueError('L3_CONTROL_PROOF_FACTS_INCOMPLETE')
        if kind=='branch':
            conditions={'kind':facts.condition_kind,'left':'parameter:'+str(parameter(facts.condition_operand_indexes[0])),
                        'right':'parameter:'+str(parameter(facts.condition_operand_indexes[1]))}
            arms={'true':parameter(facts.true_value_operand_index),'false':parameter(facts.false_value_operand_index)}
        else:conditions=None;arms={'selected':parameter(facts.selected_value_operand_index)}
        proof_identity=facts.facts_identity
        scope=function.get('compilerAtomicFunctionScope') or {}
        if scope.get('scope')!='single_asm_no_other_memory_or_control_effects' or scope.get('sourceDigest')!=function['sourceDigest'] or scope.get('functionIdentity')!=function['functionId'] or scope.get('scopeIdentity')!=identity({k:v for k,v in scope.items() if k!='scopeIdentity'}):
            raise ValueError('L3_CONTROL_COMPILER_REGION_SCOPE_REQUIRED')
    body={'schemaVersion':'riscv2x86.l3-control-spec.v1','fragmentId':fragment['id'],'programId':ob['programId'],
          'functionId':function['functionId'],'sourceDigest':function['sourceDigest'],'kind':kind,
          'predicate':conditions,'arms':arms,'controlProofIdentity':proof_identity,
          'authorityIdentity':sidecar.authority_identity,'obligations':ob,
          'requiredControlObligations':['logical-continuation','actual-transfer-shape'],
          'claimScope':'bounded-successful-architectural-control-intent',
          'physicalMicroarchitectureClaimed':False}
    return dict(body,specIdentity=identity(body))


def signature(function):
    raw=function.get('compilerIntegerCallSignature')
    if (not isinstance(raw,dict) or set(raw)!={'schemaVersion','functionIdentity','sourceDigest','targetABI','parameters','result','factsIdentity'}
            or raw.get('schemaVersion')!='riscv2x86.compiler-integer-call-signature.v1' or raw.get('targetABI')!='linux-lp64-integer64'
            or raw.get('factsIdentity')!=identity({k:v for k,v in raw.items() if k!='factsIdentity'}) or raw.get('functionIdentity')!=function['functionId'] or raw.get('sourceDigest')!=function['sourceDigest']):
        raise ValueError('L3_CONTROL_COMPILER_CALL_SIGNATURE_REQUIRED')
    from .l3_scalar_call import validate_signature
    params=raw['parameters'];result=raw['result']
    body={'schemaVersion':'riscv2x86.l3-scalar-call.v1','functionIdentity':function['functionId'],
          'sourceDigest':function['sourceDigest'],'abi':'linux-lp64-integer64',
          'parameters':params,'result':result}
    return validate_signature(dict(body,signatureIdentity=identity(body)))


def samples(control,call):
    from .l3_scalar_call import validate_signature
    from .l3_control_machine import condition,value_of
    validate_signature(call);n=len(call['parameters']);rows=[]
    seeds=[0,1,0x7fffffffffffffff,0x8000000000000000,0xffffffffffffffff]
    for a in seeds:
        for b in seeds:
            row=[(0x123456789abcdef0+i*0x111111111111111)&((1<<64)-1) for i in range(n)]
            p=control['predicate']
            if p:
                row[int(p['left'].split(':')[1])]=a
                if isinstance(p['right'],str):row[int(p['right'].split(':')[1])]=b
            else:row=[(a+i)&((1<<64)-1) for i in range(n)]
            if row not in rows:rows.append(row)
    if len(rows)>32:raise ValueError('L3_CONTROL_SAMPLE_BUDGET_EXCEEDED')
    if control['predicate']:
        p=control['predicate']
        if {condition(p['kind'],value_of(p['left'],r),value_of(p['right'],r)) for r in rows}!={False,True}:
            raise ValueError('L3_CONTROL_PREDICATE_COVERAGE_INCOMPLETE')
    body={'schemaVersion':'riscv2x86.control-sample-plan.v1','specIdentity':control['specIdentity'],
          'signatureIdentity':call['signatureIdentity'],'inputs':[[f'{x:016x}' for x in r] for r in rows],
          'coverageClaim':'listed-vectors-and-required-predicate-outcomes'}
    return dict(body,planIdentity=identity(body))


def harness(name,call,plan):
    from .l3_scalar_trace import vector_harness
    return vector_harness({'name':name,'callSignature':call},len(plan['inputs']),plan=plan)


def parse_samples(stdout,token,plan):
    import json,re
    rows=[]
    for line in stdout.splitlines():
        r=json.loads(line)
        if (not isinstance(r,dict) or set(r)!={'schemaVersion','token','sample','inputs','value','planIdentity'}
                or r['schemaVersion']!='riscv2x86.l3-scalar-sample.v2' or r['token']!=token
                or type(r['sample']) is not int or r['sample']!=len(rows) or len(rows)>=len(plan['inputs'])
                or r['inputs']!=plan['inputs'][len(rows)] or r['planIdentity']!=plan['planIdentity']
                or not isinstance(r['value'],str) or re.fullmatch('[0-9a-f]{16}',r['value']) is None):raise ValueError('L3_CONTROL_RUNTIME_SAMPLE_INVALID')
        rows.append(r)
    if len(rows)!=len(plan['inputs']):raise ValueError('L3_CONTROL_RUNTIME_SAMPLES_MISSING')
    return rows
