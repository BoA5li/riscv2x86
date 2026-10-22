"""Replayable bridge from the CSR field proof to Phase 7/L2.

The bridge transports an existing proof; it never approves a new CSR relation.
"""
from dataclasses import asdict, is_dataclass
from types import SimpleNamespace
from .semantic_content import semantic_payload, semantic_identity
from .csr_field_proof import prove_csr_fields
from .csr_structured_renderer import CsrRuntimeRecipe
from .csr_runtime_implementation import validate_implementation
from .csr_runtime_shell import prove_runtime_shell, render_runtime_shell
from .l2_effect_proof import (L2EffectProofFacts, SourceEffectFact, TargetEffectFact,
                             EffectRelationFact, ShellRelationFact)


def _namespace(value):
    if isinstance(value, dict): return SimpleNamespace(**{k:_namespace(v) for k,v in value.items()})
    if isinstance(value, list): return [_namespace(x) for x in value]
    return value


def _fragment_shell(fragment):
    raw = asdict(fragment) if is_dataclass(fragment) else fragment
    return {'id': raw.get('id') or raw.get('fragmentId'),
            'isVolatile': raw.get('isVolatile') is True,
            'isAsmGoto': raw.get('isAsmGoto') is True,
            'gotoLabels': raw.get('gotoLabels') or [],
            'inputs': [{'constraint': x.get('constraint'), 'isEarlyClobber': x.get('isEarlyClobber',False)} for x in raw.get('inputs',[])],
            'outputs': [{'constraint': x.get('constraint'), 'isEarlyClobber': x.get('isEarlyClobber',False)} for x in raw.get('outputs',[])],
            'clobbers': raw.get('clobbers') or []}


def _effect_facts(payload, proof_id, plan_id, constraint_id, renderer_id):
    model = payload['fieldProof']['sourceModel']; source=[]; target=[]; relations=[]
    functional = any(x.get('counter_relation_kind') == 'functional-monotonic-observation'
                     for x in payload['fieldProof']['constraints'])
    for effect, binding in zip(model['effects'], model['operand_bindings']):
        eid=binding['source_effect_id']; tid='target:'+eid
        source.append(SourceEffectFact(eid, 'PrivilegedOperation', effect['csr_id'], True))
        target.append(TargetEffectFact(tid, 'PrivilegedOperation', effect['csr_id'], True))
        properties = ('external_detail','kind','subject') if functional else ('csr_value','privilege_state','subject','value')
        relations.append(EffectRelationFact('relation:'+eid,eid,(tid,), 'runtime_mediated',
            properties, ('architectural_counter_value',) if functional else (),
            payload['runtimeContractId'], semantic_identity(payload), True))
    shell=payload['shellProof']
    shell_fact=ShellRelationFact(tuple('output' for _ in shell['outputConstraints']),
        tuple(shell['outputConstraints']), (), (), True, True, True, True, True, True)
    return L2EffectProofFacts(payload['sourceShell']['id'], proof_id, plan_id,
        constraint_id, renderer_id, tuple(source), tuple(target), tuple(relations), shell_fact, True)


def build_csr_runtime_approval(fragment, result, *, machine_code, decoder_profile, target_environment_id, functional_observability=None, normalization_facts=()):
    if (result.status != 'approved' or result.proof is None or not result.proof.approved
            or not result.shell_payload or not result.recipe_payload or not result.implementation_identity):
        raise ValueError('CSR_RUNTIME_APPROVAL_PRECONDITION_MISSING')
    payload = {'schemaVersion':'riscv2x86.csr-runtime-proof.v1',
        'machineCodeHex':machine_code.hex(), 'decoderProfile':decoder_profile,
        'planFamily':result.route, 'fieldProof':result.proof.proof_payload, 'fieldProofIdentity':result.proof.proof_identity,
        'shellProof':result.shell_payload, 'recipe':result.recipe_payload,
        'implementationIdentity':result.implementation_identity,
        'runtimeContractId':validate_implementation(CsrRuntimeRecipe(**result.recipe_payload),
            _namespace(result.proof.proof_payload['sourceModel']).effects,
            tuple(_namespace(x) for x in result.proof.proof_payload['constraints']))[0]['implementation'].implementation_id + '@v1',
        'compilerAuthorityIdentity':(asdict(fragment) if is_dataclass(fragment) else fragment).get('compilerFragmentAuthority',{}).get('authorityIdentity',''),
        'sourceShell':_fragment_shell(fragment), 'targetEnvironmentId':target_environment_id,
        'functionalObservability':semantic_payload(functional_observability)}
    if result.backend_contract is not None:
        payload['schemaVersion']='riscv2x86.csr-runtime-proof.v2'
        payload['backendContract']=result.backend_contract
    if normalization_facts:
        payload['schemaVersion']='riscv2x86.csr-runtime-proof.v3'
        payload['backendContract']=result.backend_contract
        payload['normalizationFacts']=semantic_payload(normalization_facts)
    proof_id=semantic_identity(payload)
    plan_id=semantic_identity({'family':result.route,'sourceModel':payload['fieldProof']['sourceModel']})
    constraint_id=semantic_identity(payload['fieldProof']['constraints'])
    renderer_id=semantic_identity({'recipe':payload['recipe'],'shell':payload['shellProof']})
    functional=any(c['counter_relation_kind']=='functional-monotonic-observation' for c in payload['fieldProof']['constraints'])
    ignored = [] if functional_observability is None else sorted({x.state_id for x in functional_observability.ignored_states})
    if functional and not ignored: raise ValueError('CSR_RUNTIME_FUNCTIONAL_OBSERVABILITY_REQUIRED')
    facts=_effect_facts(payload,proof_id,plan_id,constraint_id,renderer_id)
    approval = {'artifactVersion':'phase6-csr-runtime-v1', 'sourceFragmentId':payload['sourceShell']['id'],
        'proofStatus':'functional_approved' if functional else 'approved',
        'preservationMode':'functional_equivalence_only' if functional else 'architecture_equivalent',
        'architectureSemanticsPreserved':not functional,'shellSemanticsPreserved':True,
        'functionalFallbackEnabled':functional, 'ignoredSourceState':ignored, 'ignoredStateIds':ignored,
        'replacementKind':'privileged_functional_fallback' if functional else 'privileged_runtime_adapter',
        'privilegedCallableIdentifier':payload['recipe']['callable_identifier'],
        'privilegedSemanticContractId':'riscv.csr.structured.v1','privilegedSemanticContractVersion':'v1',
        'privilegedSourceRegistryVersion':'csr-phase5-model-v2',
        'privilegedRendererManifestId':'csr-runtime-shell-renderer','privilegedRendererManifestVersion':'v1',
        'privilegedEffectProofIds':[payload['fieldProofIdentity'],proof_id],
        'privilegedEffectProofIdentity':proof_id,'proofId':proof_id,
        'observableEffectsProved':sorted({x for relation in facts.relations for x in relation.preserved_properties}),
        'microarchitectureSemanticsPreserved':False,
        'sourceExecutionProfile':payload['fieldProof']['executionProfile'],
        'knownNonEquivalences':['architectural_counter_value','clock_domain'] if functional else [],
        'sourceSemanticContractId':'riscv.csr.structured.v1',
        'targetSemanticContractId':payload['runtimeContractId'],
        'targetEnvironmentId':target_environment_id,'targetCatalogVersion':'csr-runtime-implementation-v1',
        'sourceModelId':semantic_identity(payload['fieldProof']['sourceModel']),
        'preservationDecisionId':semantic_identity({'mode':'functional' if functional else 'strict','proof':proof_id}),
        'rendererId':'csr-runtime-shell-renderer','rendererVersion':'v1',
        'rendererRegistryId':semantic_identity({'recipe':payload['recipe'],'implementation':payload['implementationIdentity']}),
        'rendererRegistryVersion':'csr-runtime-implementation-v1',
        'rendererContractId':renderer_id,'shellFactsIdentity':semantic_identity(payload['shellProof']),
        'proofIdentity':proof_id, 'proofPayload':payload, 'planId':plan_id,
        'constraintsId':constraint_id,'rendererContractIdentity':renderer_id,
        'runtimeContractId':payload['runtimeContractId'],'runtimeContractVersion':'v1',
        'requiredHeaders':list(result.render.required_headers),
        'requiredLibraries':list(result.render.required_libraries),
        'replacementDigest':semantic_identity({'replacement':result.suggested_replacement}),
        'l2EffectProofFacts':facts.to_dict()}
    if normalization_facts:
        validate_csr_runtime_approval(approval, fragment, result.suggested_replacement)
    return approval


def validate_csr_runtime_approval(approval, fragment, replacement=None):
    if approval.get('artifactVersion')!='phase6-csr-runtime-v1':
        raise ValueError('CSR_RUNTIME_APPROVAL_SCHEMA_INVALID')
    p=approval['proofPayload']
    version3=p.get('schemaVersion')=='riscv2x86.csr-runtime-proof.v3'
    version2=p.get('schemaVersion')=='riscv2x86.csr-runtime-proof.v2' or (version3 and p.get('backendContract') is not None)
    expected_fields={'schemaVersion','machineCodeHex','decoderProfile','planFamily','fieldProof','fieldProofIdentity','shellProof','recipe',
                   'implementationIdentity','runtimeContractId','compilerAuthorityIdentity','sourceShell','targetEnvironmentId','functionalObservability'}
    if version2 or version3:expected_fields.add('backendContract')
    if version3:expected_fields.add('normalizationFacts')
    if (set(p)!=expected_fields
            or p['schemaVersion'] not in {'riscv2x86.csr-runtime-proof.v1','riscv2x86.csr-runtime-proof.v2','riscv2x86.csr-runtime-proof.v3'}
            or semantic_identity(p)!=approval.get('proofIdentity')
            or p['sourceShell']!=_fragment_shell(fragment)):
        raise ValueError('CSR_RUNTIME_APPROVAL_BINDING_MISMATCH')
    raw_fragment=asdict(fragment) if is_dataclass(fragment) else fragment
    if p['compilerAuthorityIdentity']!=raw_fragment.get('compilerFragmentAuthority',{}).get('authorityIdentity',''):
        raise ValueError('CSR_RUNTIME_COMPILER_BINDING_MISMATCH')
    f=p['fieldProof']
    proof=prove_csr_fields(source_model=_namespace(f['sourceModel']),
        constraints=tuple(_namespace(x) for x in f['constraints']), execution_profile=f['executionProfile'],
        shell_preserved=f['shellPreserved'], external_state_complete=f['externalStateComplete'],
        registry_identity=f['registryIdentity'],target_environment_id=f['targetEnvironmentId'],
        shell_facts=tuple(f['shellFacts']),allow_functional_relations=f['functionalRelationsEnabled'])
    if not proof.approved or proof.proof_identity!=p['fieldProofIdentity']:
        raise ValueError('CSR_RUNTIME_FIELD_PROOF_REPLAY_FAILED')
    from .csr_metadata_ingress import (decode_csr_instruction, canonical_csr_operations_from_decoded, CsrDecoderProfile)
    from .privileged_state_analysis import _field_effect
    code=bytes.fromhex(p['machineCodeHex'])
    if len(code)!=4 or len(f['sourceModel']['effects'])!=1:
        raise ValueError('CSR_RUNTIME_DECODER_REGION_MISMATCH')
    effect=f['sourceModel']['effects'][0]
    profile=CsrDecoderProfile(**p['decoderProfile'])
    decoded=decode_csr_instruction(code)
    if decoded is None: raise ValueError('CSR_RUNTIME_DECODER_INSTRUCTION_INVALID')
    op=canonical_csr_operations_from_decoded(addr=effect['block_address'],
        decoded=decoded,xlen_bits=effect['xlen_bits'],profile=profile)[0]
    if version3:
        from .csr_pcode_normalization import replay
        records=p['normalizationFacts']
        if (not isinstance(records,list) or len(records)!=1 or records[0].get('address')!=effect['block_address']
                or records[0].get('instructionSize')!=len(code)):
            raise ValueError('CSR_NORMALIZATION_REGION_BINDING_MISMATCH')
        replay(records[0],privileged_operations=(op,))
    writes=op.csr_operation.value in {'write','read_write','set_bits','clear_bits'}
    fields=semantic_payload(tuple(_field_effect(x,write_required=writes) for x in op.affected_csr_fields))
    if (not op.state_complete or op.csr_id!=effect['csr_id']
            or op.csr_operation.value!=effect['operation']
            or fields!=effect['affected_fields']
            or op.read_value_node_id!=effect['read_value_node_id']
            or op.write_value_node_id!=effect['write_value_node_id']
            or op.immediate_mask!=effect['immediate_mask']
            or list(op.access_gate_ids)!=effect['access_gate_ids']
            or op.csr_semantic_class!=effect['csr_class']
            or effect['access_allowed'] is not True
            or effect['may_trap'] is not False):
        raise ValueError('CSR_RUNTIME_SOURCE_EFFECT_MISMATCH')
    recipe=CsrRuntimeRecipe(**p['recipe'])
    bindings=f['sourceModel']['operand_bindings']
    if len(bindings)!=1: raise ValueError('CSR_RUNTIME_OPERAND_CARDINALITY_MISMATCH')
    binding=bindings[0]
    read_index=binding['read_result_operand_index']; write_index=binding['write_value_operand_index']
    read_required=op.read_value_node_id is not None and op.read_result_suppressed is not True
    write_required=(op.write_value_node_id is not None and op.immediate_mask is None
                    and op.write_value_suppressed is not True)
    if (read_required != (read_index is not None) or write_required != (write_index is not None)
            or any(type(i) is not int or i<0 for i in (read_index,write_index) if i is not None)
            or binding.get('immediate_value') != op.immediate_mask):
        raise ValueError('CSR_RUNTIME_DECODER_OPERAND_ROLE_MISMATCH')
    ordered=raw_fragment.get('outputs',[])+raw_fragment.get('inputs',[])
    if raw_fragment.get('compilerFragmentAuthority'):
        from .csr_result_flow import result_flows_from_compiler
        expected_flows=result_flows_from_compiler(p['sourceShell']['id'],
            raw_fragment['compilerFragmentAuthority'])
        read=bindings[0]['read_result_operand_index']
        expected_flow=None if read is None else expected_flows.get(read)
        if (bindings[0].get('result_value_flow')!=semantic_payload(expected_flow)
                or (read is not None and (expected_flow is None or not expected_flow.complete))):
            raise ValueError('CSR_RUNTIME_RESULT_VALUE_FLOW_MISMATCH')
    for field,index_key in (('output_expression','read_result_operand_index'),('input_expression','write_value_operand_index')):
        index=bindings[0][index_key]
        expected=None if index is None else ordered[index]['exprText'] if type(index) is int and 0<=index<len(ordered) else None
        if field=='input_expression' and index is None:
            immediate=bindings[0].get('immediate_value')
            expected=None if immediate is None else str(immediate)
            if recipe.input_expression!=expected:
                raise ValueError('CSR_RUNTIME_IMMEDIATE_OR_INPUT_BINDING_MISMATCH')
        if index is not None and (expected is None or getattr(recipe,field)!=expected):
            raise ValueError('CSR_RUNTIME_RENDERER_OPERAND_BINDING_MISMATCH')
        if field=='output_expression' and index is None and recipe.output_expression is not None:
            raise ValueError('CSR_RUNTIME_UNBOUND_OUTPUT_EXPRESSION')
    implementation_payload, implementation=validate_implementation(recipe, _namespace(f['sourceModel']).effects,
        tuple(_namespace(x) for x in f['constraints']))
    if (implementation!=p['implementationIdentity']
            or p['runtimeContractId']!=implementation_payload['implementation'].implementation_id+'@v1'):
        raise ValueError('CSR_RUNTIME_IMPLEMENTATION_IDENTITY_MISMATCH')
    time_backend = version2 and 'timeContract' in p['backendContract']
    if time_backend:
        backend = p['backendContract']
        from .time_trace_contract import validate_time_contract
        if set(backend) != {'timeContract','sourceExecutionSnapshot','targetEnvironmentSnapshot'}:
            raise ValueError('TIME_BACKEND_SNAPSHOT_INVALID')
        validate_time_contract(backend['timeContract'], fragment_id=p['sourceShell']['id'],
            source_digest=(raw_fragment.get('compilerFragmentAuthority') or {}).get('sourceDigest'),
            source_execution=semantic_identity(backend['sourceExecutionSnapshot']),
            target_environment=semantic_identity(backend['targetEnvironmentSnapshot']))
        if (semantic_identity(backend['targetEnvironmentSnapshot']) != f['targetEnvironmentId']
                or backend['timeContract'] != (f['constraints'][0].get('counter_contract_payload') or {}).get('trace_relation')
                or implementation_payload['implementation'].semantic_family != 'controlled-time-trace'):
            raise ValueError('TIME_BACKEND_SNAPSHOT_MISMATCH')
    elif version2:
        from .csr_state_contract import validate_state_contract
        backend=p['backendContract']
        if (not isinstance(backend,dict) or set(backend)!={'stateContract','sourceExecutionSnapshot','targetEnvironmentSnapshot'}
                or len(f['constraints'])!=1):
            raise ValueError('CSR_RUNTIME_BACKEND_CONTRACT_INVALID')
        validate_state_contract(backend['stateContract'],state_object=f['constraints'][0]['target_state_object_id'],
            source_execution=semantic_identity(backend['sourceExecutionSnapshot']),
            target_environment=semantic_identity(backend['targetEnvironmentSnapshot']))
        if (semantic_identity(backend['targetEnvironmentSnapshot'])!=f['targetEnvironmentId']
                or implementation_payload['implementation'].semantic_family!='logical-csr-state'
                or recipe.context_expression!=backend['stateContract']['contextExpression']):
            raise ValueError('CSR_RUNTIME_BACKEND_ENVIRONMENT_MISMATCH')
    elif implementation_payload['implementation'].semantic_family=='controlled-time-trace':
        raise ValueError('TIME_BACKEND_SNAPSHOT_REQUIRED')
    elif implementation_payload['implementation'].semantic_family=='logical-csr-state':
        raise ValueError('CSR_RUNTIME_STATE_ENVIRONMENT_CONTRACT_REQUIRED')
    trace = (f['constraints'][0].get('counter_contract_payload') or {}).get('trace_relation')
    if trace is not None:
        from .time_trace_contract import validate_time_contract
        validate_time_contract(trace, fragment_id=p['sourceShell']['id'],
            source_digest=(raw_fragment.get('compilerFragmentAuthority') or {}).get('sourceDigest'),
            target_environment=f['targetEnvironmentId'])
    shell=prove_runtime_shell(fragment,implementation,p['shellProof']['buildContract'],
        operand_binding=_namespace(bindings[0]),
        time_contract=(f['constraints'][0].get('counter_contract_payload') or {}).get('trace_relation'))
    if shell!=p['shellProof'] or tuple(f['shellFacts'])!=(semantic_identity(shell),):
        raise ValueError('CSR_RUNTIME_SHELL_REPLAY_FAILED')
    from .csr_structured_renderer import render_csr_recipe
    rendered=render_csr_recipe(recipe,approved_recipe_ids={recipe.recipe_id:recipe.runtime_version},
                              expected_runtime_version=recipe.runtime_version)
    if rendered.emitted_text is None: raise ValueError('CSR_RUNTIME_RECIPE_INVALID')
    text=render_runtime_shell(rendered.emitted_text,shell)
    if (approval.get('replacementDigest')!=semantic_identity({'replacement':text})
            or (replacement is not None and text!=replacement)):
        raise ValueError('CSR_RUNTIME_REPLACEMENT_MISMATCH')
    from .csr_plan_families import derive_csr_plan_candidates
    families=derive_csr_plan_candidates(_namespace(f['sourceModel']),allow_functional_fallbacks=f['functionalRelationsEnabled'])
    if p['planFamily'] not in {x.family.value for x in families if x.complete}:
        raise ValueError('CSR_RUNTIME_PLAN_FAMILY_MISMATCH')
    plan_id=semantic_identity({'family':p['planFamily'],'sourceModel':f['sourceModel']})
    if approval.get('planId')!=plan_id: raise ValueError('CSR_RUNTIME_PLAN_IDENTITY_MISMATCH')
    expected_facts=_effect_facts(p,approval['proofIdentity'],plan_id,
        semantic_identity(f['constraints']),semantic_identity({'recipe':p['recipe'],'shell':shell})).to_dict()
    if (approval.get('constraintsId')!=expected_facts['constraintIdentity']
            or approval.get('rendererContractIdentity')!=expected_facts['rendererContractIdentity']
            or approval.get('l2EffectProofFacts')!=expected_facts
            or approval.get('runtimeContractId')!=p['runtimeContractId']
            or approval.get('requiredHeaders')!=list(rendered.required_headers)
            or approval.get('requiredLibraries')!=list(rendered.required_libraries)):
        raise ValueError('CSR_RUNTIME_EFFECT_CLOSURE_MISMATCH')
    functional=any(c['counter_relation_kind']=='functional-monotonic-observation' for c in f['constraints'])
    if (approval.get('proofStatus')!=('functional_approved' if functional else 'approved')
            or approval.get('architectureSemanticsPreserved') is not (not functional)
            or approval.get('preservationMode')!=('functional_equivalence_only' if functional else 'architecture_equivalent')):
        raise ValueError('CSR_RUNTIME_CLAIM_SCOPE_MISMATCH')
    ignored=[] if p['functionalObservability'] is None else sorted({x['state_id'] for x in p['functionalObservability']['ignored_states']})
    if (approval.get('ignoredSourceState')!=ignored or (functional and not ignored)
            or approval.get('targetEnvironmentId')!=p['targetEnvironmentId']
            or approval.get('sourceModelId')!=semantic_identity(f['sourceModel'])):
        raise ValueError('CSR_RUNTIME_OBSERVABILITY_BINDING_MISMATCH')
    return expected_facts
