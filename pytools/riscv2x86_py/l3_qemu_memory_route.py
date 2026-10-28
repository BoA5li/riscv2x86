"""Normal-production ordinary-memory TCG route and optional explicit cache model.

This is bounded compiler-region observation, never a physical-cache experiment.
L0-L2 prerequisite executions keep their own environment identities; the TCG
executions and byte-identical deployments are recorded separately and checked.
"""
import subprocess
import json
from pathlib import Path

from .l3_trace_support import digest, identity, save
from .l3_memory_intent import memory_spec, CAPABILITY, LIMITATIONS
from .l3_cache_model import validate as cache_validate, evaluate as cache_evaluate
from .l3_memory_backend import validate_backend, capture
from .l3_qemu_backend import parse_capture
from .l3_trace_deployment import prepare as prepare_deployment, validate as validate_deployment
from .l3_evidence_closure import close_fragment, validate_fragment_against_requirement
from .l3_intent_requirements import parse_l3_intent_profile, parse_l3_requirement_manifest
from .translation_validation import ValidationLayerResult, ValidationLevel, ValidationProfile
from .validation_status import ValidationStatus

CONTRACT_SCHEMA='riscv2x86.compiler-region-trace-experiment.v1'
STORE_CONTRACT_SCHEMA='riscv2x86.compiler-region-trace-experiment.v2'
TYPED_LOAD_CONTRACT_SCHEMA='riscv2x86.compiler-region-trace-experiment.v6'
TYPED_STORE_CONTRACT_SCHEMA='riscv2x86.compiler-region-trace-experiment.v5'
SCALAR_CONTRACT_SCHEMA='riscv2x86.compiler-region-trace-experiment.v3'
VECTOR_CONTRACT_SCHEMA='riscv2x86.compiler-region-trace-experiment.v4'
ROUTE_SCHEMA='riscv2x86.compiler-region-trace-route.v1'
RUNNER_SCHEMA='riscv2x86.compiler-region-trace-runner.v1'


from .l3_trace_support import require_json_document,require_json_match

def parse_contract(value):
    from .l3_experiment_runner import ExperimentContract, LogicalAccess
    fields={'schemaVersion','experimentId','translationPlanId','proofIdentity','intentProfileIdentity',
            'requirementIdentity','approvedTargetRelationIdentity','programId','fragmentId','spec',
            'deployment','backendPath','backendDigest','cacheModel','requiredProperties','propertyBindings',
            'sampleCount','knownNonEquivalences'}
    typed_load=isinstance(value,dict) and value.get('schemaVersion')==TYPED_LOAD_CONTRACT_SCHEMA
    if typed_load:fields.add('loadCall')
    typed_store=isinstance(value,dict) and value.get('schemaVersion')==TYPED_STORE_CONTRACT_SCHEMA
    if typed_store:fields.add('storeCall')
    vector=isinstance(value,dict) and value.get('schemaVersion')==VECTOR_CONTRACT_SCHEMA
    scalar=isinstance(value,dict) and value.get('schemaVersion') in {SCALAR_CONTRACT_SCHEMA,VECTOR_CONTRACT_SCHEMA}
    if scalar:fields.add('propertyObligations')
    if vector:fields.add('samplePlan')
    if not isinstance(value,dict) or set(value)!=fields or value['schemaVersion'] not in {CONTRACT_SCHEMA,STORE_CONTRACT_SCHEMA,TYPED_STORE_CONTRACT_SCHEMA,TYPED_LOAD_CONTRACT_SCHEMA,SCALAR_CONTRACT_SCHEMA,VECTOR_CONTRACT_SCHEMA}:
        raise ValueError('L3_TRACE_CONTRACT_SCHEMA_INVALID')
    if type(value['sampleCount']) is not int or not 2<=value['sampleCount']<=16:
        raise ValueError('L3_TRACE_SAMPLE_COUNT_INVALID')
    spec=value['spec']
    spec_fields={'fragmentId','programId','objectId','sourceEffectId','offset','width','size','alignment','access','observationUnit','authorityIdentity'}
    if not isinstance(spec,dict) or set(spec)!=spec_fields:
        raise ValueError('L3_TRACE_CONTRACT_SPEC_INVALID')
    if scalar:
        if any(spec[k]!=v or type(spec[k]) is not type(v) for k,v in
                {'objectId':'','sourceEffectId':'','offset':0,'width':0,'size':0,'alignment':0,
                 'access':'none','observationUnit':'compiler-asm-region'}.items()):
            raise ValueError('L3_SCALAR_CONTRACT_SPEC_INVALID')
        from .l3_property_obligations import check_properties, validate as validate_obligations
        obligations=value['propertyObligations']
        from .l3_trace_support import identity
        if (not isinstance(obligations,dict) or obligations.get('obligationIdentity')!=identity({k:v for k,v in obligations.items() if k!='obligationIdentity'})
                or obligations.get('fragmentId')!=value['fragmentId'] or obligations.get('programId')!=value['programId']
                or obligations.get('proofIdentity')!=value['proofIdentity']
                or obligations.get('approvedTargetRelationIdentity')!=value['approvedTargetRelationIdentity']):
            raise ValueError('L3_SCALAR_OBLIGATION_BINDING_INVALID')
        validate_obligations(obligations)
        check_properties(obligations,value['requiredProperties'])
        if value['cacheModel'] is not None:raise ValueError('L3_SCALAR_OBJECT_RELATIVE_CACHE_MODEL_UNSUPPORTED')
    else:
        if (type(spec['width']) is not int or spec['width'] not in (1,2,4,8) or
                type(spec['offset']) is not int or spec['offset']<0 or spec['offset']%spec['width'] or
                type(spec['size']) is not int or not spec['offset']+spec['width']<=spec['size']<=65536 or
                type(spec['alignment']) is not int or not spec['width']<=spec['alignment']<=64 or
                spec['alignment'] & (spec['alignment']-1) or spec['observationUnit']!='compiler-asm-region'):
            raise ValueError('L3_TRACE_CONTRACT_OBJECT_DOMAIN_INVALID')
        if spec['fragmentId']!=value['fragmentId'] or spec['programId']!=value['programId'] or spec['access'] not in {'read','write'}:
            raise ValueError('L3_TRACE_CONTRACT_SPEC_MISMATCH')
        if typed_load:
            if spec['access']!='read':raise ValueError('L3_MEMORY_LOAD_ACCESS_REQUIRED')
            if value['deployment'].get('schemaVersion')!='riscv2x86.compiler-region-execution-deployment.v3':raise ValueError('L3_MEMORY_LOAD_DEPLOYMENT_VERSION_REQUIRED')
            from .l3_memory_call import validate_load_call
            validate_load_call(value['loadCall'])
            require_json_match(value['deployment']['functionScope']['callSignature'],value['loadCall'],'L3_MEMORY_LOAD_CALL_CHANGED')
            if value['loadCall']['widthBytes']!=spec['width']:raise ValueError('L3_MEMORY_LOAD_CALL_WIDTH_MISMATCH')
        if spec['access']=='read' and not typed_load and 'callSignature' in value['deployment'].get('functionScope',{}):
            raise ValueError('L3_MEMORY_TYPED_LOAD_CONTRACT_VERSION_REQUIRED')
        if typed_store:
            if spec['access']!='write':raise ValueError('L3_MEMORY_STORE_ACCESS_REQUIRED')
            require_json_match(value['deployment']['functionScope']['callSignature'],value['storeCall'],'L3_MEMORY_STORE_CALL_CHANGED')
            if value['storeCall']['widthBytes']!=spec['width']:
                raise ValueError('L3_MEMORY_STORE_CALL_WIDTH_MISMATCH')
        if spec['access']=='write' and not typed_store and 'callSignature' in value['deployment'].get('functionScope',{}):
            raise ValueError('L3_MEMORY_TYPED_STORE_CONTRACT_VERSION_REQUIRED')
        if spec['access']=='write' and not typed_store and (value['schemaVersion']!=STORE_CONTRACT_SCHEMA or spec['width']!=8):
            raise ValueError('L3_TRACE_STORE_CONTRACT_VERSION_REQUIRED')
    if spec['fragmentId']!=value['fragmentId'] or spec['programId']!=value['programId']:
        raise ValueError('L3_TRACE_CONTRACT_SPEC_MISMATCH')
    if value['deployment']['spec']!=spec or value['deployment']['sampleCount']!=value['sampleCount']:
        raise ValueError('L3_TRACE_CONTRACT_DEPLOYMENT_MISMATCH')
    if scalar and not vector and 'callSignature' in value['deployment'].get('functionScope',{}):
        raise ValueError('L3_SCALAR_CALL_CONTRACT_VERSION_REQUIRED')
    if vector:
        from .l3_scalar_call import sample_plan
        deployment=value['deployment']
        if deployment.get('schemaVersion')!='riscv2x86.compiler-region-execution-deployment.v2':
            raise ValueError('L3_SCALAR_CALL_DEPLOYMENT_VERSION_REQUIRED')
        signature=deployment['functionScope']['callSignature']
        if value.get('samplePlan')!=sample_plan(signature,value['sampleCount']):
            raise ValueError('L3_SCALAR_SAMPLE_PLAN_MISMATCH')
    model=value['cacheModel']
    if model is not None: cache_validate(model)
    expected_limits=sorted(LIMITATIONS+([] if model is None else ['cache-model-is-object-relative-fragment-stream-only']))
    if value['knownNonEquivalences']!=expected_limits: raise ValueError('L3_TRACE_CONTRACT_LIMITATIONS_MISSING')
    expected=[{'propertyId':'memory.fragment-access','dimension':'access_pattern','unit':'fragment'}]
    if model is not None: expected.insert(0,{'propertyId':'cache.fragment-stream-model','dimension':'cache_model','unit':'fragment'})
    if value['requiredProperties']!=expected: raise ValueError('L3_TRACE_CONTRACT_PROPERTIES_MISMATCH')
    access=None if scalar else LogicalAccess('memory:approved-'+spec['access'],spec['objectId'],spec['offset'],spec['width'],spec['access'],spec['alignment'],'non_atomic','relaxed',())
    classes=('memory_access',) if model is None else ('cache_model','memory_access')
    contract=ExperimentContract(value['experimentId'],value['translationPlanId'],value['proofIdentity'],
        ('executed scalar region with no successful data accesses' if scalar else 'approved object-relative memory stream'),'byte-identical compiler-region TCG observation',
        'registered:compiler-region-memory-trace.v1','bounded_execution_intent',classes,
        (() if scalar else (access,)),(),(),(),(),'not-a-timing-experiment',value['sampleCount'],0,0,
        'single-guest-thread-no-timing-claim','complete-stream-no-sample-exclusion',{}, {},
        tuple(value['knownNonEquivalences']),True,value,value['intentProfileIdentity'],value['requirementIdentity'],
        value['approvedTargetRelationIdentity'],value['programId'])
    from .l3_property_bindings import validate_property_bindings
    validate_property_bindings(contract,expected)
    return contract


def validate_profile_scope(profile, spec, model, obligations=None):
    scope={'spec':spec,'model':model}
    if spec['access']=='none':
        # Scalar profiles bind the independently replayed policy obligations.
        scope['obligations']=obligations
    if (profile.observation_boundary_kind!='compiler-asm-region' or
            profile.observation_boundary_identity!=identity(scope) or
            tuple(profile.source_capabilities)!=(CAPABILITY,) or tuple(profile.target_capabilities)!=(CAPABILITY,)):
        raise ValueError('L3_TRACE_REGISTERED_INTENT_SCOPE_MISMATCH')


def parse_objects(stdout, token, spec, samples, signature=None):
    if spec['access']=='none':
        from .l3_scalar_trace import parse_samples
        return parse_samples(stdout,token,samples,signature)
    typed_load=bool(signature and signature.get('schemaVersion')=='riscv2x86.l3-memory-load-call.v1')
    objects=[]
    for line in stdout.splitlines():
        value=json.loads(line)
        fields={'token','sample','objectBase','objectSize','value'}
        if spec['access']=='write' or typed_load:fields.add('objectHex')
        if (not isinstance(value,dict) or set(value)!=fields or
                value['token']!=token or type(value['sample']) is not int or value['sample']!=len(objects) or
                type(value['objectSize']) is not int or value['objectSize']<spec['size'] or
                int(value['objectBase'],16)%spec['alignment'] or int(value['objectBase'],16)<=0 or
                not ((signature and spec['access']=='write' and signature.get('returnKind')=='void' and value['value'] is None)
                     or isinstance(value['value'],str) and len(value['value'])==16)):
            raise ValueError('L3_TRACE_RUNTIME_OBJECT_BINDING_INVALID')
        if value['value'] is not None:int(value['value'],16)
        if spec['access']=='write':
            unit=spec['width'] if signature else 8
            if value['objectSize']!=((spec['size']+unit-1)//unit)*unit:
                raise ValueError('L3_TRACE_RUNTIME_OBJECT_BINDING_INVALID')
            # Both executions must match the declared input and full object
            # result, not merely each other or an identical return value.
            expected=bytearray((0x31+17*i+len(objects))&255 for i in range(value['objectSize']))
            from .l3_memory_call import store_value
            written=store_value(len(objects),spec['width'])
            expected[spec['offset']:spec['offset']+spec['width']]=written.to_bytes(spec['width'],'little')
            void=signature is not None and signature.get('returnKind')=='void'
            if (value.get('objectHex')!=expected.hex() or (value['value'] is not None if void else value['value'] is None or int(value['value'],16)!=written)):
                raise ValueError('L3_TRACE_STORE_VALUE_OR_OBJECT_MISMATCH')
        if typed_load:
            import re
            if re.fullmatch('[0-9a-f]{16}',value['value']) is None:raise ValueError('L3_MEMORY_LOAD_RESULT_ENCODING_INVALID')
            from .l3_memory_call import load_value,load_initial_bytes
            expected=load_initial_bytes(spec,len(objects))
            raw=int.from_bytes(expected[spec['offset']:spec['offset']+spec['width']],'little')
            if (value['objectSize']!=len(expected) or value['objectHex']!=expected.hex()
                    or int(value['value'],16)!=load_value(raw,signature)):
                raise ValueError('L3_TRACE_LOAD_VALUE_OR_OBJECT_MISMATCH')
        objects.append(value)
    if len(objects)!=samples: raise ValueError('L3_TRACE_RUNTIME_SAMPLES_MISSING')
    return objects


def normalize(events, objects, spec):
    if spec['access']=='none':
        return list(events),(['L3_SCALAR_UNEXPECTED_DATA_ACCESS'] if events else [])
    normalized=[]; reasons=[]
    for sample,obj in enumerate(objects):
        selected=[e for e in events if e['sample']==sample]
        if len(selected)!=1: reasons.append('L3_TRACE_ACCESS_MULTIPLICITY_MISMATCH:'+str(sample))
        for event in selected:
            offset=event['address']-int(obj['objectBase'],16)
            if not 0<=offset or offset+event['size']>obj['objectSize']:
                reasons.append('L3_TRACE_OBJECT_BOUNDS_MISMATCH:'+str(sample))
            if (offset,event['size'],event['access'])!=(spec['offset'],spec['width'],spec['access']):
                reasons.append('L3_TRACE_APPROVED_ACCESS_MISMATCH:'+str(sample))
            normalized.append({'sample':sample,'objectId':spec['objectId'],'offset':offset,
                               'size':event['size'],'access':event['access']})
    return normalized,sorted(set(reasons))


def report_from_capture(side, backend, deployment, events, objects, evidence):
    spec=deployment['spec']; normalized,reasons=normalize(events,objects,spec)
    scalar=spec['access']=='none'
    return {'schemaVersion':('riscv2x86.compiler-region-trace-observation.v4' if spec['access']=='read' and 'callSignature' in deployment.get('functionScope',{}) else 'riscv2x86.compiler-region-trace-observation.v3' if scalar and 'callSignature' in deployment.get('functionScope',{}) else 'riscv2x86.compiler-region-trace-observation.v2' if scalar else 'riscv2x86.compiler-region-trace-observation.v1'),'side':side,
            'backendIdentity':backend['backendIdentity'],'deploymentIdentity':deployment['deploymentIdentity'],
            'captureBoundary':'compiler-asm-region-only',('samples' if scalar else 'objects'):objects,'events':normalized,
            'evidence':evidence,'environment':{'executor':backend[side+'Executor'],
                'executorDigest':digest(backend[side+'Executor']),'runnerArguments':backend[side+'RunnerArguments'],
                'observationKind':'tcg-successful-guest-memory-accesses','physicalMicroarchitectureClaimed':False},
            'reasonCodes':reasons}


def replay_reports(detail, contract, source_artifact, target_artifact):
    """Independently re-read actual trace/command files; hashes are not event facts."""
    require_json_document(detail,'L3_TRACE_REPLAY_JSON_INVALID')
    raw=contract.payload
    if digest(raw['backendPath'])!=raw['backendDigest']: raise ValueError('L3_TRACE_BACKEND_MANIFEST_CHANGED')
    backend=validate_backend(raw['backendPath'])
    deployment=validate_deployment(raw['deployment'],backend,source_artifact,target_artifact)
    data=json.loads(Path(deployment['inputs']['report']).read_text())
    finding=next(f for f in data['findings'] if f['fragment']['id']==raw['fragmentId'])
    profile=parse_l3_intent_profile(finding['l3IntentProfile'],fragment_id=raw['fragmentId'])
    validate_profile_scope(profile,raw['spec'],raw['cacheModel'],raw.get('propertyObligations'))
    if raw['spec']['access']=='none':
        from .l3_property_obligations import analyze
        if analyze(finding)!=raw['propertyObligations'] or detail.get('propertyObligations')!=raw['propertyObligations']:
            raise ValueError('L3_SCALAR_OBLIGATION_REPLAY_MISMATCH')
    if profile.profile_identity!=contract.intent_profile_identity or profile.proof_identity!=contract.proof_identity:
        raise ValueError('L3_TRACE_DEPLOYMENT_INTENT_CHANGED')
    require_json_match(deployment,detail.get('traceDeployment'),'L3_TRACE_REPORTED_DEPLOYMENT_MISMATCH')
    reports=detail['platformReports']; rebuilt={}
    for side in ('source','target'):
        report=reports[side]; evidence=report['evidence']
        if digest(evidence['rawTracePath'])!=evidence['rawTraceDigest']:
            raise ValueError('L3_TRACE_RAW_OBSERVATION_CHANGED')
        command_path=Path(evidence['rawTracePath']).with_name('execute.command.json')
        if digest(command_path)!=evidence['commandRecordDigest']: raise ValueError('L3_TRACE_COMMAND_RECORD_CHANGED')
        record=json.loads(command_path.read_text())
        if record['returnCode']!=0 or record['timedOut'] is not False or record['stderr']:
            raise ValueError('L3_TRACE_EXECUTION_INCOMPLETE')
        region=deployment['sides'][side]['region']
        events=parse_capture(Path(evidence['rawTracePath']).read_text(),token=evidence['token'],
            target='riscv64' if side=='source' else 'x86_64',region=region,calls=raw['sampleCount'])
        objects=parse_objects(record['stdout'],evidence['token'],raw['spec'],raw['sampleCount'],deployment['functionScope'].get('callSignature'))
        command=record['command']; binary=deployment['sides'][side]['executionArtifact']['artifactPath']
        expected_plugin=','.join([backend['plugin'],'start='+hex(region['start']),'end='+hex(region['end']),
                                 'limit=4096','output='+str(Path(evidence['rawTracePath']).resolve()),'token='+evidence['token']])
        if command!=[backend[side+'Executor'],*backend[side+'RunnerArguments'],'-plugin',expected_plugin,binary,evidence['token']]:
            raise ValueError('L3_TRACE_LAUNCHED_PROGRAM_MISMATCH')
        rebuilt[side]=report_from_capture(side,backend,deployment,events,objects,evidence)
        require_json_match(rebuilt[side],report,'L3_TRACE_NORMALIZATION_REPLAY_MISMATCH')
    rows='samples' if raw['spec']['access']=='none' else 'objects'
    if [x['value'] for x in rebuilt['source'][rows]] != [x['value'] for x in rebuilt['target'][rows]]:
        raise ValueError('L3_TRACE_DEPLOYMENT_FUNCTIONAL_MISMATCH')
    return rebuilt


def build_observer(config):
    fields={'schemaVersion','contractPath','contractDigest','sourceCommand','targetCommand','timeoutSeconds'}
    if not isinstance(config,dict) or set(config)!=fields or config['schemaVersion']!=RUNNER_SCHEMA:
        raise ValueError('L3_TRACE_RUNNER_CONFIG_INVALID')
    def validate(**kwargs):
        work=Path(kwargs['l3_plan_directory'])/('trace-observer-'+kwargs['translation_artifact'].fragment_id.encode().hex()[-32:])
        try:
            if digest(config['contractPath'])!=config['contractDigest']: raise ValueError('L3_TRACE_CONTRACT_CHANGED')
            contract=parse_contract(json.loads(Path(config['contractPath']).read_text()))
            raw=contract.payload; backend=validate_backend(raw['backendPath'])
            source=kwargs['source_program_artifact']; target=kwargs['target_program_artifact']
            deployment=validate_deployment(raw['deployment'],backend,source,target)
            context=kwargs['l3_execution_context']; context.validate(source,target)
            prior=kwargs['prior_layer_results']
            if len(prior)!=3 or tuple(x.level.value for x in prior)!=('L0','L1','L2') or any(x.status is not ValidationStatus.VERIFIED for x in prior):
                raise ValueError('L3_TRACE_PREREQUISITES_INCOMPLETE')
            l2_scope=json.loads(prior[2].detail)['claimScope']
            if l2_scope!='architectural': raise ValueError('L3_TRACE_ARCHITECTURAL_PREREQUISITE_REQUIRED')
            manifest=parse_l3_requirement_manifest(kwargs['l3_requirement_manifest'])
            reqs=[r for r in manifest.requirements if r['fragmentId']==raw['fragmentId']]
            if len(reqs)!=1 or reqs[0]['requirementIdentity']!=contract.requirement_identity or reqs[0]['requiredProperties']!=raw['requiredProperties']:
                raise ValueError('L3_TRACE_REQUIREMENT_MISMATCH')
            profile=parse_l3_intent_profile(kwargs['l3_intent_profile'],fragment_id=raw['fragmentId'])
            validate_profile_scope(profile,raw['spec'],raw['cacheModel'],raw.get('propertyObligations'))
            if (profile.profile_identity!=contract.intent_profile_identity or profile.proof_identity!=contract.proof_identity or
                    kwargs['translation_artifact'].proof_identity!=contract.proof_identity or
                    kwargs['translation_artifact'].translation_plan_id!=contract.translation_plan_id or
                    [p.to_dict() for p in profile.required_properties]!=raw['requiredProperties']):
                raise ValueError('L3_TRACE_PROFILE_OR_PROOF_MISMATCH')
            reports={}
            for side in ('source','target'):
                events,stdout,evidence=capture(backend,side,deployment['sides'][side]['executionArtifact']['artifactPath'],
                    deployment['sides'][side]['region'],work/side,raw['sampleCount'],config['timeoutSeconds'])
                # Stderr has to remain empty; capture protocol is a separate file.
                record=json.loads((work/side/'execute.command.json').read_text())
                if record['stderr']: raise ValueError('L3_TRACE_EXECUTOR_STDERR_UNEXPECTED')
                objects=parse_objects(stdout,evidence['token'],raw['spec'],raw['sampleCount'],deployment['functionScope'].get('callSignature'))
                reports[side]=report_from_capture(side,backend,deployment,events,objects,evidence)
            detail={'traceDeployment':deployment,'contractPath':config['contractPath'],'contractDigest':config['contractDigest'],
                'platformReports':reports,'executionBindings':{s:context.request_binding(s) for s in ('source','target')},
                'observationScope':'compiler-asm-region-only','physicalMicroarchitectureClaimed':False,
                'prerequisiteEnvironment':kwargs['target_environment']}
            if raw['spec']['access']=='none':detail['propertyObligations']=raw['propertyObligations']
            replay_reports(detail,contract,source,target)
            reasons=sorted(set(r for report in reports.values() for r in report['reasonCodes']))
            if reports['source']['events']!=reports['target']['events']: reasons.append('L3_TRACE_SOURCE_TARGET_STREAM_MISMATCH')
            cache_results=None
            if raw['cacheModel'] is not None and not reasons:
                cache_results={side:cache_evaluate([{k:e[k] for k in ('offset','size','access')} for e in report['events']],raw['cacheModel']) for side,report in reports.items()}
                if cache_results['source']!=cache_results['target']: reasons.append('L3_CACHE_MODEL_RELATION_MISMATCH')
            status='failed' if reasons else 'verified'
            dimensions=[]; req=reqs[0]
            execution=identity({'context':context.identity,'reports':reports,'deployment':deployment['deploymentIdentity']})
            for prop in raw['requiredProperties']:
                comparison=cache_results if prop['dimension']=='cache_model' else {s:reports[s]['events'] for s in reports}
                payload={'schemaVersion':'riscv2x86.l3-dimension-result.v1','fragmentId':req['fragmentId'],'programId':req['programId'],
                    **prop,'status':('inconclusive' if prop['dimension']=='cache_model' and cache_results is None else status),'claimScope':'architectural_intent','requirementIdentity':req['requirementIdentity'],
                    'profileIdentity':contract.intent_profile_identity,'contractIdentity':contract.identity,
                    'translationArtifactIdentity':kwargs['translation_artifact'].identity,'sourceArtifactIdentity':source.artifact_digest,
                    'targetArtifactIdentity':target.artifact_digest,'sourceReportIdentity':identity(reports['source']),
                    'targetReportIdentity':identity(reports['target']), 'sourceEnvironmentIdentity':identity(reports['source']['environment']),
                    'targetEnvironmentIdentity':identity(reports['target']['environment']),'executionIdentity':execution,
                    'comparisonEvidenceIdentity':identity({'property':prop,'comparison':comparison}),
                    'l0EvidenceIdentity':prior[0].evidence_identity,'l1EvidenceIdentity':prior[1].evidence_identity,
                    'l2EvidenceIdentity':prior[2].evidence_identity,'l2ClaimScope':l2_scope,
                    'declaredLimitations':list(profile.not_claimed_properties),'uncoveredEffects':[],'reasonCodes':sorted(set(reasons))}
                dimensions.append(dict(payload,resultIdentity=identity(payload)))
            fragment=close_fragment(req,dimensions,claim_scope='architectural_intent')
            detail.update(fragmentResult=fragment,cacheModelResults=cache_results)
            save(work/'observation-result.json',detail)
            return ValidationLayerResult(ValidationLevel.L3,ValidationStatus(status),identity(detail),json.dumps(detail,sort_keys=True))
        except (OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired) as exc:
            return ValidationLayerResult(ValidationLevel.L3,ValidationStatus.INCONCLUSIVE,
                detail=json.dumps({'reasonCodes':[str(exc)],'failureStage':'l3-memory-trace','evidenceProductionDisposition':'not_complete'}))
    return validate


def build_route(config):
    fields={'schemaVersion','sourcePath','targetPath','reportPath','backendPath','backendDigest','cacheModel',
            'workDirectory','sampleCount','timeoutSeconds'}
    if not isinstance(config,dict) or set(config)!=fields or config['schemaVersion']!=ROUTE_SCHEMA:
        raise ValueError('L3_TRACE_ROUTE_CONFIG_INVALID')
    def validate(**kwargs):
        try:
            if kwargs['validation_plan'].profile is not ValidationProfile.MICROARCH:
                raise ValueError('L3_TRACE_MICROARCH_PROFILE_REQUIRED')
            if digest(config['backendPath'])!=config['backendDigest']: raise ValueError('L3_TRACE_BACKEND_SELECTION_CHANGED')
            backend=validate_backend(config['backendPath']); source=kwargs['source_program_artifact']; target=kwargs['target_program_artifact']
            prior=kwargs.get('prior_layer_results')
            if not isinstance(prior,tuple) or len(prior)!=3 or any(x.status is not ValidationStatus.VERIFIED for x in prior):
                raise ValueError('L3_TRACE_PREREQUISITES_MISSING')
            from .l3_intent_ingress import validate_receipt
            report=Path(config['reportPath']); data=json.loads(report.read_text())
            matches=[f for f in data['findings'] if (f.get('fragment') or {}).get('id')==kwargs['translation_artifact'].fragment_id]
            if len(matches)!=1 or len(data['findings'])!=1: raise ValueError('L3_TRACE_SINGLE_FRAGMENT_PROGRAM_REQUIRED')
            finding=matches[0]
            requirements=parse_l3_requirement_manifest(kwargs['l3_requirement_manifest'])
            selected=[r for r in requirements.requirements if r['fragmentId']==kwargs['translation_artifact'].fragment_id]
            if len(selected)!=1:raise ValueError('L3_TRACE_REQUIREMENT_INELIGIBLE')
            if selected[0]['eligibilityStatus']!='eligible':
                return ValidationLayerResult(ValidationLevel.L3,ValidationStatus.INCONCLUSIVE,
                    detail=json.dumps({'reasonCodes':selected[0]['reasonCodes'],
                        'failureStage':'l3-requirement-resolution','evidenceProductionDisposition':'not_produced'}))
            from .l3_scalar_trace import trace_spec
            from .l3_property_obligations import analyze, check_properties
            obligations=analyze(finding)
            spec=trace_spec(finding)
            profile=validate_receipt(finding,kwargs['translation_artifact'],config['sourcePath'],report)
            manifest=parse_l3_requirement_manifest(kwargs['l3_requirement_manifest']); reqs=[r for r in manifest.requirements if r['fragmentId']==spec['fragmentId']]
            if len(reqs)!=1 or reqs[0]['eligibilityStatus']!='eligible': raise ValueError('L3_TRACE_REQUIREMENT_INELIGIBLE')
            model=None if config['cacheModel'] is None else cache_validate(config['cacheModel'])
            check_properties(obligations,[p.to_dict() for p in profile.required_properties])
            validate_profile_scope(profile,spec,model,obligations if spec['access']=='none' else None)
            req=reqs[0]; samples=config['sampleCount']
            if type(samples) is not int or not 2<=samples<=16: raise ValueError('L3_TRACE_SAMPLE_COUNT_INVALID')
            work=Path(config['workDirectory']).resolve(); work.mkdir(parents=True,exist_ok=False)
            deployment=prepare_deployment(config['sourcePath'],config['targetPath'],report,finding,backend,source,target,work/'deployment',samples)
            properties=[x.to_dict() for x in profile.required_properties]
            bindings=[dict(p,comparatorId=('object-relative-cache-model.v1' if p['dimension']=='cache_model' else 'logical-access-contract.v1'),
                obligationIds=['fragment-stream-lru-state'] if p['dimension']=='cache_model' else (['memory:empty-executed-region'] if spec['access']=='none' else ['memory:approved-'+spec['access']])) for p in properties]
            contract={'schemaVersion':VECTOR_CONTRACT_SCHEMA if spec['access']=='none' else ((TYPED_STORE_CONTRACT_SCHEMA if 'callSignature' in deployment['functionScope'] else STORE_CONTRACT_SCHEMA) if spec['access']=='write' else (TYPED_LOAD_CONTRACT_SCHEMA if 'callSignature' in deployment['functionScope'] else CONTRACT_SCHEMA)),'experimentId':'compiler-region:'+profile.profile_identity,
                'translationPlanId':kwargs['translation_artifact'].translation_plan_id,'proofIdentity':profile.proof_identity,
                'intentProfileIdentity':profile.profile_identity,'requirementIdentity':req['requirementIdentity'],
                'approvedTargetRelationIdentity':profile.approved_target_relation_identity,'programId':spec['programId'],'fragmentId':spec['fragmentId'],
                'spec':spec,'deployment':deployment,'backendPath':str(Path(config['backendPath']).resolve()),'backendDigest':config['backendDigest'],
                'cacheModel':model,'requiredProperties':properties,'propertyBindings':bindings,'sampleCount':samples,
                'knownNonEquivalences':list(profile.not_claimed_properties)}
            if spec['access']=='write' and 'callSignature' in deployment['functionScope']:
                contract['storeCall']=deployment['functionScope']['callSignature']
            if spec['access']=='read' and 'callSignature' in deployment['functionScope']:
                contract['loadCall']=deployment['functionScope']['callSignature']
            if spec['access']=='none':
                from .l3_scalar_call import sample_plan
                contract['propertyObligations']=obligations
                contract['samplePlan']=sample_plan(deployment['functionScope']['callSignature'],samples)
            parse_contract(contract); path=save(work/'experiment-contract.json',contract)
            observer={'schemaVersion':RUNNER_SCHEMA,'contractPath':str(path),'contractDigest':digest(path),
                'sourceCommand':[backend['sourceExecutor']], 'targetCommand':[backend['targetExecutor']],
                'timeoutSeconds':config['timeoutSeconds']}
            from .l3_provider_resolution import PROVIDER_SCHEMA,REGISTRY_SCHEMA,build_l3_capability_registry_validator
            provider={'schemaVersion':PROVIDER_SCHEMA,'providerId':'compiler-region-trace-v1','bindingKind':'explicit',
                'validatorType':'l3-qemu-memory-trace','config':observer,'experimentClasses':list(profile.experiment_classes),
                'propertyDimensions':sorted({p['dimension'] for p in properties}),'sourceCapabilities':[CAPABILITY],'targetCapabilities':[CAPABILITY],
                'executionProfiles':['rv64gc-user-to-x86_64-user'],'contractSchemas':[contract['schemaVersion']],
                'fragmentIds':[spec['fragmentId']],'profileIdentities':[]}
            registry={'schemaVersion':REGISTRY_SCHEMA,'providers':[provider],'executionProfile':'rv64gc-user-to-x86_64-user',
                'environmentId':kwargs['target_environment']['environmentId'],'sourceCapabilities':[CAPABILITY],'targetCapabilities':[CAPABILITY]}
            save(work/'provider-registry.json',registry)
            return build_l3_capability_registry_validator(registry,{'l3-qemu-memory-trace':build_observer})(**kwargs)
        except (OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired) as exc:
            return ValidationLayerResult(ValidationLevel.L3,ValidationStatus.INCONCLUSIVE,
                detail=json.dumps({'reasonCodes':[str(exc)],'failureStage':'l3-trace-preparation','evidenceProductionDisposition':'not_produced'}))
    return validate


def verify_detail(detail, contract, source_artifact, target_artifact):
    reports=replay_reports(detail,contract,source_artifact,target_artifact)
    if any(report['reasonCodes'] for report in reports.values()) or reports['source']['events']!=reports['target']['events']:
        raise ValueError('L3_TRACE_SUCCESS_CONTAINS_COUNTEREXAMPLE')
    expected=None
    if contract.payload['cacheModel'] is not None:
        expected={side:cache_evaluate([{k:e[k] for k in ('offset','size','access')} for e in report['events']],contract.payload['cacheModel']) for side,report in reports.items()}
    require_json_match(expected,detail.get('cacheModelResults'),'L3_CACHE_MODEL_REPLAY_MISMATCH')
    fragment=detail['fragmentResult']
    bindings=detail['executionBindings']
    expected_execution=identity({'context':bindings['source']['contextIdentity'],'reports':reports,
                                 'deployment':detail['traceDeployment']['deploymentIdentity']})
    for prop in contract.payload['requiredProperties']:
        dimension=fragment['dimensionResults'][prop['propertyId']]
        comparison=expected if prop['dimension']=='cache_model' else {s:reports[s]['events'] for s in reports}
        if (dimension['executionIdentity']!=expected_execution or
                dimension['sourceEnvironmentIdentity']!=identity(reports['source']['environment']) or
                dimension['targetEnvironmentIdentity']!=identity(reports['target']['environment']) or
                dimension['declaredLimitations']!=contract.payload['knownNonEquivalences']):
            raise ValueError('L3_TRACE_EXECUTION_OR_SCOPE_REPLAY_MISMATCH')
        if dimension['comparisonEvidenceIdentity']!=identity({'property':prop,'comparison':comparison}):
            raise ValueError('L3_TRACE_COMPARISON_REPLAY_MISMATCH')
    return detail
