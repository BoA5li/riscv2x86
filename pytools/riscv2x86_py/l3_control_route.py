"""Normal-production control capture, property comparison and independent replay."""
import json
from pathlib import Path
import shutil
import subprocess
from .l3_trace_support import digest,identity,save,require_json_document,require_json_match
from .l3_control_spec import CAPABILITY,LIMITS
from .l3_control_machine import selected_path,condition,value_of
from .l3_control_backend import validate as backend_validate,capture,parse_capture,command
from .l3_control_deployment import prepare as deploy,validate as replay_deployment
from .l3_intent_requirements import parse_l3_requirement_manifest
from .l3_evidence_closure import close_fragment,validate_fragment_against_requirement
from .translation_validation import ValidationLayerResult,ValidationLevel,ValidationProfile
from .validation_status import ValidationStatus

SCHEMA='riscv2x86.control-trace-route.v1'
CONTRACT='riscv2x86.control-trace-contract.v1'


def predicate_normal(p):
    kind,left,right=p['kind'],p['left'],p['right'];neg=False
    if kind in ('equal','not_equal'):
        kind,neg='equal',kind=='not_equal'
        if str(left)>str(right):left,right=right,left
    else:
        prefix='signed_' if kind.startswith('signed_') else 'unsigned_'
        op=kind[len(prefix):]
        if op in ('greater','less_equal'):left,right=right,left
        neg=op in ('greater_equal','less_equal');kind=prefix+'less'
    return (kind,left,right),neg


def observed_events(deployment,side,observed,rows):
    graph=deployment['sides'][side]['machineGraph'];spec=deployment['spec'];events=[]
    expected=spec['predicate'];wanted=predicate_normal(expected) if expected else None
    for sample,(raw,row) in enumerate(zip(observed['paths'],rows)):
        inputs=[int(x,16) for x in row['inputs']];reasons=[];logical=None;shape=[]
        try:
            path=selected_path(graph,raw['pcs'],raw['exit'],inputs)
            shape=[t['kind'] for t in path['transfers']]
            if expected:
                if len(path['conditions'])!=1:raise ValueError('L3_CONTROL_PREDICATE_COUNT_MISMATCH')
                predicate=path['conditions'][0];actual=predicate_normal(predicate)
                if actual[0]!=wanted[0]:raise ValueError('L3_CONTROL_PREDICATE_BINDING_MISMATCH')
                logical=predicate['taken'] ^ actual[1] ^ wanted[1]
                if spec['kind']=='asm_goto':
                    expected_exit=graph['region']['exitRoles']['taken' if logical else 'fallthrough']
                    if raw['exit']!=expected_exit:raise ValueError('L3_CONTROL_GOTO_CONTINUATION_MISMATCH')
                else:
                    index=spec['arms']['true' if logical else 'false']
                    if int(row['value'],16)!=inputs[index]:raise ValueError('L3_CONTROL_SELECTED_VALUE_MISMATCH')
            else:
                if path['conditions']:raise ValueError('L3_CONTROL_UNEXPECTED_CONDITIONAL_TRANSFER')
                if int(row['value'],16)!=inputs[spec['arms']['selected']]:raise ValueError('L3_CONTROL_SELECTED_VALUE_MISMATCH')
        except (ValueError,KeyError,IndexError) as exc:reasons.append(str(exc))
        events.append({'sample':sample,'logicalOutcome':logical,'actualTransferShape':shape,
                       'continuation':('taken' if logical else 'not-taken') if expected else 'target',
                       'value':row['value'],'reasonCodes':reasons})
    return events


def report(side,backend,deployment,observed,rows,evidence):
    return {'schemaVersion':'riscv2x86.control-observation.v1','side':side,
        'backendIdentity':backend['backendIdentity'],'deploymentIdentity':deployment['deploymentIdentity'],
        'rawPaths':observed['paths'],'memory':observed['memory'],'samples':rows,
        'controlEvents':observed_events(deployment,side,observed,rows),'evidence':evidence,
        'environment':{'executor':backend[side+'Executor'],'executorDigest':digest(backend[side+'Executor']),
            'runnerArguments':backend[side+'RunnerArguments'],'observationKind':'qemu-architectural-execution-path',
            'physicalMicroarchitectureClaimed':False}}


def comparison(reports,control):
    source=reports['source']['controlEvents'];target=reports['target']['controlEvents'];reasons=[]
    if len(source)!=len(target):raise ValueError('L3_CONTROL_OBSERVATION_COUNT_MISMATCH')
    logical=True;shape=True
    for a,b in zip(source,target):
        if a['reasonCodes'] or b['reasonCodes'] or (a['continuation'],a['value'])!=(b['continuation'],b['value']):logical=False
        if a['actualTransferShape']!=b['actualTransferShape']:shape=False
    if control['predicate']:
        # Coverage comes from observed and validated paths, not planned values.
        for events in (source,target):
            if {e['logicalOutcome'] for e in events if not e['reasonCodes']}!={False,True}:logical=False;reasons.append('L3_CONTROL_OBSERVED_COVERAGE_INCOMPLETE')
    if not logical:reasons.append('L3_CONTROL_LOGICAL_CONTINUATION_MISMATCH')
    if not shape:reasons.append('L3_CONTROL_ACTUAL_TRANSFER_SHAPE_MISMATCH')
    return {'control':{'logicalContinuation':'verified' if logical else 'failed',
                       'actualTransferShape':'verified' if shape else 'failed','status':'verified' if logical and shape else 'failed','reasonCodes':sorted(set(reasons))},
            'memory':{'status':'failed' if reports['source']['memory'] or reports['target']['memory'] else 'verified',
                      'reasonCodes':['L3_CONTROL_UNEXPECTED_DATA_ACCESS'] if reports['source']['memory'] or reports['target']['memory'] else []}}


def dimensions(contract,reports,bindings,artifact,source,target,prior,l2_scope):
    req=contract['requirement'];results=comparison(reports,contract['deployment']['spec']);items=[]
    execution=identity({'context':bindings['source']['contextIdentity'],'reports':reports,'deployment':contract['deployment']['deploymentIdentity']})
    for prop in req['requiredProperties']:
        cmp=results['control' if prop['dimension']=='control_flow' else 'memory']
        body={'schemaVersion':'riscv2x86.l3-dimension-result.v1','fragmentId':req['fragmentId'],'programId':req['programId'],**prop,
              'status':cmp['status'],'claimScope':'architectural_intent','requirementIdentity':req['requirementIdentity'],
              'profileIdentity':req['profileIdentity'],'contractIdentity':contract['contractIdentity'],
              'translationArtifactIdentity':artifact.identity,'sourceArtifactIdentity':source.artifact_digest,'targetArtifactIdentity':target.artifact_digest,
              'sourceReportIdentity':identity(reports['source']),'targetReportIdentity':identity(reports['target']),
              'sourceEnvironmentIdentity':identity(reports['source']['environment']),'targetEnvironmentIdentity':identity(reports['target']['environment']),
              'executionIdentity':execution,'comparisonEvidenceIdentity':identity({'property':prop,'comparison':cmp}),
              'l0EvidenceIdentity':prior[0].evidence_identity,'l1EvidenceIdentity':prior[1].evidence_identity,'l2EvidenceIdentity':prior[2].evidence_identity,
              'l2ClaimScope':l2_scope,'declaredLimitations':sorted(LIMITS),'uncoveredEffects':[],'reasonCodes':cmp['reasonCodes']}
        items.append(dict(body,resultIdentity=identity(body)))
    return close_fragment(req,items,claim_scope='architectural_intent'),results


def replay(detail,source,target):
    require_json_document(detail,'L3_CONTROL_REPLAY_JSON_INVALID')
    contract_path=Path(detail['contractPath'])
    if digest(contract_path)!=detail['contractDigest']:raise ValueError('L3_CONTROL_CONTRACT_CHANGED')
    contract=json.loads(contract_path.read_text())
    if contract.get('schemaVersion')!=CONTRACT or contract.get('contractIdentity')!=identity({k:v for k,v in contract.items() if k!='contractIdentity'}):raise ValueError('L3_CONTROL_CONTRACT_IDENTITY_INVALID')
    if contract['controlPolicy']!='logical-continuation-and-actual-transfer-shape.v1' or contract['limitations']!=sorted(LIMITS):raise ValueError('L3_CONTROL_CONTRACT_POLICY_CHANGED')
    if digest(contract['backendPath'])!=contract['backendDigest']:raise ValueError('L3_CONTROL_BACKEND_SELECTION_CHANGED')
    backend=backend_validate(contract['backendPath']);deployment=replay_deployment(contract['deployment'],backend,source,target)
    require_json_match(deployment,detail.get('controlDeployment'),'L3_CONTROL_REPORTED_DEPLOYMENT_MISMATCH')
    from .l3_control_spec import parse_samples
    rebuilt={}
    for side in ('source','target'):
        observed=detail['platformReports'][side];e=observed['evidence'];trace=Path(e['rawTracePath']);cmdpath=trace.with_name('execute.command.json')
        if digest(trace)!=e['rawTraceDigest'] or digest(cmdpath)!=e['commandRecordDigest']:raise ValueError('L3_CONTROL_RAW_CAPTURE_CHANGED')
        cmd=json.loads(cmdpath.read_text());binary=deployment['sides'][side]['executionArtifact']['artifactPath'];region=deployment['sides'][side]['region']
        if cmd['command']!=command(backend,side,binary,region,trace,e['token']) or cmd['returnCode']!=0 or cmd['timedOut'] is not False or cmd['stderr']:raise ValueError('L3_CONTROL_LAUNCHED_EXECUTION_MISMATCH')
        paths=parse_capture(trace.read_text(),e['token'],'riscv64' if side=='source' else 'x86_64',region,len(deployment['samplePlan']['inputs']))
        rows=parse_samples(cmd['stdout'],e['token'],deployment['samplePlan'])
        rebuilt[side]=report(side,backend,deployment,paths,rows,e)
        require_json_match(rebuilt[side],observed,'L3_CONTROL_OBSERVATION_REPLAY_MISMATCH')
    require_json_match(comparison(rebuilt,deployment['spec']),detail['comparison'],'L3_CONTROL_COMPARISON_REPLAY_MISMATCH')
    return contract


def build_route(config):
    fields={'schemaVersion','sourcePath','targetPath','reportPath','backendPath','backendDigest','cacheModel','workDirectory','sampleCount','timeoutSeconds','clang'}
    if not isinstance(config,dict) or set(config)!=fields or config['schemaVersion']!=SCHEMA or config['cacheModel'] is not None or config['sampleCount'] is not None:raise ValueError('L3_CONTROL_ROUTE_CONFIGURATION_INVALID')
    def validate(**kwargs):
        stage='prerequisites'
        try:
            if kwargs['validation_plan'].profile is not ValidationProfile.MICROARCH:raise ValueError('L3_CONTROL_MICROARCH_PROFILE_REQUIRED')
            prior=kwargs['prior_layer_results']
            if len(prior)!=3 or tuple(p.level.value for p in prior)!=('L0','L1','L2') or any(p.status is not ValidationStatus.VERIFIED for p in prior):raise ValueError('L3_CONTROL_PRIOR_LAYER_REQUIRED')
            l2_scope=json.loads(prior[2].detail)['claimScope']
            if l2_scope!='architectural':raise ValueError('L3_CONTROL_ARCHITECTURAL_PREREQUISITE_REQUIRED')
            if digest(config['backendPath'])!=config['backendDigest']:raise ValueError('L3_CONTROL_BACKEND_CHANGED')
            backend=backend_validate(config['backendPath']);source=kwargs['source_program_artifact'];target=kwargs['target_program_artifact'];artifact=kwargs['translation_artifact']
            manifest=parse_l3_requirement_manifest(kwargs['l3_requirement_manifest']);reqs=[r for r in manifest.requirements if r['fragmentId']==artifact.fragment_id]
            if len(reqs)!=1 or reqs[0]['eligibilityStatus']!='eligible':raise ValueError('L3_CONTROL_REQUIREMENT_INELIGIBLE:'+json.dumps(reqs))
            req=reqs[0];data=json.loads(Path(config['reportPath']).read_text());findings=data['findings']
            if len(findings)!=1 or findings[0]['fragment']['id']!=artifact.fragment_id:raise ValueError('L3_CONTROL_SINGLE_FRAGMENT_REQUIRED')
            from .l3_intent_ingress import validate_receipt
            profile=validate_receipt(findings[0],artifact,config['sourcePath'],config['reportPath'])
            work=Path(config['workDirectory']).resolve();work.mkdir(parents=True,exist_ok=False);stage='deployment'
            deployment=deploy(config['sourcePath'],config['targetPath'],config['reportPath'],findings[0],backend,source,target,work/'deployment',config['clang'])
            if (profile.observation_boundary_identity!=deployment['spec']['specIdentity'] or profile.observation_boundary_kind!='compiler-control-region'
                    or tuple(profile.source_capabilities)!=(CAPABILITY,) or tuple(profile.target_capabilities)!=(CAPABILITY,)
                    or [p.to_dict() for p in profile.required_properties]!=deployment['spec']['obligations']['requiredProperties']
                    or req['requiredProperties']!=[p.to_dict() for p in profile.required_properties]
                    or req['profileIdentity']!=profile.profile_identity or req['proofIdentity']!=artifact.proof_identity or req['approvedTargetRelationIdentity']!=artifact.effect_relation_set_identity):raise ValueError('L3_CONTROL_PROFILE_OR_ARTIFACT_MISMATCH')
            body={'schemaVersion':CONTRACT,'backendPath':config['backendPath'],'backendDigest':config['backendDigest'],
                  'requirement':req,'deployment':deployment,'controlPolicy':'logical-continuation-and-actual-transfer-shape.v1','limitations':sorted(LIMITS)}
            contract=dict(body,contractIdentity=identity(body));contract_path=save(work/'control-contract.json',contract)
            context=kwargs['l3_execution_context'];context.validate(source,target);bindings={s:context.request_binding(s) for s in ('source','target')};reports={};stage='capture'
            for side in ('source','target'):
                item=deployment['sides'][side]
                observed,stdout,evidence=capture(backend,side,item['executionArtifact']['artifactPath'],item['region'],work/side,len(deployment['samplePlan']['inputs']),config['timeoutSeconds'])
                from .l3_control_spec import parse_samples
                reports[side]=report(side,backend,deployment,observed,parse_samples(stdout,evidence['token'],deployment['samplePlan']),evidence)
            fragment,cmp=dimensions(contract,reports,bindings,artifact,source,target,prior,l2_scope)
            detail={'controlDeployment':deployment,'contractPath':str(contract_path),'contractDigest':digest(contract_path),
                    'platformReports':reports,'executionBindings':bindings,'fragmentResult':fragment,'comparison':cmp,
                    'propertyObligations':deployment['spec']['obligations'],'physicalMicroarchitectureClaimed':False}
            detail['reasonCodes']=sorted({r for c in cmp.values() for r in c['reasonCodes']})
            stage='independent_replay';replay(detail,source,target);save(work/'observation-result.json',detail)
            return ValidationLayerResult(ValidationLevel.L3,ValidationStatus(fragment['status']),identity(detail),json.dumps(detail,sort_keys=True))
        except (OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired) as exc:
            return ValidationLayerResult(ValidationLevel.L3,ValidationStatus.INCONCLUSIVE,detail=json.dumps({'reasonCodes':[str(exc)],'failureStage':'l3-control-'+stage,'evidenceProductionDisposition':'not_complete'}))
    return validate


def audit_prerequisites(evaluation):
    from .l3_audit_prerequisites import check
    check(evaluation,'L3_CONTROL',single_fragment=True)


def audit_result(evaluation):
    """Audit verified AND counterexample results; never promote a failed result."""
    from .translation_validation import program_artifact_from_dict,translation_artifact_from_dict
    from types import SimpleNamespace
    audit_prerequisites(evaluation)
    source=program_artifact_from_dict(evaluation['sourceProgramArtifact']);target=program_artifact_from_dict(evaluation['targetProgramArtifact'])
    requirements=parse_l3_requirement_manifest(evaluation['translationEvaluationLink']['l3Requirements']).requirements
    attempts=evaluation['attempts']
    if len(requirements)!=1 or len(attempts)!=1 or requirements[0]['eligibilityStatus']!='eligible':raise ValueError('L3_CONTROL_AUDIT_SINGLE_ELIGIBLE_FRAGMENT_REQUIRED')
    attempt=attempts[0];artifact=translation_artifact_from_dict(attempt['translationArtifact']);layers=attempt['validation']['layers']
    if [l['level'] for l in layers]!=['L0','L1','L2','L3'] or any(l['status']!='verified' for l in layers[:3]):raise ValueError('L3_CONTROL_AUDIT_PRIOR_LAYERS_REQUIRED')
    detail=layers[3]['detail'];detail=json.loads(detail) if isinstance(detail,str) else detail
    if 'providerDetail' in detail:detail=json.loads(detail['providerDetail'])
    contract=replay(detail,source,target);req=requirements[0]
    if contract['requirement']!=req or (artifact.fragment_id,artifact.proof_identity,artifact.effect_relation_set_identity)!=(req['fragmentId'],req['proofIdentity'],req['approvedTargetRelationIdentity']):raise ValueError('L3_CONTROL_AUDIT_REQUIREMENT_CHANGED')
    bindings=detail['executionBindings']
    for side,program in (('source',source),('target',target)):
        expected={'artifactId':program.artifact_id,'artifactPath':str(Path(program.artifact_path).resolve()),'artifactDigest':program.artifact_digest,'buildIdentity':program.build_identity}
        b=bindings[side]
        if b['schemaVersion']!='riscv2x86.l3-observer-execution-binding.v1' or b['side']!=side or b['program']!=expected or digest(program.artifact_path)!=program.artifact_digest:raise ValueError('L3_CONTROL_AUDIT_EXECUTION_BINDING_MISMATCH')
    if not bindings['source']['invocationId'] or bindings['source']['invocationId']!=bindings['target']['invocationId']:raise ValueError('L3_CONTROL_AUDIT_INVOCATION_MISMATCH')
    context=identity({'schemaVersion':'riscv2x86.l3-execution-context.v1','invocationId':bindings['source']['invocationId'],'source':bindings['source']['program'],'target':bindings['target']['program']})
    if any(b['contextIdentity']!=context for b in bindings.values()):raise ValueError('L3_CONTROL_AUDIT_CONTEXT_MISMATCH')
    prior=[SimpleNamespace(evidence_identity=l['evidenceIdentity']) for l in layers[:3]];l2_scope=json.loads(layers[2]['detail'])['claimScope']
    expected,cmp=dimensions(contract,detail['platformReports'],bindings,artifact,source,target,prior,l2_scope)
    require_json_match(expected,detail['fragmentResult'],'L3_CONTROL_AUDIT_RESULT_REPLAY_MISMATCH')
    require_json_match(cmp,detail['comparison'],'L3_CONTROL_AUDIT_RESULT_REPLAY_MISMATCH')
    if (l2_scope!='architectural' or expected!=detail['fragmentResult'] or cmp!=detail['comparison']
            or detail.get('physicalMicroarchitectureClaimed') is not False
            or detail.get('reasonCodes')!=sorted({r for c in cmp.values() for r in c['reasonCodes']})
            or detail['propertyObligations']!=contract['deployment']['spec']['obligations'] or layers[3]['evidenceIdentity']!=identity(detail)):
        raise ValueError('L3_CONTROL_AUDIT_RESULT_REPLAY_MISMATCH')
    validate_fragment_against_requirement(expected,req,source_report=detail['platformReports']['source'],target_report=detail['platformReports']['target'])
    status=expected['status']
    if evaluation['status']!=status or attempt['status']!=status or layers[3]['status']!=status or attempt['validation']['status']!=status:raise ValueError('L3_CONTROL_AUDIT_REPORTED_STATUS_MISMATCH')
    return {'status':status,'independentResultAuditComplete':True,'productionAcceptanceComplete':status=='verified',
            'fragmentId':req['fragmentId'],'resultIdentity':expected['resultIdentity'],'comparison':cmp,
            'physicalMicroarchitectureClaimed':False,'claimScope':'architectural_intent'}
