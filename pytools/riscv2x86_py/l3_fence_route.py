"""Normal-production fence capture, property comparison and independent replay."""
import json
from pathlib import Path
import shutil
import subprocess
from .l3_trace_support import digest,identity,save,require_json_document,require_json_match
from .l3_fence_spec import CAPABILITY,LIMITS
from .l3_fence_backend import validate as backend_validate,capture,parse_capture,command
from .l3_fence_deployment import prepare as deploy,validate as replay_deployment
from .l3_intent_requirements import parse_l3_requirement_manifest
from .l3_evidence_closure import close_fragment,validate_fragment_against_requirement
from .translation_validation import ValidationLayerResult,ValidationLevel,ValidationProfile
from .validation_status import ValidationStatus

SCHEMA='riscv2x86.fence-trace-route.v1'
CONTRACT='riscv2x86.fence-trace-contract.v1'


from .l3_fence_compare import report,comparison


def dimensions(contract,reports,bindings,artifact,source,target,prior,l2_scope):
    req=contract['requirement'];results=comparison(reports,contract['deployment']['spec']);items=[]
    execution=identity({'context':bindings['source']['contextIdentity'],'reports':reports,'deployment':contract['deployment']['deploymentIdentity']})
    for prop in req['requiredProperties']:
        cmp=results['synchronization' if prop['dimension']=='synchronization' else 'memory']
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


def replay(detail,source,target,artifact):
    require_json_document(detail,'L3_FENCE_REPLAY_JSON_INVALID')
    contract_path=Path(detail['contractPath'])
    if digest(contract_path)!=detail['contractDigest']:raise ValueError('L3_FENCE_CONTRACT_CHANGED')
    contract=json.loads(contract_path.read_text())
    if contract.get('schemaVersion')!=CONTRACT or contract.get('contractIdentity')!=identity({k:v for k,v in contract.items() if k!='contractIdentity'}):raise ValueError('L3_FENCE_CONTRACT_IDENTITY_INVALID')
    if contract['fencePolicy']!='executed-fence-and-approved-ordering-contract.v1' or contract['limitations']!=sorted(LIMITS):raise ValueError('L3_FENCE_CONTRACT_POLICY_CHANGED')
    if digest(contract['backendPath'])!=contract['backendDigest']:raise ValueError('L3_FENCE_BACKEND_SELECTION_CHANGED')
    backend=backend_validate(contract['backendPath']);deployment=replay_deployment(contract['deployment'],backend,source,target)
    from .l3_intent_ingress import validate_receipt
    from .l3_intent_requirements import classify_l3_requirements
    data=json.loads(Path(deployment['inputs']['report']).read_text())
    if len(data['findings'])!=1:raise ValueError('L3_FENCE_REPLAY_SINGLE_FINDING_REQUIRED')
    profile=validate_receipt(data['findings'][0],artifact,deployment['inputs']['source'],deployment['inputs']['report'])
    requirements=classify_l3_requirements(data).requirements
    if (len(requirements)!=1 or contract['requirement']!=requirements[0]
            or profile.observation_boundary_identity!=deployment['spec']['specIdentity']
            or profile.observation_boundary_kind!='compiler-fence-region'
            or tuple(profile.source_capabilities)!=(CAPABILITY,) or tuple(profile.target_capabilities)!=(CAPABILITY,)
            or [p.to_dict() for p in profile.required_properties]!=deployment['spec']['obligations']['requiredProperties']):
        raise ValueError('L3_FENCE_REPLAY_RECEIPT_OR_REQUIREMENT_CHANGED')
    require_json_match(deployment,detail.get('fenceDeployment'),'L3_FENCE_REPORTED_DEPLOYMENT_MISMATCH')
    from .l3_fence_spec import parse_samples
    rebuilt={}
    for side in ('source','target'):
        observed=detail['platformReports'][side];e=observed['evidence'];trace=Path(e['rawTracePath']);cmdpath=trace.with_name('execute.command.json')
        if digest(trace)!=e['rawTraceDigest'] or digest(cmdpath)!=e['commandRecordDigest']:raise ValueError('L3_FENCE_RAW_CAPTURE_CHANGED')
        cmd=json.loads(cmdpath.read_text());binary=deployment['sides'][side]['executionArtifact']['artifactPath'];region=deployment['sides'][side]['region']
        if cmd['command']!=command(backend,side,binary,region,trace,e['token']) or cmd['returnCode']!=0 or cmd['timedOut'] is not False or cmd['stderr']:raise ValueError('L3_FENCE_LAUNCHED_EXECUTION_MISMATCH')
        paths=parse_capture(trace.read_text(),e['token'],'riscv64' if side=='source' else 'x86_64',region,len(deployment['samplePlan']['inputs']))
        rows=parse_samples(cmd['stdout'],e['token'],deployment['samplePlan'])
        rebuilt[side]=report(side,backend,deployment,paths,rows,e)
        require_json_match(rebuilt[side],observed,'L3_FENCE_OBSERVATION_REPLAY_MISMATCH')
    require_json_match(comparison(rebuilt,deployment['spec']),detail['comparison'],'L3_FENCE_COMPARISON_REPLAY_MISMATCH')
    return contract


def build_route(config):
    fields={'schemaVersion','sourcePath','targetPath','reportPath','backendPath','backendDigest','cacheModel','workDirectory','sampleCount','timeoutSeconds','clang'}
    if not isinstance(config,dict) or set(config)!=fields or config['schemaVersion']!=SCHEMA or config['cacheModel'] is not None or config['sampleCount'] is not None:raise ValueError('L3_FENCE_ROUTE_CONFIGURATION_INVALID')
    def validate(**kwargs):
        stage='prerequisites'
        try:
            if kwargs['validation_plan'].profile is not ValidationProfile.MICROARCH:raise ValueError('L3_FENCE_MICROARCH_PROFILE_REQUIRED')
            prior=kwargs['prior_layer_results']
            if len(prior)!=3 or tuple(p.level.value for p in prior)!=('L0','L1','L2') or any(p.status is not ValidationStatus.VERIFIED for p in prior):raise ValueError('L3_FENCE_PRIOR_LAYER_REQUIRED')
            l2_scope=json.loads(prior[2].detail)['claimScope']
            if l2_scope!='architectural':raise ValueError('L3_FENCE_ARCHITECTURAL_PREREQUISITE_REQUIRED')
            if digest(config['backendPath'])!=config['backendDigest']:raise ValueError('L3_FENCE_BACKEND_CHANGED')
            backend=backend_validate(config['backendPath']);source=kwargs['source_program_artifact'];target=kwargs['target_program_artifact'];artifact=kwargs['translation_artifact']
            manifest=parse_l3_requirement_manifest(kwargs['l3_requirement_manifest']);reqs=[r for r in manifest.requirements if r['fragmentId']==artifact.fragment_id]
            if len(reqs)!=1 or reqs[0]['eligibilityStatus']!='eligible':raise ValueError('L3_FENCE_REQUIREMENT_INELIGIBLE:'+json.dumps(reqs))
            req=reqs[0];data=json.loads(Path(config['reportPath']).read_text());findings=data['findings']
            if len(findings)!=1 or findings[0]['fragment']['id']!=artifact.fragment_id:raise ValueError('L3_FENCE_SINGLE_FRAGMENT_REQUIRED')
            from .l3_intent_ingress import validate_receipt
            profile=validate_receipt(findings[0],artifact,config['sourcePath'],config['reportPath'])
            work=Path(config['workDirectory']).resolve();work.mkdir(parents=True,exist_ok=False);stage='deployment'
            deployment=deploy(config['sourcePath'],config['targetPath'],config['reportPath'],findings[0],backend,source,target,work/'deployment',config['clang'])
            if (profile.observation_boundary_identity!=deployment['spec']['specIdentity'] or profile.observation_boundary_kind!='compiler-fence-region'
                    or tuple(profile.source_capabilities)!=(CAPABILITY,) or tuple(profile.target_capabilities)!=(CAPABILITY,)
                    or [p.to_dict() for p in profile.required_properties]!=deployment['spec']['obligations']['requiredProperties']
                    or req['requiredProperties']!=[p.to_dict() for p in profile.required_properties]
                    or req['profileIdentity']!=profile.profile_identity or req['proofIdentity']!=artifact.proof_identity or req['approvedTargetRelationIdentity']!=artifact.effect_relation_set_identity):raise ValueError('L3_FENCE_PROFILE_OR_ARTIFACT_MISMATCH')
            body={'schemaVersion':CONTRACT,'backendPath':config['backendPath'],'backendDigest':config['backendDigest'],
                  'requirement':req,'deployment':deployment,'fencePolicy':'executed-fence-and-approved-ordering-contract.v1','limitations':sorted(LIMITS)}
            contract=dict(body,contractIdentity=identity(body));contract_path=save(work/'fence-contract.json',contract)
            context=kwargs['l3_execution_context'];context.validate(source,target);bindings={s:context.request_binding(s) for s in ('source','target')};reports={};stage='capture'
            for side in ('source','target'):
                item=deployment['sides'][side]
                observed,stdout,evidence=capture(backend,side,item['executionArtifact']['artifactPath'],item['region'],work/side,len(deployment['samplePlan']['inputs']),config['timeoutSeconds'])
                from .l3_fence_spec import parse_samples
                reports[side]=report(side,backend,deployment,observed,parse_samples(stdout,evidence['token'],deployment['samplePlan']),evidence)
            fragment,cmp=dimensions(contract,reports,bindings,artifact,source,target,prior,l2_scope)
            detail={'fenceDeployment':deployment,'contractPath':str(contract_path),'contractDigest':digest(contract_path),
                    'platformReports':reports,'executionBindings':bindings,'fragmentResult':fragment,'comparison':cmp,
                    'propertyObligations':deployment['spec']['obligations'],'physicalMicroarchitectureClaimed':False}
            detail['reasonCodes']=sorted({r for c in cmp.values() for r in c['reasonCodes']})
            stage='independent_replay';replay(detail,source,target,artifact);save(work/'observation-result.json',detail)
            return ValidationLayerResult(ValidationLevel.L3,ValidationStatus(fragment['status']),identity(detail),json.dumps(detail,sort_keys=True))
        except (OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired) as exc:
            return ValidationLayerResult(ValidationLevel.L3,ValidationStatus.INCONCLUSIVE,detail=json.dumps({'reasonCodes':[str(exc)],'failureStage':'l3-fence-'+stage,'evidenceProductionDisposition':'not_complete'}))
    return validate


def audit_prerequisites(evaluation):
    from .l3_audit_prerequisites import check
    check(evaluation,'L3_FENCE',single_fragment=True)


def audit_result(evaluation):
    """Audit verified AND counterexample results; never promote a failed result."""
    from .translation_validation import program_artifact_from_dict,translation_artifact_from_dict
    from types import SimpleNamespace
    audit_prerequisites(evaluation)
    source=program_artifact_from_dict(evaluation['sourceProgramArtifact']);target=program_artifact_from_dict(evaluation['targetProgramArtifact'])
    requirements=parse_l3_requirement_manifest(evaluation['translationEvaluationLink']['l3Requirements']).requirements
    attempts=evaluation['attempts']
    if len(requirements)!=1 or len(attempts)!=1 or requirements[0]['eligibilityStatus']!='eligible':raise ValueError('L3_FENCE_AUDIT_SINGLE_ELIGIBLE_FRAGMENT_REQUIRED')
    attempt=attempts[0];artifact=translation_artifact_from_dict(attempt['translationArtifact']);layers=attempt['validation']['layers']
    if [l['level'] for l in layers]!=['L0','L1','L2','L3'] or any(l['status']!='verified' for l in layers[:3]):raise ValueError('L3_FENCE_AUDIT_PRIOR_LAYERS_REQUIRED')
    detail=layers[3]['detail'];detail=json.loads(detail) if isinstance(detail,str) else detail
    if 'providerDetail' in detail:detail=json.loads(detail['providerDetail'])
    contract=replay(detail,source,target,artifact);req=requirements[0]
    if contract['requirement']!=req or (artifact.fragment_id,artifact.proof_identity,artifact.effect_relation_set_identity)!=(req['fragmentId'],req['proofIdentity'],req['approvedTargetRelationIdentity']):raise ValueError('L3_FENCE_AUDIT_REQUIREMENT_CHANGED')
    bindings=detail['executionBindings']
    for side,program in (('source',source),('target',target)):
        expected={'artifactId':program.artifact_id,'artifactPath':str(Path(program.artifact_path).resolve()),'artifactDigest':program.artifact_digest,'buildIdentity':program.build_identity}
        b=bindings[side]
        if b['schemaVersion']!='riscv2x86.l3-observer-execution-binding.v1' or b['side']!=side or b['program']!=expected or digest(program.artifact_path)!=program.artifact_digest:raise ValueError('L3_FENCE_AUDIT_EXECUTION_BINDING_MISMATCH')
    if not bindings['source']['invocationId'] or bindings['source']['invocationId']!=bindings['target']['invocationId']:raise ValueError('L3_FENCE_AUDIT_INVOCATION_MISMATCH')
    context=identity({'schemaVersion':'riscv2x86.l3-execution-context.v1','invocationId':bindings['source']['invocationId'],'source':bindings['source']['program'],'target':bindings['target']['program']})
    if any(b['contextIdentity']!=context for b in bindings.values()):raise ValueError('L3_FENCE_AUDIT_CONTEXT_MISMATCH')
    prior=[SimpleNamespace(evidence_identity=l['evidenceIdentity']) for l in layers[:3]];l2_scope=json.loads(layers[2]['detail'])['claimScope']
    expected,cmp=dimensions(contract,detail['platformReports'],bindings,artifact,source,target,prior,l2_scope)
    require_json_match(expected,detail['fragmentResult'],'L3_FENCE_AUDIT_RESULT_REPLAY_MISMATCH')
    require_json_match(cmp,detail['comparison'],'L3_FENCE_AUDIT_RESULT_REPLAY_MISMATCH')
    if (l2_scope!='architectural' or expected!=detail['fragmentResult'] or cmp!=detail['comparison']
            or detail.get('physicalMicroarchitectureClaimed') is not False
            or detail.get('reasonCodes')!=sorted({r for c in cmp.values() for r in c['reasonCodes']})
            or detail['propertyObligations']!=contract['deployment']['spec']['obligations'] or layers[3]['evidenceIdentity']!=identity(detail)):
        raise ValueError('L3_FENCE_AUDIT_RESULT_REPLAY_MISMATCH')
    validate_fragment_against_requirement(expected,req,source_report=detail['platformReports']['source'],target_report=detail['platformReports']['target'])
    status=expected['status']
    if evaluation['status']!=status or attempt['status']!=status or layers[3]['status']!=status or attempt['validation']['status']!=status:raise ValueError('L3_FENCE_AUDIT_REPORTED_STATUS_MISMATCH')
    return {'status':status,'independentResultAuditComplete':True,'productionAcceptanceComplete':status=='verified',
            'fragmentId':req['fragmentId'],'resultIdentity':expected['resultIdentity'],'comparison':cmp,
            'physicalMicroarchitectureClaimed':False,'claimScope':'architectural_intent'}
