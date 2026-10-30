"""One dual-ISA capture, all ordered joint regions, per-member closed results."""
import json
from pathlib import Path
from .l3_trace_support import digest,identity,save
from .l3_joint_backend import validate as backend_validate,capture,parse_capture,command
from .l3_joint_deployment import prepare,validate as replay_deployment
from .l3_joint_spec import CAPABILITY,LIMITS
from .l3_joint_observation import parse_samples,compare
from .l3_intent_requirements import parse_l3_requirement_manifest
from .l3_evidence_closure import close_fragment,validate_fragment_against_requirement
from .translation_validation import ValidationLayerResult,ValidationLevel,ValidationProfile
from .validation_status import ValidationStatus

SCHEMA='riscv2x86.joint-program-route.v1'


from .l3_trace_support import require_json_document,require_json_match

def platform(side,b,deployment,events,rows,evidence):
    return {'schemaVersion':'riscv2x86.joint-region-observation.v1','side':side,
        'backendIdentity':b['backendIdentity'],'deploymentIdentity':deployment['deploymentIdentity'],
        'events':[dict(e,access={'R':'read','W':'write','fence':'fence'}[e['access']]) for e in events],'samples':rows,'evidence':evidence,
        'environment':{'executor':b[side+'Executor'],'executorDigest':digest(b[side+'Executor']),
            'runnerArguments':b[side+'RunnerArguments'],'physicalMicroarchitectureClaimed':False}}


def replay_group(group,source,target):
    require_json_document(group,'L3_JOINT_CAPTURE_JSON_INVALID')
    if (group.get('schemaVersion')!='riscv2x86.joint-region-capture.v1' or group['groupIdentity']!=identity({k:v for k,v in group.items() if k!='groupIdentity'})
            or digest(group['backendPath'])!=group['backendDigest']):raise ValueError('L3_JOINT_CAPTURE_GROUP_CHANGED')
    b=backend_validate(group['backendPath']);d=replay_deployment(group['deployment'],b,source,target)
    from .l3_intent_requirements import classify_l3_requirements
    expected=classify_l3_requirements(json.loads(Path(d['inputs']['report']).read_text())).requirements
    if group['requirements']!=list(expected):raise ValueError('L3_JOINT_CAPTURE_REQUIREMENTS_CHANGED')
    for side in ('source','target'):
        r=group['reports'][side];e=r['evidence'];path=Path(e['rawTracePath']);cp=path.with_name('execute.command.json');c=json.loads(cp.read_text());item=d['sides'][side]
        if (digest(path)!=e['rawTraceDigest'] or digest(cp)!=e['commandRecordDigest']
                or c['command']!=command(b,side,item['executionArtifact']['artifactPath'],item['regions'],path,e['token'])
                or c['returnCode']!=0 or c['timedOut'] is not False or c['stderr']):raise ValueError('L3_JOINT_RAW_EXECUTION_CHANGED')
        events=parse_capture(path.read_text(),e['token'],side,item['regions'],len(d['samplePlan']['inputs']))
        rows=parse_samples(c['stdout'],e['token'],d['spec'],d['samplePlan'])
        require_json_match(platform(side,b,d,events,rows,e),r,'L3_JOINT_OBSERVATION_REPLAY_MISMATCH')
    return group


def project(group,index):
    reports={}
    for side,r in group['reports'].items():
        reports[side]={'schemaVersion':'riscv2x86.joint-member-observation.v1','side':side,
            'programCaptureIdentity':group['groupIdentity'],'regionIndex':index,'programSpec':group['deployment']['spec'],
            'events':[e for e in r['events'] if e['region']==index],'samples':r['samples'],
            'programEvents':r['events'],
            'environment':r['environment']}
    return reports


def comparison(reports):
    return compare(reports,reports['source']['programSpec'],reports['source']['regionIndex'])


def fragment_result(req,group,reports,artifact,source,target,prior):
    cmp=comparison(reports);items=[]
    for prop in req['requiredProperties']:
        if prop not in ({'dimension':'access_pattern','propertyId':'memory.fragment-access','unit':'fragment'},
                       {'dimension':'synchronization','propertyId':'synchronization.fragment-events','unit':'fragment'}):
            raise ValueError('L3_JOINT_PROPERTY_SET_UNSUPPORTED')
        if prop['dimension']=='synchronization' and reports['source']['programSpec']['members'][reports['source']['regionIndex']].get('fenceBasis') is None:
            raise ValueError('L3_JOINT_FENCE_BASIS_REQUIRED')
        body={'schemaVersion':'riscv2x86.l3-dimension-result.v1','fragmentId':req['fragmentId'],'programId':req['programId'],**prop,
            'status':cmp['status'],'claimScope':'architectural_intent','requirementIdentity':req['requirementIdentity'],
            'profileIdentity':req['profileIdentity'],'contractIdentity':group['groupIdentity'],
            'translationArtifactIdentity':artifact.identity,'sourceArtifactIdentity':source.artifact_digest,'targetArtifactIdentity':target.artifact_digest,
            'sourceReportIdentity':identity(reports['source']),'targetReportIdentity':identity(reports['target']),
            'sourceEnvironmentIdentity':identity(reports['source']['environment']),'targetEnvironmentIdentity':identity(reports['target']['environment']),
            'executionIdentity':identity({'captureGroup':group['groupIdentity'],'unit':'whole-program'}),
            'comparisonEvidenceIdentity':identity({'property':prop,'comparison':cmp,'reports':reports}),
            'l0EvidenceIdentity':prior[0].evidence_identity,'l1EvidenceIdentity':prior[1].evidence_identity,'l2EvidenceIdentity':prior[2].evidence_identity,
            'l2ClaimScope':'architectural','declaredLimitations':sorted(LIMITS),'uncoveredEffects':[],'reasonCodes':cmp['reasonCodes']}
        items.append(dict(body,resultIdentity=identity(body)))
    return close_fragment(req,items,claim_scope='architectural_intent'),cmp


def build_route(config):
    fields={'schemaVersion','sourcePath','targetPath','reportPath','backendPath','backendDigest','cacheModel','workDirectory','sampleCount','timeoutSeconds','clang'}
    if not isinstance(config,dict) or set(config)!=fields or config['schemaVersion']!=SCHEMA or config['cacheModel'] is not None:raise ValueError('L3_JOINT_CONFIG_INVALID')
    def validate(**kw):
        stage='prerequisites'
        try:
            prior=kw['prior_layer_results'];source=kw['source_program_artifact'];target=kw['target_program_artifact'];artifact=kw['translation_artifact']
            if (kw['validation_plan'].profile is not ValidationProfile.MICROARCH or len(prior)!=3
                    or tuple(x.level.value for x in prior)!=('L0','L1','L2') or any(x.status is not ValidationStatus.VERIFIED for x in prior)
                    or json.loads(prior[2].detail)['claimScope']!='architectural'):raise ValueError('L3_JOINT_PRIOR_ARCHITECTURAL_LAYERS_REQUIRED')
            if digest(config['backendPath'])!=config['backendDigest']:raise ValueError('L3_JOINT_BACKEND_CHANGED')
            b=backend_validate(config['backendPath']);requirements=parse_l3_requirement_manifest(kw['l3_requirement_manifest']).requirements
            report=Path(config['reportPath']);findings=json.loads(report.read_text())['findings'];selected=[f for f in findings if f['fragment']['id']==artifact.fragment_id]
            if len(selected)!=1:raise ValueError('L3_JOINT_SELECTED_FRAGMENT_AMBIGUOUS')
            from .l3_intent_ingress import validate_receipt
            profile=validate_receipt(selected[0],artifact,config['sourcePath'],report)
            work=Path(config['workDirectory']).resolve();work.mkdir(parents=True,exist_ok=True);group_path=work/'capture-group.json';stage='capture'
            if group_path.exists():group=replay_group(json.loads(group_path.read_text()),source,target)
            else:
                d=prepare(config['sourcePath'],config['targetPath'],report,b,source,target,work/'deployment',config['clang'],config['sampleCount']);reports={}
                for side in ('source','target'):
                    item=d['sides'][side];events,stdout,e=capture(b,side,item['executionArtifact']['artifactPath'],item['regions'],work/side,len(d['samplePlan']['inputs']),config['timeoutSeconds'])
                    reports[side]=platform(side,b,d,events,parse_samples(stdout,e['token'],d['spec'],d['samplePlan']),e)
                body={'schemaVersion':'riscv2x86.joint-region-capture.v1','deployment':d,'reports':reports,'requirements':list(requirements),'backendPath':config['backendPath'],'backendDigest':config['backendDigest']}
                group=dict(body,groupIdentity=identity(body));replay_group(group,source,target);save(group_path,group)
            if (group['backendPath']!=config['backendPath'] or group['backendDigest']!=config['backendDigest']
                    or len(group['deployment']['samplePlan']['inputs'])!=config['sampleCount']):raise ValueError('L3_JOINT_CAPTURE_REQUEST_CHANGED')
            members=group['deployment']['spec']['members'];ids=[m['fragmentId'] for m in members];reqs={r['fragmentId']:r for r in requirements}
            if group['requirements']!=list(requirements) or len(requirements)!=len(ids) or set(reqs)!=set(ids) or any(r['eligibilityStatus']!='eligible' for r in requirements):raise ValueError('L3_JOINT_FULL_REQUIREMENT_MEMBERSHIP_REQUIRED')
            index=ids.index(artifact.fragment_id);req=reqs[artifact.fragment_id];member=members[index]
            if (member['proofIdentity']!=artifact.proof_identity or member['relationIdentity']!=artifact.effect_relation_set_identity
                    or profile.profile_identity!=req['profileIdentity'] or req['proofIdentity']!=artifact.proof_identity or req['approvedTargetRelationIdentity']!=artifact.effect_relation_set_identity
                    or profile.observation_boundary_kind!='compiler-joint-regions' or profile.observation_boundary_identity!=group['deployment']['spec']['specIdentity']
                    or tuple(profile.source_capabilities)!=(CAPABILITY,) or tuple(profile.target_capabilities)!=(CAPABILITY,)
                    or [p.to_dict() for p in profile.required_properties]!=req['requiredProperties']):raise ValueError('L3_JOINT_PROFILE_OR_PROOF_MISMATCH')
            reports=project(group,index);result,cmp=fragment_result(req,group,reports,artifact,source,target,prior)
            context=kw['l3_execution_context'];context.validate(source,target)
            detail={'jointCapturePath':str(group_path),'jointCaptureDigest':digest(group_path),'programCaptureIdentity':group['groupIdentity'],
                'platformReports':reports,'fragmentResult':result,'comparison':cmp,'reasonCodes':cmp['reasonCodes'],
                'executionBindings':{s:context.request_binding(s) for s in ('source','target')},'physicalMicroarchitectureClaimed':False}
            return ValidationLayerResult(ValidationLevel.L3,ValidationStatus(result['status']),identity(detail),json.dumps(detail,sort_keys=True))
        except (OSError,ValueError,KeyError,TypeError,IndexError) as exc:
            return ValidationLayerResult(ValidationLevel.L3,ValidationStatus.INCONCLUSIVE,detail=json.dumps({'reasonCodes':[str(exc)],'failureStage':'l3-program-'+stage,'evidenceProductionDisposition':'not_complete'}))
    return validate


def audit_prerequisites(evaluation):
    from .l3_audit_prerequisites import check
    check(evaluation,'L3_JOINT',single_fragment=False)


def audit_result(evaluation):
    from types import SimpleNamespace
    from .translation_validation import program_artifact_from_dict,translation_artifact_from_dict
    from .l3_execution_context import L3ExecutionContext
    from .l3_evidence_closure import aggregate_statuses
    audit_prerequisites(evaluation)
    source=program_artifact_from_dict(evaluation['sourceProgramArtifact']);target=program_artifact_from_dict(evaluation['targetProgramArtifact'])
    requirements=parse_l3_requirement_manifest(evaluation['translationEvaluationLink']['l3Requirements']).requirements
    reqs={r['fragmentId']:r for r in requirements};attempts=evaluation['attempts'];seen=set();closed=[];groups=set();replayed={}
    if len(reqs)!=len(requirements) or len(attempts)!=len(reqs) or any(r['eligibilityStatus']!='eligible' for r in requirements):raise ValueError('L3_JOINT_AUDIT_COMPLETE_MEMBERS_REQUIRED')
    for attempt in attempts:
        if not json.loads(attempt['validation']['layers'][3]['detail']).get('jointCapturePath'):raise ValueError('L3_JOINT_AUDIT_COMPLETE_MEMBERS_REQUIRED')
        fid=attempt['fragmentId'];artifact=translation_artifact_from_dict(attempt['translationArtifact']);layers=attempt['validation']['layers']
        if fid in seen or fid not in reqs or [l['level'] for l in layers]!=['L0','L1','L2','L3'] or any(l['status']!='verified' for l in layers[:3]) or json.loads(layers[2]['detail'])['claimScope']!='architectural':raise ValueError('L3_JOINT_AUDIT_PRIOR_OR_MEMBER_INVALID')
        seen.add(fid);req=reqs[fid];detail=json.loads(layers[3]['detail']);p=Path(detail['jointCapturePath'])
        if digest(p)!=detail['jointCaptureDigest']:raise ValueError('L3_JOINT_AUDIT_CAPTURE_CHANGED')
        group=json.loads(p.read_text())
        if group['requirements']!=list(requirements):raise ValueError('L3_JOINT_AUDIT_REQUIREMENTS_CHANGED')
        if detail['jointCaptureDigest'] not in replayed:replayed[detail['jointCaptureDigest']]=replay_group(group,source,target)
        ids=[m['fragmentId'] for m in group['deployment']['spec']['members']]
        if set(ids)!=set(reqs) or (artifact.fragment_id,artifact.proof_identity,artifact.effect_relation_set_identity)!=(fid,req['proofIdentity'],req['approvedTargetRelationIdentity']):raise ValueError('L3_JOINT_AUDIT_ARTIFACT_CHANGED')
        member=group['deployment']['spec']['members'][ids.index(fid)]
        if member['proofIdentity']!=req['proofIdentity'] or member['relationIdentity']!=req['approvedTargetRelationIdentity']:raise ValueError('L3_JOINT_AUDIT_PROOF_CHANGED')
        from .l3_intent_ingress import validate_receipt
        report=Path(group['deployment']['inputs']['report']);finding=next(f for f in json.loads(report.read_text())['findings'] if f['fragment']['id']==fid)
        from .l2_results import L2FragmentResult
        from .l2_provider_artifacts import read_provider_evidence
        l2=L2FragmentResult.from_dict(json.loads(layers[2]['detail']))
        if l2.evidence_identity!=layers[2]['evidenceIdentity']:raise ValueError('L3_JOINT_AUDIT_L2_IDENTITY_CHANGED')
        read_provider_evidence(l2,case_root=report.parents[2],translation_artifact=attempt['translationArtifact'])
        profile=validate_receipt(finding,artifact,group['deployment']['inputs']['source'],report)
        if (profile.profile_identity!=req['profileIdentity'] or [p.to_dict() for p in profile.required_properties]!=req['requiredProperties']
                or profile.observation_boundary_kind!='compiler-joint-regions' or profile.observation_boundary_identity!=group['deployment']['spec']['specIdentity']
                or tuple(profile.source_capabilities)!=(CAPABILITY,) or tuple(profile.target_capabilities)!=(CAPABILITY,)):
            raise ValueError('L3_JOINT_AUDIT_PROFILE_CHANGED')
        bindings=detail['executionBindings'];invocation=bindings['source']['invocationId']
        context=L3ExecutionContext(source,target,invocation)
        context.validate(source,target)
        if bindings!={s:context.request_binding(s) for s in ('source','target')}:raise ValueError('L3_JOINT_AUDIT_CONTEXT_CHANGED')
        reports=project(group,ids.index(fid));prior=[SimpleNamespace(evidence_identity=l['evidenceIdentity']) for l in layers[:3]]
        result,cmp=fragment_result(req,group,reports,artifact,source,target,prior)
        require_json_match({'reports':reports,'result':result,'comparison':cmp},
            {'reports':detail['platformReports'],'result':detail['fragmentResult'],'comparison':detail['comparison']},'L3_JOINT_AUDIT_RESULT_CHANGED')
        if (detail['platformReports']!=reports or detail['fragmentResult']!=result or detail['comparison']!=cmp or detail['reasonCodes']!=cmp['reasonCodes']
                or detail['programCaptureIdentity']!=group['groupIdentity'] or detail['physicalMicroarchitectureClaimed'] is not False
                or layers[3]['evidenceIdentity']!=identity(detail) or any(s!=result['status'] for s in (layers[3]['status'],attempt['status'],attempt['validation']['status']))):raise ValueError('L3_JOINT_AUDIT_RESULT_CHANGED')
        validate_fragment_against_requirement(result,req,source_report=reports['source'],target_report=reports['target']);closed.append(result);groups.add(group['groupIdentity'])
    status=aggregate_statuses([r['status'] for r in closed])
    if len(groups)!=1 or evaluation['status']!=status:raise ValueError('L3_JOINT_AUDIT_AGGREGATE_CHANGED')
    return {'status':status,'independentResultAuditComplete':True,'productionAcceptanceComplete':status=='verified',
        'fragments':[{k:r[k] for k in ('fragmentId','resultIdentity','status','claimScope')} for r in closed],
        'captureGroupCount':1,'programExecutionUnitCount':1,'physicalMicroarchitectureClaimed':False}
