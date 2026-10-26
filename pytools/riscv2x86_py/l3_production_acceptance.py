"""Mandatory real-artifact L3 acceptance, separate from L0-L2 success.

No hardware capability or intent classification is invented by this audit.
Run against explicitly selected L3-eligible production evaluation reports.
"""
import argparse
import json
from pathlib import Path

from .l3_evidence_closure import validate_fragment_against_requirement, _sha, identity
from .l3_intent_requirements import parse_l3_requirement_manifest
from .l3_intent_ingress import digest


def _detail(layer):
    value = layer.get('detail')
    value = json.loads(value) if isinstance(value, str) else value
    if not isinstance(value, dict):
        raise ValueError('l3.acceptance.detail-missing')
    nested = value.get('providerDetail')
    return json.loads(nested) if isinstance(nested, str) else value


def audit_evaluation(evaluation):
    if evaluation.get('status') != 'verified':
        raise ValueError('l3.acceptance.evaluation-not-verified')
    if any(_detail(layer).get('programCapturePath') for attempt in evaluation.get('attempts',[])
            for layer in (attempt.get('validation') or {}).get('layers',[]) if layer.get('level')=='L3'):
        from .l3_program_route import audit_result
        audited=audit_result(evaluation)
        return {'status':audited['status'],'requirementManifestIdentity':evaluation['translationEvaluationLink']['l3Requirements']['manifestIdentity'],
            'fragments':audited['fragments'],'programExecutionUnitCount':audited['programExecutionUnitCount'],'physicalMicroarchitectureEquivalenceClaimed':False}
    atomic=[]
    for attempt in evaluation.get('attempts',[]):
        for layer in (attempt.get('validation') or {}).get('layers',[]):
            if layer.get('level')=='L3' and _detail(layer).get('atomicDeployment') is not None:
                atomic.append(layer)
    if atomic:
        if len(atomic)!=1:raise ValueError('l3.acceptance.atomic-fragment-ambiguous')
        from .l3_atomic_route import audit_result
        audited=audit_result(evaluation)
        if audited['status']!='verified':raise ValueError('l3.acceptance.atomic-result-not-verified')
        return {'status':'verified','requirementManifestIdentity':evaluation['translationEvaluationLink']['l3Requirements']['manifestIdentity'],
                'fragments':[audited],'physicalMicroarchitectureEquivalenceClaimed':False}
    fence=[]
    for attempt in evaluation.get('attempts',[]):
        for layer in (attempt.get('validation') or {}).get('layers',[]):
            if layer.get('level')=='L3' and _detail(layer).get('fenceDeployment') is not None:
                fence.append(layer)
    if fence:
        if len(fence)!=1:raise ValueError('l3.acceptance.fence-fragment-ambiguous')
        from .l3_fence_route import audit_result
        audited=audit_result(evaluation)
        if audited['status']!='verified':raise ValueError('l3.acceptance.fence-result-not-verified')
        return {'status':'verified','requirementManifestIdentity':evaluation['translationEvaluationLink']['l3Requirements']['manifestIdentity'],
                'fragments':[audited],'physicalMicroarchitectureEquivalenceClaimed':False}
    control=[]
    for attempt in evaluation.get('attempts',[]):
        for layer in (attempt.get('validation') or {}).get('layers',[]):
            if layer.get('level')=='L3' and _detail(layer).get('controlDeployment') is not None:
                control.append(layer)
    if control:
        if len(control)!=1:raise ValueError('l3.acceptance.control-fragment-ambiguous')
        from .l3_control_route import audit_result
        audited=audit_result(evaluation)
        if audited['status']!='verified':raise ValueError('l3.acceptance.control-result-not-verified')
        return {'status':'verified','requirementManifestIdentity':evaluation['translationEvaluationLink']['l3Requirements']['manifestIdentity'],
                'fragments':[audited],'physicalMicroarchitectureEquivalenceClaimed':False}
    manifest = parse_l3_requirement_manifest(evaluation['translationEvaluationLink']['l3Requirements'])
    if not manifest.requirements or any(r['eligibilityStatus'] != 'eligible' for r in manifest.requirements):
        raise ValueError('l3.acceptance.selected-scope-not-fully-eligible')
    requirements = {r['fragmentId']: r for r in manifest.requirements}
    if len(requirements) != len(manifest.requirements):
        raise ValueError('l3.acceptance.duplicate-requirement')
    closed = {}
    for attempt in evaluation.get('attempts', []):
        fid = attempt.get('fragmentId')
        if fid not in requirements:
            continue
        if attempt.get('status') != 'verified' or (attempt.get('validation') or {}).get('status') != 'verified':
            raise ValueError('l3.acceptance.attempt-not-verified:' + fid)
        layers = (attempt.get('validation') or {}).get('layers', [])
        if [x.get('level') for x in layers] != ['L0', 'L1', 'L2', 'L3']:
            raise ValueError('l3.acceptance.full-layer-chain-missing:' + fid)
        if any(x.get('status') != 'verified' for x in layers):
            raise ValueError('l3.acceptance.layer-not-verified:' + fid)
        for layer in layers: _sha(layer.get('evidenceIdentity'), 'layer evidence')
        detail = _detail(layers[-1])
        reports = detail.get('platformReports')
        if not isinstance(reports, dict) or set(reports) != {'source', 'target'}:
            raise ValueError('l3.acceptance.platform-reports-missing')
        from .translation_validation import translation_artifact_from_dict
        artifact = translation_artifact_from_dict(attempt['translationArtifact'])
        if artifact.fragment_id != fid or artifact.proof_identity != requirements[fid]['proofIdentity'] or artifact.effect_relation_set_identity != requirements[fid]['approvedTargetRelationIdentity']:
            raise ValueError('l3.acceptance.translation-proof-mismatch')
        expected_context = {'translationArtifactIdentity': artifact.identity,
                            **{name: layers[i]['evidenceIdentity'] for i, name in enumerate(
                                ('l0EvidenceIdentity', 'l1EvidenceIdentity', 'l2EvidenceIdentity'))}}
        fragment = validate_fragment_against_requirement(detail.get('fragmentResult'), requirements[fid],
            source_report=reports['source'], target_report=reports['target'], expected_context=expected_context)
        if detail.get('traceDeployment') is not None:
            from .l3_qemu_memory_route import parse_contract, verify_detail
            contract_path=Path(detail['contractPath'])
            if digest(contract_path)!=detail['contractDigest']:
                raise ValueError('l3.acceptance.trace-contract-changed')
            contract=parse_contract(json.loads(contract_path.read_text()))
            from .translation_validation import program_artifact_from_dict
            verify_detail(detail,contract,program_artifact_from_dict(evaluation['sourceProgramArtifact']),
                          program_artifact_from_dict(evaluation['targetProgramArtifact']))
            if {d['contractIdentity'] for d in fragment['dimensionResults'].values()} != {contract.identity}:
                raise ValueError('l3.acceptance.trace-contract-mismatch')
        if fragment['status'] != 'verified':
            raise ValueError('l3.acceptance.fragment-not-verified:' + fid)
        bindings = detail.get('executionBindings')
        if not isinstance(bindings, dict) or set(bindings) != {'source', 'target'}:
            raise ValueError('l3.acceptance.execution-binding-missing')
        for side in ('source', 'target'):
            binding = bindings[side]
            if set(binding) != {'schemaVersion', 'contextIdentity', 'invocationId', 'side', 'program'} or binding['schemaVersion'] != 'riscv2x86.l3-observer-execution-binding.v1' or binding['side'] != side:
                raise ValueError('l3.acceptance.execution-binding-invalid')
            actual = evaluation[side + 'ProgramArtifact']
            program = binding['program']
            expected = {'artifactId': actual['artifact_id'], 'artifactPath': str(Path(actual['artifact_path']).resolve()),
                        'artifactDigest': actual['artifact_digest'], 'buildIdentity': actual['build_identity']}
            if program != expected or digest(program['artifactPath']) != program['artifactDigest']:
                raise ValueError('l3.acceptance.actual-program-mismatch:' + side)
            for dimension in fragment['dimensionResults'].values():
                if dimension[side + 'ReportIdentity'] != identity(reports[side]) or dimension[side + 'ArtifactIdentity'] != program['artifactDigest']:
                    raise ValueError('l3.acceptance.report-or-artifact-mismatch:' + side)
        if (bindings['source']['invocationId'] != bindings['target']['invocationId'] or
                not isinstance(bindings['source']['invocationId'], str) or not bindings['source']['invocationId']):
            raise ValueError('l3.acceptance.invocation-mismatch')
        expected_context = identity({'schemaVersion': 'riscv2x86.l3-execution-context.v1',
            'invocationId': bindings['source']['invocationId'],
            'source': bindings['source']['program'], 'target': bindings['target']['program']})
        if any(b['contextIdentity'] != expected_context for b in bindings.values()):
            raise ValueError('l3.acceptance.context-mismatch')
        if fid in closed:
            raise ValueError('l3.acceptance.duplicate-fragment-result')
        closed[fid] = {'fragmentId': fid, 'claimScope': fragment['claimScope'],
                       'resultIdentity': fragment['resultIdentity'], 'contextIdentity': expected_context,
                       'verifiedPropertyIds': sorted(fragment['dimensionResults'])}
        if detail.get('propertyObligations') is not None:
            closed[fid]['evaluationPolicyIdentity']=detail['propertyObligations']['policyIdentity']
            closed[fid]['excludedProperties']=detail['propertyObligations']['policy']['excluded']
    if set(closed) != set(requirements):
        raise ValueError('l3.acceptance.required-fragment-not-run')
    return {'status': 'verified', 'requirementManifestIdentity': manifest.manifest_identity,
            'fragments': list(closed.values()), 'physicalMicroarchitectureEquivalenceClaimed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evaluation', action='append', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    records = []
    for name in args.evaluation:
        try:
            records.append(dict(audit_evaluation(json.loads(Path(name).read_text())), path=name))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            records.append({'path': name, 'status': 'inconclusive', 'reason': str(exc)})
    complete = bool(records) and all(r['status'] == 'verified' for r in records)
    result = {'schemaVersion': 'riscv2x86.l3-production-acceptance.v1',
              'productionAcceptanceComplete': complete, 'evaluations': records}
    with Path(args.output).open('x') as stream: json.dump(result, stream, indent=2, ensure_ascii=False)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if complete else 2


if __name__ == '__main__':
    raise SystemExit(main())
