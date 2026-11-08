"""Audit prerequisites are artifact-bound; JSON booleans alone are insufficient."""
import json
from pathlib import Path

from .native_captured_deployment import read, seal, snapshot, verify_snapshot, validate
from .native_external_providers import checked
from .project_compile_context import digest

SCHEMA = 'riscv2x86.deployment-candidate-audit.v1'


def output_path(path):
    p = Path(path).resolve()
    if p.parent == Path('/') or p == Path('/'):
        raise ValueError('NATIVE_CLOSURE_RESULT_PARENT_REQUIRED')
    return p


def audit(plan, output, timeout=300):
    from . import native_project_translation, native_audit_evidence
    verify_candidate = native_project_translation.audit
    validate(plan); root = output_path(output)
    result = verify_candidate(read(plan['candidatePath']), root, timeout=timeout)
    if result.get('nativeCandidateIndependentAuditComplete') is not True:
        raise ValueError('DEPLOYMENT_CANDIDATE_AUDIT_NOT_COMPLETE')
    body = {'schemaVersion': SCHEMA, 'deploymentPlanIdentity': plan['deploymentPlanIdentity'],
            'candidateIdentity': plan['candidateIdentity'], 'candidate': snapshot(plan['candidatePath']),
            'auditDirectory': str(root), 'artifactDigests': {str(p.relative_to(root)): digest(p)
                for p in root.rglob('*') if p.is_file()},
            'proofScope': result['proofScope'], 'semanticApproval': False, 'productionAcceptanceComplete': False}
    body['verifierFiles'] = {str(Path(p).resolve()): digest(p) for p in
        (__file__, native_project_translation.__file__, native_audit_evidence.__file__)}
    receipt = seal(body, 'auditPrerequisiteIdentity')
    (root/'deployment-audit.json').write_text(json.dumps(receipt, indent=2)+'\n')
    return dict(result, auditPrerequisitePath=str(root/'deployment-audit.json'))


def check(plan, path):
    from . import native_project_translation, native_audit_evidence
    from .native_audit_evidence import command_projection
    from .native_project_translation import read as candidate_read, AUDIT_POLICY
    from .project_native_binding import validate_artifacts
    value = read(path); checked(value, 'auditPrerequisiteIdentity')
    verifier_files = {str(Path(p).resolve()): digest(p) for p in
        (__file__, native_project_translation.__file__, native_audit_evidence.__file__)}
    if value.get('verifierFiles') != verifier_files:
        raise ValueError('DEPLOYMENT_AUDIT_VERIFIER_CHANGED')
    if (value['schemaVersion'] != SCHEMA or value['deploymentPlanIdentity'] != plan['deploymentPlanIdentity']
            or value['candidateIdentity'] != plan['candidateIdentity']
            or value['semanticApproval'] is not False or value['productionAcceptanceComplete'] is not False):
        raise ValueError('DEPLOYMENT_AUDIT_PREREQUISITE_MISMATCH')
    verify_snapshot(value['candidate'])
    if value['candidate'] != snapshot(plan['candidatePath']):
        raise ValueError('DEPLOYMENT_AUDIT_CANDIDATE_CHANGED')
    root = Path(value['auditDirectory']).resolve(strict=True)
    if Path(path).resolve(strict=True) != root/'deployment-audit.json':
        raise ValueError('DEPLOYMENT_AUDIT_LOCATION_MISMATCH')
    fresh = {str(p.relative_to(root)): digest(p) for p in root.rglob('*')
             if p.is_file() and p != root/'deployment-audit.json'}
    if fresh != value['artifactDigests']:
        raise ValueError('DEPLOYMENT_AUDIT_ARTIFACT_CHANGED')
    status = read(root/'run-status.json'); checked(status, 'stateIdentity')
    result = read(root/'audit.json')
    if (status['status'] != 'complete' or status.get('primaryFailure') is not None
            or status.get('acquisitionComplete') is not True
            or status.get('nativeCandidateIndependentAuditComplete') is not True
            or status.get('auditPath') != str(root/'audit.json')
            or status['auditDigest'] != digest(root/'audit.json')
            or result['candidateIdentity'] != plan['candidateIdentity']
            or result.get('nativeCandidateIndependentAuditComplete') is not True
            or result.get('comparisonPolicy') != AUDIT_POLICY
            or status.get('comparisonPolicy') != AUDIT_POLICY
            or result.get('semanticApproval') is not False
            or result.get('productionAcceptanceComplete') is not False
            or result['proofScope'] != value['proofScope']):
        raise ValueError('DEPLOYMENT_AUDIT_COMPLETION_INVALID')
    original = candidate_read(plan['candidatePath']); rebuilt = candidate_read(root/'rebuild/candidate.json')
    for c in (original, rebuilt):
        checked(c, 'candidateIdentity')
        for name, sha in c['artifactDigests'].items():
            if Path(name).name != name or digest(Path(c['candidatePath']).parent/name) != sha:
                raise ValueError('DEPLOYMENT_AUDIT_PROOF_CHANGED')
        for p, sha in c['tools'].items():
            if digest(p) != sha: raise ValueError('DEPLOYMENT_AUDIT_TOOL_CHANGED')
        if digest(c['bindingBundlePath']) != c['bindingBundleDigest']:
            raise ValueError('DEPLOYMENT_AUDIT_BINDING_CHANGED')
        if digest(c['bindingReplayBundlePath']) != c['bindingReplayBundleDigest']:
            raise ValueError('DEPLOYMENT_AUDIT_BINDING_REPLAY_CHANGED')
        validate_artifacts(read(c['bindingBundlePath']))
        validate_artifacts(read(c['bindingReplayBundlePath']))
        command_projection(c)
    # Same canonical comparison used by the candidate audit, including actual
    # proof/ELF artifacts. Output-dependent receipt identities are kept separate.
    excluded = {'candidateIdentity', 'candidatePath', 'commands', 'bindingReplay',
                'bindingReplayBundlePath', 'bindingReplayBundleDigest'}
    if ({k:v for k,v in original.items() if k not in excluded}
            != {k:v for k,v in rebuilt.items() if k not in excluded}
            or command_projection(original) != command_projection(rebuilt)):
        raise ValueError('DEPLOYMENT_AUDIT_REBUILD_MISMATCH')
    return snapshot(path)
