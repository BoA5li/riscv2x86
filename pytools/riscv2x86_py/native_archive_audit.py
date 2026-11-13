"""Independent replay of observed, uniquely attributed archive contributions.

Reuses captured deployment replay, byte equality, capture provenance and map /
ELF section attribution. No absence, whole-extraction, ABI or behavior claims.
"""
import json
from pathlib import Path

from . import native_captured_deployment as deployment
from .native_archive_selection import derive as selection
from .native_link_contexts import derive as producers
from .native_external_providers import checked

SCHEMA='riscv2x86.native-archive-selection-audit.v1'


def projection(report):
    return [{'archive':row['archive'],'nodeIdentity':row['nodeIdentity'],
             'producerChainVerified':row['producerChainVerified'],
             'observedMemberSelections':row['observedMemberSelections'],
             'unresolvedContributions':row['unresolvedContributions']}
            for row in report['archives']]


def derive(original_path,replay_path):
    original=deployment.check_result(original_path)
    replay=deployment.read(replay_path);checked(replay,'replayIdentity')
    if replay['schemaVersion']!='riscv2x86.captured-deployment-replay.v1':
        raise ValueError('ARCHIVE_AUDIT_REPLAY_SCHEMA_INVALID')
    expected=Path(replay_path).resolve().parent/'rebuild/result.json'
    if (Path(replay['freshDeploymentPath']).resolve()!=expected
            or expected==Path(original_path).resolve()):
        raise ValueError('ARCHIVE_AUDIT_ISOLATED_REPLAY_REQUIRED')
    fresh=deployment.check_result(replay['freshDeploymentPath'])
    if (replay['originalDeploymentIdentity']!=original['deploymentIdentity']
            or replay['freshDeploymentIdentity']!=fresh['deploymentIdentity']
            or fresh['deploymentPlanIdentity']!=original['deploymentPlanIdentity']):
        raise ValueError('ARCHIVE_AUDIT_REPLAY_PARENT_MISMATCH')
    def artifacts(value):return [(a['stage'],a['digest']) for a in value['artifacts']]
    reproduced=artifacts(original)==artifacts(fresh)
    if (replay['artifactBytesReproduced'] is not reproduced
            or replay['independentDeploymentRebuildComplete'] is not reproduced):
        raise ValueError('ARCHIVE_AUDIT_REPLAY_BYTES_MISMATCH')
    plan=deployment.read(original['planPath'])
    left=selection(plan,original,producers(plan,original))
    right=selection(plan,fresh,producers(plan,fresh))
    same=projection(left)==projection(right)
    verified=reproduced and same and left['observedArchiveMemberCount']>0
    return deployment.seal({'schemaVersion':SCHEMA,'deploymentIdentity':original['deploymentIdentity'],
        'deploymentPlanIdentity':original['deploymentPlanIdentity'],
        'replayIdentity':replay['replayIdentity'],
        'originalSelection':left,'freshSelection':right,
        'artifactBytesReproduced':reproduced,'archiveContributionRelationsReproduced':same,
        'independentObservedArchiveContributionsVerified':verified,
        'verifiedObservedArchiveMemberCount':left['observedArchiveMemberCount'] if verified else 0,
        'actualLinkSelectionClosureVerified':False,'nativeAbiClosureVerified':False,
        'semanticApproval':False,'productionAcceptanceComplete':False},'archiveSelectionAuditIdentity')


def acquire(deployment_path,output,*,timeout=300):
    from .native_deployment_prerequisites import output_path
    deployment.check_result(deployment_path)
    root=output_path(output);root.mkdir()
    deployment.replay(deployment_path,root/'independent-replay',timeout)
    inputs={'schemaVersion':'riscv2x86.native-archive-selection-audit-inputs.v1',
        'deployment':deployment.snapshot(deployment_path),
        'replay':deployment.snapshot(root/'independent-replay/replay.json')}
    result=derive(deployment_path,inputs['replay']['path'])
    (root/'inputs.json').write_text(json.dumps(deployment.seal(inputs,'archiveAuditInputsIdentity'),indent=2)+'\n')
    (root/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    check(root/'result.json');return result


def check(path):
    path=Path(path).resolve(strict=True)
    value=deployment.read(path);checked(value,'archiveSelectionAuditIdentity')
    inputs=deployment.read(path.parent/'inputs.json');checked(inputs,'archiveAuditInputsIdentity')
    if (set(inputs)!={'schemaVersion','deployment','replay','archiveAuditInputsIdentity'}
            or inputs['schemaVersion']!='riscv2x86.native-archive-selection-audit-inputs.v1'):
        raise ValueError('ARCHIVE_AUDIT_INPUT_SCHEMA_INVALID')
    for key in ('deployment','replay'):deployment.verify_snapshot(inputs[key])
    if derive(inputs['deployment']['path'],inputs['replay']['path'])!=value:
        raise ValueError('ARCHIVE_AUDIT_REDERIVATION_MISMATCH')
    return value
