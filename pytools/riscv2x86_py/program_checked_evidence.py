"""Fresh original receipt checks for bounded program subclaims.

No supplied completeness/approval marker grants a fact. These receipts establish
recorded builds and acquisition of a bounded inventory, never complete ABI,
object legality, execution coverage or semantic refinement.
"""
from . import native_captured_deployment as d
from .verification_session import measured


def build_reference(program):
    from pathlib import Path
    path = Path(program['path'])
    return d.snapshot(path.parent / (path.name + '.project') / 'result.json')


def references(spec_path, builds, inventory=None):
    return {'project': d.snapshot(spec_path),
            'builds': {side: build_reference(builds[side]['program']) for side in ('source', 'target')},
            'machineInventory': inventory}


@measured('program-evidence.checked-subclaims')
def inspect(project_identity, references):
    from . import native_original_api as api
    from . import native_project_evaluation as project
    if not isinstance(references, dict) or set(references) != {'project', 'builds', 'machineInventory'}:
        raise ValueError('PROGRAM_EVIDENCE_REFERENCES_INVALID')
    if set(references['builds']) != {'source', 'target'}:
        raise ValueError('PROGRAM_EVIDENCE_BOTH_BUILDS_REQUIRED')
    refs = [references['project'], *references['builds'].values()]
    if references['machineInventory'] is not None: refs.append(references['machineInventory'])
    for ref in refs: d.verify_snapshot(ref)
    spec = project.check(references['project']['path'])
    if spec['projectEvaluationIdentity'] != project_identity:
        raise ValueError('PROGRAM_EVIDENCE_PROJECT_MISMATCH')
    builds = api.current_builds(spec, {'builds': references['builds']})
    for side, build in builds.items():
        if build_reference(build['program']) != references['builds'][side]:
            raise ValueError('PROGRAM_EVIDENCE_BUILD_LOCATION_MISMATCH')
    kinds = ['recorded-project-builds']
    if references['machineInventory'] is not None:
        from .program_machine_inventory import check
        inventory = check(references['machineInventory']['path'])
        if (inventory['project'] != references['project'] or inventory['builds'] != references['builds']
                or inventory['facts']['projectEvaluationIdentity'] != project_identity):
            raise ValueError('PROGRAM_EVIDENCE_INVENTORY_BINDING_MISMATCH')
        kinds.append('bounded-machine-inventory')
    for ref in refs: d.verify_snapshot(ref)
    return kinds
