"""One compiler-instance join for diagnostic and original L2 entry points.

Source exclusion never becomes machine elimination, execution or approval.
The caller must supply a freshly checked applicability receipt and API selection.
"""
from .project_build_records import identity


def classify(finding, selected, applicability, project_snapshot):
    if applicability['project'] != project_snapshot:
        raise ValueError('L2_TYPED_APPLICABILITY_PROJECT_MISMATCH')
    identities = selected['instanceBindingIdentities']
    if not identities or len(set(identities)) != len(identities):
        raise ValueError('L2_TYPED_INSTANCE_SELECTION_INVALID')
    rows = [r for r in applicability['facts']['instances']
            if r['instanceBindingIdentity'] in identities]
    if (set(identities) != {r['instanceBindingIdentity'] for r in rows}
            or len(rows) != len(identities)):
        raise ValueError('L2_TYPED_APPLICABILITY_INSTANCE_JOIN_REQUIRED')
    physical = finding.get('physicalEditBinding') or {}
    # Production physical bindings carry the canonical INSTANCE identity, not
    # an astPath. Never classify every edited site in the selected function as
    # though it were the current finding (mixed live/excluded sites are legal).
    instance = physical.get('instanceBindingIdentity')
    path = physical.get('astPath')
    if instance is not None:
        rows = [r for r in rows if r['instanceBindingIdentity'] == instance]
        if len(rows) != 1 or (path is not None and rows[0]['astPath'] != path):
            raise ValueError('L2_TYPED_APPLICABILITY_PHYSICAL_INSTANCE_JOIN_REQUIRED')
    elif path is not None:
        rows = [r for r in rows if r['astPath'] == path]
        if len(rows) != 1:
            raise ValueError('L2_TYPED_APPLICABILITY_AST_JOIN_REQUIRED')
    elif len(rows) != 1:
        raise ValueError('L2_TYPED_APPLICABILITY_FINDING_INSTANCE_AMBIGUOUS')
    excluded = all(r['sourceGuardClassification'] ==
                   'excluded-under-compiler-query-contracts' for r in rows)
    body = {'schemaVersion': 'riscv2x86.instance-execution-disposition.v1',
            'project': project_snapshot, 'fragmentId': finding['fragment']['id'],
            'functionBindingIdentity': selected['functionBindingIdentity'],
            'instanceBindingIdentities': [r['instanceBindingIdentity'] for r in rows],
            'instanceFacts': rows, 'sourceConditionExcluded': excluded,
            'disposition': 'source-excluded-machine-unproved' if excluded else 'execution-evidence-required',
            'canonicalInstructionCoverageVerified': False,
            'machineEliminationVerified': False,
            'scope': 'checked-source-applicability-not-machine-disposition'}
    return dict(body, dispositionIdentity=identity(body))
