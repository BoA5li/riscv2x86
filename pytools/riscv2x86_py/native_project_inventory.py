"""Inventory EVERY finding in explicitly registered checked project contexts.

Only compiler instance membership identifies an entry. No function-name search,
domain synthesis, source-condition forcing or alternate translation is used.
"""
from pathlib import Path
from . import native_api_campaign as campaign
from . import native_original_api as api
from . import native_captured_deployment as d
from .native_external_providers import checked
from .project_acquisition import publish_checked

SCHEMA = 'riscv2x86.original-project-instance-inventory.v1'


def derive(references):
    if not isinstance(references, list) or not references:
        raise ValueError('API_INVENTORY_PREFLIGHTS_REQUIRED')
    if len({r['resolvedPath'] for r in references}) != len(references):
        raise ValueError('API_INVENTORY_DUPLICATE_PREFLIGHT')
    contexts = []
    for ref in references:
        d.verify_snapshot(ref); preflight = campaign.check_preflight(ref['path'])
        spec_ref = preflight['project']; d.verify_snapshot(spec_ref)
        spec = d.read(spec_ref['path']); d.verify_snapshot(spec['run'])
        run = d.read(spec['run']['path']); d.verify_snapshot(run['translation'])
        translated = d.read(run['translation']['path']); report_ref = translated['report']
        d.verify_snapshot(report_ref); report = d.read(report_ref['path'])
        inspection = api.inspect(spec_ref['path'])
        if inspection['projectEvaluationIdentity'] != spec['projectEvaluationIdentity']:
            raise ValueError('API_INVENTORY_INSPECTION_PROJECT_MISMATCH')
        applications = {r['instanceBindingIdentity']: r
                        for r in preflight['reportCoverage']['findings']
                        if r['instanceBindingIdentity'] is not None}
        rows = []
        for index, finding in enumerate(report['findings']):
            physical = finding.get('physicalEditBinding') or {}
            instance = physical.get('instanceBindingIdentity')
            functions = [f for f in inspection['functions']
                         if instance in f['instanceBindingIdentities']]
            if len(functions) > 1:
                raise ValueError('API_INVENTORY_INSTANCE_ENTRY_AMBIGUOUS')
            function = functions[0] if functions else None
            app = applications.get(instance)
            selected = (function is not None and
                        function['functionBindingIdentity'] == preflight['functionBindingIdentity'])
            rows.append({
                'findingIndex': index, 'fragmentId': (finding.get('fragment') or {}).get('id'),
                'instanceBindingIdentity': instance, 'translationOutcome': finding.get('translationOutcome'),
                'compilerEntry': function,
                'entryContractAvailable': selected,
                'entryStatus': ('checked-finite-contract' if selected else
                                'explicit-domain-and-precondition-contract-required' if function else
                                'compiler-entry-unavailable'),
                'sourceConditionExcluded': app['sourceConditionExcluded'] if app else None,
                'canonicalInstructionCoverageVerified': False,
            })
        contexts.append({
            'preflight': ref, 'project': spec_ref, 'report': report_ref,
            'findings': rows, 'reportFindingCount': len(rows),
            'unsupportedFunctions': inspection['unsupportedFunctions'],
            'unrepresentedEditedInstances': preflight['reportCoverage']['unrepresentedEditedInstances'],
        })
        for dependency in (report_ref, run['translation'], spec['run'], spec_ref, ref):
            d.verify_snapshot(dependency)
    return d.seal({
        'schemaVersion': SCHEMA, 'preflights': references, 'contexts': contexts,
        'registeredContextCount': len(contexts),
        'reportFindingCount': sum(c['reportFindingCount'] for c in contexts),
        'scope': 'all-findings-in-registered-project-contexts-not-entire-upstream-corpus',
        'semanticApproval': False, 'productionAcceptanceComplete': False,
    }, 'instanceInventoryIdentity')


def check(path):
    value = d.read(path); checked(value, 'instanceInventoryIdentity')
    if value != derive(value['preflights']):
        raise ValueError('API_INVENTORY_REDERIVATION_MISMATCH')
    return value


def acquire(preflight_paths, output):
    value = derive([d.snapshot(p) for p in preflight_paths])
    publish_checked(Path(output), value, check)
    return value
