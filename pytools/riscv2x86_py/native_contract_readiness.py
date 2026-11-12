"""Re-derived work inventory for the existing validation consumers.

This inventories static contexts, not the reachable execution domain. Counts
must not become an acceptance threshold or substitute for L0--L3 admission.
"""
from collections import Counter


def inventory(graphs, entries, joins, relocations, entry_gaps, runtime, comparison):
    scopes = dict(graphs)
    scopes.update({'entry:'+str(i): row['graph'] for i, row in enumerate(entries)})
    contexts = {}
    for name, graph in scopes.items():
        calls = graph['callSites']; definitions = graph['functionDefinitions']
        contexts[name] = {
            'functionDefinitionCount': len(definitions), 'callSiteCount': len(calls),
            'unresolvedCallEvidenceIdentities': [c['callSiteEvidenceIdentity'] for c in calls
                if c['resolution']['classification'] == 'unresolved'],
            'externalOrAmbiguousDefinitionCallEvidenceIdentities': [c['callSiteEvidenceIdentity']
                for c in calls if not c['definitionIncluded']],
            'variadicCallEvidenceIdentities': [c['callSiteEvidenceIdentity'] for c in calls
                if c['localDeclaration'] and c['localDeclaration']['signature']['variadic']],
            'nativeAbiMachineJoinRequiredFunctionIdentities': [f['functionEvidenceIdentity']
                for f in definitions if not f['machineJoinComplete']],
            'nativeAbiRequiredCallEvidenceIdentities': [c['callSiteEvidenceIdentity'] for c in calls
                if not c['nativeAbiContractVerified']],
            'legalObjectContractRequiredEvidenceIdentities': [o['objectEvidenceIdentity']
                for o in graph['objectDeclarations'] if not all(o[k] for k in (
                    'initializationSemanticsVerified','lifetimeVerified','boundsVerified','aliasContractVerified'))],
            'nativeLayoutRequiredTypeEvidenceIdentities': [t['typeEvidenceIdentity']
                for t in graph['typeGraph'] if not t['nativeLayoutVerified']]}
    runtime_state = 'not-acquired' if runtime is None else (
        'diagnostic-endpoints-mapped' if runtime['diagnosticEndpointMappingComplete'] else 'partial')
    return {
        'scope': 'static-context-inventory-not-reachability-or-semantic-admission',
        'contexts': contexts,
        'declarationCorrespondenceMissingCount': sum(not j['byteLineageDeclarationCorrespondenceVerified'] for j in joins),
        'entryInputGapReasonCounts': dict(sorted(Counter(g['reasonCode'] for g in entry_gaps).items())),
        'relocationContractKindCounts': dict(sorted(Counter(r['contractKind'] for r in relocations).items())),
        'unverifiedRelocationContractIdentities': [r['relocationContractIdentity'] for r in relocations
                                                if not r['semanticsVerified']],
        'runtimeEvidenceState': runtime_state,
        'runtimeEndpointFailureReasonCounts': runtime['endpointFailureReasonCounts'] if runtime else None,
        'runtimeMetadataFailureReasonCounts': runtime['metadataFailureReasonCounts'] if runtime else None,
        'boundedProcessComparisonState': comparison['processObservableComparisonStatus'] if comparison else 'not-acquired',
        'reachabilityScopeVerified': False, 'candidateInstructionExecutionCoverageVerified': False,
        'commonFrameworkAdmissionVerified': False}
