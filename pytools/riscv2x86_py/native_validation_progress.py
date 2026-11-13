"""Separate verified subgoals from unresolved program acceptance obligations.

This consumes already-checked artifacts in contract derivation. It never reads
user-supplied approval flags and never upgrades a whole validation stage from
an acquisition success or an empty obligation list.
"""


def derive(context,deployed,observed,producer,runtime,comparison):
    def goal(verified,scope,missing):
        return {'status':'verified' if verified else 'inconclusive',
                'scope':scope,'reasonCodes':[] if verified else [missing]}
    return {
        'schemaVersion':'riscv2x86.native-validation-progress.v1',
        'subgoals':{
            'source-content-lineage':goal(context['sourceContentLineageVerified'],
                'bound-source-content-only','SOURCE_CONTENT_LINEAGE_REQUIRED'),
            'candidate-input-replacement':goal(deployed['capturedInputReplacementVerified']
                and deployed['candidateDefinitionAttributionVerified'],
                'checked-object-replacement-not-semantic-audit-or-execution','CANDIDATE_REPLACEMENT_ATTRIBUTION_REQUIRED'),
            'target-build-replay':goal(deployed['capturedBaselineBytesReproduced']
                and deployed['derivedEntryBuildComplete'] and deployed['derivedLibraryBuildComplete'],
                'captured-target-build-not-whole-L0','TARGET_BUILD_REPLAY_REQUIRED'),
            'explicit-input-producer-origin':goal(producer['capturedProducerClosureComplete'],
                'captured-explicit-input-origins-not-extraction-or-runtime',
                'EXPLICIT_INPUT_PRODUCER_ORIGIN_REQUIRED'),
            'diagnostic-endpoint-mapping':goal(runtime is not None
                and runtime['diagnosticEndpointMappingComplete']
                and not runtime['metadataFailureReasonCounts'],
                'this-diagnostic-run-not-natural-run','DIAGNOSTIC_ENDPOINT_MAPPING_REQUIRED'),
            'bounded-process-observations':{
                'status':comparison['processObservableComparisonStatus'] if comparison else 'not_run',
                'scope':'declared-process-observations-not-L1-eligibility',
                'reasonCodes':[] if comparison else ['SOURCE_TARGET_COMPARISON_NOT_EXECUTED']}},
        'requiredCapabilities':[
            {'id':'actual-link-selection','state':'evidence-and-consumer-required'},
            {'id':'three-context-relation-and-pic-effects','state':'evidence-and-consumer-required'},
            {'id':'native-abi-machine-cfg-frame-join','state':'evidence-and-consumer-required'},
            {'id':'legal-object-input-domain','state':'evidence-and-consumer-required'},
            {'id':'candidate-instance-execution','state':'evidence-and-consumer-required'},
            {'id':'common-L0-L3-admission-and-independent-audit','state':'consumer-and-applicable-evidence-required'}],
        'sourceTargetSemanticEquivalenceVerified':False,
        'productionAcceptanceComplete':False}


def summary(path):
    from .native_contract_evidence import check
    report=check(path)
    producer=report['producerContextClosure']
    resolved=report.get('contextResolution')
    gaps=[]
    for gap in producer['inputGaps']:
        if gap['reasonCode']!='ARCHIVE_OPERATION_CHAIN_NOT_UNIQUE_OR_UNAVAILABLE':continue
        gaps.append({'nodeIdentity':gap['nodeIdentity'],'candidateCount':gap.get('candidateCount'),
            'attempts':[{'captureConfigIdentity':a['captureConfigIdentity'],
                'eligibleActionCount':a['eligibleActionCount'],'selection':a['selection']}
                for a in gap.get('selectionAttempts',[])]})
    return {'schemaVersion':'riscv2x86.native-validation-summary.v1',
        'contractEvidenceIdentity':report['contractEvidenceIdentity'],
        'stages':report['stages'],'validationProgress':report['validationProgress'],
        'crossStageCaptureReplayPerformed':producer['crossStageCaptureReplayPerformed'],
        'captureScopes':producer['captureScopes'],
        'producerNodeCount':len(producer['nodes']),
        'producerCompileContextCount':len(producer['compileContexts']),
        'capturedProducerClosureComplete':producer['capturedProducerClosureComplete'],
        'archiveGaps':gaps,'entryInputGaps':report['entryInputGaps'],
        'observedArchiveMemberCount':report['archiveMemberSelectionEvidence']['observedArchiveMemberCount'],
        'archiveSelectionAudit':report.get('archiveSelectionAudit'),
        'contextResolutionIdentity':resolved['contextResolutionIdentity'] if resolved else None,
        'remainingWorkReasonCounts':resolved['remainingWorkReasonCounts'] if resolved else None,
        'callReasonCounts':resolved['resolution']['callReasonCounts'] if resolved else None,
        'suggestedContextIndices':resolved['resolution']['suggestedContextIndices'] if resolved else [],
        'potentialFunctionCount':resolved['resolution']['potentialFunctionCount'] if resolved else None,
        'frameworkEvaluationReadiness':report['frameworkEvaluationReadiness'],
        'apiExperimentEvidence':report.get('apiExperimentEvidence'),
        'candidateStatementEvidence':report.get('candidateStatementEvidence'),
        'nativeFrameworkEvidence':report.get('nativeFrameworkEvidence'),
        'semanticApproval':report['semanticApproval'],'productionAcceptanceComplete':report['productionAcceptanceComplete']}
