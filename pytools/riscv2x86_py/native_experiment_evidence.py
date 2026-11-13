"""Join bounded API, statement and original-framework evidence into contracts."""
from . import native_captured_deployment as d


def augment(body,*,api_path=None,statement_path=None,framework_path=None):
    base=d.seal(body,'contractEvidenceIdentity')['contractEvidenceIdentity']
    checks=[]
    if api_path:
        from .native_api_experiment import check
        result=check(api_path)
        checks.append((result['contractEvidenceIdentity'],'api'))
        body['apiExperimentEvidence']={k:result[k] for k in ('apiExperimentIdentity','compilerDeclarationWitnessesComplete',
            'objectConstructionContract','harnessObservationProtocolComplete','processObservationStatus',
            'nativeAbiClosureVerified','legalObjectDomainVerified','scope')}
        body['validationProgress']['subgoals']['bounded-api-observations']={
            'status':result['processObservationStatus'],'scope':result['scope'],
            'reasonCodes':[] if result['processObservationStatus']=='verified' else ['BOUNDED_API_OBSERVATIONS_NOT_VERIFIED']}
    if statement_path:
        from .native_statement_probe import check
        result=check(statement_path)
        checks.append((result['contractEvidenceIdentity'],'statement'))
        body['candidateStatementEvidence']={k:result[k] for k in ('statementProbeIdentity',
            'instrumentedStatementCoverageComplete','canonicalInstructionCoverageVerified',
            'untracedRunCoverageVerified','instrumentedLibraryRuntimeIdentityVerified','scope')}
        body['validationProgress']['subgoals']['instrumented-statement-completion']={
            'status':'verified' if result['instrumentedStatementCoverageComplete'] else 'inconclusive',
            'scope':result['scope'],'reasonCodes':[] if result['instrumentedStatementCoverageComplete'] else ['TRANSLATED_STATEMENT_NOT_OBSERVED_COMPLETE']}
    if framework_path:
        from .native_framework_admission import check
        result=check(framework_path)
        checks.append((result['contractEvidenceIdentity'],'framework'))
        body['nativeFrameworkEvidence']={k:result[k] for k in ('nativeFrameworkIdentity','originalFrameworkInvoked','executedOriginalValidatorLevels','frameworkResult','scope')}
        body['validationProgress']['subgoals']['original-framework-execution']={
            'status':result['frameworkResult']['status'],'scope':result['scope'],
            'reasonCodes':result['frameworkResult']['reasonCodes']}
        from copy import deepcopy
        readiness=deepcopy(body['frameworkEvaluationReadiness'])
        for layer in result['frameworkResult']['layers']:
            if layer['level'] in result['executedOriginalValidatorLevels']:
                readiness[layer['level']]={'status':layer['status'],'evidenceIdentity':layer['evidenceIdentity'],
                    'detail':layer['detail'],'originalValidatorInvoked':True}
            else:
                readiness[layer['level']]={'status':'not_run','originalValidatorInvoked':False,
                    'admissionStatus':layer['status'],'admissionDetail':layer['detail']}
        body['frameworkEvaluationReadiness']=readiness
        body['stages']['program-validation']['nativeFrameworkIdentity']=result['nativeFrameworkIdentity']
        if result['frameworkResult']['status']=='failed':
            body['stages']['program-validation']['status']='failed'
            body['stages']['program-validation']['reasonCodes']=['ORIGINAL_FRAMEWORK_VALIDATION_FAILED']
    if any(value!=base for value,_ in checks):raise ValueError('CONTRACT_NATIVE_EXPERIMENT_BASE_MISMATCH')
    body['schemaVersion']='riscv2x86.native-contract-evidence.v4'
    return body
