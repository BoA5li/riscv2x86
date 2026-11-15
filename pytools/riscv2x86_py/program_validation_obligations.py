"""Freeze declared program scope and generate evidence-production obligations.

This is a work plan for ORIGINAL validators. It cannot manufacture runtime
coverage, approve a trusted provider, or replace layer status aggregation.
"""
import json
from pathlib import Path
from . import native_captured_deployment as d
from .native_original_pipeline import check_translation,translation_complete
from .native_verifier_manifest import current,compare
from .project_acquisition import Runner,publish_checked

SCHEMA='riscv2x86.program-validation-obligations.v1'
SCOPE='riscv2x86.declared-program-scope.v1'


def derive(translation_path,scope):
    from .schema import load_report
    value=check_translation(translation_path)
    if not translation_complete(value):raise ValueError('PROGRAM_PLAN_COMPLETE_ORIGINAL_TRANSLATION_REQUIRED')
    if (not isinstance(scope,dict) or set(scope)!={'schemaVersion','entryContract','inputDomainContract',
            'observationContract','trustBoundaryContract','requiredLevels','buildCells'} or scope['schemaVersion']!=SCOPE):
        raise ValueError('PROGRAM_DECLARED_SCOPE_SCHEMA_INVALID')
    refs={}
    for key in ('entryContract','inputDomainContract','observationContract','trustBoundaryContract'):
        if not isinstance(scope[key],str) or not scope[key]:raise ValueError('PROGRAM_EXPLICIT_CONTRACT_REQUIRED:'+key)
        refs[key]=d.snapshot(scope[key])
    levels=scope['requiredLevels'];order=['L0','L1','L2','L3']
    if not isinstance(levels,list) or not levels or levels!=order[:len(levels)] or len(levels)>4:
        raise ValueError('PROGRAM_ORIGINAL_LEVEL_ORDER_REQUIRED')
    cells=scope['buildCells']
    if (not isinstance(cells,list) or not cells or len(cells)>128 or any(not isinstance(c,dict)
            or set(c)!={'cellId','buildContract'} or not isinstance(c['cellId'],str) or not c['cellId']
            or not isinstance(c['buildContract'],str) or not c['buildContract'] for c in cells)
            or len({c['cellId'] for c in cells})!=len(cells)):
        raise ValueError('PROGRAM_BUILD_CELL_IDENTITY_REQUIRED')
    builds=[{'cellId':c['cellId'],'contract':d.snapshot(c['buildContract'])} for c in cells]
    findings=load_report(value['report']['path'])
    instances=[{'findingIndex':i,'fragmentId':f.fragment.id if f.fragment else '',
                'physicalBinding':f.physicalEditBinding,
                'translationOutcome':f.translationOutcome} for i,f in enumerate(findings)]
    rows=[]
    def obligation(kind,phase,consumer,bindings):
        body={'kind':kind,'phase':phase,'consumer':consumer,'bindings':bindings,
              'status':'evidence-production-required'}
        rows.append(dict(body,obligationIdentity=d.identity(body)))
    for cell in builds:
        obligation('source-target-materialization-and-link','before-L0','l0_build_matrix',cell)
        if 'L1' in levels:
            for kind in ('legal-inputs-and-entry-interface','runtime-selected-artifacts','declared-comparison-policy'):
                obligation(kind,'before-L1','original-runtime-registry',cell)
            obligation('actual-output-error-and-termination-relation','after-L1','l1_differential',cell)
        if 'L2' in levels:
            for instance in instances:
                for kind in ('instance-survival-or-elimination','compiler-instance-to-canonical-region',
                             'canonical-region-runtime-events','operand-shell-and-applicable-effects'):
                    obligation(kind,'before-or-during-L2','original-L2-providers',{'cell':cell,'instance':instance})
        if 'L3' in levels:
            obligation('declared-intent-applicability-environment-and-observations','before-or-during-L3',
                       'original-L3-providers',cell)
    obligation('applicable-ABI-object-and-external-call-contracts','scoped-program-prerequisites',
               'checked-contract-consumers',{'contracts':refs})
    obligation('independent-program-evidence-audit','after-required-levels',
               'original-validation-and-audit',{'requiredLevels':levels})
    return {'translationIdentity':value['originalTranslationIdentity'],'contractReferences':refs,'buildCells':builds,
        'instances':instances,'obligations':rows,'requiredLevels':levels,
        'executionPreconditionsSeparatedFromPostconditions':True,
        'programScopeFrozen':True,'programPrerequisitesVerified':False,
        'canonicalInstructionCoverageVerified':False,'programValidationPerformed':False,
        'scope':'evidence-production-plan-not-evaluation-or-proof'}


def acquire(translation_path,scope_path,output):
    scope=d.read(scope_path);facts=derive(translation_path,scope);runner=Runner(output,'program-validation-plan')
    try:
        value=d.seal({'schemaVersion':SCHEMA,'verifier':current(),'translation':d.snapshot(translation_path),
            'declaredScope':d.snapshot(scope_path),'facts':facts,
            'semanticApproval':False,'productionAcceptanceComplete':False},'programObligationsIdentity')
        publish_checked(runner.output/'result.json',value,check)
        runner.state.update(status='complete',currentStage='complete',acquisitionComplete=True);runner.save();return value
    except Exception as exc:runner.failure('program-obligations',exc);raise


def check(path):
    from .native_external_providers import checked
    value=d.read(path);checked(value,'programObligationsIdentity');compare(value['verifier'],current())
    for key in ('translation','declaredScope'):d.verify_snapshot(value[key])
    if (value['schemaVersion']!=SCHEMA
            or value['facts']!=derive(value['translation']['path'],d.read(value['declaredScope']['path']))
            or value['semanticApproval'] is not False or value['productionAcceptanceComplete'] is not False):
        raise ValueError('PROGRAM_OBLIGATIONS_REDERIVATION_MISMATCH')
    return value
