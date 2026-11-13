"""Compiler-identity correspondence and explicit unproved contract boundaries."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from .test_native_captured_deployment import captured
from riscv2x86_py import native_contract_evidence as contracts
from riscv2x86_py import native_captured_deployment as d


def fn(name,id,start,stop,previous=None,body=False):
    node={'kind':'FunctionDecl','id':id,'name':name,'type':{'qualType':'int (int)'},
          'range':{'begin':{'offset':start},'end':{'offset':stop}},
          'inner':[{'kind':'ParmVarDecl','type':{'qualType':'int'}}]}
    if previous:node['previousDecl']=previous
    if body:node['inner'].append({'kind':'CompoundStmt','inner':[]})
    return node


def test_declaration_mapping_uses_transported_bytes_not_name_or_ast_index():
    source={'kind':'TranslationUnitDecl','inner':[fn('arbitrary','node:1',0,30)]}
    edit={'sourceRange':[10,15],'replacement':'longer_statement'}
    shift=len(edit['replacement'])-5
    target={'kind':'TranslationUnitDecl','inner':[
        fn('arbitrary','node:2',100,130),fn('arbitrary','node:3',0,30+shift)]}
    rows=contracts.function_correspondence(source,target,[edit],'source-id','target-id')
    assert rows[0]['candidateAstPath']==[1]
    assert rows[0]['byteLineageDeclarationCorrespondenceVerified']
    assert rows[0]['inspectionSignatureShapeEqual']
    assert not rows[0]['nativeAbiContractVerified']
    target['inner'].append(deepcopy(target['inner'][1]))
    row=contracts.function_correspondence(source,target,[edit],'source-id','target-id')[0]
    assert not row['byteLineageDeclarationCorrespondenceVerified']


def test_position_transport_uses_byte_lengths_and_blocks_inside_replacement():
    edits=[{'sourceRange':[10,15],'replacement':'变量'}]
    assert contracts.transport(20,edits)==21
    assert contracts.transport(10,edits) is None
    assert contracts.transport(15,edits)==16


def test_signature_difference_is_not_concealed_by_name_match():
    a={'kind':'TranslationUnitDecl','inner':[fn('api','node:1',0,30)]}
    b=deepcopy(a);b['inner'][0]['type']['qualType']='long (int)'
    row=contracts.function_correspondence(a,b,[],'a','b')[0]
    assert row['byteLineageDeclarationCorrespondenceVerified']
    assert not row['inspectionSignatureShapeEqual'] and not row['nativeAbiContractVerified']


def test_call_graph_uses_declaration_chain_and_preserves_object_initializers():
    forward=fn('same_spelling','node:1',0,10)
    definition=fn('same_spelling','node:2',20,40,previous='node:1',body=True)
    unrelated=fn('same_spelling','node:3',50,70,body=True)
    caller=fn('caller','node:4',80,100,body=True)
    call={'kind':'CallExpr','type':{'qualType':'int'},'inner':[
        {'kind':'ImplicitCastExpr','castKind':'FunctionToPointerDecay','inner':[
            {'kind':'DeclRefExpr','referencedDecl':{'kind':'FunctionDecl','id':'node:1','name':'same_spelling'}}]},
        {'kind':'IntegerLiteral','value':'7','type':{'qualType':'int'}}]}
    caller['inner'][-1]['inner']=[call,{'kind':'VarDecl','id':'node:5','name':'x',
        'type':{'qualType':'int'},'inner':[{'kind':'IntegerLiteral','value':'1'}]}]
    ast={'kind':'TranslationUnitDecl','inner':[forward,definition,unrelated,caller,
        {'kind':'TypedefDecl','id':'node:6','name':'word','type':{'qualType':'unsigned long'}}]}
    graph=contracts.ast_graph(ast,'actual-ast-id')
    site=graph['callSites'][0]
    assert site['definitionAstPaths']==[[1]] and site['definitionIncluded']
    assert site['redeclarationIds']==['node:1','node:2']
    assert not site['actualExecutionVerified'] and not site['nativeAbiContractVerified']
    assert graph['objectDeclarations'][0]['initializerAst'][0]['value']=='1'
    assert not graph['objectDeclarations'][0]['lifetimeVerified']
    assert graph['functionDefinitions'][0]['machineJoinMissingFacts']
    assert not graph['typeGraph'][0]['nativeLayoutVerified']


def test_indirect_call_and_variadic_declaration_are_not_assumed_supported():
    ast={'kind':'TranslationUnitDecl','inner':[dict(fn('varargs','node:1',0,9),variadic=True),
        {'kind':'CallExpr','inner':[{'kind':'DeclRefExpr','referencedDecl':{'kind':'VarDecl','id':'node:2','name':'fp'}}]}]}
    graph=contracts.ast_graph(ast,'id')
    assert graph['callSites'][0]['resolution']['classification']=='unresolved'
    assert not graph['callSites'][0]['nativeAbiContractVerified']


def test_relocation_kind_selects_obligations_without_granting_semantics():
    def row(type,role='unsupported',symbol_type=0):
        return {'relocation':{'type':type},'role':role,'symbol':{'type':symbol_type}}
    dynamic={'objects':[{'file':{'path':'arbitrary-library'},'elf':{'machine':62},
        'relocationObligations':[row(18),row(0x7fffffff),row(5,'copy'),row(37,'indirect-relative'),row(7,'jump-slot',10)]},
        {'file':{'path':'other-isa'},'elf':{'machine':243},'relocationObligations':[row(18)]}]}
    rows=contracts.relocation_contracts(dynamic)
    assert rows[0]['contractKind']=='tls-thread-pointer-offset'
    assert rows[1]['contractKind']=='unsupported' and rows[-1]['contractKind']=='unsupported'
    assert 'INITIALIZER_PROVIDER_SELECTION' in rows[2]['requirements']
    assert all(not r['semanticsVerified'] and r['status']=='inconclusive' for r in rows)
    assert all('RESOLVER_EXECUTION_AND_IMPLEMENTATION_ADDRESS' in r['requirements'] for r in rows[3:5])


def test_entry_context_is_selected_by_captured_producer_and_temporal_order(captured):
    root,p,plan=captured
    producers,gaps=contracts.entry_producers(plan)
    assert len(producers)==1
    assert Path(producers[0]['context']['sourcePath'])==p/'main.c'
    assert any(g['reasonCode']=='EXTERNAL_PROVIDER_CONTEXT_REQUIRED' for g in gaps)
    path=Path(plan['testRecords']['path']);records=d.read(path)
    for action in records['actions']:
        if action['kind']=='compile':
            action['observedInvocationInterval']['finish']=plan['entry']['action']['observedInvocationInterval']['start']+1
    path.write_text(json.dumps(records))
    producers,gaps=contracts.entry_producers(plan)
    assert not producers and any(g['reasonCode']=='ENTRY_DIRECT_OBJECT_PRODUCER_NOT_UNIQUE' for g in gaps)


@pytest.mark.parametrize('value',['','.'])
def test_cli_rejects_empty_or_directory_plan_before_creating_outputs(tmp_path,value):
    script=Path(__file__).resolve().parents[2]/'experiment/advance_native_closure.py'
    p=subprocess.run([sys.executable,str(script),'audit-candidate','--plan',value,
                      '--output',str(tmp_path/'output')],capture_output=True,text=True)
    assert p.returncode==2 and 'CLOSURE_INPUT_REGULAR_FILE_REQUIRED:plan' in p.stderr
    assert not (tmp_path/'output').exists()


@pytest.fixture
def contract_pipeline(prepared,tmp_path,monkeypatch):
    """Real entry GCC acquisition/loader with explicit source/Clang boundaries.

    prepared supplies the mocked inspection/source binding, never ISA proof.
    Entry producer matching and native preprocessing execute normally.
    """
    from .test_native_captured_deployment import captured_project
    from riscv2x86_py.native_deployment_observation import observe
    source_root,_,candidate,source,artifacts,producer,bindings,contexts,context=prepared
    root=tmp_path/'entry-project';root.mkdir()
    _,p,plan=captured_project(root,language_flags=('-std=gnu11',))
    planfile=root/'plan.json';planfile.write_text(json.dumps(plan))
    d.execute(plan,root/'deployment',diagnostic_only=True)
    observed=observe(root/'deployment/result.json',root/'observation',diagnostic=True)
    context=deepcopy(context)
    context['deploymentPlanIdentity']=plan['deploymentPlanIdentity']
    context['runtimeObservationInventory']={'observationIdentity':observed['observationIdentity']}
    folder=root/'context';folder.mkdir()
    (folder/'inputs.json').write_text(json.dumps({'plan':d.snapshot(planfile),
        'targetReceipt':d.snapshot(source_root/'bridge/target-native-input/native-input.json')}))
    (folder/'result.json').write_text(json.dumps(context))
    # Existing independent source-chain validation is a protocol boundary here.
    monkeypatch.setattr(contracts.bridge,'check',lambda path:context)
    monkeypatch.setattr(contracts.bridge,'inputs',lambda plan:(candidate,source,artifacts,producer,bindings,contexts))
    result=contracts.acquire(folder/'result.json',root/'observation/result.json',root/'contracts',clang=sys.executable)
    return root,result


# Import the fixture under its original name so pytest can resolve it.
from .test_native_context_bridge import prepared


def test_entry_acquisition_and_contract_report_are_rederived(contract_pipeline):
    root,result=contract_pipeline
    assert result['entryDirectObjectContextAcquisitionComplete']
    assert len(result['entryContexts'])==1
    assert not result['entryCapturedInputContextCoverageComplete']
    assert result['entryInputGaps'] and not result['entryAbiClosureVerified']
    assert contracts.check(root/'contracts/result.json')==result
    assert not result['semanticApproval']
    assert all(v['status']=='inconclusive' for v in result['stages'].values())
    coverage=result['coverageInventory']
    assert coverage['runtimeEvidenceState']=='not-acquired'
    assert coverage['boundedProcessComparisonState']=='not-acquired'
    assert not coverage['candidateInstructionExecutionCoverageVerified']
    assert coverage['entryInputGapReasonCounts']
    assert coverage['unverifiedRelocationContractIdentities']
    assert 'entry:0' in coverage['contexts']
    assert 'RUNTIME_EVIDENCE_NOT_ACQUIRED' in result['stages']['runtime-binding']['reasonCodes']
    assert result['producerContextClosure']['capturedProducerClosureComplete']
    assert len(result['producerContextClosure']['deployedReplacements'])==2
    assert not result['programScope']['fullProgramScopeComplete']
    assert 'source' in result['constantInitializerEvidence']


def test_readiness_inventory_tracks_unresolved_calls_objects_and_variadic_abi():
    from riscv2x86_py.native_contract_readiness import inventory
    callee=dict(fn('callee','decl:1',0,10),variadic=True)
    caller=fn('caller','decl:2',20,60,body=True)
    caller['inner'][-1]['inner']=[
        {'kind':'CallExpr','inner':[{'kind':'DeclRefExpr','referencedDecl':
            {'kind':'FunctionDecl','id':'decl:1','name':'callee'}}]},
        {'kind':'CallExpr','inner':[{'kind':'DeclRefExpr','referencedDecl':
            {'kind':'VarDecl','id':'decl:3','name':'fp'}}]},
        {'kind':'VarDecl','id':'decl:4','name':'array','type':{'qualType':'int[4]'}}]
    graph=contracts.ast_graph({'kind':'TranslationUnitDecl','inner':[callee,caller]},'fixture-ast')
    coverage=inventory({'source':graph},[],[],[],[],None,None)
    source=coverage['contexts']['source']
    assert source['callSiteCount']==2
    assert len(source['unresolvedCallEvidenceIdentities'])==1
    assert len(source['variadicCallEvidenceIdentities'])==1
    assert len(source['legalObjectContractRequiredEvidenceIdentities'])==1
    assert len(source['nativeAbiRequiredCallEvidenceIdentities'])==2
    assert source['nativeAbiMachineJoinRequiredFunctionIdentities']
    assert not coverage['commonFrameworkAdmissionVerified']


@pytest.mark.parametrize('change',['rehashed-result','entry-log','input-schema'])
def test_contract_evidence_corruption_is_rejected(contract_pipeline,change):
    root,_=contract_pipeline;path=root/'contracts/result.json'
    if change=='rehashed-result':
        value=d.read(path);value['entryAbiClosureVerified']=True
        path.write_text(json.dumps(d.seal({k:v for k,v in value.items() if k!='contractEvidenceIdentity'},'contractEvidenceIdentity')))
    elif change=='entry-log':(root/'contracts/entry-000/native-expanded.stdout').write_bytes(b'changed')
    else:
        p=root/'contracts/inputs.json';value=d.read(p);value['schemaVersion']='unknown'
        p.write_text(json.dumps(d.seal({k:v for k,v in value.items() if k!='contractInputsIdentity'},'contractInputsIdentity')))
    with pytest.raises(ValueError):contracts.check(path)


def test_refinement_reuses_validated_entry_receipts_and_rejects_wrong_parent(contract_pipeline,monkeypatch):
    root,result=contract_pipeline
    from riscv2x86_py import native_program_comparison as comparison
    observed=d.read(root/'observation/result.json')
    fake=root/'comparison.json';fake.write_text('{}')
    report={'deploymentIdentity':observed['deploymentIdentity'],'processObservableComparisonStatus':'failed',
            'processComparisonIdentity':'fixture-observable-comparison'}
    # This boundary stands for the separately tested comparison verifier.
    monkeypatch.setattr(comparison,'check',lambda _:report)
    monkeypatch.setattr(contracts.native,'acquire',lambda *args,**kwargs:pytest.fail('compiler reran'))
    refined=contracts.refine(root/'contracts/result.json',root/'refined',comparison_path=fake)
    assert refined['entryContexts']==result['entryContexts']
    assert refined['stages']['output-termination']['status']=='failed'
    assert not refined['semanticApproval']
    assert contracts.check(root/'refined/result.json')==refined
    report['deploymentIdentity']='different'
    with pytest.raises(ValueError,match='COMPARISON_DEPLOYMENT_MISMATCH'):
        contracts.refine(root/'contracts/result.json',root/'wrong',comparison_path=fake)
    assert not (root/'wrong').exists()


def test_context_batch_reuses_bound_parent_input_without_recompilation(contract_pipeline,monkeypatch):
    from riscv2x86_py import native_context_batch as batch
    root,result=contract_pipeline
    monkeypatch.setattr(batch.native,'acquire',lambda *a,**k:pytest.fail('parent receipt should be reused'))
    value=batch.acquire(root/'contracts/result.json',root/'context-batch',clang=sys.executable,start=0,count=1)
    assert value['selectedContextAcquisitionComplete']
    assert value['rows'][0]['reusedParentReceipt']
    assert not value['nativeAbiClosureVerified'] and not value['legalObjectDomainVerified']
    assert batch.check(root/'context-batch/result.json')==value
    path=root/'context-batch/result.json';value['semanticApproval']=True
    path.write_text(json.dumps(d.seal({k:v for k,v in value.items() if k!='contextBatchIdentity'},'contextBatchIdentity')))
    with pytest.raises(ValueError,match='REDERIVATION_MISMATCH'):batch.check(path)


def test_context_batch_acquires_dependency_cpp_and_binds_new_receipt(contract_pipeline):
    # contract_pipeline runs real native GCC; its Clang inspection protocol is
    # explicitly mocked. This tests acquisition/binding, never ISA semantics.
    from riscv2x86_py import native_context_batch as batch
    root,_=contract_pipeline
    value=batch.acquire(root/'contracts/result.json',root/'dependency-batch',clang=sys.executable,start=0,count=2)
    assert value['selectedContextAcquisitionComplete']
    assert value['rows'][0]['reusedParentReceipt']
    assert not value['rows'][1]['reusedParentReceipt']
    assert Path(value['rows'][1]['receipt']['path']).parent.name=='context-000001'
    assert batch.check(root/'dependency-batch/result.json')==value


@pytest.mark.parametrize('start,count',[(-1,1),(0,0),(0,65),(9999,1)])
def test_context_batch_rejects_invalid_ranges_before_output_creation(contract_pipeline,start,count):
    from riscv2x86_py import native_context_batch as batch
    root,_=contract_pipeline
    with pytest.raises(ValueError,match='RANGE_INVALID'):
        batch.acquire(root/'contracts/result.json',root/'invalid-batch',clang=sys.executable,start=start,count=count)
    assert not (root/'invalid-batch').exists()


def test_function_entry_evidence_returns_to_contracts_without_stage_promotion(contract_pipeline,monkeypatch):
    from riscv2x86_py import native_entry_probe
    root,base=contract_pipeline
    source=root/'contracts/result.json';evidence=root/'entry-fixture.json'
    evidence.write_text('{}')
    # Entry checker is a protocol boundary; real capture/replay has separate tests.
    observed={'entryCoverageIdentity':'fixture-entry-identity',
        'contractEvidenceIdentity':base['contractEvidenceIdentity'],
        'deploymentIdentity':d.read(root/'deployment/result.json')['deploymentIdentity'],
        'candidateFunctionEntriesObserved':True,'observedFunctionCount':1,'expectedFunctionCount':1,
        'candidateInstructionExecutionCoverageVerified':False,'nativeAbiClosureVerified':False,
        'legalObjectDomainVerified':False,'untracedRunCoverageVerified':False}
    monkeypatch.setattr(native_entry_probe,'check',lambda path:observed)
    result=contracts.refine(source,root/'entry-refined',entry_coverage_path=evidence)
    assert result['validationProgress']['subgoals']['instrumented-candidate-function-entry']['status']=='verified'
    assert result['stages']==base['stages'] and not result['entryAbiClosureVerified']
    assert not result['semanticApproval'] and contracts.check(root/'entry-refined/result.json')==result
    observed['contractEvidenceIdentity']='different-base'
    with pytest.raises(ValueError,match='ENTRY_COVERAGE_BASE_MISMATCH'):
        contracts.refine(source,root/'wrong-entry',entry_coverage_path=evidence)
    assert not (root/'wrong-entry').exists()


def test_bounded_api_and_statement_evidence_join_without_global_stage_promotion(contract_pipeline,monkeypatch):
    from riscv2x86_py import native_api_experiment,native_statement_probe
    root,base=contract_pipeline
    api_path=root/'api-fixture.json';api_path.write_text('{}')
    statement_path=root/'statement-fixture.json';statement_path.write_text('{}')
    bounded={'contractEvidenceIdentity':base['contractEvidenceIdentity'],'apiExperimentIdentity':'fixture-api',
        'compilerDeclarationWitnessesComplete':True,'objectConstructionContract':{'calleeAllAccessesProvedLegal':False},
        'harnessObservationProtocolComplete':True,'processObservationStatus':'verified',
        'nativeAbiClosureVerified':False,'legalObjectDomainVerified':False,'scope':'bounded-api-under-declared-preconditions'}
    statement={'contractEvidenceIdentity':base['contractEvidenceIdentity'],'statementProbeIdentity':'fixture-statement',
        'instrumentedStatementCoverageComplete':True,'canonicalInstructionCoverageVerified':False,
        'untracedRunCoverageVerified':False,'instrumentedLibraryRuntimeIdentityVerified':False,
        'scope':'instrumented-statement-only'}
    # Protocol boundaries only; native compiler / marker tests execute separately.
    monkeypatch.setattr(native_api_experiment,'check',lambda path:bounded)
    monkeypatch.setattr(native_statement_probe,'check',lambda path:statement)
    result=contracts.refine(root/'contracts/result.json',root/'bounded-refined',api_path=api_path,statement_path=statement_path)
    assert result['stages']==base['stages']
    assert result['validationProgress']['subgoals']['bounded-api-observations']['status']=='verified'
    assert not result['candidateStatementEvidence']['canonicalInstructionCoverageVerified']
    assert contracts.check(root/'bounded-refined/result.json')==result
    bounded['contractEvidenceIdentity']='wrong-base'
    with pytest.raises(ValueError,match='NATIVE_EXPERIMENT_BASE_MISMATCH'):
        contracts.refine(root/'contracts/result.json',root/'wrong-bounded',api_path=api_path)


def test_framework_summary_records_actual_invocation_not_guard_as_execution(contract_pipeline,monkeypatch):
    from riscv2x86_py import native_framework_admission as framework
    root,base=contract_pipeline;path=root/'framework-fixture.json';path.write_text('{}')
    value={'contractEvidenceIdentity':base['contractEvidenceIdentity'],'nativeFrameworkIdentity':'fixture-native-framework',
        'originalFrameworkInvoked':True,'executedOriginalValidatorLevels':['L0'],
        'frameworkResult':{'status':'inconclusive','reasonCodes':['native.stage-required:entry-abi'],
            'layers':[{'level':'L0','status':'verified','evidenceIdentity':'fixture-l0','detail':'actual fixture callback'},
                      {'level':'L1','status':'inconclusive','evidenceIdentity':'','detail':'native-admission-not-layer-execution'}]},
        'scope':'requested-profile-with-native-admission-prerequisites'}
    monkeypatch.setattr(framework,'check',lambda path:value)
    result=contracts.refine(root/'contracts/result.json',root/'framework-refined',framework_path=path)
    assert result['frameworkEvaluationReadiness']['L0']['status']=='verified'
    assert result['frameworkEvaluationReadiness']['L1']['status']=='not_run'
    assert result['frameworkEvaluationReadiness']['L1']['admissionStatus']=='inconclusive'
    assert result['stages']['program-validation']['status']=='inconclusive'
    assert contracts.check(root/'framework-refined/result.json')==result
