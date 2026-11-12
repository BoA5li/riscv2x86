"""Context consumers: declaration identity + real symbols, never name-only ABI."""
from copy import deepcopy
import json
import sys

import pytest

from riscv2x86_py import native_context_resolution as resolution
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py import native_contract_evidence as contracts
from .test_native_contract_evidence import fn, prepared, contract_pipeline


def unit(uid, name, *, callee=None, linker=None, internal=False):
    definition=fn(name,uid+':def',0,80,body=True)
    definition['mangledName']=linker or name
    if internal:definition['storageClass']='static'
    ast={'kind':'TranslationUnitDecl','inner':[]}
    if callee:
        decl=fn(callee,uid+':decl',100,120);decl['mangledName']=callee
        ast['inner'].append(decl)
        definition['inner'][-1]['inner']=[{'kind':'CallExpr','inner':[
            {'kind':'DeclRefExpr','referencedDecl':{'kind':'FunctionDecl','id':decl['id'],'name':callee}}]}]
    ast['inner'].append(definition)
    graph=contracts.ast_graph(ast,uid+':ast')
    return {'unitIdentity':uid,'object':{'digest':uid},'machine':62,'graph':graph,
            'symbols':[{'name':linker or name,'defined':True,'binding':1,'type':2,
                'sectionIndex':1,'tableIndex':3,'entryIndex':1}]}


def test_cross_context_call_consumes_definition_and_exact_elf_symbol():
    a=unit('a','caller',callee='foreign');b=unit('b','foreign')
    value=resolution.consume([a,b],{'a':[[1]]})
    row=value['callJoins'][0];assert len(row['providerCandidates'])==1
    provider=row['providerCandidates'][0]
    assert provider['unitIdentity']=='b'
    assert provider['inspectionDefinitionAndStrongFunctionSymbolJoined']
    assert provider['inspectionSignatureShapeEqual']
    assert row['inKnownLocalScope']
    assert not provider['actualLinkSelectionVerified'] and not row['nativeAbiContractVerified']
    assert value['uniqueStrongFunctionCandidateCallCount']==1
    assert not value['fullProgramScopeComplete']


@pytest.mark.parametrize('change',['wrong-symbol','static','weak','notype','data','duplicate','signature'])
def test_equal_spelling_cannot_approve_wrong_provider_or_abi(change):
    a=unit('a','caller',callee='foreign');b=unit('b','foreign');units=[a,b]
    if change=='wrong-symbol':b['symbols'][0]['name']='other'
    elif change=='static':b['graph']['functionDefinitions'][0]['storageClass']='static'
    elif change=='weak':b['symbols'][0]['binding']=2
    elif change=='notype':b['symbols'][0]['type']=0
    elif change=='data':b['symbols'][0]['type']=1
    elif change=='duplicate':units.append(unit('c','foreign'))
    else:b['graph']['functionDefinitions'][0]['signature']['type']={'qualType':'long (int)'}
    row=resolution.consume(units,{'a':[[1]]})['callJoins'][0]
    assert not row['nativeAbiContractVerified'] and not row['actualLinkSelectionVerified']
    assert row['reasonCodes']!=['ACTUAL_LINK_SELECTION_NATIVE_ABI_AND_EFFECTS_REQUIRED']


def test_internal_and_missing_linker_names_do_not_escape_tu():
    a=unit('a','caller',callee='foreign');b=unit('b','foreign')
    decl=a['graph']['callSites'][0]['localDeclaration'];decl['internalLinkage']=True
    assert resolution.consume([a,b],{})['callJoins'][0]['providerCandidates']==[]
    decl['internalLinkage']=False;decl['linkerName']=None
    assert resolution.consume([a,b],{})['callJoins'][0]['reasonCodes']==['COMPILER_LINKER_NAME_REQUIRED']


def test_resolution_acquires_from_checked_batches_and_rejects_forged_approval(contract_pipeline):
    from riscv2x86_py import native_context_batch as batch
    root,_=contract_pipeline
    batch.acquire(root/'contracts/result.json',root/'batch',clang=sys.executable,count=2)
    value=resolution.acquire(root/'contracts/result.json',[root/'batch/result.json'],root/'resolution')
    assert value['consumedContextCount']==2
    assert resolution.check(root/'resolution/result.json')==value
    substituted=[u for u in value['units'] if u['candidateSubstitutionApplied']]
    assert substituted
    parent=d.read(root/'contracts/result.json')['producerContextClosure']['candidateSubstitution']
    assert all(u['object']==parent['candidateObject'] and u['graph']==d.read(root/'contracts/result.json')['graphs']['candidate'] for u in substituted)
    assert not value['nativeAbiClosureVerified'] and not value['semanticApproval']
    p=root/'resolution/result.json';value['nativeAbiClosureVerified']=True
    p.write_text(json.dumps(d.seal({k:v for k,v in value.items() if k!='contextResolutionIdentity'},'contextResolutionIdentity')))
    with pytest.raises(ValueError,match='REDERIVATION_MISMATCH'):resolution.check(p)


def test_reuse_dependency_receipts_after_revalidation_without_compiler(contract_pipeline,monkeypatch):
    from riscv2x86_py import native_context_batch as batch
    root,_=contract_pipeline
    old=batch.acquire(root/'contracts/result.json',root/'batch',clang=sys.executable,count=2)
    monkeypatch.setattr(batch.native,'acquire',lambda *a,**k:pytest.fail('validated receipt should be reused'))
    new=batch.acquire(root/'contracts/result.json',root/'reused',clang=sys.executable,count=2,
                      reuse_paths=[r['receipt']['path'] for r in old['rows']])
    assert new['selectedContextAcquisitionComplete']
    assert batch.check(root/'reused/result.json')==new


def test_resolution_rejects_duplicate_batches_before_output(contract_pipeline):
    from riscv2x86_py import native_context_batch as batch
    root,_=contract_pipeline
    batch.acquire(root/'contracts/result.json',root/'batch',clang=sys.executable,count=1)
    with pytest.raises(ValueError,match='DUPLICATE_BATCH'):
        resolution.acquire(root/'contracts/result.json',[root/'batch/result.json']*2,root/'invalid')
    assert not (root/'invalid').exists()


def test_new_contract_consumes_revalidated_entry_without_recompiling(contract_pipeline,monkeypatch):
    root,old=contract_pipeline
    old_inputs=d.read(root/'contracts/inputs.json')
    monkeypatch.setattr(contracts.native,'acquire',lambda *a,**k:pytest.fail('entry compiler should not rerun'))
    value=contracts.acquire(root/'context/result.json',root/'observation/result.json',root/'reused-contract',
        clang=sys.executable,reuse_receipts=[r['path'] for r in old_inputs['entryReceipts']])
    assert value==old
    assert contracts.check(root/'reused-contract/result.json')==value


def test_reuse_mismatched_context_is_rejected_before_output(contract_pipeline):
    from riscv2x86_py import native_context_batch as batch
    root,_=contract_pipeline
    old=batch.acquire(root/'contracts/result.json',root/'batch',clang=sys.executable,count=1)
    path=old['rows'][0]['receipt']['path'];receipt=d.read(path)
    from riscv2x86_py.native_context_bridge import reusable_input
    wrong=deepcopy(receipt['context']);wrong['sourceDigest']='different'
    with pytest.raises(ValueError,match='REUSE_CONTEXT_OR_COMPILER_MISMATCH'):
        reusable_input(path,wrong,sys.executable)


def test_context_resolution_is_consumed_by_existing_contract_refinement(contract_pipeline):
    from riscv2x86_py import native_context_batch as batch
    root,_=contract_pipeline
    batch.acquire(root/'contracts/result.json',root/'batch',clang=sys.executable,count=2)
    resolved=resolution.acquire(root/'contracts/result.json',[root/'batch/result.json'],root/'resolution')
    value=contracts.refine(root/'contracts/result.json',root/'with-resolution',
                           resolution_path=root/'resolution/result.json')
    assert value['schemaVersion']=='riscv2x86.native-contract-evidence.v4'
    assert value['contextResolution']['contextResolutionIdentity']==resolved['contextResolutionIdentity']
    assert value['stages']['entry-abi']['consumedProducerContextCount']==2
    assert contracts.check(root/'with-resolution/result.json')==value
    assert not value['entryAbiClosureVerified']
    with pytest.raises(ValueError,match='BASE_V3_REPORT_REQUIRED'):
        resolution.acquire(root/'with-resolution/result.json',[root/'batch/result.json'],root/'recursive')


def test_bridge_reuses_exact_validated_native_receipt(prepared,monkeypatch):
    from riscv2x86_py import native_context_bridge as bridge
    root,*_=prepared
    old= d.read(root/'bridge/inputs.json')
    monkeypatch.setattr(bridge.native,'acquire',lambda *a,**k:pytest.fail('native compiler should not rerun'))
    value=bridge.acquire(old['plan']['path'],root/'reused-bridge',clang=sys.executable,
                         reuse_receipt=old['targetReceipt']['path'])
    assert bridge.check(root/'reused-bridge/result.json')==value
    assert d.read(root/'reused-bridge/inputs.json')['targetReceipt']==old['targetReceipt']


def test_actual_elf_symbols_are_consumed_without_name_only_provider(tmp_path):
    import shutil,subprocess
    from riscv2x86_py.native_elf_runtime import parse
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native GCC required')
    source=tmp_path/'provider.c';source.write_text('int actual_export(int x){return x+1;}')
    obj=tmp_path/'provider.o'
    subprocess.run([cc,'-c',str(source),'-o',str(obj)],check=True)
    # AST protocol boundary is explicit; symbol table and object are real GCC.
    a=unit('a','caller',callee='actual_export');b=unit('b','actual_export')
    b['symbols']=parse(obj.read_bytes())['staticSymbols'];b['object']=d.snapshot(obj)
    row=resolution.consume([a,b],{'a':[[1]]})['callJoins'][0]
    assert row['providerCandidates'][0]['inspectionDefinitionAndStrongFunctionSymbolJoined']
    b['graph']['functionDefinitions'][0]['linkerName']='same_spelling_but_no_symbol'
    assert resolution.consume([a,b],{'a':[[1]]})['callJoins'][0]['providerCandidates']==[]
