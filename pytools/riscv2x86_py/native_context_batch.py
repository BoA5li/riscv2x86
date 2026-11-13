"""Bounded native CPP/AST acquisition for automatically traced C producers.

Reuse only parent-bound receipts with the same compiler/context. This is input
acquisition for existing consumers, not ABI, object or L0--L3 acceptance.
"""
import json
from pathlib import Path

from . import native_captured_deployment as deployment
from . import native_contract_evidence as contracts
from .native_context_bridge import validated_input
from .native_external_providers import checked
from . import project_native_input as native
from .project_tool_resolution import resolve_executable

SCHEMA='riscv2x86.native-context-batch.v1'


def selection_indices(report,start,count,indices=None):
    contexts=report['producerContextClosure']['compileContexts']
    if indices is not None:
        if (not isinstance(indices,list) or not 1<=len(indices)<=64
                or any(type(i) is not int or not 0<=i<len(contexts) for i in indices)
                or len(set(indices))!=len(indices)):
            raise ValueError('CONTEXT_BATCH_INDICES_INVALID')
        return indices
    if type(start) is not int or type(count) is not int or not 0<=start<len(contexts) or not 1<=count<=64:
        raise ValueError('CONTEXT_BATCH_RANGE_INVALID')
    return list(range(start,min(start+count,len(contexts))))


def selected(report,start,count,indices=None):
    return [report['producerContextClosure']['compileContexts'][i]
            for i in selection_indices(report,start,count,indices)]


def parent_receipts(path,report):
    inputs=deployment.read(Path(path).resolve().parent/'inputs.json')
    bridge=deployment.read(Path(inputs['context']['path']).parent/'inputs.json')
    rows=[*inputs['entryReceipts'],bridge['targetReceipt']];result={}
    for snapshot in rows:
        deployment.verify_snapshot(snapshot)
        receipt=deployment.read(snapshot['path']);validated_input(receipt)
        result[(receipt['context']['contextIdentity'],receipt['inspectionCompiler'])]=snapshot
    return result


def blockers(report,context):
    machines={n.get('elfMachine') for n in report['producerContextClosure']['nodes']
              if n['compileContextIdentity']==context['contextIdentity']}
    return (['CONTEXT_BATCH_X86_64_PRODUCER_REQUIRED'] if machines!={62} else context['blockers'])


def derive(inputs,receipts):
    if type(inputs['timeoutSeconds']) is not int or not 1<=inputs['timeoutSeconds']<=86400:
        raise ValueError('CONTEXT_BATCH_TIMEOUT_INVALID')
    deployment.verify_snapshot(inputs['contracts']);deployment.verify_snapshot(inputs['clang'])
    report=contracts.check(inputs['contracts']['path'])
    if inputs['schemaVersion']=='riscv2x86.native-context-batch-inputs.v2' and (
            not isinstance(inputs.get('contextIndices'),list)
            or inputs['count']!=len(inputs['contextIndices']) or inputs['startIndex']!=0):
        raise ValueError('CONTEXT_BATCH_SPARSE_RECIPE_INVALID')
    indices=selection_indices(report,inputs['startIndex'],inputs['count'],inputs.get('contextIndices'))
    contexts=selected(report,inputs['startIndex'],inputs['count'],inputs.get('contextIndices'))
    if len(contexts)!=len(receipts):raise ValueError('CONTEXT_BATCH_RECEIPT_COUNT_MISMATCH')
    reusable=parent_receipts(inputs['contracts']['path'],report)
    rows=[]
    for index,context,snapshot in zip(indices,contexts,receipts):
        missing=blockers(report,context)
        if snapshot is None:
            if not missing:raise ValueError('CONTEXT_BATCH_READY_CONTEXT_OMITTED')
            rows.append({'contextIndex':index,'contextIdentity':context['contextIdentity'],
                         'nativeInputAcquired':False,'reasonCodes':missing,'receipt':None});continue
        if missing:raise ValueError('CONTEXT_BATCH_UNSUPPORTED_CONTEXT_ACQUIRED')
        deployment.verify_snapshot(snapshot);receipt=deployment.read(snapshot['path']);validated_input(receipt)
        if (receipt['context']!=context or receipt['target']!='x86_64'
                or receipt['inspectionCompiler']!=inputs['clang']['resolvedPath']):
            raise ValueError('CONTEXT_BATCH_RECEIPT_CONTEXT_OR_TOOL_MISMATCH')
        rows.append({'contextIndex':index,'contextIdentity':context['contextIdentity'],
                     'nativeInputAcquired':True,'nativeInputIdentity':receipt['nativeInputIdentity'],
                     'reusedParentReceipt':snapshot==reusable.get((context['contextIdentity'],receipt['inspectionCompiler'])),
                     'reasonCodes':[],'receipt':snapshot})
    body={'schemaVersion':SCHEMA,'contractEvidenceIdentity':report['contractEvidenceIdentity'],
          'startIndex':inputs['startIndex'] if inputs.get('contextIndices') is None else None,
          'nextIndex':inputs['startIndex']+len(rows) if inputs.get('contextIndices') is None else None,
          'selectedContextIndices':indices,
          'selectionMode':'explicit-indices' if inputs.get('contextIndices') is not None else 'range',
          'totalContextCount':len(report['producerContextClosure']['compileContexts']),
          'rows':rows,'selectedContextAcquisitionComplete':bool(rows) and all(r['nativeInputAcquired'] for r in rows),
          'nativeAbiClosureVerified':False,'legalObjectDomainVerified':False,
          'semanticApproval':False,'productionAcceptanceComplete':False}
    return deployment.seal(body,'contextBatchIdentity')


def acquire(path,output,*,clang,start=0,count=4,timeout=300,reuse_paths=(),indices=None):
    from .native_deployment_prerequisites import output_path
    if type(timeout) is not int or not 1<=timeout<=86400:raise ValueError('CONTEXT_BATCH_TIMEOUT_INVALID')
    report=contracts.check(path);contexts=selected(report,start,count,indices)
    selected_indices=selection_indices(report,start,count,indices)
    compiler=str(resolve_executable(clang));reusable=parent_receipts(path,report)
    allowed={c['contextIdentity']:c for c in report['producerContextClosure']['compileContexts']}
    for receipt_path in reuse_paths:
        receipt=deployment.read(receipt_path);validated_input(receipt)
        cid=receipt['context']['contextIdentity']
        if (cid not in allowed or receipt['context']!=allowed[cid]
                or receipt['target']!='x86_64' or receipt['inspectionCompiler']!=compiler):
            raise ValueError('CONTEXT_BATCH_REUSE_CONTEXT_OR_TOOL_MISMATCH')
        key=(cid,compiler);snapshot=deployment.snapshot(receipt_path)
        if key in reusable and deployment.read(reusable[key]['path'])['nativeInputIdentity']!=receipt['nativeInputIdentity']:
            raise ValueError('CONTEXT_BATCH_CONFLICTING_REUSE_RECEIPTS')
        reusable[key]=snapshot
    root=output_path(output);root.mkdir()
    inputs={'schemaVersion':'riscv2x86.native-context-batch-inputs.v1',
            'contracts':deployment.snapshot(path),'clang':deployment.snapshot(compiler),
            'startIndex':start,'count':count,'timeoutSeconds':timeout}
    if indices is not None:
        inputs['schemaVersion']='riscv2x86.native-context-batch-inputs.v2'
        inputs['contextIndices']=indices
        inputs['count']=len(indices);inputs['startIndex']=0
    receipts=[]
    for index,context in zip(selected_indices,contexts):
        if blockers(report,context):receipts.append(None);continue
        cached=reusable.get((context['contextIdentity'],compiler))
        if cached is not None:receipts.append(cached);continue
        folder=root/('context-%06d'%index)
        native.acquire(context,compiler,folder,target='x86_64',timeout=timeout)
        receipts.append(deployment.snapshot(folder/'native-input.json'))
    inputs['receipts']=receipts
    (root/'inputs.json').write_text(json.dumps(deployment.seal(inputs,'batchInputsIdentity'),indent=2)+'\n')
    value=derive(inputs,receipts)
    (root/'result.json').write_text(json.dumps(value,indent=2)+'\n')
    check(root/'result.json');return value


def check(path):
    path=Path(path).resolve(strict=True);value=deployment.read(path);checked(value,'contextBatchIdentity')
    inputs=deployment.read(path.parent/'inputs.json');checked(inputs,'batchInputsIdentity')
    expected={'schemaVersion','contracts','clang','startIndex','count','timeoutSeconds','receipts','batchInputsIdentity'}
    if inputs['schemaVersion']=='riscv2x86.native-context-batch-inputs.v2':expected.add('contextIndices')
    if (set(inputs)!=expected or inputs['schemaVersion'] not in (
            'riscv2x86.native-context-batch-inputs.v1','riscv2x86.native-context-batch-inputs.v2')):
        raise ValueError('CONTEXT_BATCH_INPUT_SCHEMA_INVALID')
    if derive(inputs,inputs['receipts'])!=value:raise ValueError('CONTEXT_BATCH_REDERIVATION_MISMATCH')
    return value
