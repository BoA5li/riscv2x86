"""Resume bounded acquisition of every eligible captured C compile context.

Only existing checked native-context-batch receipts are consumed/produced.
Blocked assembly/origin domains stay explicit. Acquisition is not ABI proof.
"""
import json
from pathlib import Path
from . import native_captured_deployment as d
from . import native_contract_evidence as contracts
from . import native_context_batch as batch
from .native_external_providers import checked
from .project_tool_resolution import resolve_executable

SCHEMA='riscv2x86.native-context-completion.v1'


def pending(report,path,compiler,batch_paths):
    contexts=report['producerContextClosure']['compileContexts']
    known={c['contextIdentity']:c for c in contexts};acquired={};seen=set()
    def add(snapshot):
        d.verify_snapshot(snapshot);receipt=d.read(snapshot['path']);batch.validated_input(receipt)
        cid=receipt['context']['contextIdentity']
        if cid not in known:return
        if receipt['context']!=known[cid] or receipt['target']!='x86_64':
            raise ValueError('CONTEXT_COMPLETION_RECEIPT_CONTEXT_MISMATCH')
        if receipt['inspectionCompiler']!=compiler:
            raise ValueError('CONTEXT_COMPLETION_INSPECTION_COMPILER_MISMATCH')
        if cid in acquired and acquired[cid]!=receipt['nativeInputIdentity']:
            raise ValueError('CONTEXT_COMPLETION_CONFLICTING_RECEIPTS')
        acquired[cid]=receipt['nativeInputIdentity']
    for snapshot in batch.parent_receipts(path,report).values():add(snapshot)
    for file in batch_paths:
        value=batch.check(file)
        if value['contractEvidenceIdentity']!=report['contractEvidenceIdentity']:
            raise ValueError('CONTEXT_COMPLETION_BATCH_PARENT_MISMATCH')
        if value['contextBatchIdentity'] in seen:raise ValueError('CONTEXT_COMPLETION_DUPLICATE_BATCH')
        recipe=d.read(Path(file).resolve().parent/'inputs.json')
        if recipe['clang']['resolvedPath']!=compiler:
            raise ValueError('CONTEXT_COMPLETION_INSPECTION_COMPILER_MISMATCH')
        seen.add(value['contextBatchIdentity'])
        for row in value['rows']:
            if row['nativeInputAcquired']:add(row['receipt'])
    blocked=[];needed=[]
    for i,context in enumerate(contexts):
        if context['contextIdentity'] in acquired:continue
        reasons=batch.blockers(report,context)
        if reasons:blocked.append({'contextIndex':i,'contextIdentity':context['contextIdentity'],'reasonCodes':reasons})
        else:needed.append(i)
    return acquired,needed,blocked


def base(path):
    if d.read(path).get('schemaVersion')!='riscv2x86.native-contract-evidence.v3':
        raise ValueError('CONTEXT_COMPLETION_BASE_V3_REQUIRED')
    return contracts.check(path)


def derive(inputs):
    if (set(inputs)!={'schemaVersion','contracts','clang','previousBatches','newBatches','maxContexts',
                      'batchSize','timeoutSeconds','completionInputsIdentity'}
            or inputs['schemaVersion']!='riscv2x86.native-context-completion-inputs.v1'):
        raise ValueError('CONTEXT_COMPLETION_INPUT_SCHEMA_INVALID')
    for name,upper in (('maxContexts',10000),('batchSize',64),('timeoutSeconds',86400)):
        if type(inputs[name]) is not int or not 1<=inputs[name]<=upper:
            raise ValueError('CONTEXT_COMPLETION_BUDGET_INVALID:'+name)
    for name in ('contracts','clang'):d.verify_snapshot(inputs[name])
    for name in ('previousBatches','newBatches'):
        if not isinstance(inputs[name],list):raise ValueError('CONTEXT_COMPLETION_BATCH_LIST_REQUIRED')
        for snap in inputs[name]:d.verify_snapshot(snap)
    path=inputs['contracts']['path'];report=base(path);compiler=inputs['clang']['resolvedPath']
    old=[s['path'] for s in inputs['previousBatches']];new=[s['path'] for s in inputs['newBatches']]
    _,needed,_=pending(report,path,compiler,old)
    selected=needed[:inputs['maxContexts']]
    chunks=[selected[i:i+inputs['batchSize']] for i in range(0,len(selected),inputs['batchSize'])]
    if len(chunks)!=len(new):raise ValueError('CONTEXT_COMPLETION_BATCH_COUNT_MISMATCH')
    for file,indices in zip(new,chunks):
        value=batch.check(file)
        if value['selectedContextIndices']!=indices or not value['selectedContextAcquisitionComplete']:
            raise ValueError('CONTEXT_COMPLETION_SELECTED_INPUTS_INCOMPLETE')
        recipe=d.read(Path(file).resolve().parent/'inputs.json')
        if recipe['clang']!=inputs['clang'] or recipe['timeoutSeconds']!=inputs['timeoutSeconds']:
            raise ValueError('CONTEXT_COMPLETION_NEW_RECIPE_MISMATCH')
    acquired,remaining,blocked=pending(report,path,compiler,old+new)
    total=len(report['producerContextClosure']['compileContexts'])
    return d.seal({'schemaVersion':SCHEMA,'contractEvidenceIdentity':report['contractEvidenceIdentity'],
        'completionInputsIdentity':inputs['completionInputsIdentity'],'totalContextCount':total,
        'acquiredContextCount':len(acquired),'newlySelectedContextIndices':selected,
        'remainingEligibleContextIndices':remaining,'blockedContexts':blocked,
        'allCapturedCContextsAcquired':bool(total) and len(acquired)==total,
        'batchResultPaths':old+new,'nativeAbiClosureVerified':False,'legalObjectDomainVerified':False,
        'semanticApproval':False,'productionAcceptanceComplete':False},'contextCompletionIdentity')


def acquire(path,batch_paths,output,*,clang,max_contexts=64,batch_size=16,timeout=300):
    from .native_deployment_prerequisites import output_path
    for value,upper in ((max_contexts,10000),(batch_size,64),(timeout,86400)):
        if type(value) is not int or not 1<=value<=upper:raise ValueError('CONTEXT_COMPLETION_BUDGET_INVALID')
    report=base(path);compiler=str(resolve_executable(clang))
    _,needed,_=pending(report,path,compiler,batch_paths)
    snapshots=[d.snapshot(p) for p in batch_paths]
    inputs={'schemaVersion':'riscv2x86.native-context-completion-inputs.v1',
        'contracts':d.snapshot(path),'clang':d.snapshot(compiler),'previousBatches':snapshots,
        'newBatches':[],'maxContexts':max_contexts,'batchSize':batch_size,'timeoutSeconds':timeout}
    root=output_path(output);root.mkdir();selected=needed[:max_contexts]
    for start in range(0,len(selected),batch_size):
        folder=root/('batch-%06d'%(start//batch_size))
        batch.acquire(path,folder,clang=compiler,indices=selected[start:start+batch_size],timeout=timeout)
        inputs['newBatches'].append(d.snapshot(folder/'result.json'))
        # A crash leaves independently checkable completed child batches. A
        # later call can reuse these via --context-batch; no status is forged.
        print(json.dumps({'completedBatchCount':len(inputs['newBatches']),
                          'selectedContextCount':len(selected),'lastBatch':str(folder/'result.json')}),flush=True)
    inputs=d.seal(inputs,'completionInputsIdentity')
    value=derive(inputs)
    (root/'inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
    (root/'result.json').write_text(json.dumps(value,indent=2)+'\n')
    check(root/'result.json');return value


def check(path):
    path=Path(path).resolve(strict=True);value=d.read(path);checked(value,'contextCompletionIdentity')
    inputs=d.read(path.parent/'inputs.json');checked(inputs,'completionInputsIdentity')
    if derive(inputs)!=value:raise ValueError('CONTEXT_COMPLETION_REDERIVATION_MISMATCH')
    return value
