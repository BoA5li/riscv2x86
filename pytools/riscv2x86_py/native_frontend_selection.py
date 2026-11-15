"""Try explicitly supplied inspectors on exact native input, with no rewriting.

Success produces a normal native-input receipt. It is input acquisition only,
not source/inspection compiler semantic equivalence or translation acceptance.
"""
import json
import subprocess
from pathlib import Path
from . import native_captured_deployment as d
from . import native_contract_evidence as contracts
from . import native_context_batch as batch
from . import project_native_input as native
from .native_context_bridge import validated_input
from .project_tool_resolution import resolve_executable
from .project_acquisition import StageFailure
from .native_external_providers import checked


def acquire(contracts_path,index,candidates,output,*,timeout=300):
    if type(timeout) is not int or not 1<=timeout<=86400:raise ValueError('INSPECTOR_SELECTION_TIMEOUT_INVALID')
    report=contracts.check(contracts_path)
    selected=batch.selected(report,0,1,[index])[0]
    if batch.blockers(report,selected):raise ValueError('INSPECTOR_SELECTION_CONTEXT_NOT_INSPECTABLE')
    if not isinstance(candidates,list) or not 1<=len(candidates)<=8:raise ValueError('INSPECTOR_SELECTION_BUDGET_INVALID')
    compilers=[str(resolve_executable(p)) for p in candidates]
    if len(set(compilers))!=len(compilers):raise ValueError('INSPECTOR_SELECTION_DUPLICATE_COMPILER')
    root=Path(output).resolve();root.mkdir(parents=True,exist_ok=False)
    inputs={'contracts':d.snapshot(contracts_path),'contextIndex':index,
            'candidates':[d.snapshot(p) for p in compilers],'timeoutSeconds':timeout}
    rows=[];receipt=None
    for i,compiler in enumerate(compilers):
        folder=root/('attempt-%03d'%i)
        try:
            native.acquire(selected,compiler,folder,target='x86_64',timeout=timeout)
        except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError,StageFailure) as exc:
            rows.append({'compiler':inputs['candidates'][i],'acquired':False,
                         'error':{'type':type(exc).__name__,'detail':str(exc)},
                         'runStatus':d.snapshot(folder/'run-status.json') if (folder/'run-status.json').is_file() else None})
        else:
            file=folder/'native-input.json';value=d.read(file);validated_input(value)
            if value['context']!=selected or value['inspectionCompiler']!=compiler or value['target']!='x86_64':
                raise ValueError('INSPECTOR_SELECTION_RECEIPT_MISMATCH')
            receipt=d.snapshot(file);rows.append({'compiler':inputs['candidates'][i],
                'acquired':True,'receipt':receipt});break
        finally:
            from .project_acquisition import publish
            publish(root/'progress.json',{'inputs':inputs,'attempts':rows,
                'inputAcquired':receipt is not None,'semanticApproval':False,'productionAcceptanceComplete':False})
    value=d.seal({'schemaVersion':'riscv2x86.native-inspector-selection.v1','inputs':inputs,
        'attempts':rows,'selectedReceipt':receipt,'inputAcquired':receipt is not None,
        'compilerEquivalenceVerified':False,'semanticApproval':False,'productionAcceptanceComplete':False},'inspectorSelectionIdentity')
    (root/'result.json').write_text(json.dumps(value,indent=2)+'\n');check(root/'result.json');return value


def check(path):
    value=d.read(path);checked(value,'inspectorSelectionIdentity')
    if value['schemaVersion']!='riscv2x86.native-inspector-selection.v1':raise ValueError('INSPECTOR_SELECTION_SCHEMA_INVALID')
    inputs=value['inputs'];d.verify_snapshot(inputs['contracts'])
    report=contracts.check(inputs['contracts']['path'])
    context=batch.selected(report,0,1,[inputs['contextIndex']])[0]
    if batch.blockers(report,context):raise ValueError('INSPECTOR_SELECTION_CONTEXT_NOT_INSPECTABLE')
    if (type(inputs['timeoutSeconds']) is not int or not 1<=inputs['timeoutSeconds']<=86400
            or not 1<=len(inputs['candidates'])<=8):raise ValueError('INSPECTOR_SELECTION_BUDGET_INVALID')
    for tool in inputs['candidates']:d.verify_snapshot(tool)
    if len({r['resolvedPath'] for r in inputs['candidates']})!=len(inputs['candidates']):
        raise ValueError('INSPECTOR_SELECTION_DUPLICATE_COMPILER')
    rows=value['attempts'];chosen=None
    if not rows or len(rows)>len(inputs['candidates']):raise ValueError('INSPECTOR_SELECTION_ATTEMPTS_INVALID')
    for i,row in enumerate(rows):
        if row['compiler']!=inputs['candidates'][i] or type(row['acquired']) is not bool:
            raise ValueError('INSPECTOR_SELECTION_ATTEMPT_TOOL_MISMATCH')
        if row['acquired']:
            if i!=len(rows)-1:raise ValueError('INSPECTOR_SELECTION_ATTEMPT_AFTER_SUCCESS')
            chosen=row['receipt'];d.verify_snapshot(chosen)
            receipt=d.read(chosen['path']);validated_input(receipt)
            if (receipt['context']!=context or receipt['inspectionCompiler']!=row['compiler']['resolvedPath']
                    or receipt['target']!='x86_64'):raise ValueError('INSPECTOR_SELECTION_RECEIPT_MISMATCH')
        elif row['runStatus'] is not None:
            d.verify_snapshot(row['runStatus'])
            if d.read(row['runStatus']['path'])['status']!='failed':raise ValueError('INSPECTOR_SELECTION_FALSE_FAILURE')
    if (value['selectedReceipt']!=chosen or value['inputAcquired'] is not (chosen is not None)
            or (chosen is None and len(rows)!=len(inputs['candidates']))
            or any(value[k] is not False for k in ('compilerEquivalenceVerified','semanticApproval','productionAcceptanceComplete'))):
        raise ValueError('INSPECTOR_SELECTION_REDERIVATION_MISMATCH')
    return value
