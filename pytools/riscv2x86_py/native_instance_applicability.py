"""Conservative source-guard analysis, NOT canonical machine-code coverage.

Uses declaration-bound AST paths, typed expressions and recorded compiler
constant-query contracts. No project names, threshold values or source lines
select a rule. Independent candidate audit remains a prerequisite for relying
on the recorded contracts. Machine elimination/execution is never inferred.
"""
from copy import deepcopy
import json
from pathlib import Path
from . import native_captured_deployment as d
from . import project_native_binding as binding
from .native_context_bridge import validated_input
from .native_external_providers import checked
from .compiler_native_instance_binding import _nodes
from .native_integer_contracts import term


def constant(node):
    op=node['op'];args=node.get('arguments',[])
    if op=='constant':return node['value']
    if op=='integer-conversion':
        value=constant(node['argument']);typ=node['type']
        if not typ['signed']:return value % (1<<typ['bits'])
        if not -(1<<(typ['bits']-1))<=value<(1<<(typ['bits']-1)):raise ValueError('SIGNED_RANGE')
        return value
    if op=='!':return int(not constant(args[0]))
    if op=='&&':return int(bool(constant(args[0])) and bool(constant(args[1])))
    if op=='||':return int(bool(constant(args[0])) or bool(constant(args[1])))
    left,right=map(constant,args) if len(args)==2 else (None,None)
    if op in ('==','!=','<','<=','>','>='):
        return int({'==':left==right,'!=':left!=right,'<':left<right,'<=':left<=right,
                    '>':left>right,'>=':left>=right}[op])
    raise ValueError('NON_CONSTANT_OR_UNSUPPORTED')


def guard_value(node,path,proofs,model):
    def substitute(value,current):
        if value.get('kind')=='CallExpr':
            proof=proofs.get(tuple(current));contract=proof.get('contract',{}) if proof else {}
            if (contract.get('operation')!='compiler-integer-literal-constant-query'
                    or type(contract.get('result')) is not int
                    or contract.get('result')!=1
                    or contract.get('requiredWitness')!='source-and-target-compiler-static-assert'):
                raise ValueError('COMPILER_QUERY_WITNESS_REQUIRED')
            # This is a conditional analysis under the RECORDED contract, not
            # verification of the witness or permission to change the program.
            return {'kind':'IntegerLiteral','type':value['type'],'value':'1'}
        result=deepcopy(value)
        result['inner']=[substitute(child,[*current,i]) for i,child in enumerate(value.get('inner',[]))]
        return result
    return bool(constant(term(substitute(node,path),model,lambda ref:ref)))


def derive(candidate):
    checked(candidate,'candidateIdentity');bundle=d.read(candidate['bindingBundlePath'])
    if d.digest(candidate['bindingBundlePath'])!=candidate['bindingBundleDigest']:
        raise ValueError('APPLICABILITY_BINDING_CHANGED')
    records,_=binding.validate_artifacts(bundle)
    receipt=d.read(bundle['nativeInputReceiptPath']);artifacts=validated_input(receipt)
    if candidate['bindingBundleIdentity']!=bundle['bindingBundleIdentity']:
        raise ValueError('APPLICABILITY_CANDIDATE_BINDING_MISMATCH')
    ast=artifacts['canonicalAst'];nodes={tuple(p):n for n,p,_ in _nodes(ast)}
    proofs={}
    for proof in candidate['builtinProofs']:
        path=tuple(proof['sourceCallAstPath'])
        if path in proofs:raise ValueError('APPLICABILITY_DUPLICATE_BUILTIN_CONTRACT')
        proofs[path]=proof
    edits={e['instanceBindingIdentity']:e for e in candidate['edits']}
    if len(edits)!=len(candidate['edits']):raise ValueError('APPLICABILITY_DUPLICATE_INSTANCE')
    rows=[];model=receipt['analysisInput']['dataModels']['native']
    for row in records['records']:
        iid=row['instanceBindingIdentity'];path=row['astPath'];guards=[];excluded=False
        if iid not in edits:continue
        for length in range(len(path)):
            prefix=path[:length];parent=nodes[tuple(prefix)]
            if parent.get('kind')!='IfStmt':continue
            children=parent.get('inner',[]);branch=path[length]
            if parent.get('hasInit') or parent.get('hasVar') or len(children) not in (2,3) or branch not in (1,2):continue
            try:
                truth=guard_value(children[0],[*prefix,0],proofs,model)
                taken=truth if branch==1 else not truth
                guards.append({'ifAstPath':prefix,'branch':branch,'constantConditionValue':truth,
                               'branchExcludedUnderRecordedContracts':not taken})
                excluded|=not taken
            except (ValueError,KeyError,TypeError):
                guards.append({'ifAstPath':prefix,'branch':branch,'constantConditionValue':None,
                               'branchExcludedUnderRecordedContracts':False})
        rows.append({'instanceBindingIdentity':iid,'sourceAstPath':path,'guards':guards,
            'sourceGuardClassification':'excluded-under-recorded-contracts' if excluded else 'unknown',
            'canonicalMachineDisposition':'unknown','canonicalInstructionExecutionVerified':False})
    if set(edits)!={r['instanceBindingIdentity'] for r in rows}:
        raise ValueError('APPLICABILITY_EDIT_INSTANCE_NOT_BOUND')
    return d.seal({'schemaVersion':'riscv2x86.native-instance-applicability.v1',
        'candidateIdentity':candidate['candidateIdentity'],'expandedTranslatedInstanceCount':len(rows),
        'rows':rows,'requiresIndependentCandidateAudit':True,
        'scope':'conditional-source-guards-not-machine-elimination-or-execution',
        'semanticApproval':False,'productionAcceptanceComplete':False},'applicabilityIdentity')


def acquire(candidate_path,output):
    root=Path(output).resolve();root.mkdir(parents=True,exist_ok=False)
    inputs=d.seal({'schemaVersion':'riscv2x86.native-instance-applicability-inputs.v1',
                  'candidate':d.snapshot(candidate_path)},'applicabilityInputsIdentity')
    value=derive(d.read(candidate_path))
    (root/'inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
    (root/'result.json').write_text(json.dumps(value,indent=2)+'\n');return value


def check(path):
    value=d.read(path);checked(value,'applicabilityIdentity')
    inputs=d.read(Path(path).resolve().parent/'inputs.json');checked(inputs,'applicabilityInputsIdentity')
    d.verify_snapshot(inputs['candidate'])
    if value!=derive(d.read(inputs['candidate']['path'])):raise ValueError('APPLICABILITY_REDERIVATION_MISMATCH')
    return value
