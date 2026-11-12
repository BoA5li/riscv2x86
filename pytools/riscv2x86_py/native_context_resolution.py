"""Consume checked producer receipts with the existing declaration/call consumers.

A compiler linker name + exact producer ELF definition is a provider candidate,
not an assertion of archive extraction, interposition, ABI or effects. All
unresolved domains remain in the worklist; local traversal never excludes them.
"""
import json
from collections import Counter
from pathlib import Path

from . import native_captured_deployment as deployment
from . import native_contract_evidence as contracts
from . import native_context_batch as batch
from .native_context_bridge import validated_input
from .native_elf_runtime import parse
from .native_external_providers import checked
from .native_program_scope import local_scope
from .project_build_records import identity

SCHEMA = 'riscv2x86.native-context-resolution.v1'


def elf_input(snapshot):
    deployment.verify_snapshot(snapshot)
    raw = Path(snapshot['path']).read_bytes()
    from .native_dependency_evidence import bytes_digest
    if bytes_digest(raw) != snapshot['digest']:
        raise ValueError('CONTEXT_RESOLUTION_ELF_CHANGED_DURING_READ')
    elf = parse(raw)
    deployment.verify_snapshot(snapshot)
    return elf


def consume(units, roots):
    """Resolve compiler-declared direct calls to context-bound ELF candidates.

    Pure input relation consumer shared by acquisition and replay. units contain
    only validated ASTs / checked ELF producers, never user approval flags.
    """
    index = {}; unit_by_id = {u['unitIdentity']:u for u in units}
    if len(unit_by_id) != len(units):
        raise ValueError('CONTEXT_RESOLUTION_DUPLICATE_UNIT')
    for unit in units:
        if unit['machine'] != 62:
            raise ValueError('CONTEXT_RESOLUTION_X86_64_REQUIRED')
        graph = unit['graph']
        for definition in graph['functionDefinitions']:
            label = definition.get('linkerName')
            if not label or definition.get('storageClass') == 'static':
                continue
            symbols = [s for s in unit['symbols'] if s['name']==label
                       and s['defined'] and s['binding'] in (1,2,10)]
            # STT_NOTYPE, IFUNC, data and weak/unique bindings require their
            # own contracts. Do not invent function ABI facts for them.
            for symbol in symbols:
                key = (unit['unitIdentity'], tuple(definition['astPath']),
                       symbol['tableIndex'], symbol['entryIndex'])
                index.setdefault(label, {})[key] = {
                    'unitIdentity':unit['unitIdentity'], 'object':unit['object'],
                    'functionEvidenceIdentity':definition['functionEvidenceIdentity'],
                    'astPath':definition['astPath'], 'signature':definition['signature'],
                    'symbol':symbol,
                    'inspectionDefinitionAndStrongFunctionSymbolJoined':
                        symbol['binding']==1 and symbol['type']==2
                        and 0<symbol['sectionIndex']<0xff00,
                    'actualLinkSelectionVerified':False,'nativeAbiContractVerified':False}
    calls = []; candidate_units = Counter(); scopes = {}
    for unit in units:
        uid = unit['unitIdentity']
        scope_roots = roots.get(uid, [])
        scopes[uid] = local_scope(unit['graph'], scope_roots, 'bound-existing-local-roots')
        visited = set(scopes[uid]['visitedCallEvidenceIdentities'])
        for call in unit['graph']['callSites']:
            kind = call['resolution']['classification']; decl = call['localDeclaration']
            providers = []; reason = []
            if kind == 'compiler-builtin':
                reason = call['resolution'].get('semanticObligations', [])
            elif kind != 'direct':
                reason = ['INDIRECT_TARGET_SET_AND_CALL_CONTRACT_REQUIRED']
            elif call['definitionIncluded']:
                reason = ['LOCAL_FUNCTION_MACHINE_ABI_AND_EFFECTS_REQUIRED']
            elif not decl or not decl.get('linkerName'):
                reason = ['COMPILER_LINKER_NAME_REQUIRED']
            elif decl.get('internalLinkage'):
                reason = ['INTERNAL_DECLARATION_LOCAL_DEFINITION_REQUIRED']
            else:
                providers = list(index.get(decl['linkerName'], {}).values())
                providers = [dict(p, inspectionSignatureShapeEqual=p['signature']==decl['signature'])
                             for p in providers]
                if not providers:
                    reason = ['EXTERNAL_PROVIDER_CONTEXT_OR_ASSEMBLY_CONTRACT_REQUIRED']
                elif len(providers)!=1:
                    reason = ['MULTIPLE_PROVIDER_CANDIDATES_ACTUAL_SELECTION_REQUIRED']
                elif not providers[0]['inspectionSignatureShapeEqual']:
                    reason = ['INSPECTION_SIGNATURE_DIFFERENCE_REQUIRES_TYPED_RELATION']
                elif not providers[0]['inspectionDefinitionAndStrongFunctionSymbolJoined']:
                    reason = ['SYMBOL_KIND_OR_BINDING_CONTRACT_REQUIRED']
                else:
                    reason = ['ACTUAL_LINK_SELECTION_NATIVE_ABI_AND_EFFECTS_REQUIRED']
                if call['callSiteEvidenceIdentity'] in visited:
                    candidate_units.update(p['unitIdentity'] for p in providers)
            body = {'unitIdentity':uid,'callSiteEvidenceIdentity':call['callSiteEvidenceIdentity'],
                    'classification':kind,'inKnownLocalScope':call['callSiteEvidenceIdentity'] in visited,
                    'declaration':decl,'providerCandidates':providers,'reasonCodes':reason,
                    'actualLinkSelectionVerified':False,'nativeAbiContractVerified':False}
            calls.append(dict(body, contextCallJoinIdentity=identity(body)))
    return {'callJoins':calls,'localScopes':scopes,
            'knownLocalScopeProviderUnitPriorities':[
                {'unitIdentity':uid,'relatedCallSiteCount':count}
                for uid,count in sorted(candidate_units.items(),key=lambda x:(-x[1],x[0]))],
            'callReasonCounts':dict(sorted(Counter(c for row in calls for c in row['reasonCodes']).items())),
            'uniqueStrongFunctionCandidateCallCount':sum(
                len(r['providerCandidates'])==1
                and r['providerCandidates'][0]['inspectionDefinitionAndStrongFunctionSymbolJoined']
                and r['providerCandidates'][0]['inspectionSignatureShapeEqual'] for r in calls),
            'unvisitedFunctionsProvedUnreachable':False,'fullProgramScopeComplete':False}


def derive(contracts_path, batch_paths):
    # Resolution inputs must be a base report. Reject a report already
    # consuming resolutions before recursive checking; never create cycles.
    if deployment.read(contracts_path).get('schemaVersion')!='riscv2x86.native-contract-evidence.v3':
        raise ValueError('CONTEXT_RESOLUTION_BASE_V3_REPORT_REQUIRED')
    base_inputs=deployment.read(Path(contracts_path).resolve().parent/'inputs.json')
    if base_inputs.get('contextResolution') is not None:
        raise ValueError('CONTEXT_RESOLUTION_RECURSIVE_PARENT_FORBIDDEN')
    report = contracts.check(contracts_path)
    closure = report['producerContextClosure']
    contexts = {c['contextIdentity']:c for c in closure['compileContexts']}
    receipts = {}; checked_batches = []
    def add(snapshot):
        deployment.verify_snapshot(snapshot)
        receipt = deployment.read(snapshot['path']); artifacts = validated_input(receipt)
        cid = receipt['context']['contextIdentity']
        if cid not in contexts: return
        if receipt['context'] != contexts[cid] or receipt['target']!='x86_64':
            raise ValueError('CONTEXT_RESOLUTION_RECEIPT_CONTEXT_MISMATCH')
        if cid in receipts and receipts[cid][0]['nativeInputIdentity']!=receipt['nativeInputIdentity']:
            raise ValueError('CONTEXT_RESOLUTION_CONFLICTING_CONTEXT_RECEIPTS')
        receipts[cid]=(receipt, artifacts, snapshot)
    for snapshot in batch.parent_receipts(contracts_path, report).values(): add(snapshot)
    seen_batches=set()
    for path in batch_paths:
        value = batch.check(path)
        if value['contractEvidenceIdentity']!=report['contractEvidenceIdentity']:
            raise ValueError('CONTEXT_RESOLUTION_BATCH_PARENT_MISMATCH')
        if value['contextBatchIdentity'] in seen_batches:
            raise ValueError('CONTEXT_RESOLUTION_DUPLICATE_BATCH')
        seen_batches.add(value['contextBatchIdentity']);checked_batches.append(value['contextBatchIdentity'])
        for row in value['rows']:
            if row['nativeInputAcquired']: add(row['receipt'])
    units=[]; work=[]; object_snapshots=[]
    original = closure['candidateSubstitution']['originalObject']
    candidate = closure['candidateSubstitution']['candidateObject']
    for node in closure['nodes']:
        if node['kind']!='object': continue
        snapshot=node['file'];object_snapshots.append(snapshot)
        # Never use the replaced original object's AST as the deployed
        # candidate definition. Both canonical output and bytes must match.
        replaced=all(snapshot[k]==original[k] for k in ('resolvedPath','digest'))
        elf=elf_input(candidate if replaced else snapshot)
        if elf['machine']!=62 or elf['elfType']!=1:
            raise ValueError('CONTEXT_RESOLUTION_OBJECT_MACHINE_OR_TYPE_MISMATCH')
        cid=node['compileContextIdentity']
        if replaced:
            graph=report['graphs']['candidate'];ast_source='audited-candidate'
            bound_receipt=None;object_snapshots.append(candidate)
        elif cid in receipts:
            receipt, artifacts, bound_receipt=receipts[cid]
            graph=contracts.ast_graph(artifacts['canonicalAst'],receipt['canonicalAstIdentity'])
            ast_source=receipt['nativeInputIdentity']
        else:
            reason=('CAPTURED_PRODUCER_CONTEXT_REQUIRED' if not node['producerBound'] else
                    'ASSEMBLY_INTERFACE_CONTRACT_REQUIRED' if cid is None else 'CONTEXT_RECEIPT_REQUIRED')
            work.append({'nodeIdentity':node['nodeIdentity'],'contextIdentity':cid,
                'reasonCode':reason,
                'contextIndex':next((i for i,c in enumerate(closure['compileContexts']) if c['contextIdentity']==cid),None),
                'object':snapshot,'interface':node.get('assemblyInterface'),
                'definedSymbols':[s for s in elf['staticSymbols']
                    if s['defined'] and s['name'] and s['binding'] in (1,2,10)]})
            continue
        body={'nodeIdentity':node['nodeIdentity'],'contextIdentity':cid,'astSourceIdentity':ast_source,
              'receipt':bound_receipt,'object':candidate if replaced else snapshot,
              'machine':elf['machine'],'symbols':elf['staticSymbols'],'graph':graph,
              'candidateSubstitutionApplied':replaced}
        units.append(dict(body,unitIdentity=identity(body)))
    roots={}
    for unit in units:
        if unit['candidateSubstitutionApplied']:
            roots[unit['unitIdentity']]=report['programScope']['localScopes']['candidate']['rootAstPaths']
        else:
            for index,entry in enumerate(report['entryContexts']):
                if unit['contextIdentity']==entry['context']['contextIdentity']:
                    roots[unit['unitIdentity']]=report['programScope']['localScopes']['entry:'+str(index)]['rootAstPaths']
    resolution=consume(units,roots)
    requests={}
    for row in resolution['callJoins']:
        declaration=row['declaration']
        if (row['inKnownLocalScope'] and row['classification']=='direct'
                and declaration and declaration.get('linkerName')
                and not declaration.get('internalLinkage')):
            requests.setdefault(declaration['linkerName'],[]).append(row['contextCallJoinIdentity'])
    priorities={}
    for row in work:
        requested=sorted({request for symbol in row.get('definedSymbols',[])
                          for request in requests.get(symbol['name'],[])})
        row['relatedKnownLocalCallJoinIdentities']=requested
        row['actualLinkSelectionVerified']=False
        if requested and row['contextIndex'] is not None:
            priorities.setdefault(row['contextIndex'],set()).update(requested)
    resolution['suggestedContextIndices']=[index for index,_ in
        sorted(priorities.items(),key=lambda item:(-len(item[1]),item[0]))]
    resolution['suggestedContextIndicesAreCompleteScope']=False
    # Acquisition priority is conservative: no omission is interpreted as
    # unreachable. Unknown archive/assembly domains stay explicit.
    work.extend({'nodeIdentity':g['nodeIdentity'],'reasonCode':g['reasonCode'],
                 'details':g} for g in closure['inputGaps']
                if g['reasonCode']!='ASSEMBLY_CONTEXT_CONTRACT_REQUIRED')
    for snapshot in object_snapshots:deployment.verify_snapshot(snapshot)
    body={'schemaVersion':SCHEMA,'contractEvidenceIdentity':report['contractEvidenceIdentity'],
          'deploymentPlanIdentity':report['deploymentPlanIdentity'],
          'contextBatchIdentities':checked_batches,'consumedContextCount':len(receipts),
          'producerCompileContextCount':len(contexts),'units':units,
          'resolution':resolution,'remainingWork':work,
          'remainingWorkReasonCounts':dict(sorted(Counter(w['reasonCode'] for w in work).items())),
          'nativeAbiClosureVerified':False,'legalObjectDomainVerified':False,
          'candidateInstructionExecutionCoverageVerified':False,
          'semanticApproval':False,'productionAcceptanceComplete':False}
    return deployment.seal(body,'contextResolutionIdentity')


def acquire(contracts_path,batch_paths,output):
    from .native_deployment_prerequisites import output_path
    if not batch_paths:raise ValueError('CONTEXT_RESOLUTION_BATCH_REQUIRED')
    inputs={'schemaVersion':'riscv2x86.native-context-resolution-inputs.v1',
            'contracts':deployment.snapshot(contracts_path),
            'batches':[deployment.snapshot(p) for p in batch_paths]}
    result=derive(contracts_path,batch_paths)
    for snapshot in [inputs['contracts'],*inputs['batches']]:deployment.verify_snapshot(snapshot)
    root=output_path(output);root.mkdir()
    (root/'inputs.json').write_text(json.dumps(deployment.seal(inputs,'resolutionInputsIdentity'),indent=2)+'\n')
    (root/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    check(root/'result.json');return result


def check(path):
    path=Path(path).resolve(strict=True)
    stored=deployment.read(path);checked(stored,'contextResolutionIdentity')
    inputs=deployment.read(path.parent/'inputs.json');checked(inputs,'resolutionInputsIdentity')
    if (stored.get('schemaVersion')!=SCHEMA or set(inputs)!={
            'schemaVersion','contracts','batches','resolutionInputsIdentity'}
            or inputs['schemaVersion']!='riscv2x86.native-context-resolution-inputs.v1'
            or not inputs['batches']):
        raise ValueError('CONTEXT_RESOLUTION_INPUT_SCHEMA_INVALID')
    for snapshot in [inputs['contracts'],*inputs['batches']]:deployment.verify_snapshot(snapshot)
    fresh=derive(inputs['contracts']['path'],[s['path'] for s in inputs['batches']])
    if fresh!=stored:raise ValueError('CONTEXT_RESOLUTION_REDERIVATION_MISMATCH')
    return stored
