"""Context-bound declaration/call/type evidence for the existing proof consumers.

Physical offsets are transported only across the already byte-verified edit
map. A declaration match is not a native ABI or whole-function proof.
"""
from pathlib import Path

from .compiler_native_instance_binding import _nodes
from .compiler_native_calls import resolve
from .function_abi_machine_join import join_function_abi_machine
from .project_build_records import identity
from . import native_context_bridge as bridge
from . import native_captured_deployment as deployment
from . import project_native_input as native
from .l2_dimensions import L2DimensionStatus as Status


def transport(offset, edits):
    if type(offset) is not int: return None
    shift = 0
    for edit in edits:
        start, stop = edit['sourceRange']
        if start <= offset < stop: return None
        if stop <= offset: shift += len(edit['replacement'].encode('utf-8'))-(stop-start)
    return offset+shift


def stripped_type(value):
    """Discard AST-local reference IDs only, not semantic qualifiers/types."""
    if isinstance(value, dict):
        return {k:stripped_type(v) for k,v in value.items() if k != 'typeAliasDeclId'}
    if isinstance(value, list): return [stripped_type(v) for v in value]
    return value


def signature(node):
    return {'type': stripped_type(node.get('type')), 'variadic': node.get('variadic',False),
            'parameters': [stripped_type(n.get('type')) for n in node.get('inner',[])
                           if n.get('kind')=='ParmVarDecl'],
            'attributes': sorted(n['kind'] for n in node.get('inner',[]) if n.get('kind','').endswith('Attr'))}


def function_correspondence(source, target, edits, source_id, target_id):
    targets = [(n,p) for n,p,_ in _nodes(target) if n.get('kind')=='FunctionDecl']
    rows = []
    for node, path, _ in _nodes(source):
        if node.get('kind') != 'FunctionDecl': continue
        start = node.get('range',{}).get('begin',{}).get('offset')
        end = node.get('range',{}).get('end',{}).get('offset')
        begin, stop = transport(start,edits), transport(end,edits)
        matches = [(n,p) for n,p in targets if begin is not None and stop is not None
                   and n.get('range',{}).get('begin',{}).get('offset')==begin
                   and n.get('range',{}).get('end',{}).get('offset')==stop
                   and n.get('name')==node.get('name')]
        match = matches[0] if len(matches)==1 else None
        body = {'sourceAstIdentity':source_id, 'sourceAstPath':path,
                'sourceDeclarationId':node.get('id'), 'name':node.get('name'),
                'sourceSignature':signature(node), 'candidateAstIdentity':target_id,
                'candidateAstPath':match[1] if match else None,
                'candidateSignature':signature(match[0]) if match else None,
                'sourceRangeTransported':[begin,stop],
                'byteLineageDeclarationCorrespondenceVerified':match is not None,
                'inspectionSignatureShapeEqual':match is not None and signature(node)==signature(match[0]),
                'nativeAbiContractVerified':False,
                'reasonCodes':[] if match else ['DECLARATION_POSITION_MAPPING_NOT_UNIQUE_OR_UNAVAILABLE']}
        rows.append(dict(body,declarationJoinIdentity=identity(body)))
    return rows


def ast_graph(ast, ast_identity):
    nodes = _nodes(ast); by_id = {n['id']:(n,p) for n,p,_ in nodes if 'id' in n}
    types = []; calls = []; definitions = []; objects = []
    redeclarations = {}
    for node, path, _ in nodes:
        if node.get('kind') == 'FunctionDecl' and node.get('previousDecl'):
            a, b = node['id'], node['previousDecl']
            redeclarations.setdefault(a,set()).add(b)
            redeclarations.setdefault(b,set()).add(a)
    for node, path, enclosing in nodes:
        kind = node.get('kind','')
        key = {'astIdentity':ast_identity,'astPath':path,'declarationId':node.get('id')}
        if kind in ('TypedefDecl','TypeAliasDecl','RecordDecl','EnumDecl'):
            # Keep all compiler-emitted type nodes/fields. Offsets and native
            # ABI are NOT fabricated when the inspection AST has none.
            body = {**key,'kind':kind,'node':node,'nativeLayoutVerified':False}
            types.append(dict(body,typeEvidenceIdentity=identity(body)))
        if kind == 'FunctionDecl' and any(n.get('kind')=='CompoundStmt' for n in node.get('inner',[])):
            required = join_function_abi_machine(declaration=None,machine=None,cfg=None,frame=None)
            body = {**key,'name':node.get('name'),'signature':signature(node),
                    'machineJoinComplete':required.complete,
                    'machineJoinMissingFacts':list(required.missing_fact_codes)}
            definitions.append(dict(body,functionEvidenceIdentity=identity(body)))
        if kind == 'CallExpr':
            resolution = resolve(node)
            ref = resolution['declaration']; decl = by_id.get(ref['id']) if ref else None
            chain=set(); pending=[ref['id']] if ref else []
            while pending:
                item=pending.pop()
                if item in chain: continue
                chain.add(item); pending.extend(redeclarations.get(item,()))
            bodies=[p for n,p,_ in nodes if n.get('kind')=='FunctionDecl' and n.get('id') in chain
                    and any(x.get('kind')=='CompoundStmt' for x in n.get('inner',[]))]
            body = {**key,'functionAstPath':enclosing,'resolution':resolution,
                    'redeclarationIds':sorted(chain),'definitionAstPaths':bodies,
                    'localDeclarationAstPath':decl[1] if decl else None,
                    'localDeclaration':{'name':decl[0].get('name'),'id':decl[0].get('id'),
                        'previousDecl':decl[0].get('previousDecl'),'signature':signature(decl[0])} if decl else None,
                    'definitionIncluded':len(bodies)==1,
                    'nativeAbiContractVerified':False,'actualExecutionVerified':False}
            calls.append(dict(body,callSiteEvidenceIdentity=identity(body)))
        if kind == 'VarDecl':
            initializer = [n for n in node.get('inner',[]) if not n.get('kind','').endswith('Attr')]
            body = {**key,'name':node.get('name'),'functionAstPath':enclosing,'type':node.get('type'),
                    'storageClass':node.get('storageClass'), 'initializerAst':initializer,
                    'initializationSemanticsVerified':False,'lifetimeVerified':False,
                    'boundsVerified':False,'aliasContractVerified':False}
            objects.append(dict(body,objectEvidenceIdentity=identity(body)))
    return {'typeGraph':types,'functionDefinitions':definitions,'callSites':calls,'objectDeclarations':objects}


def relocation_contracts(dynamic):
    rows = []
    # ELF ABI operation codes, not project/symbol-name rules. Recognizing an
    # operation only selects obligations; it does not emulate the loader.
    extra = {62:{16:('tls-module-id',['TLS_MODULE_IDENTITY']),
                  17:('tls-module-offset',['TLS_MODULE_LAYOUT']),
                  18:('tls-thread-pointer-offset',['TLS_MODULE_LAYOUT','THREAD_POINTER_AND_THREAD_IDENTITY']),
                  36:('tls-descriptor',['TLS_DESCRIPTOR_RESOLUTION'])}}
    for obj in dynamic['objects']:
        for obligation in obj['relocationObligations']:
            role = obligation['role']; requirements = []
            if role=='unsupported':
                role,requirements = extra.get(obj['elf']['machine'],{}).get(obligation['relocation']['type'],
                    ('unsupported',['RELOCATION_SEMANTICS_UNSUPPORTED']))
            if role=='copy': requirements += ['INITIALIZER_PROVIDER_SELECTION','DESTINATION_STORAGE_AND_BYTES']
            if role=='indirect-relative' or obligation['symbol']['type']==10:
                requirements += ['RESOLVER_EXECUTION_AND_IMPLEMENTATION_ADDRESS']
            if not requirements: requirements=['ACTUAL_APPLICABLE_RELOCATION_EFFECT']
            body = {'file':obj['file'],'machine':obj['elf']['machine'],
                    'relocation':obligation['relocation'],'symbol':obligation['symbol'],
                    'contractKind':role,'requirements':requirements,
                    'semanticsVerified':False,'status':Status.INCONCLUSIVE.value}
            rows.append(dict(body,relocationContractIdentity=identity(body)))
    return rows


def derive(context_path, observation_path, *, entry_receipts=(), runtime_path=None, comparison_path=None):
    from .native_deployment_observation import check_observation
    context = bridge.check(context_path); observed = check_observation(observation_path)
    manifest = deployment.read(Path(context_path).resolve().parent/'inputs.json')
    plan = deployment.read(manifest['plan']['path'])
    deployed = deployment.check_result(observed['deploymentPath'])
    if (deployed['deploymentPlanIdentity'] != context['deploymentPlanIdentity']
            or context['runtimeObservationInventory'] is None
            or context['runtimeObservationInventory']['observationIdentity'] != observed['observationIdentity']):
        raise ValueError('CONTRACT_EVIDENCE_PARENT_BINDING_MISMATCH')
    candidate, source, artifacts, producer, bindings, contexts = bridge.inputs(plan)
    target_receipt = deployment.read(manifest['targetReceipt']['path'])
    target = bridge.validated_input(target_receipt)
    candidate_ast = deployment.read(Path(candidate['candidatePath']).parent/'target-ast.json')
    model_commands=[r for r in candidate['commands'] if r['stage']=='target-data-model']
    candidate_model=native.data_model(Path(model_commands[0]['stdoutPath']).read_text()) if len(model_commands)==1 else None
    joins = function_correspondence(artifacts['canonicalAst'],candidate_ast,candidate['edits'],
                                    source['canonicalAstIdentity'],candidate['targetAstIdentity'])
    graphs = {'source':ast_graph(artifacts['canonicalAst'],source['canonicalAstIdentity']),
              'candidate':ast_graph(candidate_ast,candidate['targetAstIdentity']),
              'nativeTarget':ast_graph(target['canonicalAst'],target_receipt['canonicalAstIdentity'])}
    producers, entry_gaps = entry_producers(plan)
    entries = []
    if len(entry_receipts) != len(producers):
        raise ValueError('CONTRACT_ENTRY_RECEIPT_COUNT_MISMATCH')
    for index, receipt_path in enumerate(entry_receipts):
        receipt = deployment.read(receipt_path); a = bridge.validated_input(receipt)
        if index >= len(producers) or receipt['context'] != producers[index]['context']:
            raise ValueError('CONTRACT_ENTRY_PRODUCER_MISMATCH')
        if receipt['target']!='x86_64': raise ValueError('CONTRACT_ENTRY_TARGET_REQUIRED')
        entries.append({'context':receipt['context'], 'nativeInputIdentity':receipt['nativeInputIdentity'],
                        'producer':producers[index]['input'],
                        'graph':ast_graph(a['canonicalAst'],receipt['canonicalAstIdentity'])})
    runtime = None
    if runtime_path is not None:
        from .native_runtime_identity import check
        runtime = check(runtime_path)
        if runtime['observationIdentity'] != observed['observationIdentity']:
            raise ValueError('CONTRACT_RUNTIME_OBSERVATION_MISMATCH')
    comparison=None
    if comparison_path is not None:
        from .native_program_comparison import check as check_comparison
        comparison=check_comparison(comparison_path)
        if comparison['deploymentIdentity'] != observed['deploymentIdentity']:
            raise ValueError('CONTRACT_COMPARISON_DEPLOYMENT_MISMATCH')
    reasons = {
        'runtime-binding':['UNTRACED_IDENTITY_AND_APPLICABLE_RELOCATION_EFFECTS_REQUIRED'],
        'entry-abi':['NATIVE_ABI_MACHINE_JOIN_AND_CONTEXT_RELATION_REQUIRED'],
        'legal-objects-inputs':['INPUT_DOMAIN_INITIALIZATION_LIFETIME_BOUNDS_ALIAS_PRECONDITIONS_REQUIRED'],
        'output-termination':['SOURCE_TARGET_COMPARISON_POLICY_AND_EXECUTIONS_REQUIRED'],
        'program-validation':['INSTANCE_INSTRUCTION_COVERAGE_AND_COMMON_FRAMEWORK_ADMISSION_REQUIRED']}
    stages = {k:{'status':Status.INCONCLUSIVE.value,'reasonCodes':v} for k,v in reasons.items()}
    if runtime is None:
        stages['runtime-binding']['reasonCodes'].append('RUNTIME_EVIDENCE_NOT_ACQUIRED')
    else:
        if not runtime['diagnosticEndpointMappingComplete']:
            stages['runtime-binding']['reasonCodes'].append('DIAGNOSTIC_ENDPOINT_MAPPING_INCOMPLETE')
        if runtime['metadataFailureReasonCounts']:
            stages['runtime-binding']['reasonCodes'].append('SYMBOL_METADATA_CONTRACTS_UNVERIFIED')
    if entry_gaps:
        stages['entry-abi']['reasonCodes'].append('ENTRY_CAPTURED_INPUT_CONTEXT_COVERAGE_INCOMPLETE')
    if comparison is not None:
        stages['output-termination']['boundedProcessObservationStatus']=comparison['processObservableComparisonStatus']
        stages['output-termination']['reasonCodes']=['OBJECT_EXTERNAL_EFFECT_ERROR_PATH_AND_TERMINATION_RELATION_CLOSURE_REQUIRED']
        if comparison['processObservableComparisonStatus']=='failed':
            stages['output-termination']['status']=Status.FAILED.value
    from .native_contract_readiness import inventory
    relocations=relocation_contracts(observed['dynamicObligations'])
    coverage=inventory(graphs, entries, joins, relocations, entry_gaps, runtime, comparison)
    return deployment.seal({'schemaVersion':'riscv2x86.native-contract-evidence.v2',
        'deploymentPlanIdentity':plan['deploymentPlanIdentity'],'observationIdentity':observed['observationIdentity'],
        'contextBridgeIdentity':context['contextBridgeIdentity'],'candidateIdentity':candidate['candidateIdentity'],
        'dataModels':{'source':source['analysisInput']['dataModels']['native'],
                      'candidate':candidate_model,'nativeTarget':target_receipt['analysisInput']['dataModels']['native']},
        'candidateVsNativeTargetDataModelEqual':candidate_model is not None and candidate_model==target_receipt['analysisInput']['dataModels']['native'],
        'declarationJoins':joins,'graphs':graphs,'entryContexts':entries,'entryInputGaps':entry_gaps,
        'entryDirectObjectContextAcquisitionComplete':len(entries)==len(producers) and not any(
            g['reasonCode'] in ('ENTRY_DIRECT_OBJECT_PRODUCER_NOT_UNIQUE','ENTRY_CONTEXT_NOT_INSPECTABLE') for g in entry_gaps),
        'entryCapturedInputContextCoverageComplete':len(entries)==len(producers) and not entry_gaps,
        'entryAbiClosureVerified':False,
        'relocationContracts':relocations, 'coverageInventory':coverage,
        'runtimeIdentityReportIdentity':runtime['runtimeIdentityReportIdentity'] if runtime else None,
        'processComparisonIdentity':comparison['processComparisonIdentity'] if comparison else None,
        'diagnosticMappedEndpointOccurrencesVerified':runtime['mappedEndpointOccurrencesVerified'] if runtime else 0,
        'stages':stages,'frameworkEvaluationReadiness':context['frameworkEvaluationReadiness'],
        'scope':'contract-input-evidence-for-existing-consumers-not-semantic-approval',
        'semanticApproval':False,'productionAcceptanceComplete':False},'contractEvidenceIdentity')


def entry_producers(plan):
    from .project_compile_context import derive as context
    actions = {}
    for key in ('testRecords','libraryRecords'):
        for a in deployment.read(plan[key]['path'])['actions']:
            actions[a['actionIdentity']] = a
    producers = []; gaps = []
    for row in plan['entry']['inputs']:
        raw = Path(row['path']).read_bytes()
        if raw.startswith(b'!<arch>'):
            gaps.append({'input':row,'reasonCode':'ARCHIVE_MEMBER_CONTEXT_CLOSURE_REQUIRED'})
            continue
        if not raw.startswith(b'\x7fELF'):
            gaps.append({'input':row,'reasonCode':'ENTRY_INPUT_FORMAT_NOT_MODELED'})
            continue
        from .native_elf_runtime import parse
        if parse(raw)['elfType'] != 1:
            gaps.append({'input':row,'reasonCode':'EXTERNAL_PROVIDER_CONTEXT_REQUIRED'})
            continue
        matches = [a for a in actions.values() if a.get('kind')=='compile'
                   and all((a.get('observedOutput') or {}).get(k)==row[k]
                           for k in ('path','resolvedPath','digest'))
                   and a.get('exitStatusObserved') is True and a.get('observedReturnCode')==0
                   and type(a.get('observedInvocationInterval',{}).get('finish')) is int
                   and type(plan['entry']['action'].get('observedInvocationInterval',{}).get('start')) is int
                   and a['observedInvocationInterval']['finish'] < plan['entry']['action']['observedInvocationInterval']['start']]
        if len(matches)!=1:
            gaps.append({'input':row,'reasonCode':'ENTRY_DIRECT_OBJECT_PRODUCER_NOT_UNIQUE'})
            continue
        c = context(matches[0])
        if not c['inspectionReady']:
            gaps.append({'input':row,'reasonCode':'ENTRY_CONTEXT_NOT_INSPECTABLE','blockers':c['blockers']})
            continue
        producers.append({'input':row,'context':c})
    return producers,gaps


def acquire(context_path, observation_path, output, *, clang, timeout=300, runtime_path=None, comparison_path=None):
    import json
    from .native_deployment_prerequisites import output_path
    # Parent validation and plan joining happen before new acquisition.
    context=bridge.check(context_path)
    from .native_deployment_observation import check_observation
    observed = check_observation(observation_path)
    manifest = deployment.read(Path(context_path).resolve().parent/'inputs.json')
    plan = deployment.read(manifest['plan']['path'])
    deployed=deployment.check_result(observed['deploymentPath'])
    if (deployed['deploymentPlanIdentity'] != plan['deploymentPlanIdentity']
            or context['runtimeObservationInventory'] is None
            or context['runtimeObservationInventory']['observationIdentity'] != observed['observationIdentity']):
        raise ValueError('CONTRACT_EVIDENCE_PARENT_BINDING_MISMATCH')
    if runtime_path is not None:
        from .native_runtime_identity import check as check_runtime
        if check_runtime(runtime_path)['observationIdentity'] != observed['observationIdentity']:
            raise ValueError('CONTRACT_RUNTIME_OBSERVATION_MISMATCH')
    if comparison_path is not None:
        from .native_program_comparison import check as check_comparison
        if check_comparison(comparison_path)['deploymentIdentity'] != observed['deploymentIdentity']:
            raise ValueError('CONTRACT_COMPARISON_DEPLOYMENT_MISMATCH')
    producers,_ = entry_producers(plan)
    if len(producers)>16: raise ValueError('CONTRACT_ENTRY_CONTEXT_BUDGET_EXCEEDED')
    root=output_path(output);root.mkdir()
    receipts=[]
    for i,producer in enumerate(producers):
        native.acquire(producer['context'],clang,root/('entry-%03d'%i),target='x86_64',timeout=timeout)
        receipts.append(str(root/('entry-%03d'%i)/'native-input.json'))
    result=derive(context_path,observation_path,entry_receipts=receipts,runtime_path=runtime_path,comparison_path=comparison_path)
    inputs={'schemaVersion':'riscv2x86.native-contract-inputs.v1',
            'context':deployment.snapshot(context_path),'observation':deployment.snapshot(observation_path),
            'entryReceipts':[deployment.snapshot(p) for p in receipts],
            'runtime':deployment.snapshot(runtime_path) if runtime_path else None,
            'comparison':deployment.snapshot(comparison_path) if comparison_path else None}
    (root/'inputs.json').write_text(json.dumps(deployment.seal(inputs,'contractInputsIdentity'),indent=2))
    (root/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    check(root/'result.json');return result


def check(path):
    from .native_external_providers import checked
    path=Path(path).resolve(strict=True);root=path.parent
    stored=deployment.read(path);checked(stored,'contractEvidenceIdentity')
    if stored.get('schemaVersion') != 'riscv2x86.native-contract-evidence.v2':
        raise ValueError('CONTRACT_EVIDENCE_V2_REDERIVATION_REQUIRED')
    inputs=deployment.read(root/'inputs.json');checked(inputs,'contractInputsIdentity')
    if (set(inputs)!={'schemaVersion','context','observation','entryReceipts','runtime','comparison','contractInputsIdentity'}
            or inputs['schemaVersion']!='riscv2x86.native-contract-inputs.v1'):
        raise ValueError('CONTRACT_INPUT_SCHEMA_INVALID')
    for row in [inputs['context'],inputs['observation'],*inputs['entryReceipts'],*([inputs['runtime']] if inputs['runtime'] else []),
                *([inputs['comparison']] if inputs['comparison'] else [])]:
        deployment.verify_snapshot(row)
    fresh=derive(inputs['context']['path'],inputs['observation']['path'],
                 entry_receipts=[r['path'] for r in inputs['entryReceipts']],
                 runtime_path=inputs['runtime']['path'] if inputs['runtime'] else None,
                 comparison_path=inputs['comparison']['path'] if inputs['comparison'] else None)
    if fresh!=stored:raise ValueError('CONTRACT_EVIDENCE_REDERIVATION_MISMATCH')
    return stored


def refine(input_path, output, *, runtime_path=None, comparison_path=None):
    """Reuse validated native input receipts; do not rerun unchanged compilers."""
    import json
    from .native_deployment_prerequisites import output_path
    if runtime_path is None and comparison_path is None:
        raise ValueError('CONTRACT_REFINEMENT_NEW_EVIDENCE_REQUIRED')
    check(input_path)
    old=deployment.read(Path(input_path).resolve().parent/'inputs.json')
    runtime_path=runtime_path or (old['runtime']['path'] if old['runtime'] else None)
    comparison_path=comparison_path or (old['comparison']['path'] if old['comparison'] else None)
    result=derive(old['context']['path'],old['observation']['path'],
                  entry_receipts=[r['path'] for r in old['entryReceipts']],
                  runtime_path=runtime_path,comparison_path=comparison_path)
    inputs={**{k:v for k,v in old.items() if k!='contractInputsIdentity'},
            'runtime':deployment.snapshot(runtime_path) if runtime_path else None,
            'comparison':deployment.snapshot(comparison_path) if comparison_path else None}
    root=output_path(output);root.mkdir()
    (root/'inputs.json').write_text(json.dumps(deployment.seal(inputs,'contractInputsIdentity'),indent=2))
    (root/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    check(root/'result.json');return result
