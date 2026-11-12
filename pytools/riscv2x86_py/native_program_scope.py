"""Local call closures and object roles, never a proof of non-reachability.

Imported headers, callbacks, constructors and external calls require separate
contracts. A node not visited by known direct edges is not declared irrelevant.
"""
from .project_build_records import identity


def local_scope(graph, roots, authority):
    functions={tuple(f['astPath']):f for f in graph['functionDefinitions']}
    pending=[tuple(p) for p in roots];visited=set();calls=[];terminal=[]
    while pending:
        key=pending.pop(0)
        if key in visited:continue
        if key not in functions:raise ValueError('PROGRAM_SCOPE_FUNCTION_ROOT_MISSING')
        visited.add(key)
        for call in graph['callSites']:
            if tuple(call['functionAstPath'] or ())!=key:continue
            calls.append(call['callSiteEvidenceIdentity'])
            resolution=call['resolution'];kind=resolution['classification']
            if kind=='direct' and call['definitionIncluded']:
                pending.extend(tuple(p) for p in call['definitionAstPaths'])
            else:
                terminal.append({'callSiteEvidenceIdentity':call['callSiteEvidenceIdentity'],
                    'classification':kind,'resolutionIdentity':resolution['callEvidenceIdentity'],
                    'requirements': resolution.get('semanticObligations',[]) if kind=='compiler-builtin' else
                        ['INDIRECT_TARGET_SET_AND_CALL_CONTRACT_REQUIRED'] if kind=='unresolved' else
                        ['EXTERNAL_DEFINITION_AND_EFFECT_CONTRACT_REQUIRED']})
    objects=[]
    for obj in graph['objectDeclarations']:
        owner=tuple(obj['functionAstPath'] or ())
        role=('external-declaration' if obj['storageClass']=='extern' and not obj['initializerAst'] else
              'global-definition-or-tentative-definition' if not owner else 'function-local-declaration')
        objects.append({'objectEvidenceIdentity':obj['objectEvidenceIdentity'],'role':role,
            'scopeMembership':'global' if not owner else 'visited-local-function' if owner in visited else
                'not-visited-by-known-local-edges',
            'initializerSyntaxPresent':bool(obj['initializerAst']),
            'runtimeObjectIdentityVerified':False,'legalObjectContractVerified':False})
    body={'rootAstPaths':roots,'rootAuthority':authority,
          'visitedFunctionAstPaths':[list(p) for p in sorted(visited)],
          'visitedCallEvidenceIdentities':calls,'terminalCallObligations':terminal,
          'unvisitedFunctionAstPaths':[list(p) for p in sorted(set(functions)-visited)],
          'objectRoles':objects,'knownLocalClosureComputed':bool(roots),
          'unvisitedFunctionsProvedUnreachable':False,'programReachabilityComplete':False,
          'candidateInstructionExecutionCoverageVerified':False}
    return dict(body,localScopeIdentity=identity(body))


def derive(context, graphs, entries, joins, deployed):
    source_roots=[];candidate_roots=[];gaps=[]
    for instance in context.get('instances',[]):
        source_path=instance['sourceFunctionAstPath']
        matches=[j for j in joins if j['sourceAstPath']==source_path
                 and j['byteLineageDeclarationCorrespondenceVerified']]
        if len(matches)!=1:
            gaps.append({'reasonCode':'BOUND_CANDIDATE_FUNCTION_CORRESPONDENCE_REQUIRED',
                         'bridgeInstanceIdentity':instance['bridgeInstanceIdentity']});continue
        source_roots.append(source_path);candidate_roots.append(matches[0]['candidateAstPath'])
    unique=lambda rows:[list(p) for p in sorted({tuple(p) for p in rows})]
    scopes={'source':local_scope(graphs['source'],unique(source_roots),'compiler-instance-binding'),
            'candidate':local_scope(graphs['candidate'],unique(candidate_roots),'verified-edit-declaration-correspondence')}
    if source_roots:
        gaps.append({'reasonCode':'NATIVE_TARGET_FUNCTION_CONTEXT_RELATION_REQUIRED'})
    # main is the C hosted entry contract, not a corpus-specific root name.
    # This is a local entry scope, not a claim about startup/constructors.
    artifacts=[a for a in deployed['artifacts'] if a['stage']=='derived-entry']
    symbols=artifacts[0]['elf']['staticSymbols'] if len(artifacts)==1 else []
    main_symbols=[s for s in symbols if s['name']=='main' and s['defined'] and s['type']==2 and s['binding']==1]
    for i,entry in enumerate(entries):
        roots=[f['astPath'] for f in entry['graph']['functionDefinitions'] if f['name']=='main']
        if len(roots)!=1 or len(main_symbols)!=1:
            roots=[];gaps.append({'reasonCode':'C_HOSTED_ENTRY_DECLARATION_AND_SYMBOL_REQUIRED','entryIndex':i})
        scopes['entry:'+str(i)]=local_scope(entry['graph'],roots,'C-hosted-main-local-scope')
    candidate_args=context.get('candidateTargetArguments',[])
    producer_args=context.get('producerTargetArguments',[])
    pic=lambda args:[a for a in args if a in ('-fPIC','-fpic','-fPIE','-fpie','-fno-pic','-fno-pie')]
    return {'schemaVersion':'riscv2x86.native-program-scope.v1','localScopes':scopes,'scopeGaps':gaps,
        'candidatePICArguments':pic(candidate_args),'producerPICArguments':pic(producer_args),
        'explicitPICArgumentsEqual':pic(candidate_args)==pic(producer_args),
        'targetContextCompatibilityVerified':False,
        'nativeAbiMachineEvidenceAcquired':False,'legalObjectDomainVerified':False,
        'fullProgramScopeComplete':False,'semanticApproval':False}
