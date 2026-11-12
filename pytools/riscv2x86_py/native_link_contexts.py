"""Captured producer graph, not linker extraction or ABI/behavior approval.

Repeated operands remain distinct edges. ar members bind through the captured
append/index chain, never a basename or a coincidental content match. All
members are inventoried; this does not assert which ones the linker extracted.
"""
from pathlib import Path
from hashlib import sha256

from . import native_captured_deployment as deployment
from .native_dependency_inventory import checked_records
from .native_dependency_evidence import archive_members
from .native_elf_runtime import parse
from .project_archive_provenance import select
from .project_compile_context import derive as compile_context
from .project_build_records import identity

SCHEMA = 'riscv2x86.native-link-producer-contexts.v1'


def before(action, consumer):
    a=action.get('observedInvocationInterval',{});b=consumer.get('observedInvocationInterval',{})
    return (action.get('exitStatusObserved') is True and type(action.get('observedReturnCode')) is int
            and action['observedReturnCode']==0 and all(type(v) is int for v in
                (a.get('start'),a.get('finish'),b.get('start'),b.get('finish')))
            and a['start']<=a['finish']<b['start']<=b['finish'])


def derive(plan, deployed, *, node_limit=4096, byte_limit=256*1024*1024):
    if type(node_limit) is not int or not 1<=node_limit<=65536:
        raise ValueError('LINK_CONTEXT_NODE_BUDGET_INVALID')
    # The caller validates the full plan/deployment; also bind their identities
    # here so another deployment cannot supply a convenient replacement DSO.
    if deployed['deploymentPlanIdentity']!=plan['deploymentPlanIdentity']:
        raise ValueError('LINK_CONTEXT_DEPLOYMENT_MISMATCH')
    records=[];actions={};origins={};configs={}
    for key in ('libraryRecords','testRecords'):
        snapshot=plan[key];deployment.verify_snapshot(snapshot)
        record=checked_records(snapshot['path']);records.append(snapshot)
        config=deployment.read(record['captureConfig']);config_key=identity(deployment.snapshot(record['captureConfig']))
        configs[config_key]=config
        for action in record['actions']:
            aid=action['actionIdentity']
            if aid in actions and actions[aid]!=action:raise ValueError('LINK_CONTEXT_ACTION_COLLISION')
            actions[aid]=action;origins.setdefault(aid,set()).add(config_key)
    nodes={};edges=[];contexts={};gaps=[];raw_cache={};snapshots={}
    def gap(node,code,**extra):
        gaps.append({'nodeIdentity':node,'reasonCode':code,**extra})
    def same_clock(a,b):
        aa=origins.get(a['actionIdentity'],set());bb=origins.get(b['actionIdentity'],set())
        if aa & bb:return True
        def clocks(keys):return {configs[k].get('archiveCapture',{}).get('clockDomain') for k in keys}-{None}
        left,right=clocks(aa),clocks(bb)
        return len(left)==1 and left==right
    def candidates(row,consumer,kinds,*,exact_path):
        return [a for a in actions.values() if a['kind'] in kinds and before(a,consumer) and same_clock(a,consumer)
                and all((a.get('observedOutput') or {}).get(k)==row[k] for k in ('resolvedPath','digest'))
                and (not exact_path or a['observedOutput']['path']==row['path'])]
    def read(row):
        snap={k:row[k] for k in ('path','resolvedPath','digest')};deployment.verify_snapshot(snap)
        snapshots[identity(snap)]=snap
        key=(row['resolvedPath'],row['digest'])
        if key not in raw_cache:
            size=Path(row['path']).stat().st_size
            if size>byte_limit or sum(len(v) for v in raw_cache.values())+size>byte_limit:
                raise ValueError('LINK_CONTEXT_BYTE_BUDGET_EXCEEDED')
            raw_cache[key]=Path(row['path']).read_bytes()
            if 'sha256:'+sha256(raw_cache[key]).hexdigest()!=row['digest']:
                raise ValueError('LINK_CONTEXT_READ_BYTES_CHANGED')
        return raw_cache[key]
    def visit(row,consumer):
        node_id=identity({'resolvedPath':row['resolvedPath'],'digest':row['digest'],
                          'consumerActionIdentity':consumer['actionIdentity']})
        if node_id in nodes:return node_id
        if len(nodes)>=node_limit:raise ValueError('LINK_CONTEXT_NODE_BUDGET_EXCEEDED')
        node={'nodeIdentity':node_id,'file':{k:row[k] for k in ('path','resolvedPath','digest')},
              'consumerActionIdentity':consumer['actionIdentity'],'producerBound':False,
              'producerActionIdentity':None,'compileContextIdentity':None}
        nodes[node_id]=node;raw=read(row)
        if raw.startswith(b'!<arch>\n'):
            node['kind']='regular-archive';members=archive_members(raw);choices=[];attempts=[]
            for config_id,config in configs.items():
                group=[a for aid,a in actions.items() if config_id in origins[aid] and before(a,consumer)
                       and same_clock(a,consumer)]
                if config.get('archiveCapture'):
                    selection=select(group,config['directory'],row['path'],row['digest'])
                    attempts.append({'captureConfigIdentity':config_id,
                        'eligibleActionCount':len(group),'selection':selection,
                        'archiveActionCandidates':[{
                            'actionIdentity':a['actionIdentity'],'arguments':a['arguments'],
                            'directory':a['directory'],
                            'observedInvocationInterval':a.get('observedInvocationInterval'),
                            'before':{k:v for k,v in a['archiveOperationEvidence']['before'].items()
                                if k in ('supported','reason','profile','plan','archive')},
                            'after':{k:v for k,v in a['archiveOperationEvidence']['after'].items()
                                if k in ('status','archive','detail','returnCode')}}
                            for a in group if a.get('archiveOperationEvidence') is not None]})
                    if selection['complete']:choices.append(selection)
                else:
                    attempts.append({'captureConfigIdentity':config_id,
                        'eligibleActionCount':len(group),'selection':{
                            'complete':False,'reason':'ARCHIVE_CAPTURE_PROFILE_REQUIRED'}})
            choices={identity(c):c for c in choices}
            node['archiveSelectionAttempts']=attempts
            node['completeArchiveChainCandidateCount']=len(choices)
            if len(choices)!=1:
                gap(node_id,'ARCHIVE_OPERATION_CHAIN_NOT_UNIQUE_OR_UNAVAILABLE',
                    candidateCount=len(choices),selectionAttempts=attempts);return node_id
            selection=next(iter(choices.values()))
            if len(members)!=len(selection['members']):raise ValueError('LINK_CONTEXT_ARCHIVE_MEMBER_COUNT_MISMATCH')
            node['archiveOperationIdentities']=selection['operationIdentities'];node['producerBound']=True
            node['actualExtractionSelectionVerified']=False
            for ordinal,(member,relation) in enumerate(zip(members,selection['members'])):
                if member['digest']!=relation['digest']:raise ValueError('LINK_CONTEXT_ARCHIVE_MEMBER_DIGEST_MISMATCH')
                archive_action=actions[relation['archiveActionIdentity']]
                target=visit(relation,archive_action)
                edges.append({'source':node_id,'target':target,'kind':'archive-member',
                    'memberOrdinal':ordinal,'memberHeaderOffset':member['headerOffset'],
                    'memberName':member['name'],'memberDigest':member['digest']})
            return node_id
        if not raw.startswith(b'\x7fELF'):
            node['kind']='unsupported';gap(node_id,'INPUT_FORMAT_NOT_MODELED');return node_id
        elf=parse(raw);node['elfMachine']=elf['machine'];node['elfType']=elf['elfType']
        if elf['elfType']==1:
            node['kind']='object'
            # A checked symlink alias of the same captured output is not a
            # second producer. Equal bytes at a different canonical output
            # path still cannot select it.
            producers=candidates(row,consumer,('compile','assemble'),exact_path=False)
        elif elf['elfType']==3:
            node['kind']='shared-library';producers=candidates(row,consumer,('link',),exact_path=False)
        else:
            node['kind']='unsupported';gap(node_id,'ELF_INPUT_KIND_NOT_MODELED');return node_id
        if len(producers)!=1:
            gap(node_id,'CAPTURED_PRODUCER_NOT_UNIQUE_OR_UNAVAILABLE',candidateCount=len(producers));return node_id
        producer=producers[0];node['producerBound']=True;node['producerActionIdentity']=producer['actionIdentity']
        read(producer['observedOutput'])
        if node['kind']=='object':
            if producer['kind']=='compile':
                context=compile_context(producer);contexts[context['contextIdentity']]=context
                node['compileContextIdentity']=context['contextIdentity']
                if not context['inspectionReady']:gap(node_id,'C_CONTEXT_NOT_INSPECTABLE',blockers=context['blockers'])
            else:gap(node_id,'ASSEMBLY_CONTEXT_CONTRACT_REQUIRED')
            if producer['kind']=='assemble':
                # ELF type is authoritative: an assembly object may export
                # data rather than functions. No calling convention is
                # inferred from its file name or from STT_NOTYPE symbols.
                node['assemblyInterface']={
                    'definedSymbols':[s for s in elf['staticSymbols']
                        if s['defined'] and s['name'] and s['binding'] in (1,2,10)],
                    'undefinedSymbols':[s for s in elf['staticSymbols']
                        if not s['defined'] and s['name']],
                    'nativeAbiContractVerified':False,
                    'objectEffectContractVerified':False}
        else:
            link=deployment.captured_link(producer)
            for child in link['inputs']:
                edges.append({'source':node_id,'target':visit(child,producer),'kind':'link-input',
                              'argumentIndex':child['argumentIndex']})
        return node_id
    roots=[]
    for row in plan['entry']['inputs']:
        roots.append({'argumentIndex':row['argumentIndex'],'path':row['path'],
                      'nodeIdentity':visit(row,plan['entry']['action'])})
    # Bind the historical DSO's actual substitution, rather than assuming its
    # bytes equal the newly linked candidate library.
    replacements=[]
    derived=[a for a in deployed['artifacts'] if a['stage']=='derived-library']
    if len(derived)!=1:raise ValueError('LINK_CONTEXT_DERIVED_LIBRARY_REQUIRED')
    for row in roots:
        if row['argumentIndex'] in plan['entryLibraryPositions']:
            replacements.append({'argumentIndex':row['argumentIndex'],'originalNodeIdentity':row['nodeIdentity'],
                'derivedArtifact':{k:derived[0][k] for k in ('path','resolvedPath','digest')},
                'candidateObjectDigest':plan['candidateObject']['digest'],
                'replacementVerified':deployed['capturedInputReplacementVerified']})
    for snapshot in snapshots.values():deployment.verify_snapshot(snapshot)
    all_bound=bool(nodes) and all(n['producerBound'] for n in nodes.values())
    body={'schemaVersion':SCHEMA,'deploymentPlanIdentity':plan['deploymentPlanIdentity'],
          'deploymentIdentity':deployed['deploymentIdentity'],'recordSnapshots':records,
          'nodes':list(nodes.values()),'edges':edges,'entryOccurrences':roots,
          'compileContexts':list(contexts.values()),'inputGaps':gaps,'deployedReplacements':replacements,
          'candidateSubstitution':{'originalObject':plan['originalObject'],
              'candidateObject':plan['candidateObject'],'candidateIdentity':plan['candidateIdentity'],
              'replacementVerified':deployed['capturedInputReplacementVerified']},
          'capturedProducerClosureComplete':all_bound,
          'scope':'captured-explicit-link-inputs-not-driver-defaults-or-runtime-providers',
          'implicitDriverDependenciesIncluded':False,
          'nativeContextAcquisitionComplete':False,'actualArchiveExtractionSelectionVerified':False,
          'entryAbiClosureVerified':False,'semanticApproval':False,'productionAcceptanceComplete':False}
    return deployment.seal(body,'linkProducerContextsIdentity')
