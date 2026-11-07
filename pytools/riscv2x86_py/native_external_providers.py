"""Versioned candidate-provider evidence; original external obligations persist."""
import os
from pathlib import Path
import tempfile

from .native_audit_evidence import strict_json
from .native_dependency_inventory import replay as replay_dependencies
from .native_elf_runtime import parse, candidates
from .native_dependency_evidence import bytes_digest
from .project_compile_context import digest
from .project_build_records import identity

SCHEMA='riscv2x86.native-external-provider-inventory.v1'


def read(path):return strict_json(Path(path).read_bytes())


def checked(value,field):
    if value.get(field)!=identity({k:v for k,v in value.items() if k!=field}):
        raise ValueError('EXTERNAL_EVIDENCE_IDENTITY_INVALID:'+field)


def _store(root,raw):
    sha=bytes_digest(raw);folder=Path(root)/'elf-blobs';folder.mkdir(exist_ok=True)
    fd,temp=tempfile.mkstemp(dir=folder)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        path=folder/sha[7:]
        try:os.link(temp,path)
        except FileExistsError:pass
        if path.read_bytes()!=raw:raise ValueError('EXTERNAL_BLOB_CHANGED')
    finally:os.unlink(temp)
    return sha


def _providers(basis,storage):
    if basis.get('schemaVersion')!='riscv2x86.native-runtime-provider-basis.v1':
        raise ValueError('EXTERNAL_RUNTIME_BASIS_REQUIRED')
    checked(basis,'basisIdentity')
    for path,expected in basis['fileDigests'].items():
        if digest(path)!=expected:raise ValueError('EXTERNAL_RUNTIME_BOUND_FILE_CHANGED:'+path)
    rows=[];seen=set()
    for item in basis['candidates']:
        if item.get('status')!='ELF-inspected':continue
        path=Path(item['path']);resolved=str(path.resolve(strict=True))
        if resolved!=item['resolvedPath']:raise ValueError('EXTERNAL_PROVIDER_ALIAS_CHANGED')
        raw=path.read_bytes();sha=bytes_digest(raw)
        if sha!=item['digest'] or basis['fileDigests'].get(resolved)!=sha:
            raise ValueError('EXTERNAL_PROVIDER_DIGEST_CHANGED')
        if resolved in seen:continue
        seen.add(resolved)
        _store(storage,raw)
        rows.append({'path':resolved,'digest':sha,'elf':parse(raw)})
    return rows


def analyze(dependencies,providers):
    objects={'root':dependencies['rootElf']}
    objects.update({m['memberId']:m['elf'] for m in dependencies['members']})
    obligations=[]
    for blocker in dependencies['blockers']:
        if blocker['reason']!='external-contract-required':continue
        obj=objects[blocker['object']]
        requests=[s for s in obj['undefined'] if s['name']==blocker['symbol']]
        if len(requests)!=1:raise ValueError('EXTERNAL_REQUEST_SYMBOL_AMBIGUOUS')
        symbol=requests[0]
        request={'name':symbol['name'],'machine':obj['machine'],'type':symbol['type'],
                 'binding':symbol['binding'],'version':None,
                 'versionEvidence':'unversioned-relocatable-request'}
        matches=candidates(request,providers)
        # Counterpart-by-name is discovery, never a cross-ISA behavioral mapping.
        counterpart=candidates(dict(request,machine=dependencies['targetElf']['machine']),providers)
        reasons=['ACTUAL_LINK_BINDING_REQUIRED','TYPED_BEHAVIOR_CONTRACT_REQUIRED',
                 'RUNTIME_SELECTION_OR_STATIC_CLOSURE_REQUIRED']
        if len(matches)!=1:reasons.insert(0,'PROVIDER_DEFINITION_MISSING' if not matches else 'PROVIDER_DEFINITION_AMBIGUOUS')
        elif matches[0]['specialContractRequired']:reasons.insert(0,'SPECIAL_SYMBOL_CONTRACT_REQUIRED')
        body={'originalObligation':blocker,'request':request,'definitionCandidates':matches,
              'targetNameCandidates':counterpart,'targetBehaviorMappingVerified':False,
              'actualLinkBindingVerified':False,'typedBehaviorContractVerified':False,
              'pendingReasons':reasons}
        obligations.append(dict(body,obligationIdentity=identity(body)))
    # Inspect versioned requests of the observed DSOs separately. Never transfer
    # requirements from a PIC/shared build onto a different archive/root build.
    references=[]
    for provider in providers:
        for symbol in provider['elf']['dynamicSymbols']:
            if symbol['defined'] or not symbol['name'] or symbol['binding']==0:continue
            request={k:symbol[k] for k in ('name','type','binding','version')}
            request['machine']=provider['elf']['machine']
            if symbol['name'] in {o['request']['name'] for o in obligations}:
                references.append({'consumer':provider['path'],'request':request,
                    'definitionCandidates':candidates(request,providers),'actualBindingVerified':False})
    return {'externalObligations':obligations,'observedVersionedReferences':references,
            'candidateDefinitionCoverageComplete':all(len(o['definitionCandidates'])==1 for o in obligations)}


def acquire(dependency_path,basis_path,output):
    dep=read(dependency_path);replay_dependencies(dep)
    basis=read(basis_path)
    input_digests={str(Path(p).resolve(strict=True)):digest(p) for p in (dependency_path,basis_path)}
    providers=_providers(basis,output)
    detail=analyze(dep,providers)
    for path,expected in input_digests.items():
        if digest(path)!=expected:raise ValueError('EXTERNAL_CLOSING_INPUT_CHANGED')
    # Recheck all observed providers/tools and aliases after the interpretation.
    for path,expected in basis['fileDigests'].items():
        if digest(path)!=expected:raise ValueError('EXTERNAL_CLOSING_PROVIDER_CHANGED')
    for item in basis['candidates']:
        if item.get('status')=='ELF-inspected' and str(Path(item['path']).resolve(strict=True))!=item['resolvedPath']:
            raise ValueError('EXTERNAL_PROVIDER_ALIAS_CHANGED')
    blockers=[{'obligationIdentity':o['obligationIdentity'],'reason':'EXTERNAL_CONTRACT_INCOMPLETE',
               'pendingReasons':o['pendingReasons']} for o in detail['externalObligations']]
    blockers.extend({'reason':'RUNTIME_BASIS_BLOCKER','original':b} for b in basis['blockers'])
    blockers.extend({'reason':'PARENT_DEPENDENCY_BLOCKER','original':b} for b in dep['blockers']
                    if b['reason']!='external-contract-required')
    body={'schemaVersion':SCHEMA,'inputDigests':input_digests,
          'dependencyPath':str(Path(dependency_path).resolve()),'runtimeBasisPath':str(Path(basis_path).resolve()),
          'dependencyInventoryIdentity':dep['inventoryIdentity'],'runtimeBasisIdentity':basis['basisIdentity'],
          'originalDependencyBlockers':dep['blockers'],'providers':providers,**detail,'blockers':blockers,
          'status':'blocked' if blockers else 'inventory-only',
          'targetDependencyCompatibilityVerified':False,'typedCallContractVerified':False,
          'actualLinkSelectionVerified':False,'programObservationVerified':False,
          'semanticApproval':False,'productionAcceptanceComplete':False}
    return dict(body,inventoryIdentity=identity(body))


def replay(value,original_output,new_output):
    checked(value,'inventoryIdentity')
    if value['schemaVersion']!=SCHEMA:raise ValueError('EXTERNAL_INVENTORY_SCHEMA_UNSUPPORTED')
    for provider in value['providers']:
        path=Path(original_output)/'elf-blobs'/provider['digest'][7:]
        raw=path.read_bytes()
        if bytes_digest(raw)!=provider['digest'] or parse(raw)!=provider['elf']:
            raise ValueError('EXTERNAL_ARCHIVED_ELF_CHANGED')
    fresh=acquire(value['dependencyPath'],value['runtimeBasisPath'],new_output)
    if fresh!=value:raise ValueError('EXTERNAL_INDEPENDENT_REPLAY_MISMATCH')
    return {'externalProviderReplayComplete':True,'replayedInventoryIdentity':value['inventoryIdentity'],
            'replayedBlockerCount':len(value['blockers']),
            'candidateDefinitionCoverageComplete':value['candidateDefinitionCoverageComplete'],
            'actualLinkSelectionVerified':False,'typedCallContractVerified':False,
            'semanticApproval':False,'productionAcceptanceComplete':False}
