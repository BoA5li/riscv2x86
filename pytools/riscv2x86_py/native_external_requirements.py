"""Reproducible per-reference external contract work, without name whitelists.

Preserves every parent obligation. ELF reference sites/build producers are
facts; required types/effects, runtime selection and cross-ISA mapping stay open.
"""
from pathlib import Path
from .native_external_providers import read, replay, checked
from .native_dependency_evidence import archive_members, bytes_digest
from .native_elf_runtime import parse
from .native_link_attribution import sections
from .project_build_records import identity
from .project_compile_context import digest

SCHEMA = 'riscv2x86.native-external-requirements.v1'


def reference_sites(raw, name):
    elf = parse(raw);table = sections(raw);sites = []
    for relocation in elf['relocations']:
        if relocation['symbol'] != name:continue
        owners = []
        for symbol in elf['staticSymbols']:
            index = symbol['sectionIndex']
            if (symbol['defined'] and symbol['type'] == 2 and 0 < index < len(table)
                    and table[index]['name'] == relocation['targetSection']
                    and symbol['value'] <= relocation['offset'] < symbol['value']+symbol['size']):
                owners.append({k:symbol[k] for k in ('name','value','size','sectionIndex')})
        sites.append({'relocation':relocation,'containingFunctions':owners,
                      'instructionSemanticsVerified':False})
    return {'objectDigest':bytes_digest(raw), 'machine':elf['machine'], 'sites':sites,
            'referenceLocationsComplete':bool(sites)}


def derive(provider, dependencies, root_raw, archive_raw):
    checked(provider,'inventoryIdentity')
    if provider['dependencyInventoryIdentity'] != dependencies['inventoryIdentity']:
        raise ValueError('EXTERNAL_REQUIREMENTS_PARENT_MISMATCH')
    raws = {'root':root_raw}
    for member in archive_members(archive_raw):
        raws[str(member['headerOffset'])+':'+member['digest']] = member['bytes']
    builds = {member['memberId']:member for member in dependencies['members']}
    rows = []
    for obligation in provider['externalObligations']:
        old = obligation['originalObligation'];obj = old['object']
        if obj not in raws:raise ValueError('EXTERNAL_REQUIREMENTS_OBJECT_MISSING')
        references = reference_sites(raws[obj],old['symbol'])
        if obj == 'root':
            if references['objectDigest'] != read(dependencies['candidatePath'])['sourceObjectDigest']:
                raise ValueError('EXTERNAL_REQUIREMENTS_ROOT_CHANGED')
            producers = [];kind = 'translated-root'
        else:
            member = builds[obj]
            if references['objectDigest'] != member['digest']:
                raise ValueError('EXTERNAL_REQUIREMENTS_MEMBER_CHANGED')
            producers = member.get('selectedBuildActions', [])
            kind = 'archive-member'
        # C type/ABI cannot be read out of STT_FUNC/STT_OBJECT. Candidate types
        # only select the list of necessary evidence, never discharge it.
        types = {m['symbol']['type'] for m in obligation['definitionCandidates']}
        requirements = ['ACTUAL_SOURCE_LINK_BINDING','TARGET_MECHANISM_MAPPING',
                        'PROGRAM_RUNTIME_SELECTION','INDEPENDENT_PROGRAM_AUDIT']
        if types == {2}:
            requirements += ['COMPILER_FUNCTION_TYPE','ARGUMENT_AND_RETURN_RELATION',
                             'MEMORY_IO_TERMINATION_EFFECT_CONTRACT']
        elif types == {1}:
            requirements += ['COMPILER_OBJECT_TYPE','OBJECT_LIFETIME_BOUNDS_ALIAS',
                             'OBJECT_READ_WRITE_AND_LOGICAL_IDENTITY_CONTRACT']
        else:
            requirements += ['SPECIAL_OR_UNRESOLVED_SYMBOL_TYPE_CONTRACT']
        if not references['sites']:requirements.append('REFERENCE_MECHANISM_NOT_LOCATED')
        body = {'obligationIdentity':obligation['obligationIdentity'],'originalObligation':old,
                'objectRole':kind,'references':references,'selectedBuildActions':producers,
                'definitionCandidates':obligation['definitionCandidates'],
                'targetNameCandidates':obligation['targetNameCandidates'],
                'requiredEvidence':requirements, 'typedBehaviorContractVerified':False,
                'crossIsaBehaviorMappingVerified':False,'status':'blocked'}
        rows.append(dict(body,requirementIdentity=identity(body)))
    body = {'schemaVersion':SCHEMA,'providerInventoryIdentity':provider['inventoryIdentity'],
            'dependencyInventoryIdentity':dependencies['inventoryIdentity'], 'requirements':rows,
            'originalProviderBlockers':provider['blockers'], 'allOriginalObligationsPreserved':True,
            'externalContractClosureComplete':False, 'semanticApproval':False,
            'productionAcceptanceComplete':False}
    return dict(body,requirementsIdentity=identity(body))


def acquire(provider_path, output):
    path = Path(provider_path).resolve(strict=True);initial = digest(path);value = read(path)
    output = Path(output)
    replay_dir = output/'provider-replay';replay_dir.mkdir()
    replay(value,path.parent,replay_dir)
    dependencies = read(value['dependencyPath'])
    candidate = read(dependencies['candidatePath'])
    directory = Path(candidate['candidatePath']).parent
    raw = (directory/'source.o').read_bytes();archive = Path(dependencies['archivePath']).read_bytes()
    if bytes_digest(archive) != dependencies['inputDigests'][str(Path(dependencies['archivePath']).resolve())]:
        raise ValueError('EXTERNAL_REQUIREMENTS_ARCHIVE_CHANGED')
    result = derive(value,dependencies,raw,archive)
    for file,expected in dependencies['inputDigests'].items():
        if digest(file) != expected:raise ValueError('EXTERNAL_REQUIREMENTS_BOUND_INPUT_CHANGED')
    if digest(path) != initial:raise ValueError('EXTERNAL_REQUIREMENTS_PROVIDER_CHANGED')
    body = {k:v for k,v in result.items() if k!='requirementsIdentity'}
    body.update(providerPath=str(path),providerDigest=initial)
    return dict(body,requirementsIdentity=identity(body))


def replay_requirements(value, output):
    checked(value,'requirementsIdentity')
    if value.get('schemaVersion') != SCHEMA:
        raise ValueError('EXTERNAL_REQUIREMENTS_SCHEMA_INVALID')
    if digest(value['providerPath']) != value['providerDigest']:
        raise ValueError('EXTERNAL_REQUIREMENTS_PROVIDER_CHANGED')
    fresh = acquire(value['providerPath'],output)
    if fresh != value:raise ValueError('EXTERNAL_REQUIREMENTS_REPLAY_MISMATCH')
    return {'requirementsReplayComplete':True, 'requirementsIdentity':value['requirementsIdentity'],
            'obligationCount':len(value['requirements']), 'externalContractClosureComplete':False,
            'semanticApproval':False,'productionAcceptanceComplete':False}
