"""Attribute observed archive member contributions in checked deployment maps.

Uses the existing GNU bfd contribution grammar and exact archive/member bytes.
Only unique ordinary allocated input sections are admitted. Missing rows do not
prove non-extraction; duplicate member names, TLS, folding and other layouts
remain explicit obligations. This is link-time evidence, never ABI/execution.
"""
from pathlib import Path
import re

from . import native_captured_deployment as deployment
from .native_dependency_evidence import archive_members,bytes_digest
from .native_link_attribution import contributions,sections
from .native_elf_runtime import parse
from .project_build_records import identity


def derive(plan,deployed,graph):
    root=Path(deployed['planPath']).resolve().parent
    stages={plan['entry']['action']['actionIdentity']:('derived-entry',plan['entry']['directory']),
            plan['library']['action']['actionIdentity']:('derived-library',plan['library']['directory'])}
    results=[]
    for node in graph['nodes']:
        if node['kind']!='regular-archive':continue
        row={'nodeIdentity':node['nodeIdentity'],'archive':node['file'],
             'producerChainVerified':node['producerBound'],'observedMemberSelections':[],
             'unresolvedContributions':[],'archiveExtractionClosureVerified':False}
        stage=stages.get(node['consumerActionIdentity'])
        if stage is None:
            row['reasonCodes']=['ARCHIVE_CONSUMER_DEPLOYMENT_MAP_REQUIRED'];results.append(row);continue
        name,cwd=stage;mapfile=root/name/'link.map';relative=str(mapfile.relative_to(root))
        final=next(a['elf'] for a in deployed['artifacts'] if a['stage']==name)
        if deployment.digest(mapfile)!=deployed['evidenceDigests'].get(relative):
            raise ValueError('ARCHIVE_SELECTION_DEPLOYMENT_MAP_CHANGED')
        row['map']=deployment.snapshot(mapfile);row['deploymentStage']=name
        deployment.verify_snapshot(node['file'])
        raw=Path(node['file']['path']).read_bytes()
        if bytes_digest(raw)!=node['file']['digest']:raise ValueError('ARCHIVE_SELECTION_BYTES_CHANGED')
        members=archive_members(raw);by_name={}
        for member in members:by_name.setdefault(member['name'],[]).append(member)
        for contribution in contributions(mapfile.read_text()):
            match=re.fullmatch(r'([^()]+)\(([^()]+)\)',contribution['owner'])
            if not match:continue
            archive,label=match.groups();path=Path(archive)
            if not path.is_absolute():path=Path(cwd)/path
            if str(path.resolve())!=node['file']['resolvedPath']:continue
            candidates=by_name.get(label,[])
            if len(candidates)!=1:
                row['unresolvedContributions'].append({'contribution':contribution,
                    'reasonCode':'ARCHIVE_MAP_MEMBER_NOT_UNIQUE_OR_UNAVAILABLE'});continue
            member=candidates[0]
            try:table=sections(member['bytes'])
            except ValueError:
                row['unresolvedContributions'].append({'contribution':contribution,
                    'reasonCode':'ARCHIVE_MEMBER_ELF_SECTION_CONTRACT_REQUIRED'});continue
            matching=[(i,s) for i,s in enumerate(table) if s['name']==contribution['section']
                      and s['size']==contribution['size'] and s['size']>0
                      and s['flags'] & 2 and not s['flags'] & (0x400|0x10|0x200)]
            if len(matching)!=1:continue
            index,section=matching[0];attributed=[]
            for symbol in parse(member['bytes'])['staticSymbols']:
                if (not symbol['defined'] or symbol['binding']!=1 or symbol['type'] not in (1,2)
                        or symbol['sectionIndex']!=index or symbol['size']<=0
                        or symbol['value']+symbol['size']>section['size']):continue
                matches=[s for s in final['staticSymbols'] if s['defined'] and s['binding']==1
                    and s['name']==symbol['name'] and s['type']==symbol['type']
                    and s['size']==symbol['size'] and s['value']==contribution['address']+symbol['value']]
                if len(matches)==1:attributed.append({'inputSymbol':symbol,'finalSymbol':matches[0]})
            if not attributed:continue
            body={'memberName':label,'memberHeaderOffset':member['headerOffset'],
                  'memberDigest':member['digest'],'contribution':contribution,
                  'inputSection':section,'attributedDefinitions':attributed,
                  'observedMemberContributionVerified':True,
                  'runtimeBindingVerified':False,'nativeAbiContractVerified':False}
            row['observedMemberSelections'].append(dict(body,memberSelectionIdentity=identity(body)))
        deployment.verify_snapshot(node['file']);deployment.verify_snapshot(row['map'])
        row['reasonCodes']=['ARCHIVE_EXTRACTION_CLOSURE_NOT_PROVED']
        results.append(row)
    return {'schemaVersion':'riscv2x86.native-archive-contributions.v1',
            'deploymentIdentity':deployed['deploymentIdentity'],'archives':results,
            'observedArchiveMemberCount':len({(r['nodeIdentity'],s['memberHeaderOffset'])
                for r in results for s in r['observedMemberSelections']}),
            'observedAllocatedContributionCount':sum(len(r['observedMemberSelections']) for r in results),
            'absenceProvesNonExtraction':False,'actualLinkSelectionClosureVerified':False}
