"""Source-bound eligibility ledger; discovery never grants edit/ABI authority."""
from collections import Counter
from pathlib import Path

from .project_activation_batches import read, summarize, validate_plan
from .project_build_records import identity
from .project_compile_context import digest


def _location(value,cwd,dependencies):
    if not isinstance(value,dict):raise ValueError('MACRO_LOCATION_INVALID')
    name=value.get('file');offset=value.get('offset');length=value.get('tokLen')
    if (not isinstance(name,str) or not name or name.startswith('<')
            or type(offset) is not int or type(length) is not int or offset<0 or length<1):
        raise ValueError('MACRO_LOCATION_FILE_OR_BYTE_RANGE_REQUIRED')
    lexical=Path(name);path=(lexical if lexical.is_absolute() else Path(cwd)/lexical).resolve(strict=True)
    matches=[d for d in dependencies if d['resolvedPath']==str(path)]
    if not matches or len({d['digest'] for d in matches})!=1 or digest(path)!=matches[0]['digest']:
        raise ValueError('MACRO_LOCATION_DEPENDENCY_CONTENT_MISMATCH')
    if offset+length>path.stat().st_size:raise ValueError('MACRO_LOCATION_OUT_OF_BOUNDS')
    return {'file':str(path),'fileDigest':matches[0]['digest'],'offset':offset,'tokLen':length}


def bind_slice(begin,end,cwd,dependencies):
    left=_location(begin,cwd,dependencies);right=_location(end,cwd,dependencies)
    if left['file']!=right['file'] or left['offset']>right['offset']:
        raise ValueError('MACRO_LOCATION_CONTIGUOUS_FILE_REQUIRED')
    raw=Path(left['file']).read_bytes();stop=right['offset']+right['tokLen']
    from hashlib import sha256
    if 'sha256:'+sha256(raw).hexdigest()!=left['fileDigest']:
        raise ValueError('MACRO_LOCATION_DEPENDENCY_CONTENT_CHANGED')
    body={'schemaVersion':'riscv2x86.compiler-location-slice.v1','file':left['file'],
        'fileDigest':left['fileDigest'],'beginOffset':left['offset'],'endOffset':stop,
        'sliceDigest':'sha256:'+sha256(raw[left['offset']:stop]).hexdigest()}
    return dict(body,sliceIdentity=identity(body))


def acquire(plan_path,result_root,ledger_path):
    before=digest(ledger_path);ledger=read(ledger_path)
    # Reconstruct recorded coverage and validate every persisted batch, rather
    # than trusting ledger labels or a rehashed occurrence array.
    rebuilt=summarize(plan_path,result_root)
    if identity(ledger)!=identity(rebuilt):raise ValueError('PROJECT_ELIGIBILITY_DISCOVERY_REPLAY_MISMATCH')
    plan=validate_plan(plan_path)
    snapshots={}
    for index,_ in enumerate(plan['batches']):
        path=Path(result_root)/f'batch-{index:04d}'/'contexts.json'
        if not path.is_file():continue
        report_digest=digest(path)
        for row in read(path)['records']:
            if row.get('inspection') is not None:
                key=row['context']['contextIdentity']
                if key in snapshots:raise ValueError('PROJECT_ELIGIBILITY_CONTEXT_DUPLICATE')
                snapshots[key]=(row['context'],row['inspection']['snapshot'],str(path.resolve()),report_digest)
    records=[];definitions={};seen=set()
    for occurrence in ledger['occurrences']:
        instance=occurrence['instance'];iid=instance['activationIdentity']
        if iid in seen:raise ValueError('PROJECT_ELIGIBILITY_OCCURRENCE_DUPLICATE')
        seen.add(iid)
        context,snapshot,report_path,report_digest=snapshots[occurrence['contextIdentity']]
        dependencies=snapshot['dependencyManifest']['dependencies'];cwd=context['workingDirectory']
        bounds={};location_blockers=[];region=instance.get('range',{})
        for label,selector in [('definitionSlice','spellingLoc'),('expansionTokenSlice','expansionLoc')]:
            begin=region.get('begin',{});end=region.get('end',{})
            try:
                bounds[label]=bind_slice(begin.get(selector,begin),end.get(selector,end),cwd,dependencies)
            except (OSError,ValueError,KeyError,TypeError) as exc:
                location_blockers.append({'stage':'source-location','component':label,'detail':str(exc)})
        definition=bounds.get('definitionSlice')
        if definition is not None:definitions[definition['sliceIdentity']]=definition
        blockers=[*location_blockers,
            {'stage':'native-preprocessing','detail':'NATIVE_INSPECTION_CPP_COMPARISON_REQUIRED'},
            {'stage':'compiler-operand-authority','detail':'MACRO_ARGUMENT_AND_GNU_OPERAND_EXPORT_REQUIRED'},
            {'stage':'macro-effects','detail':'COMPLETE_MACRO_EFFECT_AND_OUTPUT_PROOF_REQUIRED'},
            {'stage':'materialization','detail':'MACRO_EDIT_AUTHORIZATION_REQUIRED'},
            {'stage':'program-call','detail':'TYPED_CALL_OBJECT_AND_DEPENDENCY_CLOSURE_REQUIRED'}]
        body={'schemaVersion':'riscv2x86.project-instance-eligibility-record.v1',
            'occurrenceIdentity':iid,'contextIdentity':context['contextIdentity'],
            'translationUnit':context['sourcePath'],'sourceDigest':context['sourceDigest'],
            'inspectionReportPath':report_path,'inspectionReportDigest':report_digest,
            'dependencyIdentity':snapshot['dependencyManifest']['dependencyIdentity'],
            'enclosingFunction':instance.get('enclosingFunction'),
            'locationEvidence':bounds,'locationEvidenceComplete':not location_blockers,
            'macroLocationPresent':instance['macroLocationPresent'],
            # An expansion token range is NOT the full macro invocation or a
            # safe replacement range, even when both endpoints are identical.
            'sourceInstanceBindingComplete':False,'editAuthorizationComplete':False,
            'eligibilityStatus':'blocked','blockers':blockers,'firstBlocker':blockers[0],
            'semanticApproval':False,'productionAcceptanceComplete':False}
        records.append(dict(body,eligibilityIdentity=identity(body)))
    if digest(ledger_path)!=before:raise ValueError('PROJECT_ELIGIBILITY_INPUT_CHANGED')
    report_digests={path:expected for _,_,path,expected in snapshots.values()}
    if any(digest(path)!=expected for path,expected in report_digests.items()):
        raise ValueError('PROJECT_ELIGIBILITY_REPORT_CHANGED')
    body={'schemaVersion':'riscv2x86.project-instance-eligibility.v1',
        'planPath':str(Path(plan_path).resolve()),'resultRoot':str(Path(result_root).resolve()),
        'ledgerPath':str(Path(ledger_path).resolve()),'discoveryLedgerDigest':before,
        'discoveryLedgerIdentity':ledger['ledgerIdentity'],'planIdentity':plan['planIdentity'],
        'sourceCount':ledger['sourceCount'],'contextCount':ledger['contextCount'],
        'batchStatusCounts':ledger['batchStatusCounts'],'planningErrors':ledger['planningErrors'],
        'recordedInspectionAstCoverageComplete':ledger['recordedInspectionAstCoverageComplete'],
        'records':records,'definitionSlices':list(definitions.values()),
        'occurrenceCount':len(records),'definitionSliceCount':len(definitions),
        'statusCounts':dict(Counter(r['eligibilityStatus'] for r in records)),
        'firstBlockerCounts':dict(Counter(r['firstBlocker']['detail'] for r in records)),
        'freshCompilerAcquisitionPerformed':False,'asmInstanceInventoryComplete':False,
        'endToEndEligibilityAssessed':False,'semanticApproval':False,'productionAcceptanceComplete':False}
    return dict(body,eligibilityInventoryIdentity=identity(body))


def validate(value):
    if (not isinstance(value,dict) or value.get('eligibilityInventoryIdentity')!=identity({k:v for k,v in value.items() if k!='eligibilityInventoryIdentity'})
            or identity(acquire(value['planPath'],value['resultRoot'],value['ledgerPath']))!=identity(value)):
        raise ValueError('PROJECT_ELIGIBILITY_REPLAY_MISMATCH')
    return value
