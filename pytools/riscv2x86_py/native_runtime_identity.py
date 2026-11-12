"""Associate diagnostic bindings with mapping images captured at stderr writes.

Definition compatibility is metadata evidence. COPY storage and initializer
providers have distinct roles; neither role proves initialized bytes/behavior.
"""
import json
from hashlib import sha256
from pathlib import Path
import os
from collections import Counter

from . import native_captured_deployment as deployment
from .native_deployment_observation import check_observation
from .native_binding_syntax import parse as binding_events
from .native_dynamic_obligations import describe
from .native_external_providers import checked
from .project_compile_context import digest
from .project_build_records import identity
from .native_process_identity import capture

SCHEMA = 'riscv2x86.diagnostic-map-bindings.v2'


def local(root, name):
    path = Path(name)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError('RUNTIME_IDENTITY_RELATIVE_PATH_REQUIRED')
    resolved = (root/path).resolve(strict=True)
    if not resolved.is_relative_to(root): raise ValueError('RUNTIME_IDENTITY_PATH_ESCAPE')
    return resolved


def epoch_objects(root, epoch):
    rows = []
    for obj in epoch['objects']:
        if 'captureFailure' in obj: continue
        raw = local(root, obj['blob']).read_bytes()
        if 'sha256:'+sha256(raw).hexdigest() != obj['digest']:
            raise ValueError('RUNTIME_IDENTITY_IMAGE_CHANGED')
        if not obj['maps'] or any(m not in epoch['maps'] for m in obj['maps']):
            raise ValueError('RUNTIME_IDENTITY_MAP_MEMBERSHIP_INVALID')
        if obj['kind'] == 'backing-file':
            device, inode, size, _, _ = obj['capturedFileStat']
            if size != len(raw) or any(m['inode'] != inode or m['device'] != [os.major(device),os.minor(device)]
                                      for m in obj['maps']):
                raise ValueError('RUNTIME_IDENTITY_BACKING_FILE_MISMATCH')
            if obj['maps'] != [m for m in epoch['maps'] if m['inode']==inode
                               and m['device']==[os.major(device),os.minor(device)]]:
                raise ValueError('RUNTIME_IDENTITY_BACKING_MAP_GROUP_INCOMPLETE')
        elif obj['kind'] == 'mapped-virtual-elf':
            if len(obj['maps']) != 1 or len(raw) != obj['maps'][0]['end']-obj['maps'][0]['start']:
                raise ValueError('RUNTIME_IDENTITY_VIRTUAL_RANGE_INVALID')
        else: raise ValueError('RUNTIME_IDENTITY_OBJECT_KIND_UNSUPPORTED')
        metadata = describe(local(root,obj['blob']))
        copy_indices = {r['relocation']['symbolIndex'] for r in metadata['relocationObligations'] if r['role']=='copy'}
        map_id=identity({'kind':obj['kind'],'imageDigest':obj['digest'],
                         'ranges':obj['maps']})
        rows.append({**obj, 'elf': metadata['elf'], 'copySymbolIndices':copy_indices, 'mapIdentity':map_id})
    return rows


def definition_candidates(obj, event):
    elf=obj['elf']; copies=obj['copySymbolIndices']
    rows = []
    for s in elf['dynamicSymbols']:
        if s['name'] != event['symbol'] or not s['defined'] or s['visibility'] not in (0,3) or s['binding'] not in (1,2,10):
            continue
        version = s['version']['name'] if s['version'] else None
        if event['version'] is not None and version != event['version']: continue
        if event['version'] is None and s['versionHidden']: continue
        role = 'copy-destination-storage' if s['entryIndex'] in copies else 'definition'
        if s['versionSource'] == 'requirement' and role != 'copy-destination-storage': continue
        rows.append({'symbol': s, 'role': role, 'specialContractRequired': role != 'definition'
                     or s['type'] in (6,10) or s['binding'] != 1})
    return rows


def instance_key(obj):
    """Conservative anchor, not an emulation of a loader link_map.

    Multiple offset-zero mappings of one inode may be multiple loads. Do not
    collapse them merely because the backing file or SONAME is the same.
    Permission changes are snapshot state, not new file/load identities.
    """
    anchors = [m for m in obj['maps'] if m['offset'] == 0]
    if len(anchors) != 1:
        return None
    anchor = anchors[0]
    body = {'kind': obj['kind'], 'digest': obj['digest'], 'anchor': anchor['start']}
    if obj['kind'] == 'backing-file':
        body['capturedFileStat'] = obj['capturedFileStat']
    else:
        body['end'] = anchor['end']
    return identity(body)


def mapping_mutation(epoch, index):
    mutation = epoch.get('mappingMutation')
    if index == 0:
        if mutation != {'kind':'exec'}:
            raise ValueError('RUNTIME_IDENTITY_INITIAL_EXEC_EPOCH_REQUIRED')
        return mutation
    if (not isinstance(mutation,dict)
            or set(mutation)!={'kind','number','arguments','returnValue'}
            or mutation['kind']!='syscall' or mutation['number'] not in (9,10,11,25)
            or type(mutation['returnValue']) is not int or mutation['returnValue']<0
            or not isinstance(mutation['arguments'],list) or len(mutation['arguments'])!=6
            or any(type(a) is not int or not 0<=a<2**64 for a in mutation['arguments'])):
        raise ValueError('RUNTIME_IDENTITY_MAPPING_MUTATION_INVALID')
    return mutation


def replaces_mapping(obj, mutation):
    if mutation['kind']!='syscall' or mutation['number']==10:
        return False
    args=mutation['arguments']
    start=mutation['returnValue'] if mutation['number']==9 else args[0]
    ranges=[(start,start+args[1])]
    if mutation['number']==25:
        ranges.append((mutation['returnValue'],mutation['returnValue']+args[2]))
    return any(start<m['end'] and m['start']<end for start,end in ranges for m in obj['maps'])


def associate(endpoint, side, event, relevant, epochs, process):
    label = endpoint['label']; reasons = []; evidence = []; selected = []
    if event['processId'] != process['processId']:
        reasons.append('EVENT_PROCESS_MISMATCH')
    if event[side+'Namespace'] != 0:
        reasons.append('LOADER_NAMESPACE_UNSUPPORTED')
    if not relevant:
        reasons.append('EVENT_WRITE_COVERAGE_MISSING')
    for write in relevant:
        aliases = [a for a in write['bindingAliases'] if a['label'] == label]
        matches = []
        if Path(label).is_absolute():
            if len(aliases) != 1:
                reasons.append('STOPPED_ALIAS_EVIDENCE_NOT_UNIQUE' if aliases else 'STOPPED_ALIAS_EVIDENCE_MISSING')
            elif 'failureReason' in aliases[0]:
                reasons.append('STOPPED_ALIAS_CAPTURE_FAILED')
            else:
                alias = aliases[0]
                matches = [o for o in epochs[write['epoch']] if o['kind'] == 'backing-file'
                           and o['capturedFileStat'] == alias['capturedFileStat']
                           and o['digest'] == alias['imageDigest']]
        else:
            matches = [o for o in epochs[write['epoch']] if o['kind'] == 'mapped-virtual-elf'
                       and label == o['elf']['soname']]
        if not matches:
            reasons.append('MAPPED_OBJECT_NOT_FOUND')
        elif len(matches) != 1:
            reasons.append('MAPPED_OBJECT_AMBIGUOUS')
        elif matches[0]['mappingInstanceIdentity'] is None:
            reasons.append('MAPPING_LOAD_ANCHOR_AMBIGUOUS_OR_MISSING')
        else:
            selected.append(matches[0])
        evidence.append({'epoch': write['epoch'], 'stopOrdinal': write['stopOrdinal'],
                         'aliasEvidence': aliases, 'candidateCount': len(matches),
                         'mapSnapshotIdentities': [o['mapIdentity'] for o in matches],
                         'mappingInstanceIdentities': [o['mappingInstanceIdentity'] for o in matches]})
    if selected and len({o['mappingInstanceIdentity'] for o in selected}) != 1:
        reasons.append('MAPPING_INSTANCE_CHANGED_ACROSS_WRITES')
    valid = not reasons and len(selected) == len(relevant)
    obj = selected[0] if valid else None
    return obj, {'diagnosticMappedIdentityVerified': bool(valid),
                 'imageDigest': obj['digest'] if obj else None,
                 'mapIdentity': obj['mapIdentity'] if obj else None,
                 'mappingInstanceIdentity': obj['mappingInstanceIdentity'] if obj else None,
                 'objectKind': obj['kind'] if obj else None,
                 'reasonCodes': sorted(set(reasons)), 'mappingEvidence': evidence,
                 'definitionCandidates': definition_candidates(obj,event) if obj and side=='provider' else [],
                 'loaderLoadInstanceIdentityVerified': False,
                 'untracedIdentityVerified': False, 'relocatedMemoryBytesVerified': False}


def derive(root, process):
    checked(process, 'processCaptureIdentity')
    if (set(process)!={'schemaVersion','backend','syscallPhaseSource','processId','arguments','directory','environment',
                        'timeoutSeconds','returnCode','failureReason','epochs','stderrWrites','stdoutDigest','stderrDigest',
                        'intervention','untracedRunEquivalenceVerified','semanticApproval','productionAcceptanceComplete',
                        'processCaptureIdentity','logLimit','imageLimit','stopLimit','stopCount'}
            or process['schemaVersion'] != 'riscv2x86.process-map-capture.v2'
            or process['backend'] != 'linux-x86_64-ptrace-syscall-single-process.v1'
            or process['failureReason'] is not None or process['intervention'] != 'ptrace'
            or process['untracedRunEquivalenceVerified'] is not False
            or type(process['returnCode']) is not int or type(process['processId']) is not int
            or process['processId'] <= 0
            or process.get('syscallPhaseSource') != 'PTRACE_GET_SYSCALL_INFO'
            or process.get('semanticApproval') is not False
            or process.get('productionAcceptanceComplete') is not False):
        raise ValueError('RUNTIME_IDENTITY_CAPTURE_SCOPE_INVALID')
    for stream in ('stdout','stderr'):
        if digest(root/(stream+'.log')) != process[stream+'Digest']:
            raise ValueError('RUNTIME_IDENTITY_LOG_CHANGED')
    if (any(type(process[k]) is not int or process[k] < 1 for k in ('logLimit','imageLimit','stopLimit','stopCount'))
            or process['stopCount']>process['stopLimit']
            or (root/'stdout.log').stat().st_size+(root/'stderr.log').stat().st_size>process['logLimit']):
        raise ValueError('RUNTIME_IDENTITY_CAPTURE_BUDGET_INVALID')
    if len(process['epochs'])>4096:raise ValueError('RUNTIME_IDENTITY_MAP_EPOCH_BUDGET_INVALID')
    epochs = []; capture_failures=[]; previous_stop=-1; images={};map_bytes=0
    previous_instances = {}; generations = Counter()
    for i, row in enumerate(process['epochs']):
        path = local(root, row['path'])
        if digest(path) != row['digest']: raise ValueError('RUNTIME_IDENTITY_EPOCH_CHANGED')
        map_bytes+=path.stat().st_size
        if map_bytes>64*1024*1024:raise ValueError('RUNTIME_IDENTITY_MAP_METADATA_BUDGET_INVALID')
        epoch = deployment.read(path)
        if (type(epoch['stopOrdinal']) is not int or not previous_stop < epoch['stopOrdinal'] <= process['stopCount']):
            raise ValueError('RUNTIME_IDENTITY_EPOCH_STOP_INVALID')
        previous_stop=epoch['stopOrdinal']
        if epoch['index'] != i: raise ValueError('RUNTIME_IDENTITY_EPOCH_ORDER_INVALID')
        mutation=mapping_mutation(epoch,i)
        capture_failures.extend({'epoch':i,**o} for o in epoch['objects'] if 'captureFailure' in o)
        objects=epoch_objects(root, epoch)
        current_instances = {}
        for obj in objects:
            key = instance_key(obj)
            if key is None:
                obj['mappingInstanceIdentity'] = None
                continue
            if key not in previous_instances or replaces_mapping(previous_instances[key],mutation):
                generations[key] += 1
            instance = identity({'processId': process['processId'], 'anchorIdentity': key,
                                 'generation': generations[key]})
            obj['mappingInstanceIdentity'] = instance
            current_instances[key] = obj
        previous_instances = current_instances
        for obj in objects: images[obj['blob']]=local(root,obj['blob']).stat().st_size
        if sum(images.values())>process['imageLimit']:raise ValueError('RUNTIME_IDENTITY_IMAGE_BUDGET_INVALID')
        epochs.append(objects)
    raw = (root/'stderr.log').read_bytes(); text = raw.decode('utf-8', errors='strict')
    events, unparsed = binding_events(text)
    lines = raw.splitlines(keepends=True); offsets = [0]
    for line in lines: offsets.append(offsets[-1]+len(line))
    last = 0; previous_stop=-1; alias_bytes=0
    for write in process['stderrWrites']:
        if (type(write['offset']) is not int or type(write['size']) is not int
                or write['offset'] != last or write['size'] < 1
                or type(write['epoch']) is not int or not 0 <= write['epoch'] < len(epochs)
                or type(write['stopOrdinal']) is not int
                or not previous_stop < write['stopOrdinal'] <= process['stopCount']):
            raise ValueError('RUNTIME_IDENTITY_WRITE_COVERAGE_INVALID')
        previous_stop=write['stopOrdinal']
        epoch=deployment.read(local(root,process['epochs'][write['epoch']]['path']))
        if epoch['stopOrdinal']>write['stopOrdinal']:raise ValueError('RUNTIME_IDENTITY_WRITE_PRECEDES_MAPPING')
        # A write must use the latest captured mapping state, not an arbitrary
        # older epoch with the same inode/digest.
        if write['epoch']+1 < len(process['epochs']):
            following=deployment.read(local(root,process['epochs'][write['epoch']+1]['path']))
            if following['stopOrdinal'] <= write['stopOrdinal']:
                raise ValueError('RUNTIME_IDENTITY_STALE_WRITE_EPOCH')
        aliases=write.get('bindingAliases')
        if not isinstance(aliases,list):raise ValueError('RUNTIME_IDENTITY_STOPPED_ALIASES_REQUIRED_RECAPTURE')
        alias_bytes += len(json.dumps(aliases).encode('utf-8'))
        if alias_bytes>64*1024*1024:raise ValueError('RUNTIME_IDENTITY_ALIAS_BUDGET_INVALID')
        for a in aliases:
            if (not isinstance(a,dict) or not isinstance(a.get('label'),str)
                    or not Path(a['label']).is_absolute()):
                raise ValueError('RUNTIME_IDENTITY_ALIAS_SCHEMA_INVALID')
            if 'failureReason' in a:
                if set(a)!={'label','failureReason'} or not isinstance(a['failureReason'],str):
                    raise ValueError('RUNTIME_IDENTITY_ALIAS_FAILURE_INVALID')
            elif (set(a)!={'label','capturedFileStat','imageDigest'}
                  or not isinstance(a['capturedFileStat'],list) or len(a['capturedFileStat'])!=5
                  or any(type(v) is not int for v in a['capturedFileStat'])
                  or not isinstance(a['imageDigest'],str)):
                raise ValueError('RUNTIME_IDENTITY_ALIAS_SCHEMA_INVALID')
        last += write['size']
    if last != len(raw): raise ValueError('RUNTIME_IDENTITY_STDERR_WRITES_INCOMPLETE')
    joined = []
    for event in events:
        start, stop = offsets[event['line']], offsets[event['line']+1]
        relevant = [w for w in process['stderrWrites'] if w['offset'] < stop and start < w['offset']+w['size']]
        endpoints = {}; objects_by_side={}
        for side in ('requester','provider'):
            obj, endpoints[side] = associate(event[side], side, event, relevant, epochs, process)
            objects_by_side[side]=obj
        requester=objects_by_side['requester']; provider=objects_by_side['provider']
        requested=[]
        if requester is not None:
            requested=[s for s in requester['elf']['dynamicSymbols'] if s['name']==event['symbol']
                       and ((s['version']['name'] if s['version'] else None)==event['version'])]
        types={s['type'] for s in requested}
        definitions=endpoints['provider']['definitionCandidates']
        compatible=(requester is not None and provider is not None
                    and requester['elf']['machine']==provider['elf']['machine']
                    and len(types)==1 and 0 not in types and len(definitions)==1
                    and (next(iter(types))==definitions[0]['symbol']['type']
                         or next(iter(types))==2 and definitions[0]['symbol']['type']==10))
        required_files={s['version'].get('file') for s in requested if s['versionSource']=='requirement' and s['version']}
        required_files.discard(None)
        if (compatible and definitions[0]['role']!='copy-destination-storage' and required_files
                and required_files!={provider['elf']['soname']}):
            compatible=False
        metadata_reasons=[]
        if requester is None or provider is None:metadata_reasons.append('ENDPOINT_MAPPING_IDENTITY_REQUIRED')
        if requester is not None and not requested:metadata_reasons.append('REQUESTED_SYMBOL_VERSION_NOT_FOUND')
        if requested and (len(types)!=1 or 0 in types):metadata_reasons.append('REQUESTED_SYMBOL_TYPE_UNKNOWN_OR_AMBIGUOUS')
        if provider is not None and len(definitions)!=1:metadata_reasons.append('PROVIDER_DEFINITION_NOT_UNIQUE')
        if requester is not None and provider is not None:
            if requester['elf']['machine']!=provider['elf']['machine']:metadata_reasons.append('ELF_MACHINE_MISMATCH')
            if len(types)==1 and definitions and len(definitions)==1 and not (
                    next(iter(types))==definitions[0]['symbol']['type']
                    or next(iter(types))==2 and definitions[0]['symbol']['type']==10):
                metadata_reasons.append('SYMBOL_TYPE_MISMATCH')
            if definitions and len(definitions)==1 and definitions[0]['role']!='copy-destination-storage' and required_files and required_files!={provider['elf']['soname']}:
                metadata_reasons.append('VERSION_PROVIDER_FILE_CONTRACT_UNPROVED')
        if event['bindingMode']!='normal':
            compatible=False;metadata_reasons.append('BINDING_MODE_UNSUPPORTED')
        body = {'event': event, 'requesterSymbolCandidates':requested,
                'requestedVersionFiles':sorted(required_files),
                'providerSymbolMetadataUnique':len(definitions)==1, 'writeEpochs': [w['epoch'] for w in relevant], **endpoints,
                'providerDefinitionCompatibilityVerified': bool(compatible),
                'metadataReasonCodes': sorted(set(metadata_reasons)),
                'actualCallExecutionVerified': False, 'behaviorContractVerified': False,
                'loaderEventAuthenticityVerified':False,'resolvedImplementationAddressVerified':False}
        joined.append(dict(body, bindingEvidenceIdentity=identity(body)))
    failures=Counter(code for r in joined for side in ('requester','provider') for code in r[side]['reasonCodes'])
    metadata_failures=Counter(code for r in joined for code in r['metadataReasonCodes'])
    verified=sum(r[k]['diagnosticMappedIdentityVerified'] for r in joined for k in ('requester','provider'))
    return {'events': joined, 'unparsedLines': unparsed, 'mappingCaptureFailures':capture_failures,
            'capturedImageDigests':sorted({o['digest'] for epoch in epochs for o in epoch}),
            'bindingEventCount':len(joined), 'mappingCaptureFailureCount':len(capture_failures),
            'mappedEndpointOccurrencesVerified': verified,
            'endpointOccurrenceCount':2*len(joined), 'unverifiedEndpointOccurrenceCount':2*len(joined)-verified,
            'endpointFailureReasonCounts':dict(sorted(failures.items())),
            'metadataFailureReasonCounts':dict(sorted(metadata_failures.items())),
            'diagnosticEndpointMappingComplete':bool(joined) and verified==2*len(joined) and not unparsed and not capture_failures,
            'metadataCompatibleProviderEvents': sum(r['providerDefinitionCompatibilityVerified'] for r in joined),
            'untracedRuntimeBindingClosureComplete': False, 'semanticApproval': False}


def acquire(observation_path, output, *, timeout=300):
    from .native_deployment_prerequisites import output_path
    observed = check_observation(observation_path)
    diagnostic = [r for r in observed['commands'] if r['stage'] == 'diagnostic']
    if len(diagnostic) != 1: raise ValueError('RUNTIME_IDENTITY_DIAGNOSTIC_PROFILE_REQUIRED')
    profile = diagnostic[0]; root = output_path(output); root.mkdir()
    inputs = {'schemaVersion': 'riscv2x86.runtime-identity-inputs.v1',
              'observation': deployment.snapshot(observation_path), 'timeoutSeconds': timeout}
    (root/'inputs.json').write_text(json.dumps(deployment.seal(inputs,'runtimeInputsIdentity'),indent=2))
    process = capture(profile['arguments'], str(root), profile['environment'], root/'trace', timeout=timeout)
    report = _report(root, observed, process, profile)
    (root/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    check(root/'result.json'); return report


def _report(root, observed, process, profile):
    if (process['arguments'] != profile['arguments'] or process['environment'] != profile['environment']
            or process['directory'] != str(root)):
        raise ValueError('RUNTIME_IDENTITY_COMMAND_PROFILE_MISMATCH')
    rows = derive(root/'trace', process)
    deployed=deployment.check_result(observed['deploymentPath'])
    expected={a['stage']:a['digest'] for a in deployed['artifacts'] if a['stage'] in ('derived-entry','derived-library')}
    expected['interpreter']=observed['loader']['digest']
    missing={k:v for k,v in expected.items() if v not in rows['capturedImageDigests']}
    return deployment.seal({'schemaVersion': SCHEMA, 'observationIdentity': observed['observationIdentity'],
        'deploymentIdentity': observed['deploymentIdentity'], 'processCaptureIdentity': process['processCaptureIdentity'],
        **rows, 'requiredMappedImagesVerified':not missing, 'missingMappedImages':missing, 'scope': 'ptrace-diagnostic-mapped-images-and-metadata-not-untraced-run-or-call-coverage',
        'workingDirectoryDiffersFromReference': True,
        'diagnosticReturnCode': process['returnCode'], 'tracedRunReturnCodeMatchesReference': process['returnCode'] == profile['returnCode'],
        'tracedRunStdoutMatchesReference': process['stdoutDigest'] == profile['stdoutDigest'],
        'productionAcceptanceComplete': False}, 'runtimeIdentityReportIdentity')


def check(path):
    path = Path(path).resolve(strict=True); root = path.parent
    value = deployment.read(path); checked(value,'runtimeIdentityReportIdentity')
    if value.get('schemaVersion') != SCHEMA:
        raise ValueError('RUNTIME_IDENTITY_V2_STOPPED_ALIAS_EVIDENCE_REQUIRED_RECAPTURE')
    inputs = deployment.read(root/'inputs.json'); checked(inputs,'runtimeInputsIdentity')
    if (set(inputs)!={'schemaVersion','observation','timeoutSeconds','runtimeInputsIdentity'}
            or inputs['schemaVersion']!='riscv2x86.runtime-identity-inputs.v1'):
        raise ValueError('RUNTIME_IDENTITY_INPUT_SCHEMA_INVALID')
    deployment.verify_snapshot(inputs['observation'])
    observed = check_observation(inputs['observation']['path'])
    profile = next(r for r in observed['commands'] if r['stage']=='diagnostic')
    process = deployment.read(root/'trace/capture.json')
    if process['timeoutSeconds'] != inputs['timeoutSeconds']: raise ValueError('RUNTIME_IDENTITY_TIMEOUT_MISMATCH')
    if _report(root,observed,process,profile) != value: raise ValueError('RUNTIME_IDENTITY_REDERIVATION_MISMATCH')
    return value
