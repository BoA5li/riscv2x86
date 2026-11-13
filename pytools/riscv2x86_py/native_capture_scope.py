"""Replay all stages of already-bound captures without trusting unselected JSON.

An invocation has a stable capture/config/invocation locator, even when stage
views give its action different identities. Selected action identities remain
anchors. Other stages enter only from a fresh raw capture replay. Failed or
unattributed parent runs cannot provide admitted producers.
"""
from copy import deepcopy
from pathlib import Path

from . import native_captured_deployment as deployment
from .native_dependency_inventory import checked_records
from .project_build_capture import inventory
from .project_build_records import identity
from .project_compile_context import digest


def locator(action):
    p=action.get('provenance',{})
    if (p.get('kind')!='compiler-exec-capture' or not p.get('invocationId')
            or not p.get('captureIdentity') or not p.get('configPath')):
        raise ValueError('CAPTURE_SCOPE_INVOCATION_PROVENANCE_REQUIRED')
    return (str(Path(p['configPath']).resolve(strict=True)),p['captureIdentity'],p['invocationId'])


def comparable(action):
    row=deepcopy(action);row.pop('actionIdentity',None)
    row['provenance'].pop('stageSelection',None)
    return row


def load(plan):
    records=[];anchors={};configs={};full={};config_snapshots={}
    for key in ('libraryRecords','testRecords'):
        snapshot=plan[key];deployment.verify_snapshot(snapshot)
        record=checked_records(snapshot['path']);records.append(snapshot)
        path=record['captureConfig'];cs=deployment.snapshot(path);cid=identity(cs)
        config_snapshots[cid]=cs;configs[cid]=deployment.read(path)
        if cid not in full:
            replay=inventory(path,stage=None)
            # Expected compiler probes may fail, but invalid raw observations
            # never become valid by belonging to another stage.
            if replay['unresolved'] or not replay['importComplete']:
                raise ValueError('CAPTURE_SCOPE_RAW_REPLAY_INCOMPLETE')
            full[cid]=replay
        for action in record['actions']:
            key=locator(action)
            if key in anchors and comparable(anchors[key])!=comparable(action):
                raise ValueError('CAPTURE_SCOPE_SELECTED_INVOCATION_CONFLICT')
            anchors.setdefault(key,action)
    actions={};origins={};stage_facts={};summaries=[]
    for cid,replay in full.items():
        deployment.verify_snapshot(config_snapshots[cid])
        runs={r['runId']:r for r in replay['runRecords']}
        found=set();counts={}
        for observed in replay['actions']:
            key=locator(observed);chosen=anchors.get(key,observed)
            if key in found:raise ValueError('CAPTURE_SCOPE_DUPLICATE_RAW_INVOCATION')
            found.add(key)
            if comparable(chosen)!=comparable(observed):
                raise ValueError('CAPTURE_SCOPE_SELECTED_RAW_INVOCATION_MISMATCH')
            aid=chosen['actionIdentity']
            if aid!=identity({k:v for k,v in chosen.items() if k!='actionIdentity'}):
                raise ValueError('CAPTURE_SCOPE_ACTION_IDENTITY_INVALID')
            run=runs.get(chosen.get('captureRunId'))
            admitted=run is not None and type(run['returnCode']) is int and run['returnCode']==0
            stage=run['stage'] if run else None
            counts[stage or '<unattributed>']=counts.get(stage or '<unattributed>',0)+1
            if aid in actions and actions[aid]!=chosen:
                raise ValueError('CAPTURE_SCOPE_ACTION_IDENTITY_COLLISION')
            actions[aid]=chosen;origins.setdefault(aid,set()).add(cid)
            stage_facts[aid]={'captureConfigIdentity':cid,'captureRunId':chosen.get('captureRunId'),
                'stage':stage,'runReturnCode':run['returnCode'] if run else None,
                'producerStageAdmitted':admitted,'selectedRecordAnchor':key in anchors}
        expected={k for k in anchors if k[0]==str(Path(replay['captureConfig']).resolve())}
        if not expected<=found:raise ValueError('CAPTURE_SCOPE_SELECTED_INVOCATION_MISSING')
        summaries.append({'captureConfig':config_snapshots[cid],
            'fullCaptureInventoryIdentity':replay['inventoryIdentity'],
            'captureFileSetIdentity':identity(replay['captureFiles']),
            'stageActionCounts':dict(sorted(counts.items())),
            'selectedAnchorCount':len(expected),'replayedInvocationCount':len(found),
            'processTreeCompletenessVerified':False})
    return records,actions,origins,configs,stage_facts,summaries,full


def close(configs,full):
    """Detect changed or appended raw observations while the graph was built."""
    for cid,replay in full.items():
        if identity(deployment.snapshot(replay['captureConfig']))!=cid:
            raise ValueError('CAPTURE_SCOPE_CONFIG_CHANGED')
        rows=replay['captureFiles']
        for row in rows:
            if digest(row['path'])!=row['digest']:
                raise ValueError('CAPTURE_SCOPE_RAW_FILE_CHANGED')
        root=Path(configs[cid]['directory'])
        current={str(p) for name in ('runs','invocations') for p in (root/name).glob('*.json')
                 if p.name.endswith(('.start.json','.finish.json'))}
        if current!={r['path'] for r in rows}:
            raise ValueError('CAPTURE_SCOPE_RAW_FILE_SET_CHANGED')


def unrelated_archive_operation(action,target):
    """Destination-only proof for a narrow GNU ar grammar, not write approval.

    Unsupported operations on the requested archive remain blockers. A bound
    ordinary r/q output on another canonical archive cannot establish this
    archive's history. Unknown forms / response files / missing outputs remain
    unclassified; never infer destinations from a basename.
    """
    evidence=action.get('archiveOperationEvidence')
    if evidence is None:return False
    before=evidence['before']
    if before.get('supported') is not False or before.get('profile') not in ('gnu-ar','gnu-ranlib'):return False
    args=action['arguments'][1:]
    if args in (['--version'],['--help']):return True
    if before['profile']!='gnu-ar':return False
    if len(args)<3:return False
    flags=args[0].removeprefix('-')
    if (not flags or any(c not in 'rqcDsUv' for c in flags)
            or sum(flags.count(c) for c in 'rq')!=1
            or any(not arg or arg.startswith(('-', '@')) for arg in args[1:])):return False
    output=action.get('observedOutput')
    expected=str(Path(action['directory']).joinpath(args[1]).absolute())
    import os
    expected=os.path.abspath(expected)
    return (output is not None and output['path']==expected
            and output['resolvedPath']!=target['resolvedPath'])
