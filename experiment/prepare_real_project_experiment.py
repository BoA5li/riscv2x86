#!/usr/bin/env python3
"""Build-log/database import and contextual inspection, not L0--L3 acceptance.

Do not feed context-inspected instances to the legacy automatic runner: it does
not yet consume these project contexts end-to-end. This tool exposes that gap
rather than validating a different default-build program under the same name.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
import sys

# Allow invocation from the repository without installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'pytools'))
from riscv2x86_py.project_build_records import import_log, import_database, identity
from riscv2x86_py.project_compile_context import derive, acquire, validate
from riscv2x86_py.compiler_call_dependencies import validate as validate_dependencies


def inspect(records, *, clang=None, target='riscv64', sources=(), limit=None):
    if (records.get('schemaVersion')!='riscv2x86.project-build-records.v1'
            or records.get('inventoryIdentity') != identity({k:v for k,v in records.items() if k!='inventoryIdentity'})
            or records.get('semanticApproval') is not False
            or records.get('buildSuccessVerified') is not False):
        raise ValueError('PROJECT_BUILD_INVENTORY_INVALID')
    selected = {str(Path(s).resolve()) for s in sources}; rows=[]; errors=[]; matched=set()
    for action in records['actions']:
        if action['kind']!='compile': continue
        try:
            context=derive(action)
            if selected and context['sourcePath'] not in selected: continue
            matched.add(context['sourcePath'])
            if limit is not None and len(rows)>=limit: continue
            row={'context':context, 'status':'context_ready' if context['inspectionReady'] else 'blocked',
                 'inspection':None,
                 'translationEvaluationBlockers':['PROJECT_END_TO_END_CONTEXT_ROUTE_REQUIRED']}
            if records.get('unresolved'):
                row['translationEvaluationBlockers'].append('PROJECT_BUILD_RECORDS_UNRESOLVED')
            if clang and context['inspectionReady'] and not records.get('unresolved'):
                try:
                    row['inspection']=acquire(context,clang=clang,target=target)
                    row['status']='inspected'
                except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as exc:
                    row['status']='inspection_failed'
                    row['inspectionFailure']={'type':type(exc).__name__,'detail':str(exc)}
            rows.append(row)
        except (OSError,ValueError,KeyError,TypeError) as exc:
            errors.append({'actionIdentity':action.get('actionIdentity'), 'detail':str(exc)})
    missing=sorted(selected-matched)
    if missing: errors.append({'reasonCode':'PROJECT_SELECTED_SOURCE_NOT_FOUND','sources':missing})
    body={'schemaVersion':'riscv2x86.real-project-context-preflight.v1',
          'buildInventoryIdentity':records['inventoryIdentity'], 'buildRecords':records,
          'records':rows,'errors':errors,'statusCounts':dict(Counter(r['status'] for r in rows)),
          'selection':{'sources':sorted(selected),'limit':limit,'target':target},
          'sourceCount':len({r['context']['sourcePath'] for r in rows}),
          'buildVariantCount':len(rows), 'buildRecordUnresolvedCount':len(records.get('unresolved', [])),
          'semanticApproval':False,'productionAcceptanceComplete':False}
    return dict(body, preflightIdentity=identity(body))


def replay(report):
    if (report.get('schemaVersion')!='riscv2x86.real-project-context-preflight.v1'
            or report.get('preflightIdentity')!=identity({k:v for k,v in report.items() if k!='preflightIdentity'})
            or report.get('semanticApproval') is not False
            or report.get('productionAcceptanceComplete') is not False):
        raise ValueError('PROJECT_PREFLIGHT_INVALID')
    records=report['buildRecords']
    if records['inventoryIdentity'] != report['buildInventoryIdentity']:
        raise ValueError('PROJECT_BUILD_INVENTORY_BINDING_MISMATCH')
    if records['inventoryIdentity'] != identity({k:v for k,v in records.items() if k!='inventoryIdentity'}):
        raise ValueError('PROJECT_BUILD_INVENTORY_INVALID')
    # Replay the recorded file, including physical-line provenance and argv.
    for provenance in {json.dumps(a['provenance'],sort_keys=True):a['provenance'] for a in records['actions']}.values():
        if provenance['kind']=='build-log':
            fresh=import_log(provenance['path'],records['actions'][0]['directory'])
        else: fresh=import_database(provenance['path'])
        if identity(fresh)!=identity(records): raise ValueError('PROJECT_BUILD_RECORD_REPLAY_MISMATCH')
        break
    actions={a['actionIdentity']:a for a in records['actions']}
    expected=inspect(records,target=report['selection']['target'],
                     sources=report['selection']['sources'],limit=report['selection']['limit'])
    if identity([r['context'] for r in expected['records']]) != identity([r['context'] for r in report['records']]):
        raise ValueError('PROJECT_SELECTED_CONTEXT_SET_MISMATCH')
    for row in report['records']:
        if row['status'] not in {'context_ready','blocked','inspected','inspection_failed'}:
            raise ValueError('PROJECT_INSPECTION_STATUS_INVALID')
        if (row['status']=='inspected') != (row['inspection'] is not None):
            raise ValueError('PROJECT_INSPECTION_STATUS_MISMATCH')
        context=row['context']; validate(context)
        if identity(context['originalAction'])!=identity(actions.get(context['actionIdentity'])):
            raise ValueError('PROJECT_CONTEXT_ACTION_BINDING_MISMATCH')
        observation=row['inspection']
        if observation is not None:
            if (observation['inspectionIdentity']!=identity({k:v for k,v in observation.items() if k!='inspectionIdentity'})
                    or observation['contextIdentity']!=context['contextIdentity']):
                raise ValueError('PROJECT_INSPECTION_BINDING_MISMATCH')
            validate_dependencies(observation['snapshot']['dependencyManifest'])
            manifest=observation['snapshot']['dependencyManifest']
            fresh=acquire(context,clang=manifest['compilerCommand'][0],target=report['selection']['target'])
            # Clang's raw AST embeds ephemeral allocation IDs; compare the
            # derived inventories and manifests, not its raw JSON byte digest.
            for key in ('functions','contextIdentity','compilerEquivalenceVerified','semanticApproval',
                        'productionAcceptanceComplete','contextAcquisitionConsistent'):
                if identity(fresh[key])!=identity(observation[key]): raise ValueError('PROJECT_INSPECTION_REPLAY_MISMATCH:'+key)
            for key in ('inventory','functionTypeInventory','dependencyManifest','compilerCommand',
                        'compilerDigest','dependencyClosureVerified','semanticApproval'):
                if identity(fresh['snapshot'][key])!=identity(observation['snapshot'][key]):
                    raise ValueError('PROJECT_INSPECTION_REPLAY_MISMATCH:'+key)
    return {'contextReplayComplete':True,'buildVariantCount':len(report['records']),
            'semanticApproval':False,'productionAcceptanceComplete':False}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__); sub=p.add_subparsers(dest='operation',required=True)
    download=sub.add_parser('download'); download.add_argument('--lock',required=True)
    download.add_argument('--directory',required=True); download.add_argument('--project',action='append',default=[])
    download.add_argument('--attempts',type=int,default=2)
    recipe=sub.add_parser('make-contract'); recipe.add_argument('--context-file',required=True)
    recipe.add_argument('--context-identity'); recipe.add_argument('--profile',required=True); recipe.add_argument('--output',required=True)
    log=sub.add_parser('import-log'); log.add_argument('--log',required=True)
    log.add_argument('--working-directory',required=True); log.add_argument('--output',required=True)
    db=sub.add_parser('import-database'); db.add_argument('--database',required=True); db.add_argument('--output',required=True)
    scan=sub.add_parser('inspect'); scan.add_argument('--records',required=True); scan.add_argument('--output',required=True)
    scan.add_argument('--source',action='append',default=[]); scan.add_argument('--limit',type=int)
    scan.add_argument('--clang'); scan.add_argument('--target',choices=['riscv64','x86_64'],default='riscv64')
    native=sub.add_parser('native-build'); native.add_argument('--report',required=True)
    native.add_argument('--output',required=True); native.add_argument('--timeout-seconds',type=int,default=240)
    audit=sub.add_parser('replay'); audit.add_argument('--report',required=True)
    args=p.parse_args(argv)
    try:
        if args.operation=='make-contract':
            from riscv2x86_py.project_build_contract import make
            value=json.loads(Path(args.context_file).read_text())
            contexts=([r['context'] for r in value['records']] if value.get('schemaVersion')=='riscv2x86.real-project-context-preflight.v1' else [value])
            selected=[c for c in contexts if args.context_identity is None or c['contextIdentity']==args.context_identity]
            if len(selected)!=1:raise ValueError('PROJECT_UNIQUE_CONTEXT_IDENTITY_REQUIRED')
            profile=json.loads(Path(args.profile).read_text())
            fields={'clang','targetCompiler','targetArguments','targetDirectory','sourceDriverArguments','targetDriverArguments'}
            if set(profile)!=fields:raise ValueError('PROJECT_EXPLICIT_BUILD_PROFILE_FIELDS_INVALID')
            result=make(selected[0],clang=profile['clang'],target_compiler=profile['targetCompiler'],
                target_arguments=profile['targetArguments'],target_directory=profile['targetDirectory'],
                source_driver_arguments=profile['sourceDriverArguments'],target_driver_arguments=profile['targetDriverArguments'])
            with Path(args.output).open('x') as stream:json.dump(result,stream,ensure_ascii=False,indent=2)
            print(json.dumps({'contractIdentity':result['contractIdentity'],'semanticApproval':False,'productionAcceptanceComplete':False}))
            return 0
        if args.operation=='download':
            from riscv2x86_py.project_archive_acquisition import fetch
            lock=json.loads(Path(args.lock).read_text()); failures=[]; found=set()
            for source in lock['sources']:
                if args.project and source['id'] not in args.project: continue
                found.add(source['id'])
                try: print(json.dumps(fetch(source,args.directory,attempts=args.attempts)))
                except (OSError,ValueError) as exc:
                    failures.append(source['id']); print(json.dumps({'project':source['id'],'error':str(exc)}))
            if set(args.project)-found: failures.extend(sorted(set(args.project)-found))
            return 2 if failures or not found else 0
        if args.operation=='native-build':
            from riscv2x86_py.project_native_build import build
            report=json.loads(Path(args.report).read_text())
            replay(report)
            if report['buildRecords'].get('unresolved') or report['errors']: raise ValueError('PROJECT_BUILD_RECORDS_UNRESOLVED')
            destination=Path(args.output); destination.mkdir(parents=True,exist_ok=False)
            results=[]
            for index,row in enumerate(report['records']):
                results.append(build(row['context'],destination/str(index),timeout=args.timeout_seconds))
            if not results: raise ValueError('PROJECT_NATIVE_EMPTY_SELECTION')
            print(json.dumps({'nativeCompileCount':len(results),'semanticApproval':False,'productionAcceptanceComplete':False}))
            return 0
        if args.operation=='import-log': result=import_log(args.log,args.working_directory)
        elif args.operation=='import-database': result=import_database(args.database)
        elif args.operation=='inspect':
            if args.limit is not None and args.limit<1: raise ValueError('PROJECT_POSITIVE_LIMIT_REQUIRED')
            result=inspect(json.loads(Path(args.records).read_text()),clang=args.clang,
                           target=args.target,sources=args.source,limit=args.limit)
        else:
            print(json.dumps(replay(json.loads(Path(args.report).read_text())),ensure_ascii=False)); return 0
        # Exclusive create: do not overwrite earlier experimental evidence.
        with Path(args.output).open('x',encoding='utf-8') as stream:
            json.dump(result,stream,ensure_ascii=False,indent=2); stream.write('\n')
        print(json.dumps({k:result[k] for k in ('actionCounts','statusCounts','sourceCount','buildVariantCount',
            'importComplete','semanticApproval','productionAcceptanceComplete') if k in result},ensure_ascii=False))
        return 2 if (result.get('unresolved') or result.get('errors') or result.get('buildRecordUnresolvedCount') or not result.get('actions',result.get('records'))
                     or any(r['status'] in {'blocked','inspection_failed'} for r in result.get('records',[]))) else 0
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        print(json.dumps({'error':type(exc).__name__,'detail':str(exc),'semanticApproval':False}),file=sys.stderr)
        return 2


if __name__=='__main__': raise SystemExit(main())
