#!/usr/bin/env python3
"""Inspect native/Clang header search for selected captured contexts only."""
import argparse
import json
from pathlib import Path
import sys
import subprocess
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'pytools'))
from riscv2x86_py.project_build_records import identity
from riscv2x86_py.project_header_search import acquire,inspect_search,PROFILE_SCHEMA


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contexts',required=True)
    parser.add_argument('--source',action='append',required=True)
    parser.add_argument('--clang',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--profile-output')
    args=parser.parse_args()
    value=json.loads(Path(args.contexts).read_text())
    if (value.get('schemaVersion')!='riscv2x86.real-project-context-preflight.v1'
            or value.get('preflightIdentity')!=identity({k:v for k,v in value.items() if k!='preflightIdentity'})):
        raise ValueError('PROJECT_HEADER_PREFLIGHT_INVALID')
    selected={str(Path(p).resolve()) for p in args.source};rows=[];contexts=[];matched=set()
    for row in value['records']:
        context=row['context']
        if context.get('sourcePath') not in selected:continue
        matched.add(context['sourcePath']);result={'contextIdentity':context['contextIdentity'],'sourcePath':context['sourcePath']}
        rows.append(result)
        try:
            receipt=acquire(context)
            inspected=inspect_search(receipt,args.clang,'riscv64')
            result.update(status='header_search_matched',nativeHeaderSearch=receipt,inspectionHeaderSearch=inspected)
            contexts.append(context)
        except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as exc:
            result.update(status='blocked',error={'type':type(exc).__name__,'detail':str(exc)})
    missing=sorted(selected-matched)
    result={'schemaVersion':'riscv2x86.project-header-inspection.v1','preflightIdentity':value['preflightIdentity'],
            'records':rows,'missingSources':missing,'semanticApproval':False,'productionAcceptanceComplete':False}
    with Path(args.output).open('x') as stream:json.dump(result,stream,indent=2)
    if args.profile_output:
        if not rows or missing or any(r['status']!='header_search_matched' for r in rows):
            raise ValueError('PROJECT_HEADER_PROFILE_INCOMPLETE')
        profile={'schemaVersion':PROFILE_SCHEMA,'contexts':contexts};profile['profileIdentity']=identity(profile)
        with Path(args.profile_output).open('x') as stream:json.dump(profile,stream,indent=2)
    print(json.dumps({'contextCount':len(rows),'missingSources':missing,
                      'blockedCount':sum(r['status']=='blocked' for r in rows),'semanticApproval':False}))
    return 0 if rows and not missing and all(r['status']=='header_search_matched' for r in rows) else 2


if __name__=='__main__':
    try:raise SystemExit(main())
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        print(json.dumps({'error':type(exc).__name__,'detail':str(exc),'semanticApproval':False}),file=sys.stderr)
        raise SystemExit(2)
