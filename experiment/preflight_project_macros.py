#!/usr/bin/env python3
"""Source-bound qualification and native CPP evidence; not translation approval."""
from pathlib import Path
import argparse
import json
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'pytools'))

from riscv2x86_py.project_activation_batches import write_new
from riscv2x86_py.project_instance_eligibility import acquire as eligibility, validate
from riscv2x86_py.project_native_macro_preflight import acquire, replay
from riscv2x86_py.project_acquisition import StageFailure
from riscv2x86_py.gnu_operand_relations import derive


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='operation',required=True)
    ledger=sub.add_parser('eligibility')
    for name in ('plan','result-root','ledger','output'):ledger.add_argument('--'+name,required=True)
    verify=sub.add_parser('verify-eligibility');verify.add_argument('--input',required=True)
    capture=sub.add_parser('capture')
    for name in ('eligibility','context-identity','output'):capture.add_argument('--'+name,required=True)
    capture.add_argument('--timeout-seconds',type=int,default=120)
    audit=sub.add_parser('replay')
    for name in ('eligibility','receipt','output'):audit.add_argument('--'+name,required=True)
    audit.add_argument('--timeout-seconds',type=int,default=120)
    relation=sub.add_parser('relations')
    relation.add_argument('--constraints',required=True);relation.add_argument('--output',required=True)
    args=parser.parse_args(argv)
    def read(p):return json.loads(Path(p).read_text())
    try:
        if args.operation=='eligibility':
            result=eligibility(args.plan,args.result_root,args.ledger);write_new(args.output,result)
            print(json.dumps({k:result[k] for k in ('occurrenceCount','definitionSliceCount','statusCounts',
                'firstBlockerCounts','recordedInspectionAstCoverageComplete','semanticApproval','productionAcceptanceComplete')}))
        elif args.operation=='verify-eligibility':
            value=validate(read(args.input));print(json.dumps({'eligibilityReplayComplete':True,
                'occurrenceCount':value['occurrenceCount'],'semanticApproval':False,'productionAcceptanceComplete':False}))
        elif args.operation=='capture':
            result=acquire(read(args.eligibility),args.context_identity,args.output,args.timeout_seconds)
            print(json.dumps({k:result[k] for k in ('contextIdentity','sourcePreprocessingMatched',
                'nativePreprocessingComplete','firstDifference','semanticApproval','productionAcceptanceComplete')}))
        elif args.operation=='replay':
            print(json.dumps(replay(read(args.receipt),read(args.eligibility),args.output,args.timeout_seconds)))
        else:
            value=read(args.constraints)
            if set(value)!={'outputs','inputs'}:raise ValueError('GNU_RELATION_FIELDS_INVALID')
            result=derive(value['outputs'],value['inputs']);write_new(args.output,result);print(json.dumps(result))
        return 0
    except StageFailure as exc:return exc.code if exc.code>=0 else 128-exc.code
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        print(json.dumps({'error':type(exc).__name__,'detail':str(exc),'semanticApproval':False}),file=sys.stderr)
        return 2


if __name__=='__main__':raise SystemExit(main())
