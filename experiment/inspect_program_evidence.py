#!/usr/bin/env python3
"""Acquire bounded program proof components; never issue program acceptance."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'pytools'))


def main(argv=None):
    from riscv2x86_py import program_machine_evidence as machine,program_object_evidence as objects
    from riscv2x86_py import program_validation_obligations as plan
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    m=sub.add_parser('machine');m.add_argument('--elf',required=True);m.add_argument('--symbol',required=True)
    o=sub.add_parser('objects');o.add_argument('--model',required=True)
    p=sub.add_parser('plan');p.add_argument('--translation',required=True);p.add_argument('--scope',required=True)
    c=sub.add_parser('check');c.add_argument('--input',required=True)
    for cmd in (m,o,p):cmd.add_argument('--output',required=True)
    args=parser.parse_args(argv)
    try:
        if args.command=='machine':value=machine.acquire(args.elf,args.symbol,args.output)
        elif args.command=='objects':value=objects.acquire(args.model,args.output)
        elif args.command=='plan':value=plan.acquire(args.translation,args.scope,args.output)
        else:
            raw=json.loads(Path(args.input).read_text())
            value={machine.SCHEMA:machine.check,objects.SCHEMA:objects.check,plan.SCHEMA:plan.check}[raw['schemaVersion']](args.input)
        print(json.dumps({'schemaVersion':value['schemaVersion'],'facts':value['facts'],
                          'semanticApproval':False,'productionAcceptanceComplete':False}));return 0
    except Exception as exc:
        print(json.dumps({'error':type(exc).__name__,'detail':str(exc),'semanticApproval':False,'productionAcceptanceComplete':False}));return 2


if __name__=='__main__':raise SystemExit(main())
