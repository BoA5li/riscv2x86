#!/usr/bin/env python3
"""Seal existing experiment inputs; this tool never approves semantic claims."""
import argparse
import json
from pathlib import Path
from riscv2x86_py.experiment_environment import DIRECTORIES, seal_environment
from riscv2x86_py.csr_architecture_profile import TEMPLATE_SCHEMA
from riscv2x86_py.route_authority import content_identity


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--environment-id',required=True)
    parser.add_argument('--privilege-spec',choices=['riscv-privileged-1.12','riscv-privileged-1.13'])
    parser.add_argument('--xlen',type=int,choices=[32,64])
    parser.add_argument('--extensions',nargs='+')
    for name in DIRECTORIES:parser.add_argument('--'+name.replace('_','-'),type=Path)
    args=parser.parse_args()
    try:
        selected=(args.privilege_spec,args.xlen,args.extensions)
        if any(x is not None for x in selected) and any(x is None for x in selected):
            raise ValueError('Specify privilege-spec, xlen and extensions together')
        template=None
        if args.privilege_spec:
            template={'schemaVersion':TEMPLATE_SCHEMA,'privilegeSpecVersion':args.privilege_spec,
                'xlenBits':args.xlen,'extensions':sorted(set(args.extensions))}
            template['templateIdentity']=content_identity(template)
        directories={k:getattr(args,k) for k in DIRECTORIES if getattr(args,k) is not None}
        if template is not None and 'csr_architecture_directory' in directories:
            raise ValueError('Architecture template conflicts with architecture directory')
        if not args.environment_id:raise ValueError('environment-id must be nonempty')
        value=seal_environment(source=args.source,directories=directories,
            environment_id=args.environment_id,architecture_template=template)
        with args.output.open('x') as handle:handle.write(json.dumps(value,indent=2,sort_keys=True)+'\n')
        print(json.dumps({'artifactPath':str(args.output),'manifestIdentity':value['manifestIdentity'],
            'semanticApproval':False}))
        return 0
    except (OSError,ValueError,TypeError) as exc:
        print(json.dumps({'failureStage':'environment_sealing','exceptionType':type(exc).__name__,
            'detail':str(exc),'semanticApproval':False}))
        return 2


if __name__=='__main__':raise SystemExit(main())
