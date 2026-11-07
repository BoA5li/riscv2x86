#!/usr/bin/env python3
"""Collect compiler/runtime provider candidates without executing a test program."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'pytools'))
from riscv2x86_py.native_runtime_basis import collect


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler',action='append',required=True)
    parser.add_argument('--library',action='append',default=[])
    parser.add_argument('--file',action='append',default=[])
    parser.add_argument('--readelf',default='readelf')
    parser.add_argument('--output',required=True)
    args=parser.parse_args(argv)
    try:
        # Reserve output first; never truncate old evidence, even on failure.
        with Path(args.output).open('x',encoding='utf-8') as stream:
            try:
                result=collect(args.compiler,args.library,args.file,args.readelf)
            except (OSError,ValueError,subprocess.SubprocessError) as exc:
                json.dump({'status':'failed','errorType':type(exc).__name__,'detail':str(exc),
                    'semanticApproval':False,'productionAcceptanceComplete':False},stream,indent=2)
                raise
            json.dump(result,stream,ensure_ascii=False,indent=2);stream.write('\n')
        print(json.dumps({'output':args.output,'candidateCount':len(result['candidates']),
            'blockerCount':len(result['blockers']),'status':'inventory-only',
            'semanticApproval':False,'productionAcceptanceComplete':False}))
        return 0
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        print(json.dumps({'error':type(exc).__name__,'detail':str(exc)}),file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
