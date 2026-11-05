#!/usr/bin/env python3
"""Read-only original-project dependency check; no semantic approval."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'pytools'))
from riscv2x86_py.project_acquisition import preflight


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',choices=('gmp','linux'),action='append',required=True)
    parser.add_argument('--output')
    args=parser.parse_args()
    rows=[preflight(p) for p in dict.fromkeys(args.project)]
    value={'schemaVersion':'riscv2x86.project-build-prerequisites.v1','projects':rows,
           'semanticApproval':False,'productionAcceptanceComplete':False}
    if args.output:
        with Path(args.output).open('x') as stream:json.dump(value,stream,indent=2)
    print(json.dumps(value,indent=2))
    return 0 if all(r['prerequisitesAvailable'] for r in rows) else 2


if __name__=='__main__':raise SystemExit(main())
