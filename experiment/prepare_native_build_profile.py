#!/usr/bin/env python3
"""Create an explicit source/target GMP build profile, without ABI approval."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'pytools'))
from riscv2x86_py.project_build_profile import create, validate, ROLES


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    make = sub.add_parser('create');make.add_argument('--side', choices=('source','target'), required=True)
    make.add_argument('--host', required=True);make.add_argument('--cflags', required=True)
    for role in ROLES:make.add_argument('--'+role, required=True)
    make.add_argument('--output', required=True)
    check = sub.add_parser('check');check.add_argument('--input', required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == 'create':
            value = create(args.side, args.host, {k:getattr(args,k) for k in ROLES}, args.cflags)
            with Path(args.output).open('x') as stream:json.dump(value, stream, indent=2);stream.write('\n')
        else:
            value = validate(json.loads(Path(args.input).read_text()))
        print(json.dumps(value));return 0
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        print(json.dumps({'error':type(exc).__name__,'detail':str(exc),'semanticApproval':False}), file=sys.stderr)
        return 2


if __name__ == '__main__':raise SystemExit(main())
