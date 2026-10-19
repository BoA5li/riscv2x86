#!/usr/bin/env python3
"""CMake runtime provenance hook; this does not grant a semantic relation."""
import argparse
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'pytools'))
from riscv2x86_py.runtime_build_manifest import write_manifest

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    for name in ('root','archive','compiler','compiler-id','output'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--compiler-flags',default='')
    args=parser.parse_args()
    write_manifest(args.root,args.archive,args.compiler,args.compiler_id,args.output,args.compiler_flags)
