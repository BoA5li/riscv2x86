#!/usr/bin/env python3
"""Require normal-production L0-L3 closure for an explicitly selected input set.

The first route supports compiler-bound ordinary reads. An unsupported selection
remains a rejection; this driver never derives success from an exit code alone.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',required=True,help='C file or explicitly selected corpus directory')
    parser.add_argument('--frontend',required=True)
    parser.add_argument('--backend',required=True)
    parser.add_argument('--cache-model')
    parser.add_argument('--output',required=True)
    parser.add_argument('--timeout-seconds',type=int,default=180)
    args=parser.parse_args()
    output=Path(args.output).resolve()
    if output.exists():
        print(json.dumps({'reasonCode':'L3_TRACE_OUTPUT_EXISTS','output':str(output)}));return 2
    output.mkdir(parents=True)
    status={'schemaVersion':'riscv2x86.l3-trace-production-run.v1','steps':[],
        'productionAcceptanceComplete':False,'currentStage':'input_validation','blockers':[],
        'claimScope':'bounded-compiler-asm-region-memory-stream',
        'physicalMicroarchitectureClaimed':False,'fullCorpusCoverageClaimed':False}
    def write():
        (output/'run-status.json').write_text(json.dumps(status,indent=2,ensure_ascii=False))
    write()
    try:
        from riscv2x86_py.l3_qemu_backend import validate_backend
        from riscv2x86_py.l3_production_acceptance import audit_evaluation
        from riscv2x86_py.l3_trace_support import digest
        backend=validate_backend(args.backend)
        if args.timeout_seconds<=0:raise ValueError('L3_TRACE_TIMEOUT_INVALID')
        source=Path(args.input).resolve();frontend=Path(args.frontend).resolve()
        if not source.exists() or not frontend.is_file():raise ValueError('L3_TRACE_INPUT_OR_FRONTEND_MISSING')
        status.update(backendIdentity=backend['backendIdentity'],backendManifestDigest=digest(args.backend),
                      frontendDigest=digest(frontend),currentStage='normal_production')
        command=[sys.executable,'-m','riscv2x86_py.automatic_batch_cli','--input',str(source),
            '--frontend',str(frontend),'--output-directory',str(output/'batch'),'--jobs','1',
            '--timeout-seconds',str(args.timeout_seconds),'--l3-memory-backend',str(Path(args.backend).resolve()),'--require-l3']
        if args.cache_model:command.extend(['--l3-cache-model',str(Path(args.cache_model).resolve())])
        write()
        with (output/'batch.log').open('w') as log:
            result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=False)
        status['steps'].append({'stage':'normal_production','command':command,'returnCode':result.returncode})
        status['currentStage']='independent_acceptance';write()
        batch=json.loads((output/'batch/batch-evaluation.json').read_text())
        records=[]
        for case in batch['cases']:
            path=output/'batch'/case['resultPath']
            records.append(dict(audit_evaluation(json.loads(path.read_text())),caseId=case['caseId'],reportPath=str(path)))
        if result.returncode or not records:raise ValueError('L3_TRACE_REQUIRED_PRODUCTION_INCOMPLETE')
        status.update(currentStage='complete',productionAcceptanceComplete=True,acceptance=records,
                      observationScope='compiler-asm-region-only',cacheModelSelected=bool(args.cache_model))
        write();print(json.dumps(status,ensure_ascii=False));return 0
    except (OSError,ValueError,KeyError,TypeError) as exc:
        status['blockers'].append(str(exc));write()
        print(json.dumps(status,ensure_ascii=False));return 2


if __name__=='__main__':
    raise SystemExit(main())
