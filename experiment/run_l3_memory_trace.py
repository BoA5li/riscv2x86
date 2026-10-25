#!/usr/bin/env python3
"""Require normal-production L0-L3 closure for an explicitly selected input set.

The bounded route supports compiler-bound ordinary reads and writes. An unsupported selection
remains a rejection; this driver never derives success from an exit code alone.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def batch_diagnostics(batch_root, batch):
    """Retain case failures without accepting paths outside the batch tree."""
    root = Path(batch_root).resolve()
    cases = batch['cases']
    if not isinstance(cases, list) or not cases:
        raise ValueError('L3_TRACE_BATCH_CASES_EMPTY_OR_INVALID')
    records = []
    for case in cases:
        path = (root / case['resultPath']).resolve()
        if root not in path.parents:
            raise ValueError('L3_TRACE_RESULT_PATH_OUTSIDE_BATCH')
        report = json.loads(path.read_text())
        records.append({
            'caseId': case['caseId'], 'reportPath': str(path),
            'status': report.get('status'),
            'reasonCodes': report.get('reasonCodes', []),
            'detail': report.get('detail'),
            'orchestrationFailure': report.get('orchestrationFailure'),
            'requirementStagingFailure': report.get('requirementStagingFailure'),
            'attempts': [{
                'translationOutcome': attempt.get('translationOutcome'),
                'status': attempt.get('status'),
                'reasonCodes': attempt.get('reasonCodes', []),
                'layers': (attempt.get('validation') or {}).get('layers', []),
            } for attempt in report.get('attempts', [])],
        })
    return records


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
        status['batchLogPath'] = str(output/'batch.log')
        status['currentStage'] = 'normal_production_result';write()
        summary = output/'batch/batch-evaluation.json'
        if not summary.is_file():
            reason = ('L3_TRACE_PRODUCTION_FAILED_WITHOUT_SUMMARY' if result.returncode
                      else 'L3_TRACE_PRODUCTION_SUMMARY_MISSING')
            raise ValueError(reason)
        batch = json.loads(summary.read_text())
        status['caseDiagnostics'] = batch_diagnostics(output/'batch', batch)
        write()
        if result.returncode:
            raise ValueError('L3_TRACE_NORMAL_PRODUCTION_FAILED')
        status['currentStage']='independent_acceptance';write()
        records=[]
        for case in status['caseDiagnostics']:
            path=Path(case['reportPath'])
            audited = audit_evaluation(json.loads(path.read_text()))
            if audited.get('status') != 'verified':
                raise ValueError('L3_TRACE_INDEPENDENT_ACCEPTANCE_NOT_VERIFIED')
            records.append(dict(audited,caseId=case['caseId'],reportPath=str(path)))
        status.update(currentStage='complete',productionAcceptanceComplete=True,acceptance=records,
                      observationScope='compiler-asm-region-only',cacheModelSelected=bool(args.cache_model))
        write();print(json.dumps(status,ensure_ascii=False));return 0
    except (OSError,ValueError,KeyError,TypeError) as exc:
        status['blockers'].append(str(exc));write()
        print(json.dumps(status,ensure_ascii=False));return 2


if __name__=='__main__':
    raise SystemExit(main())
