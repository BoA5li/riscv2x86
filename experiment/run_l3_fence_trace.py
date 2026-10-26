#!/usr/bin/env python3
"""Run real fence regions and independently audit the result."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
from riscv2x86_py.l3_status import write_status_atomic, record_failure


def main():
    p=argparse.ArgumentParser();p.add_argument('--input',required=True);p.add_argument('--frontend',required=True);p.add_argument('--backend',required=True);p.add_argument('--output',required=True);p.add_argument('--timeout-seconds',type=int,default=240);a=p.parse_args()
    out=Path(a.output).resolve()
    if out.exists():print(json.dumps({'reasonCode':'L3_FENCE_OUTPUT_EXISTS','output':str(out)}));return 2
    out.mkdir(parents=True)
    status={'schemaVersion':'riscv2x86.fence-production-run.v1','currentStage':'input_validation','steps':[],
        'executionComplete':False,'independentResultAuditComplete':False,'productionAcceptanceComplete':False,
        'physicalMicroarchitectureClaimed':False,'blockers':[]}
    def write(): write_status_atomic(out/'run-status.json',status)
    try:
        write()
        from riscv2x86_py.l3_fence_backend import validate
        from riscv2x86_py.l3_trace_support import digest
        validate(a.backend)
        if a.timeout_seconds<=0:raise ValueError('L3_FENCE_TIMEOUT_INVALID')
        status.update(currentStage='normal_production',backendDigest=digest(a.backend),frontendDigest=digest(a.frontend));write()
        cmd=[sys.executable,'-m','riscv2x86_py.automatic_batch_cli','--input',str(Path(a.input).resolve()),'--frontend',str(Path(a.frontend).resolve()),'--output-directory',str(out/'batch'),'--jobs','1','--timeout-seconds',str(a.timeout_seconds),'--l3-fence-backend',str(Path(a.backend).resolve()),'--require-l3']
        with (out/'batch.log').open('w') as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,check=False)
        status['steps'].append({'stage':'normal_production','command':cmd,'returnCode':r.returncode});write()
        if not (out/'batch/batch-evaluation.json').is_file():
            status['normalProductionLogTail']=(out/'batch.log').read_text(errors='replace')[-12000:]
            raise ValueError('L3_FENCE_NORMAL_PRODUCTION_REPORT_MISSING:exit='+str(r.returncode))
        status['currentStage']='independent_result_audit';write()
        from run_l3_memory_trace import batch_diagnostics
        batch=json.loads((out/'batch/batch-evaluation.json').read_text());cases=batch_diagnostics(out/'batch',batch);status['caseDiagnostics']=cases;write()
        from riscv2x86_py.l3_fence_route import audit_result
        audits=[]
        for case in cases:audits.append(dict(audit_result(json.loads(Path(case['reportPath']).read_text())),caseId=case['caseId'],reportPath=case['reportPath']))
        complete=bool(audits) and all(x['independentResultAuditComplete'] for x in audits)
        accepted=complete and all(x['status']=='verified' for x in audits)
        if (accepted and r.returncode!=0) or (not accepted and r.returncode==0):raise ValueError('L3_FENCE_BATCH_EXIT_STATUS_MISMATCH')
        status.update(currentStage='complete',executionComplete=complete,independentResultAuditComplete=complete,
            productionAcceptanceComplete=accepted,acceptance=audits)
        if not accepted:status['blockers']=['L3_FENCE_PROPERTY_COUNTEREXAMPLE']
        write();print(json.dumps(status,ensure_ascii=False));return 0 if accepted else 1
    except (OSError,ValueError,KeyError,TypeError) as exc:
        status['blockers'].append(str(exc))
        record_failure(out/'run-status.json',status,exc,stage_key='currentStage',
                       completion_keys=('productionAcceptanceComplete',))
        print(json.dumps(status,ensure_ascii=False));return 2

if __name__=='__main__':raise SystemExit(main())
