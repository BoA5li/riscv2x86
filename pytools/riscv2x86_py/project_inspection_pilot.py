"""Execute an explicitly frozen compiler-inspection pilot, not L0--L3.

Run exactly the declared sources/all their captured variants, verify member
closure, then independently replay the contextual report. No asm eligibility or
semantic acceptance is inferred from successful parsing or zero asm counts.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys

from .project_acquisition import Runner, StageFailure
from .project_build_records import identity
from .project_compile_context import digest


def load_plan(path):
    path=Path(path).resolve(strict=True);before=digest(path);value=json.loads(path.read_text())
    if (not isinstance(value,dict) or value.get('purpose')!='compiler-acquisition-pilot-only'
            or not isinstance(value.get('sourcePaths'),list) or not value['sourcePaths']
            or not isinstance(value.get('contextIdentities'),list) or not value['contextIdentities']
            or value.get('semanticApproval') is not False):
        raise ValueError('PROJECT_INSPECTION_PILOT_PLAN_INVALID')
    sources=value['sourcePaths'];contexts=value['contextIdentities']
    if (any(not isinstance(s,str) or not Path(s).is_absolute() or not Path(s).is_file() for s in sources)
            or len(set(sources))!=len(sources) or len(set(contexts))!=len(contexts)
            or any(not isinstance(s,str) or len(s)!=71 or not s.startswith('sha256:') for s in contexts)):
        raise ValueError('PROJECT_INSPECTION_PILOT_MEMBER_SET_INVALID')
    if digest(path)!=before:raise ValueError('PROJECT_INSPECTION_PILOT_PLAN_CHANGED')
    return value,before


def verify_members(report,plan):
    if (report.get('schemaVersion')!='riscv2x86.real-project-context-preflight.v1'
            or report.get('preflightIdentity')!=identity({k:v for k,v in report.items() if k!='preflightIdentity'})
            or report.get('semanticApproval') is not False or report.get('productionAcceptanceComplete') is not False
            or report.get('errors')):
        raise ValueError('PROJECT_INSPECTION_PILOT_REPORT_INVALID')
    rows=report['records'];actual=[r['context']['contextIdentity'] for r in rows]
    if (len(actual)!=len(set(actual)) or set(actual)!=set(plan['contextIdentities'])
            or {r['context']['sourcePath'] for r in rows}!=set(plan['sourcePaths'])):
        raise ValueError('PROJECT_INSPECTION_PILOT_MEMBER_CLOSURE_MISMATCH')
    if any(r['status']!='inspected' or not r.get('inspection')
           or r['inspection'].get('contextAcquisitionConsistent') is not True for r in rows):
        raise ValueError('PROJECT_INSPECTION_PILOT_ACQUISITION_REQUIRED')
    return {'contextCount':len(rows),'statusCounts':dict(Counter(r['status'] for r in rows)),
        'primaryFunctionCount':sum(len(r['inspection']['functions']) for r in rows),
        'primaryFunctionsWithAsmSyntax':sum('GCCAsmStmt' in f.get('effectSyntax',[])
            for r in rows for f in r['inspection']['functions']),
        'asmInstanceInventoryComplete':False,'endToEndEligibilityAssessed':False,
        'semanticApproval':False,'productionAcceptanceComplete':False}


def execute(tooling,records,plan,clang,output):
    runner=Runner(output,'compiler-inspection-pilot')
    runner.state.update(schemaVersion='riscv2x86.project-inspection-pilot-run.v1',
        compilerInspectionComplete=False,independentContextReplayComplete=False,
        asmInstanceInventoryComplete=False,endToEndEligibilityAssessed=False,
        pilotImplementation={'module':str(Path(__file__).resolve()),'digest':digest(__file__)})
    runner.save()
    try:
        tooling=Path(tooling).resolve(strict=True);records=Path(records).resolve(strict=True);plan=Path(plan).resolve(strict=True)
        runner.state['currentStage']='plan';value,plan_digest=load_plan(plan)
        program_path=tooling/'experiment/prepare_real_project_experiment.py'
        inputs={str(plan):plan_digest,str(records):digest(records),str(program_path):digest(program_path)}
        runner.state['inputs']=inputs;runner.save()
        (runner.output/'pilot-plan.json').write_text(json.dumps(value,indent=2)+'\n')
        program=[sys.executable,str(tooling/'experiment/prepare_real_project_experiment.py')]
        command=[*program,'inspect','--records',str(records),'--clang',clang,'--target','riscv64',
                 '--output',str(runner.output/'contexts.json')]
        for source in value['sourcePaths']:command+=['--source',source]
        runner.step('inspect',command)
        runner.state['currentStage']='member-closure';runner.save()
        report_path=runner.output/'contexts.json';report_digest=digest(report_path)
        summary=verify_members(json.loads(report_path.read_text()),value)
        runner.state['compilerInspectionComplete']=True;runner.save()
        log=runner.step('replay',[*program,'replay','--report',str(report_path)])
        replay=json.loads(log.read_text())
        if (replay.get('contextReplayComplete') is not True or type(replay.get('buildVariantCount')) is not int
                or replay.get('buildVariantCount')!=summary['contextCount']
                or replay.get('semanticApproval') is not False or replay.get('productionAcceptanceComplete') is not False):
            raise ValueError('PROJECT_INSPECTION_PILOT_REPLAY_INCOMPLETE')
        if any(digest(p)!=h for p,h in inputs.items()) or digest(report_path)!=report_digest:
            raise ValueError('PROJECT_INSPECTION_PILOT_INPUT_CHANGED')
        (runner.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
        runner.state.update(currentStage='complete',status='complete',acquisitionComplete=True,
                            independentContextReplayComplete=True)
        runner.save();print(json.dumps(summary));return 0
    except StageFailure as exc:
        return exc.code if exc.code>=0 else 128-exc.code
    except (OSError,ValueError,KeyError,TypeError) as exc:
        runner.failure(runner.state['currentStage'],exc);return 2


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('tooling','records','plan','clang','output'):parser.add_argument('--'+name,required=True)
    args=parser.parse_args(argv)
    try:return execute(**vars(args))
    except OSError as exc:
        print(json.dumps({'error':type(exc).__name__,'detail':str(exc),'semanticApproval':False}),file=sys.stderr)
        return 2
