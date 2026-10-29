"""Opt-in real frontend, L0-L3 and one-capture independent joint acceptance."""
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest


@pytest.mark.parametrize('pointer',[0,1])
@pytest.mark.parametrize('operation',['add','xor','and','or'])
def test_real_joint_load_scalar_store_and_audit(tmp_path,pointer,operation):
    backend=os.environ.get('RV2X86_L3_JOINT_BACKEND')
    if not backend:pytest.skip('explicit freshly calibrated joint backend required')
    frontend=os.environ.get('RISCV2X86_TEST_FRONTEND');assert frontend and Path(frontend).is_file()
    inputs=tmp_path/'inputs';inputs.mkdir();source=inputs/'independent.c'
    args='uint64_t *address,uint64_t input' if pointer==0 else 'uint64_t input,uint64_t *address'
    source.write_text('#include <stdint.h>\nuint64_t independently_named('+args+'){uint64_t loaded,result;\n'
        '__asm__ volatile("ld %0,8(%1)":"=r"(loaded):"r"(address):"memory");\n'
        '__asm__ volatile("'+operation+' %0,%1,%2":"=r"(result):"r"(loaded),"r"(input):"cc");\n'
        '__asm__ volatile("sd %0,16(%1)"::"r"(result),"r"(address):"memory");\nreturn result;}\n')
    repo=Path(__file__).resolve().parents[2];output=tmp_path/'production'
    done=subprocess.run([sys.executable,str(repo/'experiment/run_l3_joint_trace.py'),'--input',str(source),
        '--frontend',frontend,'--backend',backend,'--timeout-seconds','240','--l3-producer-timeout-seconds','600',
        '--output',str(output)],capture_output=True,text=True,check=False,timeout=3600)
    logs='\n'.join(str(p)+':\n'+p.read_text(errors='replace')[-12000:] for p in output.glob('*.log'))
    assert done.returncode==0,done.stdout+done.stderr+logs
    state=json.loads((output/'run-status.json').read_text())
    assert all(state[k] is True for k in ('executionComplete','independentResultAuditComplete','productionAcceptanceComplete'))
    paths=list(output.glob('batch/cases/*/evaluation-result.json'));assert len(paths)==1
    report=json.loads(paths[0].read_text());assert len(report['attempts'])==3
    from riscv2x86_py.l3_joint_route import audit_result
    from riscv2x86_py.l3_production_acceptance import audit_evaluation
    audit=audit_result(report);assert audit['status']=='verified' and audit['captureGroupCount']==1
    assert audit_evaluation(report)['programExecutionUnitCount']==1
    groups=set();units=set()
    for attempt in report['attempts']:
        assert [x['status'] for x in attempt['validation']['layers']]==['verified']*4
        d=json.loads(attempt['validation']['layers'][3]['detail']);groups.add(d['jointCapturePath'])
        units.update(v['executionIdentity'] for v in d['fragmentResult']['dimensionResults'].values())
    assert len(groups)==len(units)==1
    group=json.loads(Path(next(iter(groups))).read_text())
    for side in ('source','target'):
        assert len(group['reports'][side]['samples'])==8
        assert len(group['reports'][side]['events'])==16
        for index,offset,access in ((0,8,'read'),(2,16,'write')):
            for event in (e for e in group['reports'][side]['events'] if e['region']==index):
                row=group['reports'][side]['samples'][event['sample']]
                assert event['address']-int(row['objectBase'],16)==offset and event['size']==8 and event['access']==access
    missing=json.loads(json.dumps(report));missing['attempts'].pop()
    with pytest.raises(ValueError):audit_evaluation(missing)
    trace=Path(group['reports']['source']['evidence']['rawTracePath'])
    trace.write_text(trace.read_text().replace(' 8 W',' 8 R',1))
    with pytest.raises(ValueError):audit_evaluation(report)


@pytest.mark.parametrize('arity,regions',[(1,2),(3,3),(4,3),(2,16)])
def test_real_joint_declared_call_and_region_boundaries(tmp_path,arity,regions):
    backend=os.environ.get('RV2X86_L3_JOINT_BACKEND')
    if not backend:pytest.skip('explicit freshly calibrated joint backend required')
    frontend=os.environ.get('RISCV2X86_TEST_FRONTEND');assert frontend and Path(frontend).is_file()
    # Single-file inputs use their parent as sourceRoot. Keep production
    # artifacts outside that tree, as required by run_evaluation().
    inputs=tmp_path/'inputs';inputs.mkdir();source=inputs/'boundary.c'
    parameters=['uint64_t *address']+['uint64_t input'+str(i) for i in range(arity-1)]
    variables=['value'+str(i) for i in range(regions-1)]
    statements=['__asm__ volatile("ld %0,8(%1)":"=r"(value0):"r"(address):"memory");']
    for i in range(1,regions-1):
        instructions=['add %0,%1,%2']+['add %0,%0,%'+str(j+2) for j in range(1,arity-1)]
        inputs=['"r"('+variables[i-1]+')']+['"r"(input'+str(j)+')' for j in range(arity-1)]
        statements.append('__asm__ volatile("'+';'.join(instructions)+'":"=&r"('+variables[i]+'):'+','.join(inputs)+':"cc");')
    statements.append('__asm__ volatile("sd %0,16(%1)"::"r"('+variables[-1]+'),"r"(address):"memory");')
    source.write_text('#include <stdint.h>\nuint64_t boundary_probe('+','.join(parameters)+'){\nuint64_t '+','.join(variables)+';\n'
        +'\n'.join(statements)+'\nreturn '+variables[-1]+';\n}\n')
    repo=Path(__file__).resolve().parents[2];output=tmp_path/'production'
    done=subprocess.run([sys.executable,str(repo/'experiment/run_l3_joint_trace.py'),'--input',str(source),
        '--frontend',frontend,'--backend',backend,'--timeout-seconds','240','--l3-producer-timeout-seconds','600',
        '--output',str(output)],capture_output=True,text=True,check=False,timeout=7200)
    logs='\n'.join(p.read_text(errors='replace')[-12000:] for p in output.glob('*.log'))
    assert done.returncode==0,done.stdout+done.stderr+logs
    report=json.loads(next(output.glob('batch/cases/*/evaluation-result.json')).read_text())
    assert len(report['attempts'])==regions
    from riscv2x86_py.l3_production_acceptance import audit_evaluation
    assert audit_evaluation(report)['status']=='verified'
