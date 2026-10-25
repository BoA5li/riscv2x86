"""Opt-in real frontend/build/execution/central L2 closure for literal inputs."""
import json
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize('operation,constant',[('addi',67),('slli',18),('addi',-7)])
def test_real_renamed_literal_production(tmp_path,operation,constant):
    from tests.test_l2_real_production_chain import _tools,_case_failure_details
    frontend=_tools()
    inputs=tmp_path/'inputs';inputs.mkdir();source=inputs/'unrelated_literal.c'
    source.write_text('#include <stdint.h>\nuint64_t independent_literal(uint64_t x){uint64_t result;\n'
        f'__asm__ volatile("{operation} %[dst],%[src],%[imm]" : [dst] "=r"(result) : [src] "r"(x),[imm] "i"({constant}));\n'
        'return result;}\n')
    output=tmp_path/'production'
    completed=subprocess.run([sys.executable,'-m','riscv2x86_py.automatic_batch_cli',
        '--input',str(source),'--frontend',frontend,'--output-directory',str(output),'--jobs','1',
        '--timeout-seconds','180'],capture_output=True,text=True,check=False,timeout=1200)
    assert completed.returncode==0,completed.stdout+completed.stderr+_case_failure_details(output)
    paths=list(output.glob('cases/*/evaluation-result.json'));assert len(paths)==1
    report=json.loads(paths[0].read_text());assert report['status']=='verified',json.dumps(report)
    attempts=report['attempts'];assert len(attempts)==1
    layers=attempts[0]['validation']['layers']
    assert all(next(x for x in layers if x['level']==level)['status']=='verified' for level in ('L0','L1','L2'))
    assert next((x for x in layers if x['level']=='L3'),{}).get('status')!='verified'
    translations=list(output.glob('cases/*/work/translation-work/translated_report.json'));assert len(translations)==1
    finding=json.loads(translations[0].read_text())['findings'][0]
    a=finding['approvalArtifact'];sidecar=a['l2AuthoritySidecar']
    assert sidecar['schemaVersion']=='riscv2x86.l2-authority-sidecar.v6'
    assert sidecar['operands'][2]['staticOperand']['value']==constant
    assert sidecar['operands'][2]['declarationId']==''
    assert sidecar['operandObservationAuthority']['bindings'][2]['closureKind']=='compiler_constant'

    from riscv2x86_py.l2_authority import l2_authority_sidecar_from_dict
    from riscv2x86_py.compiler_provenance import bind_compiler_provenance
    from riscv2x86_py.l2_evidence_reader import read_l2_fragment_results
    parsed=l2_authority_sidecar_from_dict(sidecar)
    assert bind_compiler_provenance(finding['fragment'],parsed)==a['compilerAuthorityConsumption']
    requirements=json.loads(Path(str(translations[0])+'.l2-requirements.json').read_text())
    fragments=read_l2_fragment_results(report,requirements)
    assert fragments
    for _attempt,result in fragments:
        dimensions=result.to_dict()['dimensionResults']
        assert set(dimensions)=={'logical_operands','shell_semantics'}
        assert all(value['status']=='verified' for value in dimensions.values())
