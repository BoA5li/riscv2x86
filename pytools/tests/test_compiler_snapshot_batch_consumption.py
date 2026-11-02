"""Batch provenance consumption preserves every single-member gate."""
import json
from pathlib import Path
import pytest
from tests.test_l3_joint_program import fixture
from riscv2x86_py.compiler_value_flow import identity
from riscv2x86_py import mechanism_route_checks as checks


def inputs(tmp_path):
    source,findings,fn=fixture(tmp_path,multi_object=True,reload_after_store=True,reuse_output=True)
    path=tmp_path/'joint.c';path.write_bytes(source);report=tmp_path/'translated_report.json'
    report.write_text(json.dumps({'findings':findings}))
    snapshot={'schemaVersion':'riscv2x86.compiler-candidates.v1','sourceDigest':fn['sourceDigest'],
        'frontendReportIdentity':identity('synthetic frontend'),'functions':[fn]}
    snapshot['manifestIdentity']=identity(snapshot)
    report.with_name('compiler-candidates.json').write_text(json.dumps(snapshot))
    return path,report,findings


def test_batch_consumes_identical_members_and_reads_documents_once(tmp_path,monkeypatch):
    path,report,findings=inputs(tmp_path)
    single=[checks.compiler_bound_finding(path,report,f['fragment']['id'])[0] for f in findings]
    read=Path.read_text;counts={}
    def counted(self,*a,**kw):counts[str(self)]=counts.get(str(self),0)+1;return read(self,*a,**kw)
    monkeypatch.setattr(Path,'read_text',counted)
    actual,snapshot=checks.compiler_bound_findings(path,report)
    assert actual==single
    assert counts[str(report)]==1 and counts[str(report.with_name('compiler-candidates.json'))]==1


@pytest.mark.parametrize('changed',['source','report','snapshot'])
def test_batch_closing_check_rejects_mutation_during_consumption(tmp_path,monkeypatch,changed):
    path,report,findings=inputs(tmp_path);original=checks._compiler_bound_from_snapshot;calls=[]
    selected={'source':path,'report':report,'snapshot':report.with_name('compiler-candidates.json')}[changed]
    def mutate(*args):
        result=original(*args);calls.append(1)
        if len(calls)==1:selected.write_bytes(selected.read_bytes()+b'\n')
        return result
    monkeypatch.setattr(checks,'_compiler_bound_from_snapshot',mutate)
    with pytest.raises(ValueError,match='OPERATION_INPUT_CHANGED'):checks.compiler_bound_findings(path,report)


def test_batch_does_not_skip_one_bad_member(tmp_path):
    path,report,findings=inputs(tmp_path)
    data=json.loads(report.read_text());data['findings'][-1]['fragment']['compilerFragmentAuthority']['candidate']['operandBindings'][0]['widthBits']=32
    report.write_text(json.dumps(data))
    with pytest.raises(ValueError):checks.compiler_bound_findings(path,report)
