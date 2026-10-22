from copy import deepcopy
import json
from pathlib import Path
import pytest
from riscv2x86_py.semantic_content import semantic_identity


def evidence():
    from riscv2x86_py.mechanism_evidence import FILES,SCHEMA
    from riscv2x86_py.local_sync_mechanism import SOURCE_DIGESTS
    from riscv2x86_py.time_trace_contract import QEMU_BASE
    value={'schemaVersion':SCHEMA,'sourceCommit':QEMU_BASE,'binaryDigest':'sha256:'+'1'*64,
        'buildConfigDigest':'sha256:'+'2'*64,'sourceDigests':dict(SOURCE_DIGESTS),
        'sourceTimeMechanism':'qemu-7.2-linux-user-x86_64-rdtsc',
        'sourceSyncMechanism':'qemu-7.2-linux-user-write-protect-invalidate-and-tb-exit','semanticApproval':False}
    value['evidenceIdentity']=semantic_identity(value);return value


def domain():
    from tests.test_instruction_visibility_production import domain as legacy
    d=legacy();d.update(schemaVersion='riscv2x86.instruction-stream-domain.v2',mechanismEvidence=evidence(),
        reviewedAssumptions={'writerPolicy':'one-thread-same-mapping-no-external-writers',
            'mappingPolicy':'private-anonymous-no-alias-no-mmio',
            'executionPolicy':'local-pinned-hart-no-active-code-overwrite',
            'targetProtocolBasis':'x86-local-serializing-smc-v1',
            'rangeRole':'observer-probe-only-domain-guarantee-from-reviewed-mechanism','reviewer':'fixture-review',
            'basisIdentity':'sha256:'+'4'*64})
    d['domainIdentity']=semantic_identity({k:v for k,v in d.items() if k!='domainIdentity'});return d


@pytest.mark.parametrize('mutation',['native','hash','mmio','writer','scope','approval','review'])
def test_mechanism_domain_rejects_rehashed_bad_assumptions(mutation):
    from riscv2x86_py.instruction_stream_domain import validate_domain
    d=domain()
    if mutation=='native':d['mechanismEvidence']['sourceTimeMechanism']='monotonic-nanoseconds'
    if mutation=='hash':d['mechanismEvidence']['sourceDigests']['include/qemu/timer.h']='invalid'
    if mutation=='mmio':d['reviewedAssumptions']['mappingPolicy']='mmio'
    if mutation=='writer':d['reviewedAssumptions']['writerPolicy']='external-dma'
    if mutation=='scope':d['coverage']='arbitrary-cross-hart'
    if mutation=='approval':d['mechanismEvidence']['semanticApproval']=True
    if mutation=='review':d['reviewedAssumptions']['reviewer']=''
    e=d['mechanismEvidence'];e['evidenceIdentity']=semantic_identity({k:v for k,v in e.items() if k!='evidenceIdentity'})
    d['domainIdentity']=semantic_identity({k:v for k,v in d.items() if k!='domainIdentity'})
    with pytest.raises(ValueError):validate_domain(d,fragment_id=d['fragmentId'],environment_id=d['targetEnvironmentId'],cpu_profile=d['targetCpuProfileId'])


def test_v2_mechanism_and_domain_survive_proof_and_approval_replay():
    from dataclasses import replace
    from tests.test_instruction_stream_sync_contracts import _contract
    from tests.test_instruction_visibility_production import approval_fixture
    from riscv2x86_py.instruction_stream_sync_contracts import prove_instruction_stream_sync
    from riscv2x86_py.l2_instruction_stream import close_instruction_stream_approval,validate_instruction_stream_approval
    f,a,_=approval_fixture();d=domain();
    from riscv2x86_py.instruction_stream_sync_contracts import ModifiedCodeRange
    contract=replace(_contract(),domain_authority=d,modified_code_range=ModifiedCodeRange('probe-code-object',0,4096,'observer.private.anonymous'))
    proof=prove_instruction_stream_sync(contract);assert proof.approved
    a,text=close_instruction_stream_approval(a,proof,f,bytes.fromhex('0f100000'),'automatic-gcc-separate-tu-no-lto-v1')
    validate_instruction_stream_approval(a,f,text,source_digest=d['sourceDigest'])


def test_time_ast_scope_refuses_initializers_calls_and_extra_statements():
    from riscv2x86_py.compiler_time_scope import time_return_scope
    ref={'kind':'DeclRefExpr','referencedDecl':{'id':'local'}}
    body=[{'kind':'DeclStmt','inner':[{'kind':'VarDecl','id':'local','type':{'qualType':'uint64_t','desugaredQualType':'unsigned long'}}]},
        {'kind':'GCCAsmStmt','inner':[ref]}, {'kind':'ReturnStmt','inner':[ref]}]
    ast={'name':'arbitrary_name','inner':[{'kind':'CompoundStmt','inner':body}]}
    def scope(a):return time_return_scope(a,source_digest='sha256:'+'1'*64,function_identity='sha256:'+'2'*64,source_range=lambda n:(1,2))
    assert scope(ast)
    for extra in ({'kind':'CallExpr'},{'kind':'GCCAsmStmt'},{'kind':'BinaryOperator'}):
        changed=deepcopy(ast);changed['inner'][0]['inner'].insert(1,extra);assert scope(changed) is None
    changed=deepcopy(ast);changed['inner'][0]['inner'][0]['inner'][0]['inner']=[{'kind':'IntegerLiteral'}]
    assert scope(changed) is None


def test_controlled_backend_patch_is_exact_and_does_not_touch_timeh():
    from riscv2x86_py.prepare_controlled_time_backend import ORIGINAL,REPLACEMENT
    assert '*val = cpu_get_host_ticks();' in ORIGINAL
    assert '*val = rv2x86_time_trace_read_v1(env->pc);' in REPLACEMENT
    assert 'CONFIG_USER_ONLY' in REPLACEMENT and 'read_timeh' not in REPLACEMENT


def test_selected_experiment_does_not_overwrite_existing_results(tmp_path):
    import subprocess,sys
    root=Path(__file__).resolve().parents[2]
    existing=tmp_path/'results';existing.mkdir();record=existing/'run-status.json';record.write_text('preserved')
    result=subprocess.run([sys.executable,str(root/'experiment/run_mechanism_routes.py'),
        '--frontend','missing','--output',str(existing),'--architecture-template','missing'],capture_output=True,text=True)
    assert result.returncode==2 and record.read_text()=='preserved'
