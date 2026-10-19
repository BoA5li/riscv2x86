from riscv2x86_py import pipeline
from riscv2x86_py.schema import Finding,AsmFragment
from riscv2x86_py.route_authority import validate_route_decision


def test_blocked_producer_archives_one_primary_reason_without_downstream_noise(monkeypatch):
    f=Finding(fragment=AsmFragment(id='f'),category='NeedsAsmTranslation')
    monkeypatch.setattr(pipeline,'_finalize_finding_privileged_manifest',lambda *a,**k:None)
    pipeline._record_route_precondition(f,route='csr',stage='csr_architecture_binding',
        reason_code='CSR_ARCHITECTURE_PROFILE_REQUIRED',detail='source ISA profile required',
        inputs={'sourceDigest':'sha256:'+'1'*64})
    assert f.translationOutcome=='needs_route' and not f.suggestedReplacement
    assert f.translationReasonCodes==['CSR_ARCHITECTURE_PROFILE_REQUIRED']
    assert f.translationAttemptArtifact is not None
    decision=f.routeAuthorityDiagnostics[0];validate_route_decision(decision)
    assert decision['inputsPayload']['evidenceProductionDisposition']=='not_produced'
    assert 'phase6d' in decision['inputsPayload']['blockedStages']


def test_runtime_materialization_retains_original_binding_exception(tmp_path):
    from dataclasses import asdict
    from tests.test_instruction_visibility_production import approval_fixture
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    from riscv2x86_py.semantic_content import semantic_identity
    fragment,approval,text=approval_fixture()
    finding={'fragment':asdict(fragment),'approvalArtifact':approval,'sourceDigest':'sha256:'+'1'*64,
        'machineCodeHex':'13000000','suggestedReplacement':text}
    frontend=tmp_path/'frontend';frontend.write_bytes(b'unit producer')
    assert materialize_automatic_l2_authority({'findings':[finding]},(),frontend)==0
    diagnostic=approval['l2RuntimeAuthorityFailure']
    assert diagnostic['reasonCode']=='ISS_MACHINE_CODE_BINDING_MISMATCH'
    assert diagnostic['exceptionType']=='ValueError'
    assert diagnostic['failureIdentity']==semantic_identity({k:v for k,v in diagnostic.items() if k!='failureIdentity'})
