from copy import deepcopy
from riscv2x86_py.l2_materialization import assess_fragment_l2_materializability
from riscv2x86_py.l2_dimensions import L2Dimension
from riscv2x86_py.route_authority import RouteAuthorityDecision,content_identity


def finding():
    payload={'executionDisposition':'precondition_rejected','evidenceProductionDisposition':'not_produced'}
    decision=RouteAuthorityDecision('instruction_stream','f','instruction_stream_contract',
        'ISS_RUNTIME_CONTRACT_MISSING','contract required',content_identity(payload),inputs_payload=payload).to_dict()
    return {'fragment':{'id':'f'},'verificationStatus':'needs_route','approvalArtifact':{},
        'routeAuthorityDiagnostics':[decision]}


def test_primary_upstream_refusal_retains_dimensions_without_derived_missing_fields():
    result=assess_fragment_l2_materializability(finding(),(L2Dimension.MEMORY_EFFECTS,L2Dimension.SHELL_SEMANTICS))
    assert not result.executable and not result.authority_identity
    assert result.reason_codes==('ISS_RUNTIME_CONTRACT_MISSING',)
    assert result.required_dimensions==(L2Dimension.MEMORY_EFFECTS,L2Dimension.SHELL_SEMANTICS)


def test_tampered_or_foreign_route_decision_never_hides_other_failures():
    for mutation in ('identity','fragment','status','disposition'):
        f=finding()
        if mutation=='identity':f['routeAuthorityDiagnostics'][0]['decisionIdentity']='sha256:'+'0'*64
        if mutation=='fragment':f['fragment']['id']='foreign'
        if mutation=='status':f['verificationStatus']='verified'
        if mutation=='disposition':f['routeAuthorityDiagnostics'][0]['inputsPayload']['executionDisposition']='executed'
        result=assess_fragment_l2_materializability(f,(L2Dimension.MEMORY_EFFECTS,L2Dimension.SHELL_SEMANTICS))
        assert not result.executable
        assert 'L2_FRAGMENT_AUTHORITY_SIDECAR_MISSING' in result.reason_codes
