"""Sparse bounded acquisition and conservative interprocedural expansion."""
import sys
from copy import deepcopy

import pytest

from .test_native_contract_evidence import contract_pipeline,prepared
from .test_native_context_resolution import unit
from riscv2x86_py import native_context_batch as batch
from riscv2x86_py import native_context_resolution as resolution
from riscv2x86_py import native_captured_deployment as d


def test_sparse_order_does_not_turn_into_a_contiguous_range():
    report={'producerContextClosure':{'compileContexts':list(range(12))}}
    assert batch.selection_indices(report,0,4,[9,2,7])==[9,2,7]
    assert batch.selected(report,0,4,[9,2,7])==[9,2,7]


@pytest.mark.parametrize('indices',[[],[True],[1,1],[-1],[12],list(range(65))])
def test_bad_sparse_indices_fail_closed(indices):
    report={'producerContextClosure':{'compileContexts':list(range(12))}}
    with pytest.raises(ValueError,match='INDICES_INVALID'):
        batch.selected(report,0,4,indices)


def test_interprocedural_candidates_expand_priority_scope_without_actual_binding():
    a=unit('a','entry',callee='middle');b=unit('b','middle',callee='leaf');c=unit('c','leaf')
    result=resolution.consume([a,b,c],{'a':[[1]]})
    call=next(r for r in result['callJoins'] if r['unitIdentity']=='b')
    assert not call['inKnownLocalScope']
    assert call['inPotentialInterproceduralScope']
    assert not call['actualLinkSelectionVerified'] and not call['nativeAbiContractVerified']
    assert result['potentialFunctionCount']==3
    assert not result['fullProgramScopeComplete']


def test_ambiguous_provider_edges_are_retained_not_chosen():
    a=unit('a','entry',callee='middle');b=unit('b','middle',callee='leaf')
    other=unit('other','middle',callee='different');c=unit('c','leaf')
    result=resolution.consume([a,b,other,c],{'a':[[1]]})
    assert result['potentialFunctionCount']==4
    first=next(r for r in result['callJoins'] if r['unitIdentity']=='a')
    assert len(first['providerCandidates'])==2 and not first['actualLinkSelectionVerified']


def test_sparse_acquisition_binds_requested_indices_and_replays(contract_pipeline):
    root,_=contract_pipeline
    value=batch.acquire(root/'contracts/result.json',root/'sparse',clang=sys.executable,indices=[1,0])
    assert value['selectedContextIndices']==[1,0]
    assert [r['contextIndex'] for r in value['rows']]==[1,0]
    assert value['startIndex'] is None and value['nextIndex'] is None
    assert value['selectedContextAcquisitionComplete']
    assert batch.check(root/'sparse/result.json')==value


def test_progress_reports_verified_subgoals_without_granting_stage_acceptance(contract_pipeline):
    root,value=contract_pipeline
    progress=value['validationProgress']
    assert progress['subgoals']['candidate-input-replacement']['status']=='verified'
    assert progress['subgoals']['explicit-input-producer-origin']['status']=='verified'
    assert not progress['sourceTargetSemanticEquivalenceVerified']
    assert value['stages']['entry-abi']['status']=='inconclusive'
    assert not value['entryAbiClosureVerified']


def test_priority_acquisition_uses_checked_resolution_indices(contract_pipeline,monkeypatch):
    root,_=contract_pipeline
    batch.acquire(root/'contracts/result.json',root/'one',clang=sys.executable,count=1)
    resolved=resolution.acquire(root/'contracts/result.json',[root/'one/result.json'],root/'resolution')
    # Independent resolver checker is the tested trust boundary. Here a
    # deterministic scheduling policy fixture supplies sparse priorities.
    value=deepcopy(resolved);value['resolution']['suggestedContextIndices']=[1]
    monkeypatch.setattr(resolution,'check',lambda _:value)
    result=resolution.acquire_priority(root/'resolution/result.json',root/'priority',clang=sys.executable,count=1)
    assert result['selectedContextIndices']==[1]
    assert batch.check(root/'priority/result.json')==result


def test_same_physical_definition_keeps_occurrences_without_fake_ambiguity():
    a=unit('a','entry',callee='leaf');b=unit('b','leaf');other=deepcopy(b)
    b['object']={'resolvedPath':'/same/leaf.o','digest':'same'}
    other['object']=dict(b['object']);other['unitIdentity']='another-occurrence'
    result=resolution.consume([a,b,other],{'a':[[1]]})
    provider=result['callJoins'][0]['providerCandidates']
    assert len(provider)==1
    assert len(provider[0]['occurrenceUnitIdentities'])==2
    assert not provider[0]['actualLinkSelectionVerified']


def test_archive_audit_refinement_and_summary_are_consumed_without_abi_approval(contract_pipeline,monkeypatch):
    from riscv2x86_py import native_archive_audit as audit
    from riscv2x86_py import native_contract_evidence as contracts
    from riscv2x86_py.native_validation_progress import summary
    root,_=contract_pipeline
    observed=d.read(root/'observation/result.json')
    path=root/'audit-boundary.json';path.write_text('{}')
    # Archive replay itself has separate real tool integration tests. This
    # boundary tests contract joining with a checked audit of this deployment.
    value={'deploymentIdentity':observed['deploymentIdentity'],
           'archiveSelectionAuditIdentity':'fixture-audit',
           'independentObservedArchiveContributionsVerified':True,
           'verifiedObservedArchiveMemberCount':1,'actualLinkSelectionClosureVerified':False}
    monkeypatch.setattr(audit,'check',lambda _:value)
    refined=contracts.refine(root/'contracts/result.json',root/'audited-contract',archive_audit_path=path)
    assert contracts.check(root/'audited-contract/result.json')==refined
    assert refined['validationProgress']['subgoals']['observed-archive-contributions']['status']=='verified'
    assert not refined['entryAbiClosureVerified']
    report=summary(root/'audited-contract/result.json')
    assert report['archiveSelectionAudit']['archiveSelectionAuditIdentity']=='fixture-audit'
    value['deploymentIdentity']='wrong'
    with pytest.raises(ValueError,match='ARCHIVE_AUDIT_DEPLOYMENT_MISMATCH'):
        contracts.refine(root/'contracts/result.json',root/'wrong',archive_audit_path=path)


def test_summary_cli_reads_final_contract_without_generic_dispatch_error(contract_pipeline,tmp_path,capsys):
    import importlib.util
    from pathlib import Path
    root,_=contract_pipeline
    script=Path(__file__).resolve().parents[2]/'experiment/advance_native_closure.py'
    spec=importlib.util.spec_from_file_location('phase179_closure_cli',script)
    cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
    output=tmp_path/'summary.json'
    assert cli.main(['summarize-contracts','--input',str(root/'contracts/result.json'),
                     '--output',str(output)])==0
    value=d.read(output)
    assert value['stages']==d.read(root/'contracts/result.json')['stages']
    assert value['crossStageCaptureReplayPerformed']
    assert not value['semanticApproval']
    assert cli.main(['summarize-contracts','--input',str(root/'contracts/result.json'),
                     '--output',str(output)])==2


def test_candidate_substitution_is_scoped_to_the_exact_library_consumer():
    original={'resolvedPath':'/capture/unit.o','digest':'same-bytes'}
    substitution={'originalObject':original,'consumerActionIdentity':'library-link'}
    node={'file':dict(original),'consumerActionIdentity':'library-link'}
    assert resolution.replaced_input(node,substitution)
    node['consumerActionIdentity']='other-archive-or-link'
    assert not resolution.replaced_input(node,substitution)
    node['consumerActionIdentity']='library-link';node['file']['resolvedPath']='/different/unit.o'
    assert not resolution.replaced_input(node,substitution)
