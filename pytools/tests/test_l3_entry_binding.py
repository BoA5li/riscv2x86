from copy import deepcopy
import pytest
from riscv2x86_py.l3_entry_binding import entry


def test_entry_selection_is_by_compiler_identity_and_not_function_order():
    wanted={'functionId':'bound','name':'target'};other={'functionId':'other','name':'helper'}
    assert entry([other,wanted],'bound') is wanted
    with pytest.raises(ValueError):entry([other],'bound')
    with pytest.raises(ValueError):entry([wanted,deepcopy(wanted)],'bound')


def test_pure_program_can_keep_unrelated_functions_without_weakening_members(tmp_path):
    from tests.test_l3_program_regions import fixture
    from riscv2x86_py.l3_program_spec import spec
    _,findings,fn=fixture(tmp_path)
    before=spec(findings,[fn])
    assert spec(findings,[{'functionId':'unrelated','name':'helper'},fn])==before
    changed=deepcopy(findings)
    changed[0]['fragment']['compilerFragmentAuthority']['functionIdentity']='unrelated'
    with pytest.raises(ValueError,match='ENTRY_CLOSURE_REQUIRED'):spec(changed,[fn])


def test_ordinary_trace_entry_binding_ignores_only_unrelated_functions(tmp_path,monkeypatch):
    from tests.test_typed_load_execution import fixture
    from riscv2x86_py.l3_trace_deployment import function_scope
    from riscv2x86_py.l3_trace_support import digest
    from riscv2x86_py.compiler_value_flow import identity
    import riscv2x86_py.mechanism_route_checks as checks
    f,fn,spec=fixture();source=tmp_path/'source.c';source.write_text('compiler fixture')
    fn['name']='probe';fn['sourceDigest']=digest(source)
    sig=fn['compilerMemoryCallSignature'];sig['sourceDigest']=fn['sourceDigest'];sig['factsIdentity']=identity({k:v for k,v in sig.items() if k!='factsIdentity'})
    scope=fn['compilerAtomicFunctionScope'];scope['sourceDigest']=fn['sourceDigest'];scope['scopeIdentity']=identity({k:v for k,v in scope.items() if k!='scopeIdentity'})
    f['fragment']['enclosingFunction']='probe';f['approvalArtifact']['l2FragmentOperandBoundary']['functionId']='function'
    monkeypatch.setattr(checks,'compiler_bound_finding',lambda *a:(f,{'functions':[{'name':'unrelated','functionId':'other'},fn]}))
    result=function_scope(source,tmp_path/'report.json',f)
    assert result['name']=='probe' and result['functionIdentity']=='function'
