from copy import deepcopy
import pytest
from riscv2x86_py.native_instance_applicability import guard_value,constant
from .test_native_integer_translation import MODEL,literal,binary


def test_typed_guard_analysis_not_bound_to_gmp_names_or_threshold_values():
    for number in (7,193,2**63-1):
        lit=literal(number,'long')
        query={'kind':'CallExpr','type':{'qualType':'int'},'inner':[]}
        condition=binary('&&',query,binary('==',lit,literal(0,'long'),'int'),'int')
        proofs={(1,0):{'contract':{'operation':'compiler-integer-literal-constant-query','result':1,
            'requiredWitness':'source-and-target-compiler-static-assert'}}}
        assert guard_value(condition,[1],proofs,MODEL) is False


def test_missing_builtin_contract_and_runtime_values_are_not_assumed():
    from .test_native_integer_translation import variable
    for condition in ({'kind':'CallExpr','type':{'qualType':'int'}},variable('n')):
        with pytest.raises(ValueError):guard_value(condition,[],{},MODEL)


def test_constant_query_other_operation_cannot_authorize_guard():
    proof={():{'contract':{'operation':'different','result':1}}}
    with pytest.raises(ValueError):guard_value({'kind':'CallExpr','type':{'qualType':'int'}},[],proof,MODEL)


def test_signed_conversion_out_of_range_not_folded():
    with pytest.raises(ValueError):constant({'op':'integer-conversion','type':{'bits':8,'signed':True},
        'argument':{'op':'constant','value':255}})


def test_guard_classification_never_becomes_machine_coverage(tmp_path,monkeypatch):
    from riscv2x86_py import native_instance_applicability as module
    from riscv2x86_py import native_captured_deployment as d
    # Synthetic compiler boundary; no machine-elimination claim is generated.
    asm={'kind':'GCCAsmStmt'}
    ast={'kind':'TranslationUnitDecl','inner':[{'kind':'IfStmt','inner':[literal(0),asm]}]}
    binding={'occurrenceCount':1,'records':[{'instanceBindingIdentity':'instance','astPath':[0,1]}]}
    receipt={'analysisInput':{'dataModels':{'native':MODEL}}}
    receipt_path=tmp_path/'receipt.json';receipt_path.write_text(__import__('json').dumps(receipt))
    bundle={'nativeInputReceiptPath':str(receipt_path),'bindingBundleIdentity':'bundle'}
    bundle_path=tmp_path/'bundle.json';bundle_path.write_text(__import__('json').dumps(bundle))
    monkeypatch.setattr(module.binding,'validate_artifacts',lambda value:(binding,{}))
    monkeypatch.setattr(module,'validated_input',lambda value:{'canonicalAst':ast})
    candidate=d.seal({'bindingBundlePath':str(bundle_path),'bindingBundleDigest':d.digest(bundle_path),
        'bindingBundleIdentity':'bundle','builtinProofs':[],
        'edits':[{'instanceBindingIdentity':'instance'}]},'candidateIdentity')
    result=module.derive(candidate);row=result['rows'][0]
    assert row['sourceGuardClassification']=='excluded-under-recorded-contracts'
    assert row['canonicalMachineDisposition']=='unknown' and not row['canonicalInstructionExecutionVerified']
    assert result['requiresIndependentCandidateAudit'] and not result['semanticApproval']
