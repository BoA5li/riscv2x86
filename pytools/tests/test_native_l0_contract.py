"""Consumer-contract regression without toolchain skips.

Compiler commands/ELFs below are explicit fixtures. This proves interchange
contracts, never real cross-ISA compilation or program semantics.
"""
from dataclasses import replace
import json
from pathlib import Path
import pytest
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py import native_framework_admission as adapter
from riscv2x86_py import l0_manifest_builder as builder
from riscv2x86_py.l0_artifact_manifest import ExpectedElf,load_l0_artifact_manifest
from riscv2x86_py.l0_build_matrix import _check_manifest_binding
from riscv2x86_py.translation_validation import translation_artifact_from_dict
from riscv2x86_py.runtime_dependency_binding import (NO_RUNTIME_CONTRACT_ID,NO_RUNTIME_CONTRACT_VERSION,
    resolve_runtime_contracts)
from .test_l0_build_matrix import _elf


def translation():
    proof=d.seal({'instanceBindingIdentity':'fixture-instance','sourceInstruction':{'operation':'unsigned-high-multiply'},
        'localIntegerStatementEquivalenceVerified':True,
        'claimScope':'architectural-integer-values-under-compiler-and-context-contracts'},'proofIdentity')
    candidate=d.seal({'localProofs':[proof],'edits':[{'instanceBindingIdentity':'fixture-instance',
        'constraintRelationIdentity':'fixture-constraint','proofScope':'local-statement-under-unchanged-C-context'}],
        'sourceAstIdentity':'fixture-ast','compilerOperandTypeWitnessesComplete':True,
        'tools':{},'sourceFlags':[],'targetFlags':[]},'candidateIdentity')
    public=adapter.artifacts(candidate)[0]
    direct=translation_artifact_from_dict(public['translationArtifact'])
    assert direct==translation_artifact_from_dict(json.loads(json.dumps(public['translationArtifact'])))
    assert direct.identity==public['translationArtifactIdentity']
    return direct


def test_native_adapter_to_original_complete_manifest_round_trip(tmp_path,monkeypatch):
    artifact=translation();commands=[]
    assert (artifact.runtime_contract_id,artifact.runtime_contract_version)==(NO_RUNTIME_CONTRACT_ID,NO_RUNTIME_CONTRACT_VERSION)
    assert not resolve_runtime_contracts([artifact.runtime_contract_id]).libraries
    def fixture_command(argv,cwd,timeout):
        commands.append(argv)
        if '-dumpmachine' in argv:return 'riscv64-linux-gnu' if argv[0]=='fixture-rvcc' else 'x86_64-linux-gnu'
        assert '-o' in argv
        Path(argv[argv.index('-o')+1]).write_bytes(json.dumps(list(argv)).encode())
        return ''
    def fixture_elf(path,cwd,timeout):
        source=path.name=='source.rv64.o';obj=path.suffix=='.o'
        return ExpectedElf.from_dict(_elf('RISC-V' if source else 'Advanced Micro Devices X86-64','REL' if obj else 'DYN'))
    monkeypatch.setattr(builder,'_checked',fixture_command);monkeypatch.setattr(builder,'_elf',fixture_elf)
    source=tmp_path/'source.c';source.write_text('/* fixture source */')
    target=tmp_path/'target.c';target.write_text('/* fixture target */')
    matrix,src,tgt=builder.build_l0_reference_manifest(source_path=source,target_path=target,
        output_directory=tmp_path/'reference',translation=artifact,link_kind='shared_library',source_compiler='fixture-rvcc')
    manifest=load_l0_artifact_manifest(matrix.translation_manifest_path,matrix.translation_manifest_digest)
    assert len(manifest.targets)==18
    assert _check_manifest_binding(manifest,matrix,artifact,src,tgt)==''
    assert len([c for c in commands if c[0] in ('gcc','clang') and '-c' in c])==18
    assert len([c for c in commands if c[0] in ('gcc','clang') and '-shared' in c])==18
    # A mutated metadata binding is not cured by a newly computed file digest.
    path=Path(matrix.translation_manifest_path);raw=json.loads(path.read_text());raw['runtimeContractVersion']='other'
    path.write_text(json.dumps(raw));changed=load_l0_artifact_manifest(path,d.digest(path))
    assert _check_manifest_binding(changed,matrix,artifact,src,tgt)


@pytest.mark.parametrize('field',['proof_identity','runtime_contract_id','runtime_contract_version','recipe_id'])
def test_incomplete_metadata_rejected_before_any_output_or_compiler(tmp_path,monkeypatch,field):
    artifact=replace(translation(),**{field:''})
    monkeypatch.setattr(builder,'_checked',lambda *a,**k:pytest.fail('invalid binding must not invoke compiler'))
    with pytest.raises(ValueError,match='non-empty string'):
        builder.build_l0_reference_manifest(source_path=tmp_path/'source.c',target_path=tmp_path/'target.c',
            output_directory=tmp_path/'invalid',translation=artifact,link_kind='shared_library')
    assert not (tmp_path/'invalid').exists()


@pytest.mark.parametrize('runtime,version',[(NO_RUNTIME_CONTRACT_ID,'invented'),('unknown-runtime','v1')])
def test_invented_runtime_binding_cannot_start_build(tmp_path,monkeypatch,runtime,version):
    artifact=replace(translation(),runtime_contract_id=runtime,runtime_contract_version=version)
    monkeypatch.setattr(builder,'_checked',lambda *a,**k:pytest.fail('invalid version must fail before compiler'))
    with pytest.raises(ValueError,match='version mismatch|unregistered runtime'):
        builder.build_l0_reference_manifest(source_path=tmp_path/'s.c',target_path=tmp_path/'t.c',
            output_directory=tmp_path/'invalid',translation=artifact,link_kind='shared_library')
    assert not (tmp_path/'invalid').exists()
