"""The executable source DSO is independently checked before object/matrix L0.

Mocked command transport isolates the binding policy; real compiler execution
and its sanitizer limitations are retained in the phase83 execution records.
"""
from pathlib import Path
from types import SimpleNamespace as NS
import pytest
from riscv2x86_py.time_trace_harness import digest
from riscv2x86_py.translation_validation import ProgramArtifact,ValidationLevel,ValidationLayerResult
from riscv2x86_py.validation_status import ValidationStatus


@pytest.mark.parametrize('mutation',[None,'source-bytes','source-kind','compiler','target-bytes','source-abi'])
def test_source_dso_does_not_bypass_independent_artifact_binding(tmp_path,monkeypatch,mutation):
    from riscv2x86_py import automatic_validation as module
    from riscv2x86_py import l0_build_matrix as matrix
    from riscv2x86_py.l0_artifact_manifest import ExpectedElf
    from tests.test_l0_build_matrix import _elf
    source=tmp_path/'source.c';source.write_text('void renamed(void){}')
    target=tmp_path/'target.c';target.write_text('void translated(void){}')
    compiler=tmp_path/'compiler';compiler.write_text('compiler identity')
    source_so=tmp_path/'actual-source.so';source_so.write_bytes(b'actual source DSO')
    target_so=tmp_path/'actual-target.so';target_so.write_bytes(b'actual target DSO')
    source_obj=tmp_path/'reference-source.o';source_obj.write_bytes(b'source object')
    reference=ProgramArtifact('source-object',str(source_obj),'object',digest(source_obj))
    supplied=ProgramArtifact('source-dso',str(source_so),'object' if mutation=='source-kind' else 'shared_library',digest(source_so))
    target_artifact=ProgramArtifact('target-dso',str(target_so),'shared_library',digest(target_so))
    config={'schemaVersion':'riscv2x86.auto-l0-runner.v2','sourcePath':str(source),'sourceDigest':digest(source),
        'targetPath':str(target),'targetDigest':digest(target),'workDirectory':str(tmp_path/'oracle'),
        'linkKind':'shared_library','timeoutSeconds':10,'sourceCompiler':str(compiler),'sourceCompilerDigest':digest(compiler)}
    def build(**kwargs):
        assert kwargs['source_compiler']==str(compiler)
        kwargs['output_directory'].mkdir()
        return NS(translation_manifest_digest='sha256:'+'a'*64),reference,NS(artifact_digest=digest(target_so))
    def command(argv,cwd,timeout):
        Path(argv[-1]).write_bytes(b'actual source DSO')
        return NS(returncode=0,stderr='',stdout='')
    elf=ExpectedElf.from_dict(_elf('RISC-V','REL' if mutation=='source-abi' else 'DYN'))
    monkeypatch.setattr(module,'build_l0_reference_manifest',build)
    monkeypatch.setattr(module,'_run',command)
    monkeypatch.setattr(matrix,'_inspect_elf',lambda *args:(elf,''))
    def run(*args,**kwargs):
        assert args[2] is reference  # independent object matrix remains required
        return ValidationLayerResult(ValidationLevel.L0,ValidationStatus.VERIFIED,detail='[]')
    monkeypatch.setattr(module,'run_l0_build_matrix',run)
    if mutation=='source-bytes':source_so.write_bytes(b'changed')
    if mutation=='compiler':compiler.write_text('changed compiler')
    if mutation=='target-bytes':target_artifact=NS(artifact_digest='sha256:'+'0'*64)
    result=module.build_auto_l0_validator(config)(level=ValidationLevel.L0,translation_artifact=NS(),
        source_program_artifact=supplied,target_program_artifact=target_artifact)
    assert result.status is (ValidationStatus.VERIFIED if mutation is None else ValidationStatus.FAILED)
