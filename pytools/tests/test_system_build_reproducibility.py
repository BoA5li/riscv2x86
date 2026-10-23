"""Real native assembler/linker reproducibility, plus explicit RV64 protocol tests.

Native fixtures do not establish QEMU or RISC-V production acceptance.
"""
import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace

import pytest
from riscv2x86_py import system_build_profile as profile
from riscv2x86_py import controlled_system_backend as backend_module
from riscv2x86_py.system_instruction_ingress import digest
from tests.test_system_build_profile import profiled_backend
from tests.test_controlled_system import backend


@pytest.mark.parametrize('operation',['ecall','wfi'])
@pytest.mark.parametrize('optimization',profile.OPTIMIZATIONS)
def test_real_native_complete_bytes_stable_and_wrappers_not_overwritten(backend,tmp_path,operation,optimization):
    path,_=backend
    source=tmp_path/'independent.c'
    helper='rv2x86_m_ecall_v1' if operation=='ecall' else 'rv2x86_m_wfi_pending_v1'
    source.write_text('void independent(void){'+helper+'();}\n')
    records=[]
    # Different work directories AND output basenames, matching production/L0.
    for output in (tmp_path/'first/target-system.elf',tmp_path/'elsewhere/program.elf'):
        records.append(backend_module.build_program(backend_path=path,side='target',source=source,
            symbol='independent',operation=operation,output=output,optimization=optimization))
    assert records[0]['programDigest']==records[1]['programDigest']
    assert Path(records[0]['programPath']).read_bytes()==Path(records[1]['programPath']).read_bytes()
    for r in records:
        assert len(r['steps'])==2
        assert r['steps'][-1]['command'].count('wrapper.o')==1
        assert all(x['returnCode']==0 for x in r['steps'])
        assert digest((Path(r['workspace'])/'system-wrapper.c').read_bytes())==r['wrapperDigest']
    # Two outputs in one parent must not overwrite each other's input or logs.
    other=tmp_path/'different.c';other.write_text('void independent(void){}\n')
    before=(Path(records[0]['workspace'])/'system-wrapper.c').read_bytes()
    backend_module.build_program(backend_path=path,side='target',source=other,symbol='independent',
        operation=operation,output=tmp_path/'first/another.elf',optimization=optimization)
    assert (Path(records[0]['workspace'])/'system-wrapper.c').read_bytes()==before


def test_real_local_assembly_without_file_uses_stable_relative_object(tmp_path):
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native GCC unavailable')
    asm=tmp_path/'boot.S'
    asm.write_text('.text\n.globl _start\n_start:\n ret\nlocal_trap:\n ret\n.section .note.GNU-stack,"",@progbits\n')
    outputs=[]
    for name in ('one','different-parent'):
        work=tmp_path/name;work.mkdir()
        subprocess.run([cc,'-c',str(asm),'-o','boot.o'],cwd=work,capture_output=True,check=True)
        subprocess.run([cc,'-nostdlib','-no-pie','boot.o','-Wl,--build-id=none','-o','program.elf'],
                       cwd=work,capture_output=True,check=True)
        outputs.append((work/'program.elf').read_bytes())
    assert outputs[0]==outputs[1]
    assert b'boot.o\0' in outputs[0] and str(tmp_path).encode() not in outputs[0]


@pytest.mark.parametrize('profiled_backend',['linker-norelax'],indirect=True)
@pytest.mark.parametrize('mutation',[None,'source','target'])
def test_l0_real_runner_keeps_strict_full_file_comparison_and_evidence(profiled_backend,tmp_path,monkeypatch,mutation):
    from riscv2x86_py import controlled_system_runner as runner,controlled_system_scope
    from riscv2x86_py.translation_validation import ProgramArtifact,ValidationLevel
    path,value=profiled_backend
    sources={}
    for side,text in [('source','void independent(void){__asm__ volatile("ecall" ::: "memory");}'),
                      ('target','void independent(void){rv2x86_m_ecall_v1();}')]:
        sources[side]=tmp_path/(side+'.c');sources[side].write_text(text)
    originals={side:backend_module.build_program(backend_path=path,side=side,source=sources[side],
        symbol='independent',operation='ecall',output=tmp_path/'original'/(side+'-system.elf')) for side in sources}
    if mutation:
        output=Path(originals[mutation]['programPath']);data=bytearray(output.read_bytes());data[-1]^=1;output.write_bytes(data)
    # Exercise actual L0 orchestration/build/rebuild. Frontend proof and source
    # execution are explicitly outside this test's simulated source protocol.
    monkeypatch.setattr(runner,'load_config',lambda c:value)
    monkeypatch.setattr(runner,'approved_finding',lambda *a:{'approvalArtifact':{'privilegedCallableIdentifier':'rv2x86_m_ecall_v1'}})
    monkeypatch.setattr(controlled_system_scope,'target_scope',lambda *a:None)
    monkeypatch.setattr(runner,'environment',lambda c:{'test':'bounded-protocol'})
    monkeypatch.setattr(runner,'environment_id',lambda c:'bounded-protocol')
    config={'backendPath':path,'sourcePath':str(sources['source']),'targetPath':str(sources['target']),
            'scope':{'functionSymbol':'independent'},'operation':'ecall','clang':'explicit-test-fixture'}
    programs={side:ProgramArtifact(side,r['programPath'],'executable',digest(Path(r['programPath']).read_bytes()),
        'sha256:'+'1'*64) for side,r in originals.items()}
    result=runner.run(config,level=ValidationLevel.L0,translation_artifact=SimpleNamespace(),
        target_environment={'environmentId':'bounded-protocol'},
        source_program_artifact=programs['source'],target_program_artifact=programs['target'])
    detail=json.loads(result.detail)
    if mutation:
        assert result.status.value=='inconclusive',detail
        assert detail['reasonCode']=='SYSTEM_L0_INDEPENDENT_REBUILD_MISMATCH:'+mutation
        diagnostic=detail['buildDiagnostic'];kept=Path(diagnostic['evidenceDirectory'])
        assert kept.is_dir() and (kept/'comparison.json').is_file()
        assert digest((kept/'original.elf').read_bytes())==diagnostic['expectedDigest']
        assert digest((kept/'rebuilt.elf').read_bytes())==diagnostic['rebuiltDigest']
        assert diagnostic['expectedDigest']!=diagnostic['rebuiltDigest']
        assert diagnostic['firstDifferenceOffset']>=0 and diagnostic['buildRecord']['steps']
        assert detail['executions']=={} and detail['evidenceProductionDisposition']=='partial'
    else:
        assert result.status.value=='verified',detail
        assert len(detail['builds'])==6
        assert all(Path(r['programPath']).is_file() and Path(r['workspace']).is_dir() for r in detail['builds'])


@pytest.mark.parametrize('profiled_backend',['linker-norelax'],indirect=True)
def test_preflight_rejects_repeat_metadata_difference_and_keeps_snapshots(profiled_backend,tmp_path,monkeypatch):
    _,value=profiled_backend;real_run=profile.run_command
    def unstable(command,**kw):
        result=real_run(command,**kw)
        if '-mcmodel=medany' in command and '-c' not in command:
            output=Path(command[command.index('-o')+1])
            if 'repeat' in output.parts:
                data=bytearray(output.read_bytes());data[-1]^=1;output.write_bytes(data)
        return result
    monkeypatch.setattr(profile,'run_command',unstable)
    out=tmp_path/'unstable';out.mkdir()
    with pytest.raises(profile.SystemBuildError,match='SYSTEM_BUILD_PROFILE_UNAVAILABLE'):
        backend_module.prepare_build_profile(value,out)
    assert not (out/'backend.json').exists() and not (out/'build-profile/profile.json').exists()
    status=json.loads((out/'build-profile-status.json').read_text())
    diagnostic=status['diagnostic']['attempts'][-1]['failure']
    assert diagnostic['reasonCode']=='SYSTEM_BUILD_PROFILE_REPRODUCTION_MISMATCH:source'
    assert (Path(diagnostic['evidenceDirectory'])/'comparison.json').is_file()
    assert diagnostic['expectedDigest']!=diagnostic['rebuiltDigest']


def test_elf_region_diagnostic_does_not_turn_metadata_difference_into_permission(tmp_path):
    from tests.test_system_build_profile import bare_elf
    original=tmp_path/'original.elf';rebuilt=tmp_path/'rebuilt.elf'
    first=bare_elf();second=bytearray(first)
    # An unused byte outside the load region still changes full-file identity.
    second[-1]^=1;original.write_bytes(first);rebuilt.write_bytes(second)
    with pytest.raises(profile.SystemBuildError) as caught:
        profile.require_identical_rebuild({'path':str(original),'digest':digest(first)},
            {'programPath':str(rebuilt),'programDigest':digest(second)},reason='strict-test-mismatch')
    diagnostic=caught.value.diagnostic
    assert diagnostic['firstDifferenceOffset']==len(first)-1
    assert diagnostic['elfDifference']['loadSegmentsEqual'] is True
    assert diagnostic['expectedDigest']!=diagnostic['rebuiltDigest']
