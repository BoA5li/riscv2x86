"""Build policy tests. Synthetic RV64 ELF is explicitly not QEMU execution.

Target matrix uses real native GCC; source transport fixtures exercise rejection,
ELF checking and old-driver capability selection without a cross compiler.
"""
import copy
import json
from pathlib import Path
import struct
import subprocess
import sys

import pytest
from riscv2x86_py import system_build_profile as profile
from riscv2x86_py import controlled_system_backend as backend_module
from riscv2x86_py.semantic_content import semantic_identity
from tests.test_controlled_system import backend


def bare_elf():
    data=bytearray(0x1500)
    data[:16]=b'\x7fELF\x02\x01\x01'+b'\0'*9
    struct.pack_into('<HHIQQQIHHHHHH',data,16,2,243,1,0x80000000,64,0x1300,0,64,56,1,64,3,0)
    struct.pack_into('<IIQQQQQQ',data,64,1,7,0x1000,0x80000000,0x80000000,0x80,0x2000,0x1000)
    struct.pack_into('<II',data,0x1000,0x2197,0x80018193)
    names={'_start':0,'__global_pointer$':0x1800,'__bss_start':0x1000,
        '__bss_end':0x1100,'__stack_top':0x11100,'__rv2x86_trap':0x40,'__rv2x86_probe':0x60}
    strings=bytearray(b'\0');symbols=bytearray(24)
    for name,offset in names.items():
        symbols+=struct.pack('<IBBHQQ',len(strings),0x10,0,1,0x80000000+offset,0)
        strings+=name.encode()+b'\0'
    data[0x1100:0x1100+len(symbols)]=symbols
    data[0x1200:0x1200+len(strings)]=strings
    struct.pack_into('<IIQQQQIIQQ',data,0x1340,0,2,0,0,0x1100,len(symbols),2,0,8,24)
    struct.pack_into('<IIQQQQIIQQ',data,0x1380,0,3,0,0,0x1200,len(strings),0,0,1,0)
    return data


@pytest.mark.parametrize('mutation',[None,'gp-opcode','gp-address','float-abi','entry','dynamic','undefined','load','stack'])
def test_bare_elf_checks_real_boot_obligations(tmp_path,mutation):
    data=bare_elf()
    if mutation=='gp-opcode':struct.pack_into('<I',data,0x1000,0x13)
    if mutation=='gp-address':struct.pack_into('<I',data,0x1004,0x80118193)
    if mutation=='float-abi':struct.pack_into('<I',data,48,4)
    if mutation=='entry':struct.pack_into('<Q',data,24,0x80000004)
    if mutation=='dynamic':struct.pack_into('<I',data,64,3)
    if mutation=='undefined':struct.pack_into('<H',data,0x1100+24+6,0)
    if mutation=='load':struct.pack_into('<Q',data,64+24,0x90000000)
    if mutation=='stack':struct.pack_into('<Q',data,0x1100+5*24+8,0x80011101)
    path=tmp_path/'program.elf';path.write_bytes(data)
    if mutation:
        with pytest.raises(ValueError,match='ELF_CONTRACT_INVALID'):profile.inspect_elf(path,'source')
    else:
        checks=profile.inspect_elf(path,'source')
        assert checks['entry']==0x80000000 and checks['gpInitialization']=='auipc-addi-to-symbol'


@pytest.fixture
def profiled_backend(backend,tmp_path,monkeypatch):
    path,value=backend
    real_tools=profile.toolchain(value['targetCompiler'])
    assert {'driver','cc1','collect2','as','ld'}==set(real_tools['tools'])
    original_tools=profile.toolchain
    # Source driver is explicitly a simulated cross toolchain in this fixture.
    monkeypatch.setattr(profile,'toolchain',lambda cc:copy.deepcopy(real_tools)
        if cc==value['sourceCompiler'] else original_tools(cc))
    real_run=profile.run_command
    calls=[]
    def source_transport(command,**kwargs):
        calls.append(command)
        if '-mcmodel=medany' not in command:return real_run(command,**kwargs)
        if '-mno-relax' in command:
            record={'command':command,'returnCode':1,'stdout':'','stderr':'unrecognized -mno-relax','timedOut':False}
            raise profile.SystemBuildError('SYSTEM_BUILD_COMMAND_FAILED',record)
        assert '-Wa,-mno-relax' in command and '-Wl,--no-relax' in command
        Path(command[command.index('-o')+1]).write_bytes(bare_elf())
        return {'command':command,'returnCode':0,'stdout':'','stderr':'','timedOut':False}
    monkeypatch.setattr(profile,'run_command',source_transport)
    built=profile.probe_profile(value,tmp_path/'capabilities')
    assert built['relaxMode']=='assembler-norelax'
    assert len(built['records'])==12
    assert all(r['returnCode']==0 for r in built['records'])
    assert len([c for c in calls if '-mcmodel=medany' in c])==7
    value=dict(value,schemaVersion=backend_module.SCHEMA,buildProfile=built)
    value.pop('backendIdentity');value['backendIdentity']=semantic_identity(value)
    path.write_text(json.dumps(value))
    return path,value


def test_full_matrix_selects_capability_and_binds_production(profiled_backend,tmp_path):
    path,value=profiled_backend
    assert backend_module.validate_backend(path)['buildProfile']['relaxMode']=='assembler-norelax'
    source=tmp_path/'renamed.c';source.write_text('void arbitrary_name(void){__asm__ volatile("ecall" ::: "memory");}')
    result=backend_module.build_program(backend_path=path,side='source',source=source,
        symbol='arbitrary_name',operation='ecall',output=tmp_path/'production/program.elf')
    assert '-Wa,-mno-relax' in result['command'] and '-mno-relax' not in result['command']
    assert result['buildProfileIdentity']==value['buildProfile']['profileIdentity']
    assert result['elfChecks']['gpInitialization']=='auipc-addi-to-symbol'


@pytest.mark.parametrize('mutation',['identity','flags','matrix','recipe','tool','environment','mode','artifact','probe'])
def test_rehashed_configuration_cannot_relax_policy_or_hide_changed_inputs(profiled_backend,monkeypatch,mutation):
    _,value=profiled_backend;built=copy.deepcopy(value['buildProfile'])
    if mutation=='identity':built['profileIdentity']='bad'
    if mutation=='flags':built['records'][0]['command'].remove('-Wl,--no-relax')
    if mutation=='matrix':built['records'].pop()
    if mutation=='recipe':built['recipeDigest']='sha256:'+'0'*64
    if mutation=='tool':built['toolchains']['source']['tools']['as']['digest']='sha256:'+'0'*64
    if mutation=='environment':monkeypatch.setenv('LIBRARY_PATH','/changed/toolchain')
    if mutation=='mode':built['relaxMode']='omit-the-flag'
    if mutation=='artifact':Path(built['records'][0]['programPath']).write_bytes(b'changed-ELF')
    if mutation=='probe':Path(built['records'][0]['sourcePath']).write_text('void probe(void){}')
    if mutation!='identity':
        built.pop('profileIdentity');built['profileIdentity']=semantic_identity(built)
    with pytest.raises(ValueError,match='SYSTEM_BUILD_'):profile.validate_profile(built,value)


def test_unavailable_complete_build_is_not_approved(backend,tmp_path,monkeypatch):
    _,value=backend
    monkeypatch.setattr(profile,'toolchain',lambda cc:{'explicitProtocolFixture':True})
    def fail(*a,**kw):raise profile.SystemBuildError('SYSTEM_BUILD_COMMAND_FAILED',{'returnCode':23})
    monkeypatch.setattr(profile,'compile_program',fail)
    output=tmp_path/'failed-profile';output.mkdir()
    with pytest.raises(profile.SystemBuildError,match='PROFILE_UNAVAILABLE') as result:
        backend_module.prepare_build_profile(value,output)
    assert len(result.value.diagnostic['attempts'])==2
    assert not (output/'build-profile/profile.json').exists()
    status=json.loads((output/'build-profile-status.json').read_text())
    assert status['status']=='failed' and status['semanticApproval'] is False


def test_legacy_backend_requires_explicit_upgrade_for_source(backend,tmp_path):
    path,_=backend;source=tmp_path/'input.c';source.write_text('void probe(void){}')
    with pytest.raises(ValueError,match='SYSTEM_BUILD_PROFILE_REQUIRED'):
        backend_module.build_program(backend_path=path,side='source',source=source,symbol='probe',
            operation='ecall',output=tmp_path/'should-not-exist/program.elf')
    assert not (tmp_path/'should-not-exist').exists()


def test_upgrade_does_not_rebuild_qemu_and_preserves_old_manifest(profiled_backend,tmp_path,monkeypatch):
    path,value=profiled_backend
    legacy=dict(value,schemaVersion=backend_module.LEGACY_SCHEMA);legacy.pop('buildProfile');legacy.pop('backendIdentity')
    legacy['backendIdentity']=semantic_identity(legacy);path.write_text(json.dumps(legacy));before=path.read_bytes()
    result=backend_module.upgrade_backend(path,tmp_path/'upgrade')
    upgraded=backend_module.validate_backend(result['backendPath'])
    assert json.loads((tmp_path/'upgrade/build-profile-status.json').read_text())['status']=='complete'
    assert path.read_bytes()==before and upgraded['qemuBinaryDigest']==legacy['qemuBinaryDigest']
    assert upgraded['backendIdentity']!=legacy['backendIdentity'] and result['semanticApproval'] is False


def test_actual_failure_and_timeout_keep_command_exit_and_partial_output(tmp_path,monkeypatch):
    with pytest.raises(profile.SystemBuildError) as failed:
        profile.run_command([sys.executable,'-c','import sys;print("compile-error");sys.exit(23)'],log=tmp_path/'failure.log')
    assert failed.value.diagnostic['returnCode']==23
    assert json.loads((tmp_path/'failure.log.json').read_text())['stdout']=='compile-error\n'
    def timeout(*a,**kw):raise subprocess.TimeoutExpired(a[0],1,output=b'partial',stderr=b'err')
    monkeypatch.setattr(profile.subprocess,'run',timeout)
    with pytest.raises(profile.SystemBuildError) as timed:
        profile.run_command(['compiler','input.c'],log=tmp_path/'timeout.log')
    assert timed.value.diagnostic['timedOut'] and timed.value.diagnostic['stdout']=='partial'


def test_compile_failure_keeps_side_and_real_exit_without_success_artifact(backend,tmp_path,monkeypatch):
    _,value=backend
    def reject(*a,**kw):raise profile.SystemBuildError('SYSTEM_BUILD_COMMAND_FAILED',{
        'command':a[0],'returnCode':23,'stderr':'unsupported-option','stdout':'','timedOut':False})
    monkeypatch.setattr(profile,'run_command',reject)
    source=tmp_path/'source.c';source.write_text('void probe(void){}')
    output=tmp_path/'build/program.elf'
    with pytest.raises(profile.SystemBuildError) as failed:
        profile.compile_program(value,side='source',source=source,symbol='probe',operation='ecall',
            output=output,optimization='-O0',relax_mode='assembler-norelax')
    assert failed.value.diagnostic['side']=='source' and failed.value.diagnostic['returnCode']==23
    assert failed.value.diagnostic['stage']=='compile-link'
    assert not output.exists() and not output.with_name(output.name+'.build.json').exists()
    assert json.loads(output.with_name(output.name+'.build.log.failure.json').read_text())['returnCode']==23
