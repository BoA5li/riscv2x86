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


@pytest.fixture(params=['assembler-norelax', 'linker-norelax'])
def profiled_backend(backend,tmp_path,monkeypatch,request):
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
        if ('-mno-relax' in command or
                (request.param=='linker-norelax' and '-Wa,-mno-relax' in command)):
            record={'command':command,'returnCode':1,'stdout':'','stderr':'unrecognized -mno-relax','timedOut':False}
            raise profile.SystemBuildError('SYSTEM_BUILD_COMMAND_FAILED',record)
        if '-c' not in command: assert '-Wl,--no-relax' in command
        assert ('-Wa,-mno-relax' in command)==(request.param=='assembler-norelax')
        output=Path(kwargs['cwd'])/command[command.index('-o')+1]
        output.write_bytes(b'explicit-simulated-object' if '-c' in command else bare_elf())
        return {'command':command,'returnCode':0,'stdout':'','stderr':'','timedOut':False}
    monkeypatch.setattr(profile,'run_command',source_transport)
    built=profile.probe_profile(value,tmp_path/'capabilities')
    assert built['relaxMode']==request.param
    assert len(built['records'])==12
    assert all(r['returnCode']==0 for r in built['records'])
    assert len([c for c in calls if '-mcmodel=medany' in c])==(49 if request.param=='assembler-norelax' else 50)
    attempts=json.loads((tmp_path/'capabilities/probe-attempts.json').read_text())
    assert [a['relaxMode'] for a in attempts]==(['driver-norelax'] if request.param=='assembler-norelax'
        else ['driver-norelax','assembler-norelax'])
    value=dict(value,schemaVersion=backend_module.SCHEMA,buildProfile=built)
    value.pop('backendIdentity');value['backendIdentity']=semantic_identity(value)
    path.write_text(json.dumps(value))
    return path,value


def test_full_matrix_selects_capability_and_binds_production(profiled_backend,tmp_path):
    path,value=profiled_backend
    mode=value['buildProfile']['relaxMode']
    assert backend_module.validate_backend(path)['buildProfile']['relaxMode']==mode
    source=tmp_path/'renamed.c';source.write_text('void arbitrary_name(void){__asm__ volatile("ecall" ::: "memory");}')
    result=backend_module.build_program(backend_path=path,side='source',source=source,
        symbol='arbitrary_name',operation='ecall',output=tmp_path/'production/program.elf')
    assert '-Wl,--no-relax' in result['command'] and '-mno-relax' not in result['command']
    assert ('-Wa,-mno-relax' in result['command'])==(mode=='assembler-norelax')
    assert result['buildProfileIdentity']==value['buildProfile']['profileIdentity']
    assert result['elfChecks']['gpInitialization']=='auipc-addi-to-symbol'


@pytest.mark.parametrize('mutation',['identity','flags','extra-flags','matrix','recipe','policy','tool','environment','mode','artifact','probe','boot','linker-script','cwd','object','wrapper','repeat','stage-exit'])
def test_rehashed_configuration_cannot_relax_policy_or_hide_changed_inputs(profiled_backend,monkeypatch,mutation):
    _,value=profiled_backend;built=copy.deepcopy(value['buildProfile'])
    if mutation=='identity':built['profileIdentity']='bad'
    if mutation=='flags':built['records'][0]['command'].remove('-Wl,--no-relax')
    if mutation=='extra-flags':built['records'][0]['command'].insert(1,'-Wl,--relax')
    if mutation=='matrix':built['records'].pop()
    if mutation=='recipe':built['recipeDigest']='sha256:'+'0'*64
    if mutation=='policy':built['policy']='rv64i-lp64-bare-no-relax.v1'
    if mutation=='tool':built['toolchains']['source']['tools']['as']['digest']='sha256:'+'0'*64
    if mutation=='environment':monkeypatch.setenv('LIBRARY_PATH','/changed/toolchain')
    if mutation=='mode':built['relaxMode']='omit-the-flag'
    if mutation=='artifact':Path(built['records'][0]['programPath']).write_bytes(b'changed-ELF')
    if mutation=='probe':Path(built['records'][0]['sourcePath']).write_text('void probe(void){}')
    if mutation=='boot':
        boot=Path(value['implementationDirectory'])/'controlled_system_boot.S'
        boot.write_text(boot.read_text().replace('.option norelax','.option relax'))
    if mutation=='linker-script':
        script=Path(value['implementationDirectory'])/'controlled_system.ld'
        script.write_text(script.read_text().replace('0x80000000','0x90000000'))
    if mutation=='cwd':built['records'][0]['steps'][0]['cwd']='/another/workspace'
    if mutation=='object':
        r=built['records'][0]['steps'][0]
        (Path(r['cwd'])/r['output']).write_bytes(b'changed-object')
    if mutation=='wrapper':
        (Path(built['records'][0]['workspace'])/'system-wrapper.c').write_text('void wrong(void){}')
    if mutation=='repeat':built['records'][0]['reproduction']['programDigest']='sha256:'+'0'*64
    if mutation=='stage-exit':built['records'][0]['steps'][0]['returnCode']=23
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
    assert len(result.value.diagnostic['attempts'])==len(profile.RELAX_FLAGS)
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


@pytest.mark.parametrize('profiled_backend',['linker-norelax'],indirect=True)
@pytest.mark.parametrize('failure_stage',['compile-link','elf-inspection'])
def test_linker_candidate_requires_late_wfi_matrix_success(profiled_backend,tmp_path,monkeypatch,failure_stage):
    _,value=profiled_backend
    real_run=profile.run_command
    def late_failure(command,**kwargs):
        if '-O3' in command and '-o' in command:
            output=Path(command[command.index('-o')+1])
            selected_side='target' if failure_stage=='compile-link' else 'source'
            if output.parts[-4:]==('wfi','O3',selected_side,'program.elf'):
                if failure_stage=='compile-link':
                    raise profile.SystemBuildError('SYSTEM_BUILD_COMMAND_FAILED',{
                        'command':command,'returnCode':23,'stderr':'late-link-failure','stdout':'','timedOut':False})
                real_run(command,**kwargs)
                output.write_bytes(b'not-an-ELF')
                return {'command':command,'returnCode':0,'stdout':'','stderr':'','timedOut':False}
        return real_run(command,**kwargs)
    monkeypatch.setattr(profile,'run_command',late_failure)
    output=tmp_path/'late-failure';output.mkdir()
    with pytest.raises(profile.SystemBuildError,match='PROFILE_UNAVAILABLE'):
        backend_module.prepare_build_profile(value,output)
    status=json.loads((output/'build-profile-status.json').read_text())
    attempts=status['diagnostic']['attempts']
    assert [x['relaxMode'] for x in attempts]==list(profile.RELAX_FLAGS)
    assert attempts[-1]['failure']['stage']==failure_stage
    assert attempts[-1]['failure']['operation']=='wfi'
    assert attempts[-1]['failure']['optimization']=='-O3'
    assert status['status']=='failed' and status['semanticApproval'] is False
    assert not (output/'build-profile/profile.json').exists()


def test_changed_boot_cannot_enter_profile_preparation(backend,tmp_path,monkeypatch):
    _,value=backend
    boot=Path(value['implementationDirectory'])/'controlled_system_boot.S'
    boot.write_text(boot.read_text().replace('.option norelax','.option relax'))
    def no_compiler(*a,**kw):pytest.fail('changed implementation reached compiler selection')
    monkeypatch.setattr(profile,'toolchain',no_compiler)
    with pytest.raises(ValueError,match='SYSTEM_BUILD_IMPLEMENTATION_COPY_CHANGED'):
        profile.probe_profile(value,tmp_path/'rejected')
    assert not (tmp_path/'rejected/profile.json').exists()


@pytest.mark.parametrize('profiled_backend',['linker-norelax'],indirect=True)
def test_selected_production_failure_never_retries_without_constraint(profiled_backend,tmp_path,monkeypatch):
    path,value=profiled_backend;real_run=profile.run_command;calls=[]
    def reject_production(command,**kwargs):
        if '-mcmodel=medany' not in command:return real_run(command,**kwargs)
        calls.append(command)
        raise profile.SystemBuildError('SYSTEM_BUILD_COMMAND_FAILED',{
            'command':command,'returnCode':23,'stdout':'','stderr':'production failure','timedOut':False})
    monkeypatch.setattr(profile,'run_command',reject_production)
    source=tmp_path/'independent.c';source.write_text('void independent(void){__asm__ volatile("wfi" ::: "memory");}')
    output=tmp_path/'actual/program.elf'
    with pytest.raises(profile.SystemBuildError,match='SYSTEM_PROGRAM_BUILD_FAILED'):
        backend_module.build_program(backend_path=path,side='source',source=source,
            symbol='independent',operation='wfi',output=output)
    assert len(calls)==1 and '-c' in calls[0]
    assert '-Wl,--no-relax' in profile.program_command(value,side='source',source=source,
        symbol='independent',operation='wfi',output=output,optimization='-O0',relax_mode='linker-norelax')[1][-1]['command']
    assert not output.exists() and not output.with_name(output.name+'.build.json').exists()
