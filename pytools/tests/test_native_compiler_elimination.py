"""Real host compiler dump acquisition; no cross-ISA/machine proof claim."""
from copy import deepcopy
import pytest
import subprocess
from riscv2x86_py import native_compiler_elimination as e
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py import native_project_evaluation as p
from .test_native_original_api import native_pair


def test_structured_rtl_ignores_strings_comments_and_keeps_asm_nodes():
    assert e.rtl_facts(b';; (asm_input "ignored")\n(note 1 "asm_operands")')['asmNodeCount'] == 0
    assert e.rtl_facts(b'(insn (asm_operands/v:DI ("add %0,%1") [ (reg:DI 1) ]))')['asmNodeCount'] == 1
    for raw in (b'', b'(note', b'(note "unterminated)', b'(note ]', b'garbage', b'("wrong-head")'):
        with pytest.raises(ValueError): e.rtl_facts(raw)


def test_real_dump_requires_identical_objects_and_readback_never_runs_compiler(native_pair, monkeypatch):
    _, _, paths, root, spec = native_pair
    builds = {s: d.read(path) for s,path in paths.items()}
    # The shared API fixture intentionally builds its original object at O0
    # but advertises O2 for observation variants. Pin an actual matching
    # canonical object here; production never substitutes the baseline.
    for side, build in builds.items():
        profile = spec['profiles'][side]['compile']
        obj = root/(side+'-canonical.o')
        subprocess.run([profile['compiler']['path'], *profile['flags'], '-c',
            build['input']['path'], '-o', str(obj)], check=True, capture_output=True)
        build['object'] = d.snapshot(obj)
    output = root/'compiler-evidence'
    result = e.inspect(spec, builds, output)
    assert result['compilerInlineAsmAbsenceObserved']
    receipt = d.read(result['receipt']['path'])
    assert all(r['object']['digest'] == r['canonicalObject']['digest'] for r in receipt['sides'])
    assert not receipt['machineEliminationVerified'] and not receipt['canonicalInstructionCoverageVerified']
    def forbidden(*a, **kw): raise AssertionError('readback executed compiler')
    monkeypatch.setattr(p, 'command', forbidden)
    assert e.inspect(spec, builds, output, readback=True) == result
    (output/'source/final.rtl').write_text('(insn (asm_input "nop"))')
    with pytest.raises(ValueError): e.inspect(spec, builds, output, readback=True)


def test_wrong_canonical_object_never_establishes_absence(native_pair):
    _, _, paths, root, spec = native_pair
    builds = {s: d.read(path) for s,path in paths.items()}
    # Own the upstream captured-object boundary: use a different valid ELF.
    builds = deepcopy(builds)
    builds['source']['object'] = builds['source']['program']
    result = e.inspect(spec, builds, root/'different-object')
    assert not result['compilerInlineAsmAbsenceObserved']
    assert d.read(result['receipt']['path'])['sides'][0]['reasonCode'] == 'COMPILER_RTL_CANONICAL_OBJECT_DIFFERS'


@pytest.mark.parametrize('active', [False, True])
def test_real_compiler_distinguishes_live_and_dead_asm_without_text_matching(tmp_path, active):
    import shutil, os
    cc = shutil.which('gcc')
    if not cc: pytest.skip('host GCC required')
    src = tmp_path/'body.c'
    src.write_text('void exercise(void){if('+str(int(active))+') __asm__ volatile("nop");}\n')
    obj = tmp_path/'canonical.o'
    subprocess.run([cc,'-O2','-c',str(src),'-o',str(obj)],check=True,capture_output=True)
    profile = {'compiler':d.snapshot(cc),'flags':['-O2'],'directory':str(tmp_path),
               'environment':{'PATH':os.environ['PATH']}}
    spec = {'profiles':{s:{'compile':deepcopy(profile)} for s in ('source','target')},'timeoutSeconds':10}
    builds = {s:{'input':d.snapshot(src),'object':d.snapshot(obj)} for s in ('source','target')}
    result = e.inspect(spec,builds,tmp_path/'observation')
    assert result['compilerInlineAsmAbsenceObserved'] is not active
    assert not d.read(result['receipt']['path'])['machineEliminationVerified']
