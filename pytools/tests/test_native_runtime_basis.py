"""Real native provider metadata; candidate discovery is never link permission."""
from pathlib import Path
import shutil
import subprocess
import sys
import pytest
from riscv2x86_py.native_runtime_basis import collect


def test_real_native_library_query_and_full_elf_metadata(tmp_path):
    cc=shutil.which('gcc');readelf=shutil.which('readelf')
    if not cc or not readelf:pytest.skip('native GCC/readelf required')
    script=tmp_path/'libfake.so';script.write_text('GROUP ( something.so )')
    result=collect([cc],['libc.so.6','not-existing-library.a'],[script],readelf)
    assert any(c['status']=='ELF-inspected' for c in result['candidates'])
    assert any(b['reason']=='RUNTIME_LIBRARY_QUERY_UNRESOLVED' for b in result['blockers'])
    assert any(b['reason']=='RUNTIME_NON_ELF_CONTRACT_REQUIRED' for b in result['blockers'])
    assert any('--dyn-syms' in c['arguments'] for c in result['commands'])
    assert not result['actualLinkSelectionVerified'] and not result['typedCallContractVerified']


def test_missing_explicit_file_and_invalid_library_do_not_gain_permission(tmp_path):
    cc=shutil.which('gcc');readelf=shutil.which('readelf')
    if not cc or not readelf:pytest.skip('native GCC/readelf required')
    result=collect([cc],[],[tmp_path/'missing'],readelf)
    assert result['blockers'][0]['reason']=='RUNTIME_CANDIDATE_UNAVAILABLE'
    with pytest.raises(ValueError,match='BASENAME_REQUIRED'):collect([cc],['../libc.so'],[],readelf)


def test_cli_existing_output_is_never_overwritten(tmp_path):
    script=Path(__file__).resolve().parents[2]/'experiment/collect_native_runtime_basis.py'
    out=tmp_path/'old.json';out.write_text('old evidence')
    result=subprocess.run([sys.executable,str(script),'--compiler','gcc','--output',str(out)],capture_output=True)
    assert result.returncode==2 and out.read_text()=='old evidence'
