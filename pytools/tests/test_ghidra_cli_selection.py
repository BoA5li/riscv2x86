"""CLI composition boundary only; the original pipeline is explicitly mocked."""
import os
import sys
from types import SimpleNamespace
from riscv2x86_py import cli


def test_selected_query_installation_is_propagated_to_pcode_runtime(tmp_path,monkeypatch):
    selected=str(tmp_path/'selected-installation');captured={}
    monkeypatch.setenv('GHIDRA_INSTALL_DIR',str(tmp_path/'other-installation'))
    monkeypatch.setattr(cli,'load_riscv_register_resolver_via_pythonrun',
                        lambda **kw:SimpleNamespace(installation_dir=selected))
    def run(*a,**kw):
        captured.update(kw);captured['installation']=os.environ['GHIDRA_INSTALL_DIR'];return {'failed':0}
    monkeypatch.setattr(cli,'run',run)
    monkeypatch.setattr(sys,'argv',['riscv2x86-py','--in',str(tmp_path/'input.json'),
                                  '--out',str(tmp_path/'output.json'),'--skip-verify'])
    assert cli.main()==0 and captured['installation']==selected
    assert captured['verify_enabled'] is False
