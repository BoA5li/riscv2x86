from copy import deepcopy
from types import SimpleNamespace
import pytest
from riscv2x86_py.asm_goto_machine_join import bind_machine_continuations, validate_machine_continuations
from riscv2x86_py.compiler_value_flow import identity
from riscv2x86_py.schema import AsmFragment, AsmGotoEdge


class Symbols:
    def get_symbol_by_name(self, name):
        return [{'st_shndx':1,'st_value':4}]


class Elf:
    def get_section_by_name(self, name):
        assert name=='.symtab'
        return Symbols()


def bind():
    edge=AsmGotoEdge('%l0','exit',0,'source:exit')
    fragment=AsmFragment(id='fragment',gotoEdges=[edge])
    raw=bind_machine_continuations(Elf(),fragment,
        SimpleNamespace(asm_goto_targets={'.Lriscv2x86_asm_goto_0':'exit'}),{1:0},b'1234')
    return raw,[('%l0','exit',0,'source:exit')]


def test_machine_layout_is_not_source_continuation_identity():
    raw,edges=bind()
    assert validate_machine_continuations(raw,'fragment',edges)[0]['machineOffset']==4
    assert raw['bindings'][0]['continuationId']=='source:exit'


@pytest.mark.parametrize('field,value', [('compilerLabel','other'),('continuationId','other'),
    ('externalLabelIndex',1),('assemblerSymbol','fake'),('machineOffset',-1)])
def test_rehashed_wrong_join_is_rejected(field,value):
    raw,edges=bind(); raw['bindings'][0][field]=value
    raw['joinIdentity']=identity({k:v for k,v in raw.items() if k!='joinIdentity'})
    with pytest.raises(ValueError): validate_machine_continuations(raw,'fragment',edges)
