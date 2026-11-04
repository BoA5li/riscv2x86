"""Real report serialization and strict floating/integer authority separation."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from riscv2x86_py.compiler_floating_type import parse
from riscv2x86_py.compiler_operand_type import compiler_operand_type_from_dict


def fact(width=64, format='ieee754-binary64'):
    return dict(schemaVersion='riscv2x86.clang-operand-type.v2',
        canonicalType='double', widthBits=width, alignmentBytes=8,
        isInteger=False, isPointer=False, isSigned=False, pointeeType='',
        pointeeWidthBits=0, pointeeAlignmentBytes=0, pointeeIsInteger=False,
        sideEffectFree=True, modifiableLvalue=True, expressionRepeatable=True,
        qualifiers='', pointeeQualifiers='', isFloating=True, floatingFormat=format)


@pytest.mark.parametrize('width,format', [(32,'ieee754-binary32'), (64,'ieee754-binary64'), (128,'unmodelled')])
def test_formats_are_facts_not_integer_admission(width, format):
    value=fact(width,format)
    got=parse(json.loads(json.dumps(value)))
    assert got.format_modelled == (width in {32,64})
    assert got.type_identity == parse(deepcopy(value)).type_identity
    with pytest.raises(ValueError,match='SCHEMA'):
        compiler_operand_type_from_dict(value)


@pytest.mark.parametrize('key,value', [
    ('widthBits',True),('widthBits',-1),('widthBits',2**32),('alignmentBytes',0),
    ('isFloating',1),('isFloating',False),('isInteger',True),('isSigned',True),
    ('pointeeType','int'),('pointeeWidthBits',32),('pointeeAlignmentBytes',True),
    ('pointeeIsInteger',True),('qualifiers',[]),('canonicalType',''),
    ('floatingFormat','ieee754-binary32'),('floatingFormat','binary64'),('floatingFormat',[]),
    ('expressionRepeatable','true'),
])
def test_malformed_facts_cannot_acquire_a_type(key,value):
    bad=fact();bad[key]=value
    with pytest.raises(ValueError):parse(bad)


def test_unknown_fields_and_lost_flags_are_rejected():
    for key in fact():
        bad=fact();del bad[key]
        with pytest.raises(ValueError):parse(bad)
    bad=fact();bad['semanticApproval']=True
    with pytest.raises(ValueError):parse(bad)


def test_real_cpp_serializer_retains_float_and_legacy_integer_classes(tmp_path):
    cxx=shutil.which('g++')
    if not cxx:pytest.skip('native C++ compiler required')
    repo=Path(__file__).resolve().parents[2]
    main=tmp_path/'main.cpp'
    main.write_text(r'''
#include "riscv2x86/Report.h"
int main(int argc,char **argv) {
    riscv2x86::ClassificationReport report;
    riscv2x86::Finding finding;
    finding.fragment.emplace();
    finding.fragment->kind=riscv2x86::AsmKind::InlineExtended;
    riscv2x86::AsmOperand operand;
    operand.isOutput=true; operand.constraint="=f"; operand.exprText="result";
    auto &t=operand.compilerType;
    t.canonicalType="double"; t.widthBits=64; t.alignmentBytes=8;
    t.isFloating=true; t.floatingFormat="ieee754-binary64";
    t.sideEffectFree=true; t.modifiableLvalue=true; t.expressionRepeatable=true;
    finding.fragment->outputs.push_back(operand);
    operand.compilerType={};
    operand.constraint="r"; operand.isOutput=false;
    operand.compilerType.canonicalType="unsigned long";
    operand.compilerType.widthBits=64; operand.compilerType.alignmentBytes=8;
    operand.compilerType.isInteger=true;
    finding.fragment->inputs.push_back(operand);
    report.findings.push_back(finding);
    report.dumpJSON(argv[1]);
}
''')
    binary=tmp_path/'serialize'
    subprocess.run([cxx,'-std=c++17','-I'+str(repo/'include'),str(main),str(repo/'src/Report.cpp'),'-o',str(binary)],
                   check=True,capture_output=True,text=True)
    output=tmp_path/'report.json'
    subprocess.run([str(binary),str(output)],check=True)
    data=json.loads(output.read_text())['findings'][0]['fragment']
    assert parse(data['outputs'][0]['compilerType']) == parse(fact())
    integer=data['inputs'][0]['compilerType']
    assert compiler_operand_type_from_dict(integer).is_integer
    assert integer['schemaVersion']=='riscv2x86.clang-operand-type.v1'
    assert 'isFloating' not in integer and 'floatingFormat' not in integer


@pytest.mark.parametrize('ctype,opcode,width,format', [
    ('float','fabs.s',32,'ieee754-binary32'),
    ('double','fabs.d',64,'ieee754-binary64'),
    ('float','fsqrt.s',32,'ieee754-binary32'),
    ('double','fsqrt.d',64,'ieee754-binary64'),
])
def test_real_clang_frontend_exports_floating_operands(tmp_path,ctype,opcode,width,format):
    import os
    frontend=os.environ.get('RISCV2X86_TEST_FRONTEND')
    if not frontend or not Path(frontend).is_file():
        pytest.skip('rebuilt RISCV2X86_TEST_FRONTEND required')
    source=tmp_path/'floating.c'
    source.write_text(ctype+' entry('+ctype+' value) { '+ctype+' result; '
        '__asm__("'+opcode+' %0, %1" : "=f"(result) : "f"(value)); return result; }\n')
    report=tmp_path/'raw.json'
    result=subprocess.run([frontend,'--analysis-only','--no-builtin-rules','-o',str(tmp_path/'unused'),
        '--src-root',str(tmp_path),'--report-json',str(report),str(source),'--',
        '--target=riscv64-linux-gnu','-std=gnu11','-march=rv64gc','-mabi=lp64d'],
        capture_output=True,text=True,check=False,timeout=120)
    assert result.returncode==0,result.stderr
    fragments=[r['fragment'] for r in json.loads(report.read_text())['findings'] if 'fragment' in r]
    assert len(fragments)==1
    for operand in fragments[0]['outputs']+fragments[0]['inputs']:
        parsed=parse(operand['compilerType'])
        assert parsed.width_bits==width and parsed.floating_format==format
        assert parsed.canonical_type==ctype and parsed.side_effect_free
