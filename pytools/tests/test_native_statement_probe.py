from copy import deepcopy
import shutil
import subprocess

import pytest
from riscv2x86_py import native_statement_probe as probe
from riscv2x86_py.native_dependency_evidence import bytes_digest


def candidate():
    first='out = a + 1;';second='out = a + 2;'
    raw=('unsigned long choose(unsigned long a){unsigned long out; if(a){'+first+'}else{'+second+'} return out;}\n').encode()
    edits=[]
    for i,text in enumerate([first,second]):
        start=raw.index(text.encode())
        edits.append({'instanceBindingIdentity':f'instance-{i}','sourceRange':[start,start+len(text)],
            'replacement':text,'proofScope':'local-statement-under-unchanged-C-context'})
    return {'candidateDigest':bytes_digest(raw),'candidateIdentity':'fixture-only-no-cross-ISA-proof','edits':edits},raw


def test_real_compiler_distinguishes_instances_on_different_branches(tmp_path):
    gcc=shutil.which('gcc')
    if not gcc:pytest.skip('native compiler required')
    receipt,raw=candidate();unit,observer,metadata=probe.materialize(receipt,raw)
    # A function entry occurs for either branch. A statement trace must retain
    # the unvisited instance instead of approving both from that entry.
    (tmp_path/'unit.c').write_bytes(unit+b'int main(void){return choose(3)==4?0:1;}\n')
    (tmp_path/'observer.c').write_text(observer)
    exe=tmp_path/'test'
    subprocess.run([gcc,'-std=gnu11','-O2','-Werror',str(tmp_path/'unit.c'),str(tmp_path/'observer.c'),'-o',str(exe)],check=True,capture_output=True)
    result=subprocess.run([str(exe)],check=True,capture_output=True)
    rows=probe.counts(result.stderr,metadata)
    assert rows[0]['instrumentedStatementCompleted']
    assert not rows[1]['instrumentedStatementCompleted'] and rows[1]['entered']==0
    assert not all(row['instrumentedStatementCompleted'] for row in rows)


@pytest.mark.parametrize('mutation',['bytes','duplicate','order','scope'])
def test_materialization_does_not_guess_replacement_positions(mutation):
    receipt,raw=candidate();receipt=deepcopy(receipt)
    if mutation=='bytes':receipt['edits'][0]['replacement']='different();'
    elif mutation=='duplicate':receipt['edits'][1]['instanceBindingIdentity']=receipt['edits'][0]['instanceBindingIdentity']
    elif mutation=='order':receipt['edits'].reverse()
    else:receipt['edits'][0]['proofScope']='unknown'
    with pytest.raises(ValueError):probe.materialize(receipt,raw)


@pytest.mark.parametrize('log',['','0:1:0','0:1:2','0:1:1\n0:1:1','99:1:1'])
def test_empty_partial_forged_or_duplicate_events_do_not_close_coverage(log):
    receipt,raw=candidate();_,_,metadata=probe.materialize(receipt,raw)
    data=b'\n'.join(('r2x-probe:'+metadata['nonce']+':'+part).encode() for part in log.splitlines())
    if log in ('','0:1:0'):
        assert not all(r['instrumentedStatementCompleted'] for r in probe.counts(data,metadata))
    else:
        with pytest.raises(ValueError):probe.counts(data,metadata)
