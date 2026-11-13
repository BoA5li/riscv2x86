"""Real compiler calls plus rejection of invalid entry-domain constructions."""
from copy import deepcopy
import shutil
import subprocess

import pytest
from riscv2x86_py import native_api_contract as api

MODEL={'__CHAR_BIT__':'8','__SIZEOF_POINTER__':'8','__SIZEOF_SHORT__':'2',
       '__SIZEOF_INT__':'4','__SIZEOF_LONG__':'8','__SIZEOF_LONG_LONG__':'8'}
SIG={'type':{'qualType':'unsigned long (unsigned long *, const unsigned long *, long)'},
     'variadic':False,'attributes':[],'parameters':[
         {'desugaredQualType':'unsigned long *','qualType':'opaque_ptr'},
         {'qualType':'const unsigned long *'},{'qualType':'long'}]}
DOMAIN={'schemaVersion':api.SCHEMA,'claimScope':'bounded-api-under-declared-preconditions',
 'preconditions':[{'gt':[{'argument':2},{'constant':0}]},
                  {'ge':[{'remainingElements':0},{'argument':2}]},
                  {'ge':[{'remainingElements':1},{'argument':2}]}],
 'cases':[{'objects':[{'id':'buf','type':'unsigned long','alignment':16,'values':[2,3,4,5]}],
           'arguments':[{'object':'buf','offsetElements':1},{'object':'buf','offsetElements':0},{'integer':2}]}]}


def interface():return api.compatible(SIG,SIG,MODEL,MODEL)


def test_actual_compiler_harness_initializes_and_preserves_declared_aliasing(tmp_path):
    gcc=shutil.which('gcc')
    if not gcc:pytest.skip('native compiler required')
    source,contract=api.harness('transform',interface(),DOMAIN)
    implementation='unsigned long transform(unsigned long *d,const unsigned long *s,long n){for(long i=0;i<n;i++)d[i]=s[i]+1;return d[n-1];}\n'
    path=tmp_path/'test.c';path.write_text(implementation+source)
    exe=tmp_path/'test'
    subprocess.run([gcc,'-std=gnu11','-Werror',str(path),'-o',str(exe)],check=True,capture_output=True)
    result=subprocess.run([str(exe)],check=True,capture_output=True)
    assert api.output_protocol(result.stdout,interface(),DOMAIN)
    assert b'object:0:2:4\n' in result.stdout  # source/dest overlap is real, not separate copies
    assert contract['aliasingBySharedObjectIdentity'] and not contract['calleeAllAccessesProvedLegal']


@pytest.mark.parametrize('change',['range','offset','object-type','alignment','precondition','arity','unknown','empty','bool','resource'])
def test_illegal_domains_are_rejected(change):
    domain=deepcopy(DOMAIN);case=domain['cases'][0]
    if change=='range':case['arguments'][2]['integer']=2**64
    elif change=='offset':case['arguments'][0]['offsetElements']=4
    elif change=='object-type':case['objects'][0]['type']='unsigned int'
    elif change=='alignment':case['objects'][0]['alignment']=3
    elif change=='precondition':case['arguments'][2]['integer']=0
    elif change=='arity':case['arguments'].pop()
    elif change=='unknown':domain['preconditions']=[{'python':'True'}]
    elif change=='empty':domain['cases']=[]
    elif change=='bool':case['arguments'][2]['integer']=True
    else:case['objects'][0]['values']=[0]*(api.MAX_ELEMENTS+1)
    with pytest.raises(ValueError):api.harness('transform',interface(),domain)


@pytest.mark.parametrize('type_name',['struct aggregate','double','unsigned __int128','void *','volatile unsigned long *','unsigned long **'])
def test_unimplemented_layouts_are_not_guessed(type_name):
    with pytest.raises(ValueError):api.ctype({'qualType':type_name},MODEL)


def test_three_context_type_layout_mismatch_and_attributes_reject():
    other=deepcopy(SIG);other['parameters'][2]['qualType']='int'
    with pytest.raises(ValueError,match='MISMATCH'):api.compatible(SIG,other,MODEL,MODEL)
    other=deepcopy(SIG);other['attributes']=['MSABIAttr']
    with pytest.raises(ValueError,match='DEFAULT_C_ABI'):api.signature(other,MODEL)


def test_narrow_argument_slots_are_not_mistaken_for_register_full_values():
    sig={'type':{'qualType':'int (int,int,int,int,int,int,int,int,int)'},
         'attributes':[],'variadic':False,'parameters':[{'qualType':'int'}]*9}
    interface=api.signature(sig,MODEL)
    x86=api.abi_layout(interface,'sysv_amd64');rv=api.abi_layout(interface,'riscv_lp64d')
    assert x86['parameters'][3]['location']=={'register':'rcx'}  # never syscall r10
    assert x86['parameters'][6]['location']=={'entryStackOffset':8}
    assert rv['parameters'][6]['location']=={'register':'a6'}
    assert rv['parameters'][8]['location']=={'entryStackOffset':0}
    assert x86['parameters'][0]['valueBits']==32 and x86['parameters'][0]['upperBits']=='not-claimed'
    assert not x86['machineAbiClosureVerified']


def test_output_protocol_requires_completion_and_all_object_elements():
    assert not api.output_protocol(b'',interface(),DOMAIN)
    assert not api.output_protocol(b'case:0:complete:1\n',interface(),DOMAIN)


def test_actual_definition_witness_rejects_wrong_prototype(tmp_path):
    gcc=shutil.which('gcc')
    if not gcc:pytest.skip('native compiler required')
    path=tmp_path/'witness.c';path.write_text('int transform(int x){return x;}'+api.declaration_witness('transform',interface()))
    assert subprocess.run([gcc,'-std=gnu11','-c',str(path),'-o',str(tmp_path/'w.o')],capture_output=True).returncode!=0


def test_typedef_resolution_uses_compiler_graph_and_rejects_shadowing():
    sig={'type':{'qualType':'Count (Ptr, Count)'},'variadic':False,'attributes':[],
         'parameters':[{'qualType':'Ptr'},{'qualType':'Count'}]}
    graph=[{'node':{'kind':'TypedefDecl','name':name,'type':{'qualType':typ}}} for name,typ in
        [('Count','unsigned long'),('Ptr','Count *')]]
    resolved=api.resolve_signature(sig,graph)
    parsed=api.signature(resolved,MODEL)
    assert parsed['return']['cType']=='unsigned long' and parsed['parameters'][0]['cType']=='unsigned long *'
    graph.append({'node':{'kind':'TypedefDecl','name':'Count','type':{'qualType':'unsigned int'}}})
    with pytest.raises(ValueError,match='NOT_UNIQUE'):api.resolve_signature(sig,graph)


def test_abi_neutral_attributes_are_retained_not_used_to_prove_effects():
    source=deepcopy(SIG);target=deepcopy(SIG)
    source['attributes']=['NoThrowAttr','NonNullAttr']
    result=api.compatible(source,target,MODEL,MODEL)
    assert result['declarationAttributes']['source']==['NoThrowAttr','NonNullAttr']
    assert result['declarationAttributes']['target']==[]


def test_alias_spans_and_alignment_are_checked_from_constructed_objects():
    domain=deepcopy(DOMAIN)
    domain['preconditions'].append({'sameObject':[0,1]})
    domain['preconditions'].append({'aligned':[0,8]})
    api.validate(domain,interface())
    domain['preconditions'].append({'disjoint':[0,1,{'argument':2},{'argument':2}]})
    with pytest.raises(ValueError,match='PRECONDITION_NOT_SATISFIED'):api.validate(domain,interface())
    domain['preconditions'].pop()
    domain['preconditions'].append({'aligned':[0,16]})
    with pytest.raises(ValueError,match='PRECONDITION_NOT_SATISFIED'):api.validate(domain,interface())
