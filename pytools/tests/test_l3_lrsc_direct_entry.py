"""Direct ingress preserves LR/SC proof and execution gates; fixtures are not ISA acceptance."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import pytest
from riscv2x86_py import automatic_batch_cli as auto
from riscv2x86_py.l3_trace_support import identity,digest


@pytest.fixture
def inventory_fixture(tmp_path,monkeypatch):
    from riscv2x86_py import l3_lrsc_backend
    source=tmp_path/'unrelated.c';source.write_text('unsigned long f(unsigned long *p,unsigned long x){return x;}')
    front=tmp_path/'frontend';front.write_text('fixture');front.chmod(0o755)
    backend=tmp_path/'backend.json';backend.write_text('{}')
    fn={'name':'f','functionId':identity('function'),'sourceDigest':digest(source),
        'arity':2,'parameterTypes':['unsigned long *','unsigned long'],'pointerParameters':[0],
        'returnType':'unsigned long','compilerAtomicFunctionScope':{'fixtureOnly':True},
        'l2OperandBoundary':{'complete':True}}
    monkeypatch.setattr(auto,'inspect_entry_points',lambda *a:(False,(deepcopy(fn),)))
    calls=[]
    def validate(path):
        calls.append(str(path))
        return {'backendIdentity':identity('fixture backend'),'sourceExecutor':'rv','targetExecutor':'x86'}
    monkeypatch.setattr(l3_lrsc_backend,'validate',validate)
    return source,front,backend,calls


def test_inventory_wires_direct_producer_and_original_route(inventory_fixture,tmp_path):
    source,front,backend,calls=inventory_fixture
    directory=tmp_path/'inventory'
    auto.prepare_automatic_inventory(source,directory,frontend=front,l3_lrsc_backend=backend)
    assert calls==[str(backend)]
    descriptor=json.loads((directory/'cases/unrelated/riscv2x86-evaluation.json').read_text())['request']
    validators=descriptor['runtimeRegistryTemplate']['validators']
    assert {'L0','L1','L2','L3'}<=set(validators)
    assert validators['L1']['config']['mode']=='memory-object-functions'
    assert any(p['providerId']=='automatic-l2-atomic-rmw-v1' for p in validators['L2']['config']['providers'])
    config=validators['L3']['config']
    assert validators['L3']['type']=='l3-lrsc-trace-route'
    assert config['schemaVersion']=='riscv2x86.lrsc-trace-route.v1'
    assert config['backendDigest']==digest(backend)
    assert config['sampleCount'] is None and config['cacheModel'] is None
    producer=json.loads((directory/'cases/unrelated/memory-intent-producer.json').read_text())
    assert 'riscv2x86_py.l3_lrsc_intent' in producer['command']
    assert '--selection-file' not in producer['command']
    from riscv2x86_py.l3_intent_ingress import validate_manifest
    validate_manifest(producer,source)
    from riscv2x86_py.validation_runtime_registry import _BUILTIN_FACTORIES
    from riscv2x86_py import l3_lrsc_route
    assert callable(_BUILTIN_FACTORIES['l3-lrsc-trace-route'](config))
    with pytest.raises(ValueError,match='CONFIGURATION_INVALID'):
        _BUILTIN_FACTORIES['l3-lrsc-trace-route']({**config,'sampleCount':0})


@pytest.mark.parametrize('other',['l3_memory_backend','l3_control_backend','l3_program_backend',
    'l3_fence_backend','l3_atomic_backend','l3_cache_model','l3_mechanism_selections'])
def test_explicit_backend_conflicts_cannot_silently_choose_a_route(inventory_fixture,tmp_path,other):
    source,front,backend,calls=inventory_fixture
    with pytest.raises(ValueError,match='CONFLICT'):
        auto.prepare_automatic_inventory(source,tmp_path/'inventory',frontend=front,
            l3_lrsc_backend=backend,**{other:backend})
    assert not calls and not (tmp_path/'inventory').exists()


def test_invalid_backend_is_not_replaced_with_static_profile(inventory_fixture,tmp_path,monkeypatch):
    from riscv2x86_py import l3_lrsc_backend
    source,front,backend,_=inventory_fixture
    def reject(path):raise ValueError('BACKEND_CHANGED')
    monkeypatch.setattr(l3_lrsc_backend,'validate',reject)
    with pytest.raises(ValueError,match='BACKEND_CHANGED'):
        auto.prepare_automatic_inventory(source,tmp_path/'inventory',frontend=front,l3_lrsc_backend=backend)
    assert not (tmp_path/'inventory').exists()


@pytest.mark.parametrize('operation',['fetch_add','fetch_sub','fetch_and','fetch_or','fetch_xor'])
@pytest.mark.parametrize('width',[32,64])
def test_direct_and_selected_producer_have_identical_semantic_response(tmp_path,width,operation):
    from tests.test_l3_lrsc_persistence import approved_spec
    from tests.test_l3_scalar_trace import request
    from riscv2x86_py.l3_lrsc_intent import produce
    from riscv2x86_py.l3_mechanism_selection import produce as selected
    f,functions,_=approved_spec(tmp_path,width,operation)
    req=request(f);req['candidates'][0]['compilerFunctions']=functions
    req['requestIdentity']=identity({k:v for k,v in req.items() if k!='requestIdentity'})
    assert produce(req)==selected(req,{'lrsc':{}})
    assert produce(req)['profiles'][0]['complete']
    changed=deepcopy(req)
    changed['candidates'][0]['finding']['approvalArtifact']['l2LrscProofFacts']['complete']=False
    changed['requestIdentity']=identity({k:v for k,v in changed.items() if k!='requestIdentity'})
    assert not produce(changed)['profiles'][0]['complete']


def test_actual_external_direct_producer_still_runs_and_pins_dependencies(tmp_path):
    from tests.test_l3_lrsc_persistence import approved_spec
    from tests.test_l3_scalar_trace import request
    from riscv2x86_py import l3_lrsc_intent as module
    from riscv2x86_py.l3_implementation_dependencies import implementation_paths
    f,functions,_=approved_spec(tmp_path,32,'fetch_sub')
    req=request(f);req['candidates'][0]['compilerFunctions']=functions
    req['requestIdentity']=identity({k:v for k,v in req.items() if k!='requestIdentity'})
    command=[sys.executable,'-m','riscv2x86_py.l3_lrsc_intent','--implementation',str(Path(module.__file__).resolve())]
    for path in implementation_paths():command.extend(('--dependency',path))
    r=subprocess.run(command,input=json.dumps(req),capture_output=True,text=True,timeout=30)
    assert r.returncode==0,r.stderr
    assert json.loads(r.stdout)==module.produce(req)
    # A static producer success is not production acceptance, and missing pinned
    # dependencies still cause rejection by the actual child entry point.
    r=subprocess.run(command[:-2],input=json.dumps(req),capture_output=True,text=True,timeout=30)
    assert r.returncode!=0 and 'DEPENDENCIES_UNPINNED' in r.stderr


@pytest.mark.parametrize('entry',['direct','selection'])
def test_driver_records_actual_entry_and_preserves_failed_production(tmp_path,monkeypatch,entry):
    from riscv2x86_py import l3_lrsc_backend
    path=Path(__file__).resolve().parents[2]/'experiment/run_l3_lrsc_trace.py'
    spec=importlib.util.spec_from_file_location('lrsc_driver_'+entry,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    tool=tmp_path/'tool';tool.write_text('fixture');out=tmp_path/'output'
    monkeypatch.setattr(l3_lrsc_backend,'validate',lambda *a:{})
    commands=[]
    def run(command,stdout,**kwargs):
        commands.append(command);stdout.write('original production failure\n');stdout.flush()
        return SimpleNamespace(returncode=2)
    monkeypatch.setattr(module.subprocess,'run',run)
    monkeypatch.setattr(sys,'argv',[str(path),'--input',str(tool),'--frontend',str(tool),
        '--backend',str(tool),'--output',str(out),'--entry-mode',entry])
    assert module.main()==2
    state=json.loads((out/'run-status.json').read_text())
    assert state['entryMode']==entry and not state['productionAcceptanceComplete']
    assert 'original production failure' in state['normalProductionLogTail']
    assert ('--l3-lrsc-backend' in commands[0])==(entry=='direct')
    assert ('--l3-mechanism-selections' in commands[0])==(entry=='selection')


def test_runtime_factory_keeps_prior_layers_and_changed_backend_gates(inventory_fixture,tmp_path):
    from riscv2x86_py.validation_runtime_registry import _BUILTIN_FACTORIES
    from riscv2x86_py.translation_validation import ValidationProfile,ValidationLayerResult,ValidationLevel
    from riscv2x86_py.validation_status import ValidationStatus
    source,front,backend,calls=inventory_fixture
    directory=tmp_path/'inventory'
    auto.prepare_automatic_inventory(source,directory,frontend=front,l3_lrsc_backend=backend)
    request=json.loads((directory/'cases/unrelated/riscv2x86-evaluation.json').read_text())['request']
    config=request['runtimeRegistryTemplate']['validators']['L3']['config']
    execute=_BUILTIN_FACTORIES['l3-lrsc-trace-route'](config)
    plan=SimpleNamespace(profile=ValidationProfile.MICROARCH)
    value=execute(validation_plan=plan,prior_layer_results=[])
    assert value.status is ValidationStatus.INCONCLUSIVE and 'PRIOR_LAYER_REQUIRED' in value.detail
    prior=[ValidationLayerResult(level,ValidationStatus.VERIFIED,
           detail=json.dumps({'claimScope':'architectural'}))
           for level in (ValidationLevel.L0,ValidationLevel.L1,ValidationLevel.L2)]
    backend.write_text('{"changed":true}')
    value=execute(validation_plan=plan,prior_layer_results=prior)
    assert value.status is ValidationStatus.INCONCLUSIVE and 'BACKEND_CHANGED' in value.detail
    assert len(calls)==1
