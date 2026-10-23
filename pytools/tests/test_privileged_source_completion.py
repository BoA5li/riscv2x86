"""Contract/production state agreement and fail-closed resolution diagnostics."""
from dataclasses import replace
import json
import os
import subprocess
import sys
import pytest

from tests.test_system_instruction_ingress import registry_fixture, source_fixture
from riscv2x86_py.privileged_source_state import complete_privileged_source_state
from riscv2x86_py.cfg import build_cfg_from_blocks
from riscv2x86_py.lift import lift
from riscv2x86_py.csr_value_flow import authority_from_phase4_facts
from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
from riscv2x86_py.privileged_runtime_contracts import PrivilegedRuntimeRegistry, privileged_source_identity
from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.phase6c_constraints import derive_target_constraints


@pytest.mark.parametrize('word', [0x73, 0x10500073])
def test_completion_is_not_equivalent_to_omitting_csr_analysis(word):
    source, target, contract, registry = registry_fixture(word)
    _, facts, _, blocks = source_fixture(word)
    lifted = lift(word.to_bytes(4, 'little'), xlen=64, base_addr=0x10000)
    from riscv2x86_py.schema import AsmFragment
    state = complete_privileged_source_state(
        state=source.privileged_state.state, fragment=AsmFragment(id='frag'),
        lifted_insns=lifted.insns, blocks=blocks, cfg=build_cfg_from_blocks(blocks),
        execution_facts=facts, csr_operand_authority=authority_from_phase4_facts(
            lifted_insns=lifted.insns, runtime_facts=TranslationRuntimeFacts()))
    completed = replace(source, privileged_state=replace(source.privileged_state, state=state))
    matched, details = registry.resolve_with_diagnostics(source.privileged_state, target)
    assert matched == contract and details['resolutionReason'] == 'matched'
    assert state.csr_state_dataflow is not None and state.source_csr_semantic_model is not None
    assert privileged_source_identity(completed.privileged_state) != contract.source_privileged_identity
    matched, details = registry.resolve_with_diagnostics(completed.privileged_state, target)
    assert matched is None and details['resolutionReason'] == 'source_identity_mismatch'
    assert details['expectedSourceIdentity'] == contract.source_privileged_identity
    assert details['actualSourceIdentity'] == privileged_source_identity(completed.privileged_state)
    derived = derive_target_constraints(source_model=completed,
        candidate_plan=generate_candidate_plans(completed)[0], target_environment=target,
        privileged_runtime_registry=registry)
    assert not derived.success and dict(derived.details) == details
    from riscv2x86_py.translate import TargetLoweringAttempt
    attempt = TargetLoweringAttempt.from_constraint_failure(generate_candidate_plans(completed)[0], derived)
    assert dict(attempt.details) == details
    # Binding to the actual completed model succeeds without disabling checks.
    current = replace(contract, source_privileged_identity=privileged_source_identity(completed.privileged_state))
    registry = PrivilegedRuntimeRegistry(version=registry.version, contracts=(current,),
        mapping_registries=registry.mapping_registries)
    assert registry.resolve(completed.privileged_state, target) == current
    assert registry.resolve(source.privileged_state, target) is None


@pytest.mark.parametrize('word', [0x73, 0x10500073])
@pytest.mark.parametrize('mutation', ['empty', 'runtime', 'identity'])
def test_resolution_distinguishes_missing_key_from_wrong_identity(word, mutation):
    source, target, contract, registry = registry_fixture(word)
    if mutation == 'runtime': contract = replace(contract, runtime_identity='another-runtime')
    if mutation == 'identity': contract = replace(contract, source_privileged_identity='sha256:'+'0'*64)
    registry = PrivilegedRuntimeRegistry(version=registry.version,
        contracts=() if mutation == 'empty' else (contract,), mapping_registries=registry.mapping_registries)
    result, details = registry.resolve_with_diagnostics(source.privileged_state, target)
    assert result is None and registry.resolve(source.privileged_state, target) is None
    assert details['resolutionReason'] == ('source_identity_mismatch' if mutation == 'identity' else 'registry_key_not_found')
    assert json.loads(details['requestedKey'])[-2:] == ['test-runtime', '1']


@pytest.mark.parametrize('word', [0x73, 0x10500073])
def test_completed_identity_is_stable_in_independent_processes(word):
    script = '''
from tests.test_system_instruction_ingress import source_fixture
from riscv2x86_py.controlled_system_contract import source_model
from riscv2x86_py.system_instruction_ingress import SystemInstructionAuthority
from riscv2x86_py.privileged_runtime_contracts import privileged_source_identity
from dataclasses import asdict
source,facts,value,_=source_fixture(WORD)
from riscv2x86_py.schema import AsmFragment
finding={'fragment':asdict(AsmFragment(id='frag',isVolatile=True,clobbers=['memory'])),
 'machineCodeHex':(WORD).to_bytes(4,'little').hex(),'sourceDigest':value['sourceDigest']}
model=source_model(finding,facts,SystemInstructionAuthority.from_dict(value))
print(privileged_source_identity(model.privileged_state))
'''.replace('WORD', str(word))
    results = []
    for seed in ('1', '2', '123'):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        result = subprocess.run([sys.executable, '-c', script], env=env,
            capture_output=True, text=True, check=True)
        results.append(result.stdout.splitlines()[-1])
    assert len(set(results)) == 1
