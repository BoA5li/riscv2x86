"""Trap/wait route authority, separate from CSR read/write authority.

The bounded route compares a declared logical event trace and complete logical
state. It cannot establish unbounded liveness or native hardware equivalence.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
from .semantic_content import semantic_identity

SCHEMA = 'riscv2x86.system-route-contract.v1'
_SHA = re.compile(r'^sha256:[0-9a-f]{64}$')


@dataclass(frozen=True)
class SystemRouteContract:
    payload: dict
    routes: tuple = ()  # No fictional CSR is introduced for a trap or wait.

    @property
    def identity(self): return semantic_identity(self.payload)


def load_system_route(value):
    fields = {'schemaVersion', 'operation', 'fragmentId', 'sourceModelIdentity', 'proofIdentity',
        'runtimeContractId', 'runtimeContractVersion', 'initialStateIdentity',
        'sourceRunnerBinaryDigest', 'targetRunnerBinaryDigest', 'sourceRunnerIdentity',
        'targetRunnerIdentity', 'expectedEvents'}
    if not isinstance(value, dict) or set(value) != fields or value['schemaVersion'] != SCHEMA:
        raise ValueError('SYSTEM_ROUTE_SCHEMA_INVALID')
    for key in ('sourceModelIdentity', 'proofIdentity', 'initialStateIdentity',
                'sourceRunnerBinaryDigest', 'targetRunnerBinaryDigest', 'sourceRunnerIdentity', 'targetRunnerIdentity'):
        if not isinstance(value[key], str) or not _SHA.fullmatch(value[key]):
            raise ValueError('SYSTEM_ROUTE_IDENTITY_INVALID:' + key)
    for key in ('fragmentId', 'runtimeContractId', 'runtimeContractVersion'):
        if not isinstance(value[key], str) or not value[key].strip():
            raise ValueError('SYSTEM_ROUTE_TEXT_INVALID:' + key)
    if value['operation'] not in ('ecall', 'wfi'):
        raise ValueError('SYSTEM_ROUTE_OPERATION_UNSUPPORTED')
    events=value['expectedEvents']
    if not isinstance(events,list) or not all(isinstance(e,str) and e for e in events):
        raise ValueError('SYSTEM_ROUTE_EVENT_TRACE_INVALID')
    operation=value['operation']
    if (len(events)<2 or events[0]!=operation+'.enter' or events[-1]!=operation+'.resume'
            or events.count(operation+'.enter')!=1 or events.count(operation+'.resume')!=1
            or (operation=='ecall' and events.count('ecall.handler')!=1)):
        raise ValueError('SYSTEM_ROUTE_EVENT_OBLIGATIONS_INCOMPLETE')
    return SystemRouteContract(dict(value))


def validate_system_route(route, config, artifact, initial_identity, mode):
    value=route.payload
    expected={'ecall':'privileged-runtime.ecall-environment.v1','wfi':'privileged-runtime.wfi-environment.v1'}
    if (getattr(artifact,'fragment_id',None)!=value['fragmentId']
            or getattr(artifact,'source_model_identity',None)!=value['sourceModelIdentity']
            or getattr(artifact,'proof_identity',None)!=value['proofIdentity']
            or getattr(artifact,'translation_plan_id',None)!=expected[value['operation']]
            or getattr(artifact,'runtime_contract_id',None)!=value['runtimeContractId']
            or getattr(artifact,'runtime_contract_version',None)!=value['runtimeContractVersion']
            or initial_identity!=value['initialStateIdentity'] or mode.value!='architecture_equivalent'):
        raise ValueError('SYSTEM_ROUTE_TRANSLATION_BINDING_MISMATCH')
    if config.target_runner.target_execution_mode not in ('logical-csr-runtime','system-adapter','vmm-adapter','emulator-only'):
        raise ValueError('SYSTEM_ROUTE_TARGET_ISOLATION_REQUIRED')
    for side in ('source','target'):
        spec=getattr(config,side+'_runner')
        if semantic_identity(spec)!=value[side+'RunnerIdentity']:
            raise ValueError('SYSTEM_ROUTE_RUNNER_IDENTITY_MISMATCH')
        binary=Path(shutil.which(spec.command[0]) or spec.command[0])
        if 'sha256:'+sha256(binary.read_bytes()).hexdigest()!=value[side+'RunnerBinaryDigest']:
            raise ValueError('SYSTEM_ROUTE_RUNNER_BINARY_MISMATCH')


def validate_system_events(route, source, target):
    expected=tuple(route.payload['expectedEvents'])
    if source.external_events!=expected or target.external_events!=expected:
        raise ValueError('SYSTEM_ROUTE_EXECUTION_EVENT_MISMATCH')
    if source.termination_class!='normal' or target.termination_class!='normal':
        raise ValueError('SYSTEM_ROUTE_EXECUTION_NOT_COMPLETED')
