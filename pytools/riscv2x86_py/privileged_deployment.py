"""Explicit, artifact-bound privileged deployment and renderer ingress.

A semantic registry does not install a helper or provide deployment capability.
This manifest binds reviewed runtime sources, actual headers/libraries and exact
renderer recipes. It is consumed only in addition to the normal Phase-6 proof.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from .semantic_content import semantic_identity
from .privileged_renderer_manifest import (
    PrivilegedRendererManifest, PrivilegedRendererManifestEntry, PrivilegedRecipeKind,
)
from .plan_types import TargetLoweringKind

SCHEMA = 'riscv2x86.privileged-deployment.v1'


@dataclass(frozen=True)
class PrivilegedDeployment:
    identity: str
    mechanism_identity: str
    capabilities: frozenset[str]
    renderer_manifest: PrivilegedRendererManifest
    artifacts: tuple[tuple[str, str], ...]


def load_privileged_deployment(path, *, runtime_registry_path):
    from .privileged_pipeline_inputs import load_privileged_runtime_registry
    path = Path(path).resolve(); root = path.parent
    value = json.loads(path.read_text())
    fields = {'schemaVersion', 'mechanismIdentity', 'runtimeRegistryDigest', 'sources',
              'headers', 'libraries', 'capabilities', 'rendererManifest', 'deploymentIdentity'}
    if not isinstance(value, dict) or set(value) != fields or value['schemaVersion'] != SCHEMA:
        raise ValueError('PRIV_DEPLOYMENT_SCHEMA_INVALID')
    payload = {k: v for k, v in value.items() if k != 'deploymentIdentity'}
    if value['deploymentIdentity'] != semantic_identity(payload):
        raise ValueError('PRIV_DEPLOYMENT_IDENTITY_MISMATCH')
    if value['runtimeRegistryDigest'] != 'sha256:' + sha256(Path(runtime_registry_path).read_bytes()).hexdigest():
        raise ValueError('PRIV_DEPLOYMENT_RUNTIME_REGISTRY_MISMATCH')
    from .system_instruction_ingress import _DIGEST
    if not isinstance(value['mechanismIdentity'], str) or not _DIGEST.fullmatch(value['mechanismIdentity']):
        raise ValueError('PRIV_DEPLOYMENT_MECHANISM_INVALID')
    artifacts = []
    def artifact(record):
        if not isinstance(record, dict) or set(record) != {'path', 'digest'} or not isinstance(record['path'], str):
            raise ValueError('PRIV_DEPLOYMENT_ARTIFACT_INVALID')
        relative = Path(record['path']); actual = (root/relative).resolve()
        if relative.is_absolute() or not actual.is_relative_to(root) or not actual.is_file():
            raise ValueError('PRIV_DEPLOYMENT_ARTIFACT_UNAVAILABLE')
        if record['digest'] != 'sha256:' + sha256(actual.read_bytes()).hexdigest():
            raise ValueError('PRIV_DEPLOYMENT_ARTIFACT_DIGEST_MISMATCH')
        artifacts.append((str(actual), record['digest']))
    if not isinstance(value['sources'], list) or not value['sources']:
        raise ValueError('PRIV_DEPLOYMENT_SOURCES_REQUIRED')
    for record in value['sources']: artifact(record)
    for key in ('headers', 'libraries'):
        if not isinstance(value[key], dict): raise ValueError('PRIV_DEPLOYMENT_ARTIFACT_MAP_INVALID')
        for token, record in value[key].items():
            if not isinstance(token, str) or not token: raise ValueError('PRIV_DEPLOYMENT_ARTIFACT_TOKEN_INVALID')
            artifact(record)
    capabilities = value['capabilities']
    if (not isinstance(capabilities, list) or not all(isinstance(x, str) and x for x in capabilities)
            or capabilities != sorted(set(capabilities))):
        raise ValueError('PRIV_DEPLOYMENT_CAPABILITIES_INVALID')
    raw = value['rendererManifest']
    if not isinstance(raw, dict) or set(raw) != {'manifestId', 'version', 'entries'} or not isinstance(raw['entries'], list):
        raise ValueError('PRIV_DEPLOYMENT_RENDERERS_INVALID')
    registry = load_privileged_runtime_registry(runtime_registry_path)
    contracts = tuple(registry._contracts.values())
    entries = []
    for item in raw['entries']:
        if not isinstance(item, dict) or set(item) != {'semanticContractId', 'planKind', 'rendererContractId'}:
            raise ValueError('PRIV_DEPLOYMENT_RENDERER_ENTRY_INVALID')
        matches = [c for c in contracts if c.semantic_contract_id == item['semanticContractId']]
        if len(matches) != 1: raise ValueError('PRIV_DEPLOYMENT_RENDERER_CONTRACT_MISMATCH')
        c = matches[0]
        expected = {'ecall': TargetLoweringKind.SYSCALL_OR_SERVICE_ABI_ADAPTER,
                    'wfi': TargetLoweringKind.PRIVILEGED_EVENT_ADAPTER}.get(c.environment_route_kind.value)
        if expected is None or item['planKind'] != expected.value:
            raise ValueError('PRIV_DEPLOYMENT_RENDERER_KIND_MISMATCH')
        libraries = (() if c.required_library is None else (c.required_library,))
        if (libraries != c.required_libraries or not libraries
                or not set(c.required_headers).issubset(value['headers'])
                or not set(libraries).issubset(value['libraries'])
                or not set(c.required_capabilities).issubset(capabilities)):
            raise ValueError('PRIV_DEPLOYMENT_RUNTIME_DEPENDENCIES_MISSING')
        entries.append(PrivilegedRendererManifestEntry(c.semantic_contract_id, expected,
            item['rendererContractId'], PrivilegedRecipeKind.RUNTIME_CALL, c.callable_identifier,
            c.argument_operand_indexes, c.result_operand_indexes, c.required_headers, libraries,
            c.required_target_capability, c.target_environment_id, registry.version))
    if not entries or len(entries) != len(contracts):
        raise ValueError('PRIV_DEPLOYMENT_RENDERER_COVERAGE_INCOMPLETE')
    if set(capabilities) != {cap for c in contracts for cap in c.required_capabilities}:
        raise ValueError('PRIV_DEPLOYMENT_CAPABILITY_SCOPE_MISMATCH')
    manifest = PrivilegedRendererManifest(manifest_id=raw['manifestId']+'@'+value['deploymentIdentity'],
        version=raw['version']+'+'+value['deploymentIdentity'], entries=entries)
    return PrivilegedDeployment(value['deploymentIdentity'], value['mechanismIdentity'],
        frozenset(capabilities), manifest, tuple(artifacts))
