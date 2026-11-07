"""Explicit source/target GMP build roles; configurations are not ABI proofs."""
import re
import subprocess
from .project_build_records import identity
from .project_tool_resolution import resolve_executable
from .project_compile_context import digest

SCHEMA = 'riscv2x86.project-build-profile.v1'
ROLES = ('cc', 'hostcc', 'ar', 'ranlib', 'ld')


def create(side, host, tools, cflags):
    if side not in ('source', 'target') or not re.fullmatch(r'[A-Za-z0-9_.+-]+', host):
        raise ValueError('BUILD_PROFILE_ROLE_OR_HOST_INVALID')
    if set(tools) != set(ROLES):
        raise ValueError('BUILD_PROFILE_EXACT_TOOL_ROLES_REQUIRED')
    # This profile is deliberately limited to flags represented by GMP CFLAGS.
    # ABI/optimization/protection flags are preserved verbatim, never rewritten.
    if not isinstance(cflags, str) or not cflags or any(c in cflags for c in '\n\r\x00'):
        raise ValueError('BUILD_PROFILE_CFLAGS_INVALID')
    bound = {}
    for role in ROLES:
        path = resolve_executable(tools[role])
        bound[role] = {'path': str(path), 'digest': digest(path)}
    result = subprocess.run([bound['cc']['path'], '-dumpmachine'], capture_output=True,
                            text=True, check=True, timeout=30)
    for role, item in bound.items():
        if digest(item['path']) != item['digest']:
            raise ValueError('BUILD_PROFILE_TOOL_CHANGED:'+role)
    triple = result.stdout.strip()
    prefix = 'riscv64' if side == 'source' else 'x86_64'
    if triple.split('-')[0] != prefix or host.split('-')[0] != prefix:
        raise ValueError('BUILD_PROFILE_COMPILER_ROLE_MISMATCH')
    body = {'schemaVersion': SCHEMA, 'side': side, 'host': host,
            'expectedMachine': 243 if side == 'source' else 62,
            'compilerTriple': triple, 'tools': bound, 'cflags': cflags,
            'abiCompatibilityVerified': False, 'semanticApproval': False}
    return dict(body, profileIdentity=identity(body))


def validate(value):
    if value.get('schemaVersion') != SCHEMA:
        raise ValueError('BUILD_PROFILE_SCHEMA_INVALID')
    fresh = create(value['side'], value['host'],
                   {k: v['path'] for k, v in value['tools'].items()}, value['cflags'])
    if value != fresh:
        raise ValueError('BUILD_PROFILE_REPLAY_MISMATCH')
    return fresh


def targets(values):
    result = list(values)
    # make goals, not arbitrary make assignments/options. No shell evaluation.
    for value in result:
        if not isinstance(value, str) or value.count(':') > 1:
            raise ValueError('BUILD_TEST_TARGET_INVALID')
        parts = value.split(':')
        if any(not re.fullmatch(r'[A-Za-z0-9_./+-]+', v) or v.startswith(('-', '/'))
               or '..' in v.split('/') for v in parts):
            raise ValueError('BUILD_TEST_TARGET_INVALID')
    return result
