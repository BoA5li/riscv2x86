"""Bounded compiler-shell proof for the canonical separate-object runtime build."""
from dataclasses import asdict, is_dataclass
from .semantic_content import semantic_identity

AUTOMATIC_RUNTIME_BUILD_CONTRACT = 'automatic-gcc-separate-tu-no-lto-v1'


def prove_runtime_shell(fragment, implementation_identity, build_contract):
    raw = asdict(fragment) if is_dataclass(fragment) else dict(fragment)
    if build_contract != AUTOMATIC_RUNTIME_BUILD_CONTRACT:
        raise ValueError('CSR_RUNTIME_SHELL_BUILD_CONTRACT_REQUIRED')
    if raw.get('isAsmGoto') or raw.get('gotoLabels'):
        raise ValueError('CSR_RUNTIME_SHELL_CONTROL_UNSUPPORTED')
    outputs, inputs = raw.get('outputs', []), raw.get('inputs', [])
    # First supported runtime shape: one read result, or a discarded read.
    # Write/RMW argument evaluation needs a separate shell proof.
    if inputs or len(outputs) > 1:
        raise ValueError('CSR_RUNTIME_SHELL_OPERAND_SHAPE_UNSUPPORTED')
    if any(x.get('constraint') != '=r' or x.get('isEarlyClobber') for x in outputs):
        raise ValueError('CSR_RUNTIME_SHELL_CONSTRAINT_UNSUPPORTED')
    clobbers = tuple(raw.get('clobbers') or ())
    if any(x not in ('memory', 'cc') for x in clobbers):
        raise ValueError('CSR_RUNTIME_SHELL_CLOBBER_UNSUPPORTED')
    if not implementation_identity:
        raise ValueError('CSR_RUNTIME_SHELL_IMPLEMENTATION_REQUIRED')
    payload = {'schemaVersion': 'riscv2x86.csr-runtime-shell.v1',
               'fragmentId': raw.get('id') or raw.get('fragmentId'),
               'outputConstraints': [x['constraint'] for x in outputs],
               'inputConstraints': [], 'clobbers': list(clobbers),
               'volatile': raw.get('isVolatile') is True,
               'implementationIdentity': implementation_identity,
               'buildContract': build_contract,
               'invocation': 'one-opaque-external-call-at-source-statement',
               'continuation': 'fallthrough',
               'barrierPlacement': 'before-and-after-call', 'complete': True}
    return {**payload, 'shellIdentity': semantic_identity(payload)}


def render_runtime_shell(call, shell):
    if shell.get('complete') is not True:
        raise ValueError('CSR_RUNTIME_SHELL_PROOF_REQUIRED')
    clobbers = shell['clobbers']
    suffix = ' ::: ' + ', '.join('"' + x + '"' for x in clobbers) if clobbers else ''
    barrier = '__asm__ __volatile__(""' + suffix + ');'
    return 'do { ' + barrier + ' ' + call + ' ' + barrier + ' } while (0);'
