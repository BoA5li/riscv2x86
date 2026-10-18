"""Registered atomic-builtin shell closure, never a generic pure-C exemption."""
from dataclasses import is_dataclass,asdict
from .compiler_value_flow import identity
from .compiler_operand_type import compiler_operand_type_from_dict
from .l2_atomic_authority import validate_atomic_proof_facts
from .l2_effect_proof import effect_proof_facts_from_dict

SCHEMA='riscv2x86.atomic-builtin-shell.v1'
SEMANTICS={f'c.builtin.atomic-{name}.u32-u64.v2' for name in
           ('fetch-add','fetch-and','fetch-or','fetch-xor','exchange')}


def fnv(text):
    state=14695981039346656037
    for byte in text.encode():state=((state^byte)*1099511628211)&0xffffffffffffffff
    return f'fnv1a64:{state:016x}'


def build_atomic_builtin_shell(fragment,approval):
    if is_dataclass(fragment):fragment=asdict(fragment)
    fragment_id=fragment.get('id') or fragment.get('fragmentId')
    if (approval.get('proofStatus')!='approved' or approval.get('replacementKind')!='c_builtin'
            or approval.get('rendererSemanticContractId') not in SEMANTICS
            or approval.get('atomicBuiltinCompilerBarrierShell') is not True
            or approval.get('architectureSemanticsPreserved') is not True
            or approval.get('shellSemanticsPreserved') is not True):
        raise ValueError('ATOMIC_BUILTIN_REGISTERED_SHELL_PROOF_REQUIRED')
    validate_atomic_proof_facts(approval.get('l2AtomicProofFacts'),approval,fragment_id)
    facts=effect_proof_facts_from_dict(approval['l2EffectProofFacts'])
    if not facts.shell_relation.complete or not facts.shell_relation.memory_clobber_preserved:
        raise ValueError('ATOMIC_BUILTIN_MEMORY_SHELL_PROOF_REQUIRED')
    clobbers=sorted(set(fragment.get('clobbers',[])))
    if 'memory' not in clobbers or set(clobbers)-{'memory','cc'}:
        raise ValueError('ATOMIC_BUILTIN_CLOBBER_CONTRACT_UNSUPPORTED')
    operands=fragment['outputs']+fragment['inputs'];types=[]
    for i,operand in enumerate(operands):
        typed=compiler_operand_type_from_dict(operand['compilerType'])
        if (not typed.side_effect_free or typed.qualifiers or typed.pointee_qualifiers
                or (i<len(fragment['outputs']) and not typed.modifiable_lvalue)):
            raise ValueError('ATOMIC_BUILTIN_EVALUATION_CONTRACT_UNSUPPORTED')
        types.append(typed.type_identity)
    payload={'schemaVersion':SCHEMA,'fragmentId':fragment_id,'proofIdentity':approval['proofIdentity'],
        'effectFactsIdentity':approval['l2EffectProofFacts']['factsIdentity'],
        'atomicFactsIdentity':approval['l2AtomicProofFacts']['factsIdentity'],
        'rendererSemanticContractId':approval['rendererSemanticContractId'],
        'rendererContractIdentity':approval['rendererContractIdentity'],
        'sourceClobbers':clobbers,'sourceVolatile':bool(fragment.get('isVolatile')),
        'sourceConstraints':[o['constraint'] for o in operands],'compilerTypeIdentities':types,
        'sourceSliceDigest':approval['sourceSliceDigest'],'replacementDigest':approval['replacementDigest'],
        'asmTemplateDigest':fnv(fragment.get('rawAsmText','')),
        'compilerBarrierShell':'seq_cst_signal_fence_before_and_after'}
    return {**payload,'shellIdentity':identity(payload)}


def validate_atomic_builtin_shell(fragment,approval,replacement):
    built=build_atomic_builtin_shell(fragment,approval)
    raw=approval.get('atomicBuiltinShell')
    asm=fragment.get('rawAsmText','') if isinstance(fragment,dict) else fragment.rawAsmText
    if (raw!=built or fnv(replacement)!=built['replacementDigest'] or fnv(asm)!=built['asmTemplateDigest']):
        raise ValueError('ATOMIC_BUILTIN_SHELL_IDENTITY_MISMATCH')
    return built
