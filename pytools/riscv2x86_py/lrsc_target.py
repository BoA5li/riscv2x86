"""Registered completion-state refinement from closed LR/SC to locked CAS.

This is a Phase6B-F route, not a bypass of the common proof/selection gates.
Exact attempt counts, reservation observations, and physical traces are outside
this contract and an explicit request for them rejects the route.
"""
from dataclasses import asdict, dataclass
from .route_authority import content_identity

CONTRACT='x86.gnu-att.lrsc.locked-cas.multi-output.v1'


@dataclass(frozen=True)
class LrScTargetContract:
    source_model_identity: str
    sequence_identity: str
    role_indexes: tuple[tuple[str,int], ...]
    memory_index: int
    width: int
    arithmetic_width: int
    operation: str
    object_identity: str
    alignment: int
    ordering_bits: tuple[bool, bool, bool, bool]
    program: tuple[tuple, ...]
    semantic_contract_id: str = CONTRACT
    claim_scope: str = 'architectural-completion-state-with-atomic-rmw-refinement'


def program(width, arithmetic, operation):
    alu={'fetch_add':'add','fetch_and':'and','fetch_or':'or','fetch_xor':'xor'}[operation]
    return (('load','old','object',width),('label','retry'),
        ('extend','old',width,64),('copy','next','old'),
        (alu,'next','input',arithmetic),('extend','next',arithmetic,64),
        ('locked_cmpxchg','object','old','next',width),('branch_failure','retry'),
        ('constant','status',0,64))


def expected_contract(source):
    seq=source.lrsc_sequence
    if seq is None or not seq.complete or not source.operands.complete:
        raise ValueError('LRSC_SOURCE_SEQUENCE_REQUIRED')
    roles=dict(seq.role_operand_indexes);by={o.source_operand_index:o for o in source.operands.operands}
    memory=by[seq.memory_operand_index]
    if (not source.shell.is_volatile or not source.shell.has_memory_clobber
            or set(source.shell.clobbers)-{'memory','cc'}
            or source.shell.has_asm_goto or source.control_flow.has_external_control_flow
            or source.control_flow.has_multiple_exits or source.operation.has_call
            or source.operation.has_return is not False
            or source.registers.reads_or_writes_stack_pointer
            or source.registers.reads_or_writes_frame_pointer
            or source.microarch.explicitly_microarch_sensitive
            or source.microarch.has_experiment_retry_loop):
        raise ValueError('LRSC_TARGET_OBSERVATION_OR_SHELL_DOMAIN_UNSUPPORTED')
    if (memory.address is None or memory.address.memory_object_identity!=seq.memory_object_identity
            or memory.address.alignment_bytes is None
            or memory.address.alignment_bytes<seq.memory_width_bits//8
            or memory.width_bits!=seq.memory_width_bits
            or memory.access.value!='read_write'
            or any(by[roles[r]].access.value!='output' or not by[roles[r]].early_clobber
                   or by[roles[r]].width_bits!=64 for r in ('old','next','status'))):
        raise ValueError('LRSC_TARGET_OBJECT_OR_OUTPUT_CONTRACT_INVALID')
    return LrScTargetContract(seq.to_dict()['modelIdentity'],seq.sequence_identity,
        seq.role_operand_indexes,seq.memory_operand_index,seq.memory_width_bits,
        seq.arithmetic_width_bits,seq.operation,seq.memory_object_identity,
        memory.address.alignment_bytes,seq.lr_ordering_bits+seq.sc_ordering_bits,
        program(seq.memory_width_bits,seq.arithmetic_width_bits,seq.operation))


def candidate(source):
    from .plan_types import (TargetLoweringPlan,TargetLoweringKind,TargetLoweringFamily,
                             PlanPriorityTier,PlanRequirement)
    seq=source.lrsc_sequence
    if seq is None:return ()
    return (TargetLoweringPlan('lrsc-cas:'+seq.to_dict()['modelIdentity'],
        TargetLoweringKind.X86_ATOMIC,TargetLoweringFamily.X86_ATOMIC,
        PlanPriorityTier.X86_ATOMIC_OR_BARRIER,0,
        required_features=frozenset({'x86:atomic'}),
        requirements=frozenset({PlanRequirement.AUTHORITATIVE_OPERAND_BINDINGS,
            PlanRequirement.AUTHORITATIVE_OPERAND_WIDTHS,PlanRequirement.PRESERVE_VOLATILE,
            PlanRequirement.PRESERVE_MEMORY_CLOBBER,PlanRequirement.PRESERVE_CC_CLOBBER,
            PlanRequirement.PRESERVE_ATOMIC_ORDERING,PlanRequirement.PRESERVE_CONTROL_FLOW}),
        metadata={'renderer_semantic_contract_id':CONTRACT}),)


def derive(source, plan, environment):
    from .phase6c_constraints import (TargetConstraintDerivationResult,TargetConstraintModel,
        TargetMemoryConstraint,TargetControlFlowConstraint,TargetOperandConstraint,
        TargetOperandRole,TargetOperandClass,TargetConstraintReasonCode)
    from .source_model import SourceMemoryOrdering
    try:
        contract=expected_contract(source)
        if (plan.kind.value!='x86_atomic' or plan.metadata.get('renderer_semantic_contract_id')!=CONTRACT
                or not environment.supports_gnu_inline_asm
                or not plan.supports_features(environment.available_features)):
            raise ValueError('LRSC_TARGET_CAPABILITY_OR_PLAN_MISMATCH')
        roles=dict(contract.role_indexes);operands=[]
        for o in source.operands.operands:
            memory=o.source_operand_index==contract.memory_index
            output=o.access.value=='output'
            operands.append(TargetOperandConstraint(o.source_operand_index,
                TargetOperandRole.READ_WRITE if memory else TargetOperandRole.OUTPUT if output else TargetOperandRole.INPUT,
                frozenset({TargetOperandClass.MEMORY if memory else TargetOperandClass.GENERAL_REGISTER}),
                early_clobber=o.early_clobber,required_width_bits=o.width_bits,
                requires_fixed_register=o.source_operand_index==roles['old'],
                fixed_register_name='rax' if o.source_operand_index==roles['old'] else None,
                gnu_constraint_body='a' if o.source_operand_index==roles['old'] else None))
        return TargetConstraintDerivationResult.succeeded(TargetConstraintModel(
            plan_id=plan.plan_id,environment=environment,operand_constraints=tuple(operands),
            lrsc_sequence_contract=contract,preserve_volatile=True,preserve_cc_clobber=True,
            memory_constraint=TargetMemoryConstraint(requires_memory_clobber=True,
                requires_atomic_ordering=True,requires_compiler_barrier=True,requires_hardware_barrier=True,
                atomic_success_ordering=SourceMemoryOrdering.SEQ_CST,
                required_atomic_width_bits=contract.width,required_alignment_bytes=contract.alignment),
            control_flow_constraint=TargetControlFlowConstraint(preserve_control_flow=True,preserve_retry_loop=True)))
    except (ValueError,KeyError) as exc:
        return TargetConstraintDerivationResult.failure(plan_id=plan.plan_id,
            reason_codes=(TargetConstraintReasonCode.LRSC_SEQUENCE_CONTRACT_REJECTED,),
            details={"reasonCode":str(exc)})


def _extend(term, width, result=64):
    return term if width==result else ('sext',width,result,term)


def _low(term, width):
    if isinstance(term,tuple) and term[0]=='word' and term[1]==width:return term
    if isinstance(term,tuple) and term[0]=='sext' and term[1]==width:return term[3]
    return ('low',width,term)


def symbolic_proof(contract):
    """Check all bit patterns by symbolic identity, plus the registered CAS invariant.

    Under a failed CAS the accumulator becomes the new observed word and the
    loop recomputes desired from that word. Under a successful CAS the update
    linearizes at the locked instruction. Reservation validity is not replaced
    by an equality test: the relation abstracts internal failed attempts.
    """
    if contract.program!=program(contract.width,contract.arithmetic_width,contract.operation):
        raise ValueError('LRSC_TARGET_PROGRAM_NOT_REGISTERED')
    old=_extend(('word',contract.width),contract.width)
    opcode={'fetch_add':'add','fetch_and':'and','fetch_or':'or','fetch_xor':'xor'}[contract.operation]
    next_value=_extend((opcode,contract.arithmetic_width,old,('input',64)),contract.arithmetic_width)
    regs={};cas=None
    for ins in contract.program:
        if ins[0]=='load':regs[ins[1]]=('word',ins[3])
        elif ins[0]=='extend':regs[ins[1]]=_extend(regs[ins[1]],ins[2],ins[3])
        elif ins[0]=='copy':regs[ins[1]]=regs[ins[2]]
        elif ins[0] in {'add','and','or','xor'}:regs[ins[1]]=(ins[0],ins[3],regs[ins[1]],('input',64))
        elif ins[0]=='locked_cmpxchg':cas=(_low(regs[ins[2]],ins[4]),_low(regs[ins[3]],ins[4]))
        elif ins[0]=='constant':regs[ins[1]]=ins[2]
    if (regs!={'old':old,'next':next_value,'status':0}
            or cas!=(('word',contract.width),_low(next_value,contract.width))):
        raise ValueError('LRSC_TARGET_STATE_RELATION_UNPROVEN')
    return {'method':'symbolic-bitvector-terms-and-registered-locked-cas-invariant-v1',
        'allBitPatterns':True,'outputRoles':['old','next','status'],
        'successLinearization':'locked-cmpxchg-success',
        'retryInvariant':'expected-is-last-observed-word;recompute-all-next-bits',
        'failureCountEqualityClaimed':False,'physicalMemoryOrderMeasured':False,
        'progressClaim':'no-individual-termination-claim',
        'observationScope':contract.claim_scope}


def prove(request):
    from .phase6d_common import reject,SemanticProofReasonCode,finalize,PreservationConclusion
    c=request.constraints;contract=c.lrsc_sequence_contract
    try:
        if contract!=expected_contract(request.source_model):raise ValueError('LRSC_CONTRACT_SOURCE_MISMATCH')
        expected=derive(request.source_model,request.candidate_plan,request.target_environment)
        if not expected.success or c!=expected.constraints:raise ValueError('LRSC_CONSTRAINTS_CHANGED')
        symbolic_proof(contract)
    except (ValueError,TypeError,KeyError):return reject(request,SemanticProofReasonCode.BINDING_UNSAFE)
    return finalize(request,(PreservationConclusion.ARCHITECTURE_EQUIVALENT,PreservationConclusion.SHELL_PRESERVED))


def recipe(approved):
    from .phase6f_renderer import GnuInlineAsmRecipe,RendererContractKind
    c=approved.constraints.lrsc_sequence_contract
    if c is None:return None
    symbolic_proof(c)
    roles=dict(c.role_indexes)
    outputs=tuple(sorted((roles['old'],roles['next'],roles['status'],c.memory_index)))
    inputs=tuple(sorted((roles['address'],roles['input'])))
    positions={i:n for n,i in enumerate(outputs+inputs)}
    old,nxt,status,mem,arg=(positions[i] for i in (roles['old'],roles['next'],roles['status'],c.memory_index,roles['input']))
    size='l' if c.width==32 else 'q'
    lines=[f'mov{size} %{mem}, %{ "k" if c.width==32 else "q"}{old}', '.Lrv2x86_lrsc_%=:']
    if c.width==32:lines.append(f'movslq %k{old}, %q{old}')
    lines.append(f'movq %q{old}, %q{nxt}')
    alu={'fetch_add':'add','fetch_and':'and','fetch_or':'or','fetch_xor':'xor'}[c.operation]
    a_size='l' if c.arithmetic_width==32 else 'q';mod='k' if a_size=='l' else 'q'
    lines.append(f'{alu}{a_size} %{mod}{arg}, %{mod}{nxt}')
    if c.arithmetic_width==32:lines.append(f'movslq %k{nxt}, %q{nxt}')
    lines += [f'lock cmpxchg{size} %{ "k" if c.width==32 else "q"}{nxt}, %{mem}',
              'jne .Lrv2x86_lrsc_%=',f'movq $0, %q{status}']
    return RendererContractKind.GNU_INLINE_ASM,GnuInlineAsmRecipe('\n\t'.join(lines),outputs,inputs)
