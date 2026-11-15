"""Registered x86 unsigned-high-product contract for Phase 6C/6D/6F.

The target recipe consumes both GNU inputs before writing the sole output.
RAX/RDX are internal clobbers, so the allocator cannot place a live input in
either. No C helper, stack access or hidden call is introduced.
"""
from functools import lru_cache

CONTRACT='x86.gnu-att.gpr.unsigned-multiply-high.u32-u64.v1'
CLOBBERS=('rax','rdx')


def applicable(s):
    from .source_model import SourceValueOperationKind as K,SourceOperandAccess as A,SourceOperandKind as O
    v=s.value_operation
    if (v is None or not v.complete or v.kind is not K.UNSIGNED_MULTIPLY_HIGH
            or v.immediate_value is not None or len(v.input_operand_indexes)!=2
            or v.temporary_operand_index is not None or v.shift_count_mask is not None
            or not s.operands.complete or not s.operation.complete or not s.implicit_state.complete
            or s.operation.kind.value!='register_only' or s.operation.may_trap is not False
            or s.operation.has_control_flow or s.operation.has_call or s.operation.has_return is not False
            or s.memory.reads_memory or s.memory.writes_memory or s.atomic.present or s.barrier.present
            or s.shell.has_asm_goto or s.shell.has_memory_clobber
            or any(c!='cc' for c in s.shell.clobbers)
            or s.registers.reads_or_writes_stack_pointer or s.registers.reads_or_writes_frame_pointer
            or s.implicit_state.reads_stack_pointer or s.implicit_state.writes_stack_pointer
            or s.implicit_state.reads_frame_pointer or s.implicit_state.writes_frame_pointer
            or s.implicit_state.reads_implicit_machine_state or s.implicit_state.writes_implicit_machine_state
            or s.implicit_state.reads_special_register_names or s.implicit_state.writes_special_register_names
            or not s.operand_relation_identity or s.operand_relation_error):return False
    by={o.source_operand_index:o for o in s.operands.operands}
    order=(v.result_operand_index,*v.input_operand_indexes)
    if len(set(order))!=3 or set(order)!=set(by):return False
    width=by[order[0]].width_bits
    if width not in (32,64) or s.xlen!=width:return False
    for index in order:
        o=by[index]
        if (o.kind is not O.REGISTER or o.width_bits!=width or not o.compiler_integer_type_complete or not o.compiler_expression_evaluation_complete
                or o.fixed_register_name or o.tied_to_source_operand_index is not None):return False
        if index==order[0]:
            if o.access is not A.OUTPUT or o.lvalue is None or not o.lvalue.is_modifiable or not o.lvalue.c_type_id:return False
        elif (o.access is not A.INPUT or o.expression is None or not o.expression.c_type_id
                or not o.expression.is_side_effect_free or not o.expression.is_repeatable or o.early_clobber):return False
    identity=tuple(range(3));swap=list(identity)
    a,b=v.input_operand_indexes;swap[a],swap[b]=swap[b],swap[a]
    return bool(s.operand_permutations) and all(p in (identity,tuple(swap)) for p in s.operand_permutations)


def derive(s,plan,env):
    from .phase6c_constraints import (TargetConstraintModel,TargetConstraintDerivationResult as R,
        TargetConstraintReasonCode as E,TargetOperandConstraint,TargetOperandRole as Role,TargetOperandClass as Class)
    from .c_module.phase6c_x86_gnu_inline_asm import X86GprOperandContract,X86OperandRole,X86GnuInlineAsmContract
    from .source_model_diagnostics import missing
    if not env.supports_gnu_inline_asm or 'x86:gpr_inline_asm' not in env.available_features:
        return R.failure(plan_id=plan.plan_id,reason_codes=(E.X86_INLINE_ASM_FEATURE_UNAVAILABLE,))
    if not applicable(s):return R.failure(plan_id=plan.plan_id,reason_codes=(E.X86_INLINE_ASM_SOURCE_INCOMPLETE,),details=missing(s))
    operands=[];target=[]
    for o in s.operands.operands:
        output=o.source_operand_index==s.value_operation.result_operand_index
        role=X86OperandRole.OUTPUT if output else X86OperandRole.INPUT
        typ=o.lvalue.c_type_id if output else o.expression.c_type_id
        operands.append(X86GprOperandContract(o.source_operand_index,role,o.width_bits,o.signedness.value,
            typ,'zero_extend' if o.width_bits==32 else 'preserve',early_clobber=o.early_clobber))
        target.append(TargetOperandConstraint(o.source_operand_index,Role.OUTPUT if output else Role.INPUT,
            frozenset({Class.GENERAL_REGISTER}),None,o.early_clobber,o.width_bits,o.signedness,False,None,'r'))
    contract=X86GnuInlineAsmContract(tuple(operands),s.shell.is_volatile,True,'x86:gpr_inline_asm',
        s.value_operation.kind,implicit_clobbers=CLOBBERS,operand_relation_identity=s.operand_relation_identity,
        allowed_operand_permutations=s.operand_permutations)
    return R.succeeded(TargetConstraintModel(plan_id=plan.plan_id,environment=env,
        operand_constraints=tuple(target),x86_gnu_inline_asm_contract=contract,
        preserve_volatile=s.shell.is_volatile,preserve_cc_clobber=True))


@lru_cache(maxsize=2)
def bitvector_lemma(width):
    """Independent bitvector check of high projection and input commutation.

    Unknown/timeout/dependency failure never approves. This lemma is about the
    registered finite target operation, not an arbitrary emitted instruction.
    """
    if width not in (32,64):return False
    try:
        import z3
        a,b=z3.BitVecs('wide_left wide_right',width)
        product=z3.ZeroExt(width,a)*z3.ZeroExt(width,b)
        source=z3.Extract(2*width-1,width,product)
        target=z3.Extract(width-1,0,z3.LShR(product,width))
        swapped=z3.Extract(2*width-1,width,z3.ZeroExt(width,b)*z3.ZeroExt(width,a))
        solver=z3.Solver();solver.set(timeout=2000)
        solver.add(z3.Or(source!=target,source!=swapped))
        return solver.check()==z3.unsat
    except ImportError:return False


def prove(r):
    from .phase6d_common import reject,finalize,SemanticProofReasonCode as E,PreservationConclusion as C
    s=r.source_model
    expected=derive(s,r.candidate_plan,r.target_environment)
    if not expected.success or expected.constraints!=r.constraints:
        return reject(r,E.PLAN_CONTRACT_MISSING)
    if not bitvector_lemma(s.operands.operands[0].width_bits):return reject(r,E.REQUIREMENT_UNPROVEN)
    return finalize(r,(C.ARCHITECTURE_EQUIVALENT,C.SHELL_PRESERVED))


def recipe(approved):
    from .phase6f_renderer import RendererContractKind,GnuInlineAsmRecipe
    c=approved.constraints.x86_gnu_inline_asm_contract
    if (approved.plan.metadata.get('renderer_semantic_contract_id')!=CONTRACT or c is None
            or c.value_operation_kind.value!='unsigned_multiply_high' or c.implicit_clobbers!=CLOBBERS
            or not c.cc_clobber or not approved.constraints.preserve_cc_clobber):return None
    outputs=[o for o in c.operands if o.role.value=='output'];inputs=[o for o in c.operands if o.role.value=='input']
    if len(outputs)!=1 or len(inputs)!=2:return None
    # Bind the semantic input order explicitly; source slots need not be read
    # in numerical order in canonical p-code.
    order=approved.plan.metadata.get('semantic_input_indexes')
    if not isinstance(order,tuple) or set(order)!={o.source_operand_index for o in inputs}:return None
    width=outputs[0].width_bits
    if width==64:text='movq %1, %%rax\nmulq %2\nmovq %%rdx, %0'
    elif width==32:text='movl %k1, %%eax\nmull %k2\nmovl %%edx, %k0'
    else:return None
    return RendererContractKind.GNU_INLINE_ASM,GnuInlineAsmRecipe(text,
        (outputs[0].source_operand_index,),order,register_clobbers=CLOBBERS)
