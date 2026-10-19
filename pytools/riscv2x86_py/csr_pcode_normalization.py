"""Replayable bounded constant control reduction for decoder-owned CSR regions.

This is not a CSR permission proof. Unknown control leaves the original region
untouched. Architectural state is joined by complete effect coverage and the
known result carrier and catalogue alias, never by an assembly-text heuristic.
"""
from .semantic_content import semantic_identity,semantic_payload
from .runtime_facts import canonicalize_riscv_register_name

SCHEMA='riscv2x86.csr-pcode-normalization.v1'


def var_payload(v):
    return None if v is None else {'kind':v.kind.value,'space':v.space,'offset':v.offset,'size':v.size,'name':v.name}


def op_payload(op):return {'addr':op.addr,'opcode':op.opcode,'output':var_payload(op.output),'inputs':[var_payload(v) for v in op.inputs]}


def _key(v):return (v.space,v.offset,v.size)


def normalize(ops,*,addr,size,privileged_operations):
    from .pcode_ir import VarKind,conditional_transfer_from_op
    original=list(ops)
    if (type(addr) is not int or addr<0 or type(size) is not int or size!=4
            or len(privileged_operations)!=1 or getattr(privileged_operations[0].kind,'value','')!='csr_access'
            or any(v.register_read_view is not None for op in ops for v in [*op.inputs,*([op.output] if op.output else [])])):
        return original,None
    constants={};out=[];decisions=[];removed=[]
    def value(v):
        if type(v.size) is not int or not 0<v.size<=16:return None
        if v.kind is VarKind.CONST:return v.offset & ((1<<(v.size*8))-1)
        return constants.get(_key(v)) if v.kind is VarKind.UNIQUE else None
    for index,op in enumerate(original):
        name=op.opcode.upper()
        if name=='CBRANCH':
            try:branch=conditional_transfer_from_op(op)
            except ValueError:return original,None
            condition=value(branch.condition)
            if condition not in (0,1):return original,None
            if condition==1 and (branch.target_kind!='machine_address' or branch.target.offset!=addr+size):
                return original,None
            decisions.append({'operationIndex':index,'conditionValue':condition,'target':var_payload(branch.target)})
            removed.append(index)
            if condition==1:
                removed.extend(range(index+1,len(original)));break
            continue
        if name in {'BRANCH','BRANCHIND','CALL','CALLIND','RETURN'}:return original,None
        values=[value(v) for v in op.inputs];computed=None
        if name=='COPY':
            if len(values)!=1 or op.output is None or op.output.size!=op.inputs[0].size:return original,None
            computed=values[0]
        elif len(values)==2 and all(v is not None for v in values):
            a,b=values
            if len({v.size for v in op.inputs})!=1:return original,None
            if name=='INT_EQUAL':computed=int(a==b)
            elif name=='INT_NOTEQUAL':computed=int(a!=b)
            elif name=='INT_AND':computed=a&b
            elif name=='INT_OR':computed=a|b
            elif name=='INT_XOR':computed=a^b
            if name in {'INT_EQUAL','INT_NOTEQUAL'} and (op.output is None or op.output.size!=1):return original,None
            if name in {'INT_AND','INT_OR','INT_XOR'} and (op.output is None or op.output.size!=op.inputs[0].size):return original,None
        if name not in {'COPY','INT_EQUAL','INT_NOTEQUAL','INT_AND','INT_OR','INT_XOR','IMARK'}:
            constants.clear()
        if op.output is not None:
            v=op.output
            for key in list(constants):
                if key[0]==v.space and key[1]<v.offset+v.size and v.offset<key[1]+key[2]:del constants[key]
            if v.kind is VarKind.UNIQUE and computed is not None and 0<v.size<=16:
                constants[_key(v)]=computed & ((1<<(v.size*8))-1)
        out.append(op)
    if not decisions:return original,None
    payload={'schemaVersion':SCHEMA,'address':addr,'instructionSize':size,
        'privilegedOperations':semantic_payload(privileged_operations),'originalOperations':[op_payload(x) for x in original],
        'normalizedOperations':[op_payload(x) for x in out],'branchDecisions':decisions,'removedOperationIndexes':removed}
    payload['normalizationIdentity']=semantic_identity(payload)
    return out,payload


def replay(payload,*,privileged_operations=None):
    from .pcode_ir import Op,Var,VarKind
    fields={'schemaVersion','address','instructionSize','privilegedOperations','originalOperations','normalizedOperations',
        'branchDecisions','removedOperationIndexes','normalizationIdentity'}
    if (not isinstance(payload,dict) or set(payload)!=fields or payload['schemaVersion']!=SCHEMA
            or payload['normalizationIdentity']!=semantic_identity({k:v for k,v in payload.items() if k!='normalizationIdentity'})):
        raise ValueError('CSR_NORMALIZATION_SCHEMA_OR_IDENTITY_INVALID')
    def var(v):
        if v is None:return None
        if set(v)!={'kind','space','offset','size','name'}:raise ValueError('CSR_NORMALIZATION_VARNODE_INVALID')
        if type(v['size']) is not int or v['size']<=0 or type(v['offset']) is not int or v['offset']<0:
            raise ValueError('CSR_NORMALIZATION_VARNODE_INVALID')
        return Var(VarKind(v['kind']),v['space'],v['offset'],v['size'],v['name'])
    from types import SimpleNamespace as NS
    metadata=privileged_operations
    if metadata is None:
        metadata=tuple(NS(kind=NS(value=x['kind'])) for x in payload['privilegedOperations'])
    elif semantic_payload(metadata)!=payload['privilegedOperations']:
        raise ValueError('CSR_NORMALIZATION_DECODER_BINDING_MISMATCH')
    raw=[]
    for op in payload['originalOperations']:
        if set(op)!={'addr','opcode','output','inputs'} or op['addr']!=payload['address']:
            raise ValueError('CSR_NORMALIZATION_OPERATION_INVALID')
        raw.append(Op(op['addr'],op['opcode'],var(op['output']),[var(v) for v in op['inputs']]))
    normalized,expected=normalize(raw,addr=payload['address'],size=payload['instructionSize'],privileged_operations=metadata)
    if expected is None:raise ValueError('CSR_NORMALIZATION_REPLAY_FAILED')
    # The full decoder payload is separately checked when replaying approval.
    expected['privilegedOperations']=payload['privilegedOperations']
    expected['normalizationIdentity']=semantic_identity({k:v for k,v in expected.items() if k!='normalizationIdentity'})
    if expected!=payload:raise ValueError('CSR_NORMALIZATION_REPLAY_FAILED')
    return normalized


def architectural_state_reads(ops,metadata):
    """Prove a sole read-only CSR -> GPR COPY, allowing pure temporary ops."""
    from .pcode_ir import VarKind
    if len(metadata)!=1:return ()
    effect=metadata[0]
    if (not effect.state_complete or effect.csr_operation.value!='read' or not effect.write_value_suppressed
            or effect.read_result_suppressed or not effect.read_value_node_id):return ()
    expected=effect.read_value_node_id.rsplit(':',1)[-1]
    copies=[]
    for op in ops:
        if op.opcode.upper()=='IMARK':continue
        if op.opcode.upper()=='COPY' and op.output is not None and op.output.kind is VarKind.REG:
            if (len(op.inputs)!=1 or op.inputs[0].kind is not VarKind.REG
                    or op.inputs[0].name not in getattr(effect,'csr_register_alias_ids',())
                    or op.inputs[0].size*8!=effect.xlen_bits or op.output.size*8!=effect.xlen_bits
                    or canonicalize_riscv_register_name(op.output.name)!=canonicalize_riscv_register_name(expected)):
                return ()
            copies.append(op.inputs[0]);continue
        if (op.output is None or op.output.kind is not VarKind.UNIQUE
                or op.opcode.upper() not in {'COPY','INT_EQUAL','INT_NOTEQUAL','INT_AND','INT_OR','INT_XOR'}
                or any(v.kind not in {VarKind.UNIQUE,VarKind.CONST} for v in op.inputs)):
            return ()
    return tuple(copies) if len(copies)==1 else ()
