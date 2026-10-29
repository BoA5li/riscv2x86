"""Proof-bound external observation projection of pure versioned arithmetic.

Intermediate register values have no memory/control/trap effects. They are
replayed from actual boundary inputs, not falsely reported as measured inside
an asm statement. Every external output is checked against its final definition.
"""
from dataclasses import asdict
import json
from .l3_trace_support import identity, require_json_match


def decode(raw):
    from .source_model import (SourceStraightLineValueProgram as Program,
        SourceStraightLineValueInstruction as Instruction, SourceStraightLineValueOpcode as Code)
    data = dict(raw)
    data['instructions'] = tuple(Instruction(Code(i['opcode']), i['output_operand_index'],
        tuple(i['input_operand_indexes']), i['immediate_value']) for i in data['instructions'])
    for key in ('input_operand_indexes','output_operand_indexes'):
        data[key] = tuple(data[key])
    data['definition_history'] = tuple(tuple(h) for h in data['definition_history'])
    p = Program(**data)
    if p.value_schema_version != 2:
        raise ValueError('VERSIONED_BOUNDARY_V2_REQUIRED')
    return p


def export(program, approval, fragment_id):
    from .source_model import SourceStraightLineValueProgram
    if not isinstance(program, SourceStraightLineValueProgram) or program.value_schema_version != 2:
        return None
    if (approval.get('proofStatus') != 'approved' or not approval.get('proofIdentity')
            or approval.get('architectureSemanticsPreserved') is not True
            or approval.get('shellSemanticsPreserved') is not True
            or approval.get('rendererSemanticContractId') != 'x86.gnu-att.gpr.straight-line-u32-u64.v1'):
        raise ValueError('VERSIONED_BOUNDARY_APPROVED_PROGRAM_REQUIRED')
    body = {'schemaVersion':'riscv2x86.versioned-program-boundary.v1',
        'fragmentId':fragment_id,'proofIdentity':approval['proofIdentity'],
        'sourceModelId':approval['sourceModelId'],'constraintsId':approval['constraintsId'],
        'program':json.loads(json.dumps(asdict(program))),'observationScope':'external-inputs-and-final-outputs',
        'intermediateValuesMeasured':False,'intermediateValuesMethod':'pure-definition-replay'}
    return dict(body,contractIdentity=identity(body))


def load(finding):
    a = finding.get('approvalArtifact') or {}
    raw = a.get('l2VersionedProgramBoundary')
    if raw is None:
        return None
    program = decode(raw['program'])
    expected = export(program,a,finding['fragment']['id'])
    require_json_match(expected,raw,'VERSIONED_BOUNDARY_CONTRACT_CHANGED')
    return program


def evaluate(program, inputs):
    mask = (1 << program.width_bits)-1
    values = dict(inputs)
    for instruction in program.instructions:
        left,right = (values[i] for i in instruction.input_operand_indexes)
        # Enum values are semantic operation names, never source mnemonics.
        from .source_model import SourceStraightLineValueOpcode as C
        functions = {C.UNSIGNED_ADD:lambda a,b:a+b, C.UNSIGNED_SUB:lambda a,b:a-b,
            C.BIT_AND:lambda a,b:a&b, C.BIT_OR:lambda a,b:a|b, C.BIT_XOR:lambda a,b:a^b}
        values[instruction.output_operand_index] = functions[instruction.opcode](left,right)&mask
    return {i:values[i] for i in program.output_operand_indexes}
