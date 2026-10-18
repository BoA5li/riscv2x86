"""Assembler symbol to compiler continuation join; addresses are layout-local."""
from collections.abc import Mapping
from hashlib import sha256
import re
from .compiler_value_flow import identity

SCHEMA='riscv2x86.asm-goto-machine-continuations.v1'


def bind_machine_continuations(elf, fragment, materialized, base_by_section, machine_code):
    symbols=elf.get_section_by_name('.symtab')
    if symbols is None:
        raise ValueError('ASM_GOTO_SYMBOL_TABLE_MISSING')
    edges=list(fragment.gotoEdges)
    records=[]
    for edge in edges:
        synthetic=f'.Lriscv2x86_asm_goto_{edge.exitCode}'
        if materialized.asm_goto_targets.get(synthetic)!=edge.cLabel:
            raise ValueError('ASM_GOTO_MATERIALIZED_LABEL_MISMATCH')
        matches=list(symbols.get_symbol_by_name(synthetic) or [])
        if len(matches)!=1:
            raise ValueError('ASM_GOTO_SYMBOL_NOT_UNIQUE')
        symbol=matches[0]
        section=symbol['st_shndx']
        if type(section) is not int or section not in base_by_section:
            raise ValueError('ASM_GOTO_SYMBOL_NOT_CODE')
        offset=symbol['st_value']
        if type(offset) is not int or offset<0:
            raise ValueError('ASM_GOTO_SYMBOL_OFFSET_INVALID')
        target=base_by_section[section]+offset
        if target>len(machine_code):
            raise ValueError('ASM_GOTO_SYMBOL_OUTSIDE_CODE')
        records.append({'compilerLabel':edge.cLabel,'continuationId':edge.targetContinuationId,
            'externalLabelIndex':edge.exitCode,'assemblerSymbol':synthetic,'machineOffset':target})
    payload={'schemaVersion':SCHEMA,'fragmentId':fragment.fragmentId or fragment.id,
        'machineCodeIdentity':'sha256:'+sha256(machine_code).hexdigest(),
        'bindings':records}
    return {**payload,'joinIdentity':identity(payload)}


def validate_machine_continuations(raw, fragment_id, edges):
    if isinstance(raw,Mapping) and raw.get('schemaVersion')=='riscv2x86.asm-goto-machine-layout.v2':
        return validate_lift_layout(raw,fragment_id,edges)
    if (not isinstance(raw,Mapping) or set(raw)!={'schemaVersion','fragmentId','machineCodeIdentity','bindings','joinIdentity'}
            or raw['schemaVersion']!=SCHEMA or raw['fragmentId']!=fragment_id
            or not isinstance(raw['machineCodeIdentity'],str)
            or re.fullmatch(r'sha256:[0-9a-f]{64}',raw['machineCodeIdentity']) is None
            or raw['joinIdentity']!=identity({k:v for k,v in raw.items() if k!='joinIdentity'})):
        raise ValueError('ASM_GOTO_MACHINE_JOIN_INVALID')
    records=raw['bindings']
    if not isinstance(records,list) or len(records)!=len(edges):
        raise ValueError('ASM_GOTO_MACHINE_JOIN_ARITY_MISMATCH')
    for record,edge in zip(records,edges):
        if (not isinstance(record,Mapping) or set(record)!={'compilerLabel','continuationId','externalLabelIndex','assemblerSymbol','machineOffset'}
                or (record['compilerLabel'],record['externalLabelIndex'],record['continuationId'])!=(edge[1],edge[2],edge[3])
                or record['assemblerSymbol']!=f'.Lriscv2x86_asm_goto_{edge[2]}'
                or type(record['machineOffset']) is not int or record['machineOffset']<0):
            raise ValueError('ASM_GOTO_MACHINE_CONTINUATION_MISMATCH')
    return records


def bind_lift_layout(join, machine_code, lift_base):
    """Bind assembler offsets to this exact lift invocation, never a C identity."""
    if type(lift_base) is not int or lift_base<0:
        raise ValueError('ASM_GOTO_LIFT_BASE_INVALID')
    if join.get('machineCodeIdentity')!='sha256:'+sha256(machine_code).hexdigest():
        raise ValueError('ASM_GOTO_MACHINE_CODE_IDENTITY_MISMATCH')
    payload={'schemaVersion':'riscv2x86.asm-goto-machine-layout.v2',
        'assemblerJoin':dict(join),'fragmentId':join['fragmentId'],
        'liftBaseAddress':lift_base,'imageSizeBytes':len(machine_code)}
    return {**payload,'joinIdentity':identity(payload)}


def validate_lift_layout(raw, fragment_id, edges):
    if (set(raw)!={'schemaVersion','assemblerJoin','fragmentId','liftBaseAddress','imageSizeBytes','joinIdentity'}
            or raw['fragmentId']!=fragment_id or type(raw['liftBaseAddress']) is not int
            or raw['liftBaseAddress']<0 or type(raw['imageSizeBytes']) is not int
            or raw['imageSizeBytes']<=0
            or raw['joinIdentity']!=identity({k:v for k,v in raw.items() if k!='joinIdentity'})
            or raw.get('assemblerJoin',{}).get('schemaVersion')!=SCHEMA):
        raise ValueError('ASM_GOTO_LIFT_LAYOUT_INVALID')
    records=validate_machine_continuations(raw['assemblerJoin'],fragment_id,edges)
    if any(r['machineOffset']>raw['imageSizeBytes'] for r in records):
        raise ValueError('ASM_GOTO_SYMBOL_OUTSIDE_CODE')
    return [{**r,'machineAddress':raw['liftBaseAddress']+r['machineOffset']} for r in records]
