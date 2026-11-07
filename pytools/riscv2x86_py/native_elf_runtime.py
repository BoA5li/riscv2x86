"""Bounded ELF64 little-endian symbols/versions/relocations, without name rules.

This is metadata interpretation, not loader emulation, ABI or behavioral proof.
Stripped sectionless objects, extended numbering and unsupported formats reject.
"""
import struct

POLICY = 'riscv2x86.elf64-le-runtime-metadata.v1'


def version_hash(name):
    value=0
    for byte in name.encode('utf-8'):
        value=(value<<4)+byte;high=value&0xf0000000
        if high:value^=high>>24
        value&=~high
    return value


def parse(raw):
    def take(offset, size):
        if offset < 0 or size < 0 or offset + size > len(raw):
            raise ValueError('RUNTIME_ELF_RANGE_INVALID')
        return raw[offset:offset+size]
    def unpack(fmt, offset):
        return struct.unpack(fmt, take(offset,struct.calcsize(fmt)))
    if len(raw)<64 or raw[:7]!=b'\x7fELF\x02\x01\x01':
        raise ValueError('RUNTIME_ELF64_LE_REQUIRED')
    kind,machine=unpack('<HH',16)
    if kind not in (1,2,3):raise ValueError('RUNTIME_ELF_TYPE_UNSUPPORTED')
    if unpack('<I',20)[0]!=1 or unpack('<H',52)[0]!=64:
        raise ValueError('RUNTIME_ELF_HEADER_INVALID')
    interpreter=None
    phoff=unpack('<Q',32)[0];phsize,phcount=unpack('<HH',54)
    if phcount and (phsize!=56 or phcount==0xffff):
        raise ValueError('RUNTIME_ELF_PROGRAM_HEADERS_UNSUPPORTED')
    for n in range(phcount):
        typ,flags,offset,vaddr,paddr,filesz,memsz,align=unpack('<IIQQQQQQ',phoff+n*56)
        payload=take(offset,filesz)
        if typ==1 and filesz>memsz:raise ValueError('RUNTIME_ELF_SEGMENT_SIZE_INVALID')
        if typ==3:
            if interpreter is not None or not payload.endswith(b'\0') or b'\0' in payload[:-1]:
                raise ValueError('RUNTIME_ELF_INTERPRETER_INVALID')
            interpreter=payload[:-1].decode('utf-8')
    section_offset=unpack('<Q',40)[0]
    entry_size,count,names_index=unpack('<HHH',58)
    if entry_size!=64 or not count or names_index==0xffff or names_index>=count:
        raise ValueError('RUNTIME_ELF_SECTION_NUMBERING_UNSUPPORTED')
    sections=[unpack('<IIQQQQIIQQ',section_offset+i*64) for i in range(count)]
    def data(index):
        section=sections[index]
        if section[1]==8:raise ValueError('RUNTIME_ELF_NOBITS_DATA_INVALID')
        return take(section[4],section[5])
    def string(table, offset):
        if offset<0 or offset>=len(table):raise ValueError('RUNTIME_ELF_STRING_RANGE_INVALID')
        end=table.find(b'\0',offset)
        if end<0:raise ValueError('RUNTIME_ELF_STRING_TERMINATOR_REQUIRED')
        return table[offset:end].decode('utf-8',errors='strict')
    def strings(index):
        if index>=count or sections[index][1]!=3:raise ValueError('RUNTIME_ELF_STRTAB_REQUIRED')
        return data(index)
    names=strings(names_index)
    section_names=[string(names,s[0]) for s in sections]

    def version_sections(symbol_table, tag):
        if tag==0x6fffffff:
            rows=[i for i,s in enumerate(sections) if s[1]==tag and s[6]==symbol_table]
        else:
            rows=[i for i,s in enumerate(sections) if s[1]==tag and s[6]==sections[symbol_table][6]]
        if len(rows)>1:raise ValueError('RUNTIME_ELF_VERSION_SECTION_AMBIGUOUS')
        return rows

    def versions(symbol_table):
        strtab=strings(sections[symbol_table][6]);definitions={};requirements={}
        for tag,dest in ((0x6ffffffd,definitions),(0x6ffffffe,requirements)):
            for index in version_sections(symbol_table,tag):
                chunk=data(index);offset=0;seen=set();records=0
                def v(fmt, pos):
                    length=struct.calcsize(fmt)
                    if pos<0 or pos+length>len(chunk):raise ValueError('RUNTIME_ELF_VERSION_RANGE_INVALID')
                    return struct.unpack_from(fmt,chunk,pos)
                while True:
                    if offset in seen:raise ValueError('RUNTIME_ELF_VERSION_CYCLE')
                    seen.add(offset);records+=1
                    if tag==0x6ffffffd:
                        version,flags,number,aux_count,hash_value,aux,next_offset=v('<HHHHIII',offset)
                        header_size=20
                    else:
                        version,aux_count,filename,aux,next_offset=v('<HHIII',offset)
                        header_size=16
                    if version!=1 or not aux_count or aux<header_size:
                        raise ValueError('RUNTIME_ELF_VERSION_HEADER_INVALID')
                    auxiliary=offset+aux;aux_seen=set();entries=[]
                    for n in range(aux_count):
                        if auxiliary in aux_seen:raise ValueError('RUNTIME_ELF_VERSION_AUX_CYCLE')
                        aux_seen.add(auxiliary)
                        if tag==0x6ffffffd:
                            label,more=v('<II',auxiliary);minimum=8
                            entries.append(string(strtab,label))
                        else:
                            h,f,num,label,more=v('<IHHII',auxiliary);minimum=16
                            key=num & 0x7fff
                            if key<=1 or key in requirements:raise ValueError('RUNTIME_ELF_VERSION_INDEX_INVALID')
                            label=string(strtab,label)
                            if h!=version_hash(label):raise ValueError('RUNTIME_ELF_VERSION_HASH_INVALID')
                            requirements[key]={'name':label,'file':string(strtab,filename),'flags':f}
                        if n+1<aux_count:
                            if more<minimum:raise ValueError('RUNTIME_ELF_VERSION_AUX_NEXT_INVALID')
                            auxiliary+=more
                        elif more!=0:raise ValueError('RUNTIME_ELF_VERSION_AUX_COUNT_INVALID')
                    if tag==0x6ffffffd:
                        if number<1 or number in definitions:raise ValueError('RUNTIME_ELF_VERSION_INDEX_INVALID')
                        if hash_value!=version_hash(entries[0]):raise ValueError('RUNTIME_ELF_VERSION_HASH_INVALID')
                        definitions[number]={'name':entries[0],'parents':entries[1:],'flags':flags}
                    if next_offset==0:break
                    if next_offset<header_size:raise ValueError('RUNTIME_ELF_VERSION_NEXT_INVALID')
                    offset+=next_offset
                if records!=sections[index][7]:raise ValueError('RUNTIME_ELF_VERSION_COUNT_INVALID')
        if set(definitions)&set(requirements):raise ValueError('RUNTIME_ELF_VERSION_INDEX_AMBIGUOUS')
        return definitions,requirements

    tables={};dynamic=[];static=[]
    for index,section in enumerate(sections):
        if section[1] not in (2,11):continue
        if section[9]!=24 or section[5]%24:raise ValueError('RUNTIME_ELF_SYMBOL_SIZE_INVALID')
        strtab=strings(section[6]);entries=[]
        defs,needs=versions(index) if section[1]==11 else ({},{})
        versym=version_sections(index,0x6fffffff) if section[1]==11 else []
        version_ids=[]
        if versym:
            chunk=data(versym[0])
            if len(chunk)!=section[5]//24*2:raise ValueError('RUNTIME_ELF_VERSYM_SIZE_INVALID')
            version_ids=list(struct.unpack('<'+'H'*(len(chunk)//2),chunk))
        elif defs or needs:raise ValueError('RUNTIME_ELF_VERSYM_REQUIRED')
        for n in range(section[5]//24):
            name,info,other,shndx,value,size=unpack('<IBBHQQ',section[4]+n*24)
            if shndx==0xffff or 0<shndx<0xff00 and shndx>=count:
                raise ValueError('RUNTIME_ELF_SYMBOL_SECTION_INVALID')
            version_id=version_ids[n] if version_ids else 1
            number=version_id & 0x7fff;version=None
            version_source=None
            if number>1:
                # A linked executable/PIE may define storage for an imported
                # versioned object (e.g. COPY relocation); this is not a new
                # standalone runtime provider definition.
                if shndx==0:
                    source=needs;version_source='requirement'
                elif number in defs:
                    source=defs;version_source='definition'
                else:
                    source=needs;version_source='requirement'
                if number not in source:raise ValueError('RUNTIME_ELF_SYMBOL_VERSION_UNRESOLVED')
                version=source[number]
            row={'name':string(strtab,name),'binding':info>>4,'type':info&15,
                 'visibility':other&3,'sectionIndex':shndx,'defined':shndx!=0,
                 'value':value,'size':size,'entryIndex':n,'tableIndex':index,
                 'versionIndex':number,'versionHidden':bool(version_id&0x8000),
                 'version':version,'versionSource':version_source}
            entries.append(row)
        tables[index]=entries
        (dynamic if section[1]==11 else static).extend(entries)
    if sum(s[1]==11 for s in sections)>1 or sum(s[1]==2 for s in sections)>1:
        raise ValueError('RUNTIME_ELF_SYMBOL_TABLE_AMBIGUOUS')
    if not tables:raise ValueError('RUNTIME_ELF_SYMBOL_TABLE_REQUIRED')
    tags=[];needed=[];soname=None;search=[]
    for index,section in enumerate(sections):
        if section[1]!=6:continue
        if section[9]!=16 or section[5]%16:raise ValueError('RUNTIME_ELF_DYNAMIC_SIZE_INVALID')
        strtab=strings(section[6]);terminated=False
        for n in range(section[5]//16):
            tag,value=unpack('<qQ',section[4]+n*16)
            if tag==0:terminated=True;break
            tags.append({'tag':tag,'value':value})
            if tag==1:needed.append(string(strtab,value))
            if tag==14:
                if soname is not None:raise ValueError('RUNTIME_ELF_SONAME_AMBIGUOUS')
                soname=string(strtab,value)
            if tag in (15,29):search.append({'tag':tag,'value':string(strtab,value)})
        if not terminated:raise ValueError('RUNTIME_ELF_DYNAMIC_TERMINATOR_REQUIRED')
    if sum(s[1]==6 for s in sections)>1:raise ValueError('RUNTIME_ELF_DYNAMIC_SECTION_AMBIGUOUS')
    relocations=[]
    for index,section in enumerate(sections):
        if section[1] not in (4,9):continue
        size=24 if section[1]==4 else 16
        if section[9]!=size or section[5]%size or section[6] not in tables:
            raise ValueError('RUNTIME_ELF_RELOCATION_TABLE_INVALID')
        if section[7]>=count:raise ValueError('RUNTIME_ELF_RELOCATION_TARGET_INVALID')
        for n in range(section[5]//size):
            offset,info=unpack('<QQ',section[4]+n*size);symbol=info>>32
            if symbol>=len(tables[section[6]]):raise ValueError('RUNTIME_ELF_RELOCATION_SYMBOL_INVALID')
            row={'section':section_names[index],'targetSection':section_names[section[7]],
                 'offset':offset,'type':info&0xffffffff,'symbolIndex':symbol,
                 'symbol':tables[section[6]][symbol]['name']}
            if size==24:row['addend']=unpack('<q',section[4]+n*size+16)[0]
            relocations.append(row)
    return {'policy':POLICY,'machine':machine,'elfType':kind,'classBits':64,'byteOrder':'little',
            'abiFlags':unpack('<I',48)[0], 'dynamicSymbols':dynamic,'staticSymbols':static,
            'needed':needed,'soname':soname,'interpreter':interpreter,'searchPaths':search,'relocations':relocations,
            'relocationSemanticsVerified':False,'abiContractVerified':False}


def candidates(request, providers):
    """Metadata-compatible candidates only. Never grant actual binding or ABI."""
    rows=[]
    for provider in providers:
        elf=provider['elf']
        if elf['machine']!=request['machine']:continue
        for symbol in elf['dynamicSymbols']:
            if (symbol['name']!=request['name'] or not symbol['defined']
                    or symbol['binding'] not in (1,2,10) or symbol['visibility'] not in (0,3)
                    or symbol.get('versionSource')=='requirement'):
                continue
            requested_type=request.get('type',0)
            if requested_type and symbol['type']!=requested_type and not (requested_type==2 and symbol['type']==10):
                continue
            required=request.get('version')
            if required is not None:
                if symbol['version'] is None or symbol['version']['name']!=required['name']:continue
                if required.get('file') and elf['soname']!=required['file']:continue
            elif symbol['versionHidden']:continue
            rows.append({'providerPath':provider['path'],'providerDigest':provider['digest'],
                'symbol':symbol,'specialContractRequired':symbol['binding']!=1 or symbol['type'] in (6,10)
                    or symbol['sectionIndex']>=0xff00})
    return rows
