"""Little-endian symbolic bytes for the bounded machine-shell interpreter.

A byte retains its origin and bit position. Only a complete, unchanged 64-bit
round trip restores an opaque identity (including a pointer). Partial stores
never restore an old full-width value. Undefined bytes reject loads.
This is not a general object-memory or pointer-arithmetic authority.
"""
MASK=(1<<64)-1


def project(value,offset,width):
    if not 0<=offset<64 or width not in (8,16,32,64) or offset+width>64:
        raise ValueError('L3_CONTROL_VALUE_PROJECTION_INVALID')
    if isinstance(value,int):return (value>>offset)&((1<<width)-1)
    if offset==0 and width==64:return value
    if isinstance(value,tuple):
        if value[0]=='bv-extract':
            _,original,start,bits=value
            if offset+width<=bits:return project(original,start+offset,width)
        if value[0]=='bv-sign' and offset+width<=value[1]:
            return project(value[2],offset,width)
    return ('bv-extract',value,offset,width)


def sign_extend(value,width):
    low=project(value,0,width)
    if width==64:return low
    if isinstance(low,int):return (low-(1<<width) if low&(1<<(width-1)) else low)&MASK
    return ('bv-sign',width,low)


def word_add(value,immediate):
    low=project(value,0,32)
    if isinstance(low,int):return sign_extend((low+immediate)&0xffffffff,32)
    if immediate:low=('bv-add32',low,immediate)
    return sign_extend(low,32)


def store(memory,address,value,width):
    if width not in (8,16,32,64):raise ValueError('L3_CONTROL_STACK_WIDTH_UNSUPPORTED')
    for index in range(width//8):
        memory[address+index]=((value>>(8*index))&255 if isinstance(value,int)
                               else ('stack-byte',value,index))


def load(memory,address,width):
    if width not in (8,16,32,64):raise ValueError('L3_CONTROL_STACK_WIDTH_UNSUPPORTED')
    if any(address+i not in memory for i in range(width//8)):
        raise ValueError('L3_CONTROL_STACK_VALUE_UNBOUND')
    cells=[memory[address+i] for i in range(width//8)]
    if all(isinstance(cell,int) for cell in cells):
        return sum(cell<<(8*i) for i,cell in enumerate(cells))
    first=cells[0]
    if (isinstance(first,tuple) and first[0]=='stack-byte'
            and all(cell==('stack-byte',first[1],first[2]+i) for i,cell in enumerate(cells))):
        return project(first[1],first[2]*8,width)
    return ('bv-bytes',tuple(cells))


def evaluate(value,inputs):
    if isinstance(value,int):return value&MASK
    if isinstance(value,str) and value.startswith('parameter:'):
        index=int(value.split(':')[1])
        if not 0<=index<len(inputs):raise ValueError('L3_CONTROL_VALUE_UNBOUND')
        return int(inputs[index])&MASK
    if isinstance(value,(tuple,list)) and value:
        tag=value[0]
        if tag=='bv-extract':return (evaluate(value[1],inputs)>>value[2])&((1<<value[3])-1)
        if tag=='bv-sign':return sign_extend(evaluate(value[2],inputs),value[1])
        if tag=='bv-add32':return (evaluate(value[1],inputs)+value[2])&0xffffffff
        if tag=='stack-byte':return (evaluate(value[1],inputs)>>(8*value[2]))&255
        if tag=='bv-bytes':return sum(evaluate(cell,inputs)<<(8*i) for i,cell in enumerate(value[1]))&MASK
    raise ValueError('L3_CONTROL_VALUE_UNBOUND')


def export(value):
    """JSON-native expression DTO without changing scalar identities."""
    if isinstance(value,tuple):return [export(item) for item in value]
    if isinstance(value,list):return [export(item) for item in value]
    if isinstance(value,dict):return {key:export(item) for key,item in value.items()}
    return value
