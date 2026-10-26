"""Decode actual region bytes; no mnemonic or expected-event synthesis.

Only normal FENCE access masks and x86 MFENCE are affirmative mechanisms.
NOP/partial fences are recognized counterexamples. Unknown code stays unproved.
"""
from .l3_trace_support import Elf,identity


def mechanism(code,machine):
    raw=bytes(code);pairs=[];kind='other';pred=[];succ=[]
    if machine==243:
        if len(raw)==4:
            word=int.from_bytes(raw,'little')
            if word & 0x000fffff == 0x0f and word>>28==0:
                mask=lambda v:[c for bit,c in ((8,'I'),(4,'O'),(2,'R'),(1,'W')) if v&bit]
                pred=mask((word>>24)&15);succ=mask((word>>20)&15)
                kind='ordinary-rw-fence' if pred==succ==['R','W'] else 'partial-or-io-fence'
                pairs=[[a,b] for a in pred for b in succ]
            elif raw==bytes.fromhex('13000000'):kind='nop'
        elif raw==bytes.fromhex('0100'):kind='nop'
    elif machine==62:
        if raw==bytes.fromhex('0faef0'):
            kind='ordinary-rw-fence';pred=succ=['R','W'];pairs=[[a,b] for a in pred for b in succ]
        elif raw in (bytes.fromhex('0faee8'),bytes.fromhex('0faef8')):kind='partial-fence'
        elif raw and all(x==0x90 for x in raw):kind='nop'
    else:raise ValueError('L3_FENCE_MACHINE_UNSUPPORTED')
    body={'schemaVersion':'riscv2x86.fence-machine-mechanism.v1','machine':machine,
          'bytes':raw.hex(),'kind':kind,'predecessors':pred,'successors':succ,'orderedPairs':pairs,
          'memoryDomain':'ordinary-coherent-memory' if kind=='ordinary-rw-fence' else 'unproved',
          'globalSequentialConsistencyClaimed':False}
    return dict(body,mechanismIdentity=identity(body))


def region_mechanism(elf,region):
    address=region['start'];size=region['end']-address
    if size<=0 or size>64:raise ValueError('L3_FENCE_REGION_SIZE_INVALID')
    matches=[s for s in elf.sections if s[2]&4 and s[3]<=address and address+size<=s[3]+s[5]]
    if len(matches)!=1:raise ValueError('L3_FENCE_REGION_SECTION_AMBIGUOUS')
    s=matches[0]
    return mechanism(elf.slice(s[4]+address-s[3],size),elf.machine)
