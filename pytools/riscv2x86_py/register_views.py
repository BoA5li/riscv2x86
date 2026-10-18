"""Backend-database-derived register read views, never offset/name guesses."""
from dataclasses import dataclass, asdict
from hashlib import sha256
import json


@dataclass(frozen=True)
class RegisterReadView:
    parent_name: str
    parent_offset: int
    parent_size: int
    offset: int
    size: int
    language_id: str
    producer: str = 'ghidra-language-register-database.v1'
    byte_order: str = 'little'

    def __post_init__(self):
        if (not self.parent_name or not self.language_id or
                self.producer != 'ghidra-language-register-database.v1' or self.byte_order != 'little'
                or any(type(x) is not int for x in (self.parent_offset,self.parent_size,self.offset,self.size))
                or self.offset != self.parent_offset or self.offset < 0
                or not 0 < self.size < self.parent_size):
            raise ValueError('REGISTER_READ_VIEW_INVALID')

    @property
    def view_identity(self):
        return 'sha256:'+sha256(json.dumps(asdict(self),sort_keys=True,separators=(',',':')).encode()).hexdigest()


def database_read_view(records, *, space, offset, size, language_id, big_endian):
    # Only same-start low reads on an explicitly little-endian language.
    # Interior slices, partial writes and uncertain aliases remain unsupported.
    if (space != 'register' or big_endian is not False or type(offset) is not int
            or type(size) is not int or offset < 0 or size <= 0):return None
    candidates=set()
    for record in records:
        if (any(type(record.get(k)) is not int for k in ('offset','baseOffset','size','baseSize','bitLength'))
                or record.get('isProcessorContext') is not False
                or record.get('offset') != offset or record.get('baseOffset') != offset
                or type(record.get('size')) is not int or record.get('size') != record.get('baseSize')
                or record.get('bitLength') != record['size']*8
                or record.get('name') != record.get('baseName')
                or not isinstance(record.get('name'),str) or not record['name']
                or record['size'] <= size):continue
        candidates.add((record['baseName'],record['baseOffset'],record['baseSize']))
    if len(candidates)!=1:return None
    name,base,parent_size=next(iter(candidates))
    return RegisterReadView(name,base,parent_size,offset,size,language_id)
