"""Explicit source-bound ISA specification profile, independent of access policy."""
import json
import re
from pathlib import Path
from .csr_metadata_ingress import CsrDecoderProfile
from .route_authority import content_identity

SCHEMA = 'riscv2x86.csr-architecture-profile.v1'
FIELDS = {'schemaVersion','sourceDigest','fragmentId','privilegeSpecVersion',
          'xlenBits','extensions','profileIdentity'}


def parse_profile(value, *, source_digest=None, fragment_id=None, xlen_bits=None):
    if not isinstance(value, dict) or set(value) != FIELDS or value['schemaVersion'] != SCHEMA:
        raise ValueError('CSR_ARCH_PROFILE_SCHEMA_INVALID')
    if value['profileIdentity'] != content_identity({k:v for k,v in value.items() if k != 'profileIdentity'}):
        raise ValueError('CSR_ARCH_PROFILE_IDENTITY_MISMATCH')
    if (not isinstance(value['sourceDigest'], str)
            or re.fullmatch(r'sha256:[0-9a-f]{64}', value['sourceDigest']) is None
            or not isinstance(value['fragmentId'], str) or not value['fragmentId']):
        raise ValueError('CSR_ARCH_PROFILE_BINDING_INVALID')
    if source_digest is not None and value['sourceDigest'] != source_digest:
        raise ValueError('CSR_ARCH_PROFILE_SOURCE_MISMATCH')
    if fragment_id is not None and value['fragmentId'] != fragment_id:
        raise ValueError('CSR_ARCH_PROFILE_FRAGMENT_MISMATCH')
    if type(value['xlenBits']) is not int or value['xlenBits'] not in (32,64) or (xlen_bits is not None and value['xlenBits'] != xlen_bits):
        raise ValueError('CSR_ARCH_PROFILE_XLEN_MISMATCH')
    if value['privilegeSpecVersion'] not in {'riscv-privileged-1.12','riscv-privileged-1.13'}:
        raise ValueError('CSR_ARCH_PROFILE_SPEC_UNSUPPORTED')
    extensions = value['extensions']
    if (not isinstance(extensions,list) or not all(isinstance(x,str) and re.fullmatch(r'[a-z][a-z0-9]*',x) for x in extensions)
            or extensions != sorted(set(extensions))):
        raise ValueError('CSR_ARCH_PROFILE_EXTENSIONS_INVALID')
    return CsrDecoderProfile(value['privilegeSpecVersion'],value['xlenBits'],tuple(extensions))


def load_profile(path, *, source=None):
    value = json.loads(Path(path).read_text())
    digest = None
    if source is not None:
        from hashlib import sha256
        digest = 'sha256:' + sha256(Path(source).read_bytes()).hexdigest()
    parse_profile(value,source_digest=digest)
    return value
