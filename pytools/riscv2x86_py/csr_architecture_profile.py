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
    profiles_from_payload(value,source_digest=digest)
    return value


TEMPLATE_SCHEMA='riscv2x86.csr-architecture-template.v1'
REGISTRY_SCHEMA='riscv2x86.csr-architecture-registry.v1'


def validate_template(value):
    expected={'schemaVersion','privilegeSpecVersion','xlenBits','extensions','templateIdentity'}
    if (not isinstance(value,dict) or set(value)!=expected or value['schemaVersion']!=TEMPLATE_SCHEMA
            or value['templateIdentity']!=content_identity({k:v for k,v in value.items() if k!='templateIdentity'})):
        raise ValueError('CSR_ARCH_TEMPLATE_SCHEMA_OR_IDENTITY_INVALID')
    profile={'schemaVersion':SCHEMA,'sourceDigest':'sha256:'+'0'*64,'fragmentId':'template-validation',
        **{k:value[k] for k in ('privilegeSpecVersion','xlenBits','extensions')}}
    profile['profileIdentity']=content_identity(profile)
    return parse_profile(profile)


def profiles_from_payload(value,*,source_digest=None,xlen_bits=None):
    if isinstance(value,dict) and value.get('schemaVersion')==SCHEMA:
        parse_profile(value,source_digest=source_digest,xlen_bits=xlen_bits)
        return {value['fragmentId']:value}
    if (not isinstance(value,dict) or set(value)!={'schemaVersion','sourceDigest','templateIdentity','profiles','registryIdentity'}
            or value['schemaVersion']!=REGISTRY_SCHEMA or not isinstance(value['profiles'],list)
            or not isinstance(value['templateIdentity'],str) or re.fullmatch(r'sha256:[0-9a-f]{64}',value['templateIdentity']) is None
            or not isinstance(value['sourceDigest'],str) or re.fullmatch(r'sha256:[0-9a-f]{64}',value['sourceDigest']) is None
            or (source_digest is not None and value['sourceDigest']!=source_digest)
            or value['registryIdentity']!=content_identity({k:v for k,v in value.items() if k!='registryIdentity'})):
        raise ValueError('CSR_ARCH_REGISTRY_SCHEMA_OR_IDENTITY_INVALID')
    result={}
    for profile in value['profiles']:
        parse_profile(profile,source_digest=value['sourceDigest'],xlen_bits=xlen_bits)
        if profile['fragmentId'] in result:raise ValueError('CSR_ARCH_REGISTRY_DUPLICATE_FRAGMENT')
        result[profile['fragmentId']]=profile
    return result


def materialize_template(template,report,*,source):
    """Bind an explicitly selected ISA description; never grant permissions."""
    validate_template(template)
    from hashlib import sha256
    digest='sha256:'+sha256(Path(source).read_bytes()).hexdigest()
    findings=report if isinstance(report,list) else report.get('findings',[])
    profiles=[];seen=set()
    for finding in findings:
        fragment=finding['fragment'];fid=fragment.get('id') or fragment.get('fragmentId')
        authority=fragment.get('compilerFragmentAuthority')
        if (not isinstance(fid,str) or not fid or fid in seen
                or (authority and authority.get('sourceDigest')!=digest)):
            raise ValueError('CSR_ARCH_TEMPLATE_FRONTEND_BINDING_INVALID')
        seen.add(fid)
        profile={'schemaVersion':SCHEMA,'sourceDigest':digest,'fragmentId':fid,
            **{k:template[k] for k in ('privilegeSpecVersion','xlenBits','extensions')}}
        profile['profileIdentity']=content_identity(profile);profiles.append(profile)
    payload={'schemaVersion':REGISTRY_SCHEMA,'sourceDigest':digest,'templateIdentity':template['templateIdentity'],
        'profiles':sorted(profiles,key=lambda x:x['fragmentId'])}
    payload['registryIdentity']=content_identity(payload)
    profiles_from_payload(payload,source_digest=digest)
    return payload
