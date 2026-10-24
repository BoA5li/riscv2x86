"""Content-bound experiment configuration. Configuration is not semantic proof."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
from .route_authority import content_identity

SCHEMA='riscv2x86.experiment-environment.v1'
DIRECTORIES=('harness_directory','privileged_config_directory','l2_provider_directory',
    'l3_provider_directory','l3_intent_producer_directory','atomic_authority_directory','csr_authority_directory',
    'csr_architecture_directory','csr_environment_contract_directory','instruction_stream_sync_directory')
_SHA=re.compile(r'sha256:[0-9a-f]{64}')


def digest(path):return 'sha256:'+sha256(Path(path).read_bytes()).hexdigest()


def source_snapshot(source):
    root=Path(source).resolve()
    paths=[root] if root.is_file() else sorted(x for x in root.rglob('*.c') if not x.name.endswith('.harness.c'))
    if not paths:raise ValueError('EXPERIMENT_SOURCE_SET_EMPTY')
    base=root.parent if root.is_file() else root
    return {x.relative_to(base).as_posix():digest(x) for x in paths}


def directory_snapshot(root):
    root=Path(root)
    if not root.is_dir():raise ValueError('EXPERIMENT_CONTRACT_DIRECTORY_UNAVAILABLE')
    result={}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():raise ValueError('EXPERIMENT_CONTRACT_SYMLINK_UNSUPPORTED')
        if path.is_file():result[path.relative_to(root).as_posix()]=digest(path)
    return result


def load_environment(path,*,source,overrides=None):
    path=Path(path).resolve();value=json.loads(path.read_text())
    expected={'schemaVersion','environmentId','sources','contractDirectories','architectureTemplate','manifestIdentity'}
    if (not isinstance(value,dict) or set(value)!=expected or value['schemaVersion']!=SCHEMA
            or not isinstance(value['environmentId'],str) or not value['environmentId']
            or value['manifestIdentity']!=content_identity({k:v for k,v in value.items() if k!='manifestIdentity'})):
        raise ValueError('EXPERIMENT_ENVIRONMENT_SCHEMA_OR_IDENTITY_INVALID')
    if value['sources']!=source_snapshot(source):raise ValueError('EXPERIMENT_SOURCE_SET_OR_IDENTITY_MISMATCH')
    directories=value['contractDirectories']
    if not isinstance(directories,dict) or set(directories)-set(DIRECTORIES):
        raise ValueError('EXPERIMENT_CONTRACT_FAMILY_INVALID')
    resolved={}
    for key,record in directories.items():
        if (not isinstance(record,dict) or set(record)!={'path','files'}
                or not isinstance(record['path'],str) or not record['path'] or not isinstance(record['files'],dict)):
            raise ValueError('EXPERIMENT_CONTRACT_DIRECTORY_RECORD_INVALID')
        for relative,identity in record['files'].items():
            p=Path(relative)
            if (not isinstance(identity,str) or _SHA.fullmatch(identity) is None or p.is_absolute()
                    or '..' in p.parts or relative!=p.as_posix() or relative in {'','.'}):
                raise ValueError('EXPERIMENT_CONTRACT_FILE_RECORD_INVALID')
        root=(path.parent/record['path']).resolve()
        if directory_snapshot(root)!=record['files']:
            raise ValueError('EXPERIMENT_CONTRACT_FILE_SET_OR_IDENTITY_MISMATCH:'+key)
        resolved[key]=root
    overrides=overrides or {}
    if set(overrides)-set(DIRECTORIES):raise ValueError('EXPERIMENT_OVERRIDE_FAMILY_INVALID')
    for key,override in overrides.items():
        if override is not None:
            if key not in resolved or Path(override).resolve()!=resolved[key]:
                raise ValueError('EXPERIMENT_DIRECTORY_OVERRIDE_CONFLICT:'+key)
    template=value['architectureTemplate']
    if template is not None:
        from .csr_architecture_profile import validate_template
        validate_template(template)
        if 'csr_architecture_directory' in resolved:
            raise ValueError('EXPERIMENT_ARCHITECTURE_TEMPLATE_DIRECTORY_CONFLICT')
    # Store all supplied declarations separately from derived approval. This
    # envelope cannot grant access, architecture equivalence or capabilities.
    snapshot={'schemaVersion':'riscv2x86.experiment-environment-resolution.v1',
        'manifestPath':str(path),'manifestIdentity':value['manifestIdentity'],
        'environmentId':value['environmentId'],'sources':value['sources'],
        'contractDirectories':{k:{'path':str(resolved[k]),'files':v['files']} for k,v in directories.items()},
        'architectureTemplate':template,'semanticApproval':False}
    snapshot['resolutionIdentity']=content_identity(snapshot)
    return resolved,snapshot


def seal_environment(*,source,directories,environment_id,architecture_template=None):
    if set(directories)-set(DIRECTORIES):raise ValueError('EXPERIMENT_CONTRACT_FAMILY_INVALID')
    if architecture_template is not None:
        from .csr_architecture_profile import validate_template
        validate_template(architecture_template)
    payload={'schemaVersion':SCHEMA,'environmentId':environment_id,'sources':source_snapshot(source),
        'contractDirectories':{k:{'path':str(Path(v).resolve()),'files':directory_snapshot(v)} for k,v in directories.items()},
        'architectureTemplate':architecture_template}
    return {**payload,'manifestIdentity':content_identity(payload)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',type=Path,required=True);parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    try:
        _,snapshot=load_environment(args.manifest,source=args.source)
        text=json.dumps(snapshot,sort_keys=True,indent=2)+'\n'
        if args.output:
            with args.output.open('x') as handle:handle.write(text)
        else:print(text,end='')
        return 0
    except (OSError,ValueError,TypeError,KeyError) as exc:
        print(json.dumps({'failureStage':'experiment_environment','exceptionType':type(exc).__name__,
            'artifactPath':str(args.manifest),'detail':str(exc),'semanticApproval':False}))
        return 2


if __name__=='__main__':raise SystemExit(main())
