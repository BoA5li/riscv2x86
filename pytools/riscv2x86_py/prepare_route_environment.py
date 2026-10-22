"""Prepare sealed route inputs from explicit declarations, never grant semantics.

The ISA description is selected by the caller. Permission, clock and visibility
contracts must already exist; this tool does not invent them from case names.
"""
import argparse
import json
from pathlib import Path
from .experiment_environment import DIRECTORIES, seal_environment, load_environment
from .csr_architecture_profile import TEMPLATE_SCHEMA, validate_template
from .route_authority import content_identity
from .contract_resolution import resolve_contract_files

FAMILIES = {
    'csr_architecture': ('csr_architecture_directory', '.csr-architecture.json'),
    'csr_authority': ('csr_authority_directory', '.csr-authority.json'),
    'csr_environment': ('csr_environment_contract_directory', '.csr-environment.json'),
    'privileged_environment': ('privileged_config_directory', '.privileged-environment.json'),
    'instruction_stream_sync': ('instruction_stream_sync_directory', '.instruction-stream-sync.json'),
    'l2_provider': ('l2_provider_directory', '.l2-providers.json'),
}


def prepare(*, source, output, environment_id, directories, architecture=None, required=()):
    source=Path(source).resolve();output=Path(output).resolve()
    if output.exists():raise ValueError('ROUTE_PREPARATION_OUTPUT_EXISTS')
    if architecture is not None:
        validate_template(architecture)
        if "csr_architecture_directory" in directories:
            raise ValueError("EXPERIMENT_ARCHITECTURE_TEMPLATE_DIRECTORY_CONFLICT")
    # Seal and independently reload before writing a usable manifest.
    manifest=seal_environment(source=source,directories=directories,
        environment_id=environment_id,architecture_template=architecture)
    snapshots=manifest['sources'];base=source if source.is_dir() else source.parent
    demands=[]
    for demand in required:
        family,separator,relative=demand.partition('=')
        if not separator or family not in FAMILIES or relative not in snapshots:
            raise ValueError('ROUTE_REQUIRED_CONTRACT_BINDING_INVALID:'+demand)
        demands.append((family,relative))
    if len(set(demands))!=len(demands):raise ValueError('ROUTE_REQUIRED_CONTRACT_DUPLICATE')
    resolutions={}
    for relative in snapshots:
        record=resolve_contract_files(base/relative,relative,
            [(family,directories.get(key),suffix) for family,(key,suffix) in FAMILIES.items()])
        resolutions[relative]=record
    gaps=[]
    for family,relative in demands:
        if family=='csr_architecture' and architecture is not None:continue
        record=next(x for x in resolutions[relative]['contracts'] if x['family']==family)
        if record['disposition']!='resolved_pending_validation':
            gaps.append({'sourceRelativePath':relative,'family':family,'disposition':record['disposition']})
    report={'schemaVersion':'riscv2x86.route-input-preparation.v1','semanticApproval':False,
        'disposition':'missing_inputs' if gaps else 'prepared_pending_semantic_validation',
        'manifestIdentity':manifest['manifestIdentity'],'requiredInputGaps':gaps,
        'resolutions':resolutions,
        'remainingObligations':['contract-schema-and-applicability','phase6d-approval',
            'provider-execution','per-dimension-evidence-closure']}
    report['preparationIdentity']=content_identity(report)
    output.mkdir(parents=True)
    (output/'preparation.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    if not gaps:
        path=output/'environment.json'
        path.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
        load_environment(path,source=source)
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--environment-id',required=True)
    parser.add_argument('--privilege-spec',choices=['riscv-privileged-1.12','riscv-privileged-1.13'])
    parser.add_argument('--xlen',type=int,choices=[32,64]);parser.add_argument('--extensions',nargs='+')
    parser.add_argument('--require-contract',action='append',default=[],metavar='FAMILY=SOURCE_RELATIVE_PATH')
    for key in DIRECTORIES:parser.add_argument('--'+key.replace('_','-'),type=Path)
    args=parser.parse_args()
    try:
        architecture=None
        values=(args.privilege_spec,args.xlen,args.extensions)
        if any(x is not None for x in values):
            if any(x is None for x in values):raise ValueError('EXPLICIT_ISA_DECLARATION_INCOMPLETE')
            architecture={'schemaVersion':TEMPLATE_SCHEMA,'privilegeSpecVersion':args.privilege_spec,
                'xlenBits':args.xlen,'extensions':sorted(args.extensions)}
            architecture['templateIdentity']=content_identity(architecture)
        report=prepare(source=args.source,output=args.output,environment_id=args.environment_id,
            directories={key:getattr(args,key) for key in DIRECTORIES if getattr(args,key) is not None},
            architecture=architecture,required=args.require_contract)
        print(json.dumps({'artifactPath':str(args.output),'disposition':report['disposition'],
            'requiredInputGaps':report['requiredInputGaps'],'semanticApproval':False},ensure_ascii=False))
        return 2 if report['requiredInputGaps'] else 0
    except (OSError,ValueError,TypeError,KeyError) as exc:
        print(json.dumps({'failureStage':'route_input_preparation','detail':str(exc),'semanticApproval':False}));return 2


if __name__=='__main__':raise SystemExit(main())
