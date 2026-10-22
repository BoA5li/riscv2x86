"""Seal explicit experimental choices. A basis digest is not a semantic proof.

No defaults select a memory/concurrency or time environment. This tool does not
produce execution authority or approval. Production preparation and proof replay
must still consume the declared choices and independently collected mechanisms.
"""
import argparse
import json
import os
from pathlib import Path
from .semantic_content import semantic_identity
from .time_trace_harness import digest


def selection(action, *, owner=None, basis=None, cpu=None, domain=None,
              environment=None, privilege_spec=None, xlen=None, extensions=None):
    if action=='architecture':
        from .csr_architecture_profile import validate_template
        value={'schemaVersion':'riscv2x86.csr-architecture-template.v1',
            'privilegeSpecVersion':privilege_spec,'xlenBits':xlen,'extensions':sorted(set(extensions or []))}
        value['templateIdentity']=semantic_identity(value);validate_template(value)
        return value
    if not isinstance(owner,str) or not owner.strip():raise ValueError('MECHANISM_REVIEW_OWNER_REQUIRED')
    if basis is None or not Path(basis).read_bytes().strip():raise ValueError('MECHANISM_REVIEW_BASIS_REQUIRED')
    identity=digest(basis)
    if action=='controlled-time':
        if environment!='shared-external-time-trajectory':raise ValueError('TIME_EXPLICIT_ENVIRONMENT_SELECTION_REQUIRED')
        return {'owner':owner.strip(),'basis':'explicit-controlled-environment-selection','evidenceIdentity':identity}
    if action!='local-sync' or domain!='local-private-single-thread':raise ValueError('ISS_EXPLICIT_DOMAIN_SELECTION_REQUIRED')
    if type(cpu) is not int or cpu not in os.sched_getaffinity(0):raise ValueError('ISS_SELECTED_CPU_UNAVAILABLE')
    return {'schemaVersion':'riscv2x86.local-sync-selection.v1','sourceCpu':cpu,'targetCpu':cpu,
        'logicalHartIdentity':'selected-local-context:cpu-'+str(cpu),
        'modifiedCodeRange':{'objectIdentity':'probe-code-object','offsetBytes':0,'lengthBytes':4096,
            'addressSpaceIdentity':'observer.private.anonymous'},
        'assumptions':{'writerPolicy':'one-thread-same-mapping-no-external-writers',
            'mappingPolicy':'private-anonymous-no-alias-no-mmio',
            'executionPolicy':'local-pinned-hart-no-active-code-overwrite',
            'targetProtocolBasis':'x86-local-serializing-smc-v1',
            'rangeRole':'observer-probe-only-domain-guarantee-from-reviewed-mechanism',
            'reviewer':owner.strip(),'basisIdentity':identity}}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='action',required=True)
    for name in ('architecture','local-sync','controlled-time'):
        command=sub.add_parser(name);command.add_argument('--output',type=Path,required=True)
        if name=='architecture':
            command.add_argument('--privilege-spec',choices=('riscv-privileged-1.12','riscv-privileged-1.13'),required=True)
            command.add_argument('--xlen',type=int,choices=(32,64),required=True)
            command.add_argument('--extensions',nargs='+',required=True)
        else:
            command.add_argument('--owner',required=True);command.add_argument('--basis',type=Path,required=True)
            if name=='local-sync':
                command.add_argument('--cpu',type=int,required=True)
                command.add_argument('--domain',choices=('local-private-single-thread',),required=True)
            else:command.add_argument('--environment',choices=('shared-external-time-trajectory',),required=True)
    a=p.parse_args()
    try:
        value=selection(a.action,**{k:v for k,v in vars(a).items() if k not in ('action','output')})
        a.output.parent.mkdir(parents=True,exist_ok=True)
        with a.output.open('x') as stream:stream.write(json.dumps(value,indent=2)+'\n')
        print(json.dumps({'selectionPath':str(a.output),'semanticApproval':False}));return 0
    except (OSError,ValueError,TypeError) as exc:
        print(json.dumps({'failureStage':'mechanism_environment_selection','detail':str(exc),'semanticApproval':False}));return 2


if __name__=='__main__':raise SystemExit(main())
