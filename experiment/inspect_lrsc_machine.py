"""Read final ELF function bytes directly; no objdump version dependency."""
import argparse
import json
from pathlib import Path
from riscv2x86_py.l3_trace_support import Elf,digest
from riscv2x86_py.l3_lrsc_spec import spec
from riscv2x86_py.l3_lrsc_machine import function_mechanism


def main():
    p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();root=Path(a.root).resolve()
    reports=sorted(root.rglob('translated_report.json'));errors=[];checked=0;fragments=0
    if not reports:errors.append({'reasonCode':'LRSC_INSPECT_REPORTS_MISSING','root':str(root)})
    for report in reports:
        print('\nREPORT:',report)
        try:
            functions=json.loads(report.with_name('compiler-candidates.json').read_text())['functions']
            findings=json.loads(report.read_text())['findings']
            for finding in findings:
                if not (finding.get('approvalArtifact') or {}).get('l2LrscProofFacts'):continue
                fragments+=1;machines=set()
                inv=spec(finding,functions);name=finding['fragment']['enclosingFunction']
                # The case directory contains the actual L2 execution binaries.
                case=report.parents[2]
                for pattern in ('atomic.rv64','atomic.x86_64','program'):
                    for binary in sorted(case.rglob(pattern)):
                        try:
                            elf=Elf(binary);raw=elf.code(name)
                            mechanism=function_mechanism(elf,name,inv);machines.add(elf.machine);checked+=1
                            print(json.dumps({'binary':str(binary),'digest':digest(binary),'function':name,'machine':elf.machine,
                                'functionBytes':raw.hex(),'mechanism':mechanism},ensure_ascii=False))
                        except (ValueError,KeyError,OSError,TypeError) as exc:
                            errors.append({'binary':str(binary),'exceptionType':type(exc).__name__,'detail':str(exc)})
                if machines!={62,243}:errors.append({'fragmentId':finding['fragment']['id'],'reasonCode':'LRSC_INSPECT_BOTH_ARCHITECTURES_REQUIRED','machines':sorted(machines)})
        except (ValueError,KeyError,OSError,TypeError) as exc:
            errors.append({'report':str(report),'exceptionType':type(exc).__name__,'detail':str(exc)})
    if not fragments:errors.append({'reasonCode':'LRSC_INSPECT_FRAGMENTS_MISSING'})
    print(json.dumps({'schemaVersion':'riscv2x86.lrsc-machine-inspection.v1','reportCount':len(reports),
        'fragmentCount':fragments,'binaryCount':checked,'complete':not errors,'errors':errors,'semanticApproval':False},ensure_ascii=False))
    return 2 if errors else 0

if __name__=='__main__':raise SystemExit(main())
