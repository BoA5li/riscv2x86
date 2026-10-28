"""Read final ELF function bytes directly; no objdump version dependency."""
import argparse
import json
from pathlib import Path
from riscv2x86_py.l3_trace_support import Elf,digest
from riscv2x86_py.l3_lrsc_spec import spec
from riscv2x86_py.l3_lrsc_machine import function_mechanism


def main():
    p=argparse.ArgumentParser();p.add_argument('--root',required=True);a=p.parse_args();root=Path(a.root).resolve()
    for report in sorted(root.rglob('translated_report.json')):
        print('\nREPORT:',report)
        try:
            functions=json.loads(report.with_name('compiler-candidates.json').read_text())['functions']
            findings=json.loads(report.read_text())['findings']
            for finding in findings:
                if not (finding.get('approvalArtifact') or {}).get('l2LrscProofFacts'):continue
                inv=spec(finding,functions);name=finding['fragment']['enclosingFunction']
                # The case directory contains the actual L2 execution binaries.
                case=report.parents[2]
                for pattern in ('atomic.rv64','atomic.x86_64','program'):
                    for binary in sorted(case.rglob(pattern)):
                        try:
                            elf=Elf(binary);raw=elf.code(name)
                            print(json.dumps({'binary':str(binary),'digest':digest(binary),'function':name,'machine':elf.machine,
                                'functionBytes':raw.hex(),'mechanism':function_mechanism(elf,name,inv)},ensure_ascii=False))
                        except (ValueError,KeyError,OSError,TypeError) as exc:print('BINARY_ERROR:',str(binary),type(exc).__name__,str(exc))
        except (ValueError,KeyError,OSError,TypeError) as exc:print('REPORT_ERROR:',type(exc).__name__,str(exc))

if __name__=='__main__':main()
