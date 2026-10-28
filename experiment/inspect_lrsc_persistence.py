"""Read-only spec replay against saved contracts; not execution/production approval."""
import argparse
import json
from pathlib import Path
from riscv2x86_py.l3_trace_support import digest,require_json_document,require_json_match
from riscv2x86_py.l3_lrsc_deployment import bound_inputs


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',required=True)
    root=Path(parser.parse_args().root).resolve()
    paths=sorted(root.rglob('atomic-contract.json'))
    checked=0;errors=[]
    for path in paths:
        try:
            contract=json.loads(path.read_text())
            if contract.get('schemaVersion')!='riscv2x86.lrsc-trace-contract.v1':
                continue
            deployment=contract['deployment'];inputs=deployment['inputs']
            require_json_document(contract,'L3_LRSC_INSPECT_JSON_INVALID')
            for name,sha in deployment['inputDigests'].items():
                if digest(name)!=sha:raise ValueError('L3_LRSC_INSPECT_INPUT_CHANGED:'+name)
            if digest(deployment['clang'])!=deployment['clangDigest']:
                raise ValueError('L3_LRSC_INSPECT_COMPILER_CHANGED')
            findings=json.loads(Path(inputs['report']).read_text())['findings']
            if len(findings)!=1:raise ValueError('L3_LRSC_INSPECT_SINGLE_FINDING_REQUIRED')
            fresh,plan,function=bound_inputs(inputs['source'],inputs['target'],inputs['report'],findings[0],deployment['clang'])
            expected={'spec':fresh,'samplePlan':plan,'functionName':function['name']}
            actual={key:deployment[key] for key in expected}
            require_json_match(expected,actual,'L3_LRSC_SPEC_REPLAY_MISMATCH')
            checked+=1
            print(json.dumps({'contract':str(path),'functionName':function['name'],
                'widthBits':fresh['operation']['width_bits'],'specIdentity':fresh['specIdentity'],
                'specReplayComplete':True,'semanticApproval':False},sort_keys=True),flush=True)
        except (OSError,ValueError,KeyError,TypeError) as exc:
            errors.append({'contract':str(path),'exceptionType':type(exc).__name__,'detail':str(exc)})
    if not checked and not errors:errors.append({'reasonCode':'L3_LRSC_INSPECT_CONTRACTS_MISSING'})
    print(json.dumps({'schemaVersion':'riscv2x86.lrsc-persistence-inspection.v1',
        'contractCount':checked,'errors':errors,'specReplayComplete':bool(checked) and not errors,
        'executionAudited':False,'productionAcceptanceComplete':False,'semanticApproval':False},sort_keys=True),flush=True)
    return 2 if errors else 0


if __name__=='__main__':raise SystemExit(main())
