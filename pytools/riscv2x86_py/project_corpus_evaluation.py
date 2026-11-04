"""Execute an explicit immutable project variant plan with independent auditing.

The plan is an experiment input, not a filter by translation success. Every
planned variant gets a row, including configuration failures and unsupported
capabilities. Only a verified production report AND its independent audit can
produce productionAcceptanceComplete=true.
"""
from collections import Counter
import argparse
import json
from pathlib import Path

from .project_build_records import identity
from .project_build_contract import load as load_contract


def execute(plan,output):
    fields={'schemaVersion','variants','planIdentity'}
    if (not isinstance(plan,dict) or set(plan)!=fields or plan['schemaVersion']!='riscv2x86.project-corpus-plan.v1'
            or plan['planIdentity']!=identity({k:v for k,v in plan.items() if k!='planIdentity'})
            or not isinstance(plan['variants'],list) or not plan['variants']):raise ValueError('PROJECT_CORPUS_PLAN_INVALID')
    keys={'variantId','projectBuildContract','frontend','mechanismSelections','harnessDirectory'}
    ids=[]
    for row in plan['variants']:
        if not isinstance(row,dict) or set(row)!=keys:raise ValueError('PROJECT_CORPUS_VARIANT_FIELDS_INVALID')
        name=row['variantId']
        if not isinstance(name,str) or not name or Path(name).name!=name or name in {'.','..'}:raise ValueError('PROJECT_CORPUS_VARIANT_ID_INVALID')
        ids.append(name)
    if len(set(ids))!=len(ids):raise ValueError('PROJECT_CORPUS_DUPLICATE_VARIANT')
    output=Path(output).resolve();output.mkdir(parents=True,exist_ok=False)
    (output/'plan.json').write_text(json.dumps(plan,indent=2)+'\n');results=[]
    for row in plan['variants']:
        result={'variantId':row['variantId'],'status':'not_run','productionAcceptanceComplete':False}
        results.append(result)
        try:
            from .automatic_batch_cli import prepare_automatic_inventory
            from .batch_evaluation_cli import run_batch_evaluation
            contract=load_contract(row['projectBuildContract']);result['contractIdentity']=contract['contractIdentity']
            work=output/row['variantId'];inventory=work/'inventory';batch=work/'batch'
            options={'frontend':row['frontend'],'project_build_contract':row['projectBuildContract']}
            if row['mechanismSelections'] is not None:options['l3_mechanism_selections']=row['mechanismSelections']
            if row['harnessDirectory'] is not None:options['harness_directory']=row['harnessDirectory']
            prepare_automatic_inventory(contract['sourceContext']['sourcePath'],inventory,**options)
            run_batch_evaluation(inventory/'cases',batch,jobs=1)
            paths=sorted(batch.glob('cases/*/evaluation-result.json'))
            if len(paths)!=1:raise ValueError('PROJECT_CORPUS_EXACT_EVALUATION_REQUIRED')
            evaluation=json.loads(paths[0].read_text());result['evaluationPath']=str(paths[0])
            result['evaluationStatus']=evaluation['status'];result['reasonCodes']=evaluation.get('reasonCodes',[])
            if evaluation['status']!='verified':result['status']='not_verified'
            else:
                if not evaluation.get('attempts'):raise ValueError('PROJECT_CORPUS_INLINE_ASM_INSTANCE_REQUIRED')
                from .l3_production_acceptance import audit_evaluation
                audit=audit_evaluation(evaluation)
                (work/'independent-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
                if audit.get('status')!='verified' or not audit.get('fragments'):raise ValueError('PROJECT_CORPUS_AUDIT_NOT_VERIFIED')
                result.update(status='accepted',productionAcceptanceComplete=True,auditIdentity=identity(audit))
        except Exception as exc:
            # Preserve every planned row and the concrete error, never skip a
            # seed to make the denominator or aggregate acceptance look better.
            result.update(status='blocked',error={'type':type(exc).__name__,'detail':str(exc)})
        finally:
            (output/'progress.json').write_text(json.dumps({'planIdentity':plan['planIdentity'],'records':results,
                'productionAcceptanceComplete':False},indent=2)+'\n')
    body={'schemaVersion':'riscv2x86.project-corpus-results.v1','planIdentity':plan['planIdentity'],
          'plannedVariantCount':len(ids),'records':results,'statusCounts':dict(Counter(r['status'] for r in results)),
          'productionAcceptanceComplete':all(r['productionAcceptanceComplete'] for r in results)}
    result=dict(body,resultIdentity=identity(body));(output/'results.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--plan',required=True);p.add_argument('--output',required=True);args=p.parse_args()
    try:
        result=execute(json.loads(Path(args.plan).read_text()),args.output)
        print(json.dumps({k:result[k] for k in ('plannedVariantCount','statusCounts','productionAcceptanceComplete')}))
        return 0 if result['productionAcceptanceComplete'] else 2
    except (OSError,ValueError,KeyError,TypeError) as exc:
        print(json.dumps({'error':type(exc).__name__,'detail':str(exc),'productionAcceptanceComplete':False}));return 2


if __name__=='__main__':raise SystemExit(main())
