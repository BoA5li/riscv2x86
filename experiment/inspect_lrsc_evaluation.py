"""Read-only concise LR/SC production diagnosis; never grants acceptance."""
import argparse
import json
from pathlib import Path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',required=True)
    root=Path(parser.parse_args().root).resolve()
    paths=sorted(root.rglob('evaluation-result.json'))
    print('report_count:',len(paths))
    for path in paths:
        if path.is_symlink() or not path.resolve().is_relative_to(root):continue
        print('\nREPORT:',path.relative_to(root))
        try:
            data=json.loads(path.read_text())
            print('status:',data.get('status'),'reasonCodes:',data.get('reasonCodes'))
            for key in ('detail','orchestrationFailure','requirementStagingFailure'):
                if data.get(key):print(key+':',json.dumps(data[key],ensure_ascii=False))
            for command in data.get('commands',[]):
                if command.get('status')!='verified':print('COMMAND:',json.dumps(command,ensure_ascii=False))
            for attempt in data.get('attempts',[]):
                print('translationOutcome:',attempt.get('translationOutcome'))
                print('attemptReasons:',attempt.get('reasonCodes'))
                for layer in (attempt.get('validation') or {}).get('layers',[]):
                    print('LAYER:',layer.get('level'),layer.get('status'))
                    if layer.get('status')!='verified':print('DETAIL:',layer.get('detail'))
        except (ValueError,KeyError,TypeError) as exc:
            print('READ_ERROR:',type(exc).__name__,str(exc))


if __name__=='__main__':main()
