import json
from pathlib import Path
import runpy
import zipfile
import pytest

ROOT=Path(__file__).resolve().parents[2]


def test_goal_acceptance_is_separate_from_regression_and_missing_cases(tmp_path):
    check=runpy.run_path(str(ROOT/'experiment/check_route_goals.py'))['check']
    path=tmp_path/'cases'/'renamable'/'evaluation-result.json';path.parent.mkdir(parents=True)
    path.write_text(json.dumps({'status':'needs_route','reasonCodes':['ISS_RUNTIME_CONTRACT_MISSING']}))
    assert not check(tmp_path,['renamable'])['goalSatisfied']
    path.write_text(json.dumps({'status':'verified','evaluationIdentity':'sha256:'+'1'*64}))
    assert check(tmp_path,['renamable'])['goalSatisfied']
    assert not check(tmp_path,['unknown'])['goalSatisfied']
    with pytest.raises(ValueError):check(tmp_path,['../elsewhere'])
    with pytest.raises(ValueError):check(tmp_path,['renamable','renamable'])


def test_collection_preserves_exact_sources_and_rejects_stale_files(tmp_path,monkeypatch):
    collect=runpy.run_path(str(ROOT/'experiment/collect_route_evidence.py'))['collect']
    import shutil
    monkeypatch.setattr(shutil,'which',lambda name:None)
    source=tmp_path/'input.c';source.write_text('void renamed(void){}')
    root=tmp_path/'run';case=root/'generated-suite-strict/cases/renamable';case.mkdir(parents=True)
    (case.parent.parent/'batch-evaluation.json').write_text(json.dumps({'batchIdentity':'batch'}))
    result={'status':'needs_route','commands':[{'phase':'translation','command':['translator','--source',str(source)]}]}
    (case/'evaluation-result.json').write_text(json.dumps(result))
    resolution=root/'generated-suite-strict-inventory/cases/renamable/contract-resolution.json'
    resolution.parent.mkdir(parents=True)
    from hashlib import sha256
    resolution.write_text(json.dumps({'sourceDigest':'sha256:'+sha256(source.read_bytes()).hexdigest()}))
    (root/'run-status.json').write_text('{"experiment":"original"}')
    output=tmp_path/'evidence.zip';manifest=collect(root,output)
    assert manifest['toolProvenanceScope']=='collection-time-only'
    assert manifest['experimentProvenanceFiles']==['run/run-status.json']
    assert manifest['semanticApproval'] is False
    with zipfile.ZipFile(output) as archive:
        assert archive.read('cases/renamable/source.c')==source.read_bytes()
        assert archive.read('run/run-status.json')==(root/'run-status.json').read_bytes()
    with pytest.raises(ValueError,match='OUTPUT_EXISTS'):collect(root,output)
    source.write_text('changed')
    with pytest.raises(ValueError,match='SOURCE_CHANGED'):collect(root,tmp_path/'stale.zip')
    assert not (tmp_path/'stale.zip').exists()
