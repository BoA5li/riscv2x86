from hashlib import sha256
from http.client import IncompleteRead
from io import BytesIO
import pytest
from riscv2x86_py.project_archive_acquisition import fetch


class Response(BytesIO):
    def geturl(self):return 'https://official.example/archive'


def source(raw):
    return {'id':'project','archive':'project.tar.gz','sha256':sha256(raw).hexdigest(),
            'urls':['https://official.example/archive','https://mirror.example/archive']}


def test_incomplete_read_retries_and_does_not_publish_partial_bytes(tmp_path,monkeypatch):
    calls=[];raw=b'complete archive'
    def open_url(url,**kwargs):
        calls.append(url)
        if len(calls)==1:raise IncompleteRead(b'partial',100)
        return Response(raw)
    monkeypatch.setattr('urllib.request.urlopen',open_url)
    result=fetch(source(raw),tmp_path)
    assert len(calls)==2 and result['sha256']==sha256(raw).hexdigest()
    assert (tmp_path/'project.tar.gz').read_bytes()==raw
    assert not list(tmp_path.glob('*.part')) and len(result['priorFailures'])==1
    assert fetch(source(raw),tmp_path)['cached']


def test_wrong_hash_tries_fallback_but_never_accepts_corrupt_data(tmp_path,monkeypatch):
    monkeypatch.setattr('urllib.request.urlopen',lambda *a,**k:Response(b'bad'))
    with pytest.raises(ValueError,match='EXHAUSTED'):fetch(source(b'correct'),tmp_path,attempts=1)
    assert not (tmp_path/'project.tar.gz').exists()
    assert not list(tmp_path.iterdir())


def test_corrupt_existing_archive_is_preserved_and_rejected(tmp_path):
    (tmp_path/'project.tar.gz').write_bytes(b'corrupt')
    with pytest.raises(ValueError,match='CACHED'):fetch(source(b'correct'),tmp_path)
    assert (tmp_path/'project.tar.gz').read_bytes()==b'corrupt'


def test_source_lock_cannot_write_outside_destination(tmp_path):
    row=source(b'correct');row['archive']='../other.tar.gz'
    with pytest.raises(ValueError,match='LOCK_INVALID'):fetch(row,tmp_path)
