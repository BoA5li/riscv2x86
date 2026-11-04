"""Retry pinned source downloads atomically; never weaken digest verification."""
from hashlib import sha256
from http.client import HTTPException
import os
from pathlib import Path
import re
import tempfile
import urllib.request


def fetch(source, output, *, attempts=2, timeout=60, max_bytes=1024**3):
    name=source['archive']; expected=source['sha256'];urls=source['urls']
    if (Path(name).name!=name or name in {'.','..'} or not re.fullmatch('[0-9a-f]{64}',expected)
            or not isinstance(urls,list) or not urls or any(not u.startswith('https://') for u in urls)
            or type(attempts) is not int or not 1<=attempts<=10):
        raise ValueError('PROJECT_ARCHIVE_LOCK_INVALID')
    output=Path(output);output.mkdir(parents=True,exist_ok=True);destination=output/name
    def file_digest(path):
        h=sha256()
        with path.open('rb') as stream:
            for block in iter(lambda:stream.read(1024*1024),b''): h.update(block)
        return h.hexdigest()
    if destination.exists():
        if file_digest(destination)!=expected:raise ValueError('PROJECT_CACHED_ARCHIVE_DIGEST_MISMATCH')
        return {'project':source['id'],'path':str(destination),'sha256':expected,'cached':True}
    failures=[]
    for url in urls:
        for attempt in range(attempts):
            temporary=None
            try:
                fd,name=tempfile.mkstemp(prefix='.archive-',suffix='.part',dir=output)
                temporary=Path(name);h=sha256();size=0
                with os.fdopen(fd,'wb') as stream, urllib.request.urlopen(url,timeout=timeout) as response:
                    while True:
                        block=response.read(1024*1024)
                        if not block:break
                        size+=len(block)
                        if size>max_bytes:raise ValueError('PROJECT_ARCHIVE_SIZE_LIMIT')
                        h.update(block);stream.write(block)
                    stream.flush();os.fsync(stream.fileno())
                    acquired=response.geturl()
                if h.hexdigest()!=expected:raise ValueError('PROJECT_ARCHIVE_DIGEST_MISMATCH')
                try:os.link(temporary,destination)
                except FileExistsError:
                    if file_digest(destination)!=expected:raise ValueError('PROJECT_CONCURRENT_ARCHIVE_DIGEST_MISMATCH')
                return {'project':source['id'],'path':str(destination),'url':url,'acquiredFrom':acquired,
                        'sha256':expected,'bytes':size,'cached':False,'priorFailures':failures}
            except (OSError,ValueError,HTTPException) as exc:
                failures.append({'url':url,'attempt':attempt+1,'type':type(exc).__name__,'detail':str(exc)})
            finally:
                if temporary is not None:temporary.unlink(missing_ok=True)
    raise ValueError('PROJECT_ARCHIVE_DOWNLOADS_EXHAUSTED:'+repr(failures))
