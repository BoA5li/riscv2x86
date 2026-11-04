"""Whole-release conservative asm census. No architecture/support-based exclusion.

Raw syntax, macro-provider references and generator hints remain pending until
an upstream build confirms activation. Original source bytes are never rewritten.
"""
import argparse
import base64
from collections import Counter, defaultdict, deque
import csv
import gzip
import io
import json
from pathlib import Path
import re
import sys
import runpy
import tarfile
import tempfile

V1 = runpy.run_path(str(Path(__file__).resolve().with_name('real_project_corpus.py')))
sha, canonical, sealed = V1['sha'], V1['canonical'], V1['sealed']
safe_path, gzip_bytes, read_snapshot = V1['safe_path'], V1['gzip_bytes'], V1['read_snapshot']
DEFAULT = Path(__file__).resolve().parent/'corpora/real-projects-v2'
SCHEMA = 'riscv2x86.whole-project-source-corpus.v2'
CHUNK = 512 * 1024
ROOT_ASM = {'asm', '__asm', '__asm__', 'asm_inline'}
C_SUFFIXES = ('.c','.h','.cc','.cpp','.cxx','.hpp','.hh','.hxx','.inc','.c.in','.h.in','.C','.H','.c++','.h++','.ipp','.tcc','.def','.c_shipped','.h_shipped')
GEN_SUFFIXES = ('.m4','.py','.pl','.sh','.in')
WORD = re.compile(rb'[A-Za-z_][A-Za-z_0-9]*')
ASM_CALL = re.compile(rb'\b(?:asm|__asm(?:__)?|asm_inline)\s*(?:(?:volatile|__volatile__|inline|goto)\s*)*\(')
ASM_HINT = re.compile(rb'\b(?:asm|__asm(?:__)?|asm_inline)\b(?!-|/(?![/*]))')
TOKEN = re.compile(rb'(?P<space>\s+)|(?P<line>//[^\n]*)|(?P<block>/\*.*?\*/)|'
                   rb'(?P<quoted>"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')|'
                   rb'(?P<identifier>[A-Za-z_][A-Za-z_0-9]*)|(?P<punct>.)', re.S)


def lex(data):
    result=[]
    for match in TOKEN.finditer(data):
        kind=match.lastgroup
        if kind in {'space','line','block'}: continue
        result.append((kind,match.start(),match.end(),
                       match[0].decode('ascii') if kind in {'identifier','punct'} and match[0].isascii() else ''))
    return result


def logical(raw): return re.sub(rb'\\\r?\n',b'',raw)


def hint(path, raw):
    if re.search(r'(^|/)(?:riscv[^/]*)(/|$)',path,re.I): return 'riscv-path'
    if re.search(rb'(?i)\b(?:__riscv\w*|CONFIG_RISCV\w*|HAVE_HOST_CPU\w*riscv\w*)\b',raw):
        return 'riscv-reference-needs-cpp'
    if re.search(r'(^|/)(?:x86[^/]*|i[3-6]86|arm[^/]*|aarch64|mips[^/]*|powerpc[^/]*|s390[^/]*|sparc[^/]*|alpha|ia64|m68k|loongarch[^/]*)(/|$)',path,re.I):
        return 'other-architecture-path-retained'
    return 'shared-or-undetermined'


def inventory(raw, project, version, path):
    data=logical(raw); ts=lex(data)
    # Offset mapping is only needed for files that actually have tokens.
    candidates=[]
    excluded=[]; off=0
    for line in data.splitlines(keepends=True):
        directive=re.match(rb'\s*#\s*(\w+)',line)
        if directive and directive[1] != b'define': excluded.append((off,off+len(line)))
        off+=len(line)
    for i,t in enumerate(ts):
        if t[0]!='identifier' or t[3] not in ROOT_ASM: continue
        if any(a<=t[1]<b for a,b in excluded): continue
        j=i+1
        while j<len(ts) and ts[j][3] in V1['QUALIFIERS']:j+=1
        end=t[2]; closed=False; sections=False
        if j<len(ts) and ts[j][3]=='(':
            depth=0
            for k in range(j,len(ts)):
                v=ts[k][3]
                if v=='(':depth+=1
                elif v==')':
                    depth-=1
                    if depth==0:end=ts[k][2];closed=True;break
                elif v==':' and depth==1: sections=True
        previous=[]
        for k in range(i-1,-1,-1):
            if ts[k][3] in {';','{','}'}:break
            previous.append(ts[k][3])
        kind=('unresolved-asm-token' if not closed else 'register-binding-candidate' if 'register' in previous
              else 'extended-asm-candidate' if sections else 'basic-file-or-macro-asm-candidate')
        candidates.append((t[1],end,kind,t[3]))
    if not candidates:return []
    spliced,mapping=V1['splice'](raw)
    if data!=spliced: raise ValueError('phase-2 normalization mismatch')
    rows=[]
    for a,b,kind,spelling in candidates:
        start=mapping[a];stop=mapping[b-1]+1
        row={'project':project,'version':version,'sourcePath':path,'sourceDigest':'sha256:'+sha(raw),
            'beginByte':start,'endByte':stop,'startLine':raw.count(b'\n',0,start)+1,
            'endLine':raw.count(b'\n',0,stop-1)+1,'sourceSliceDigest':'sha256:'+sha(raw[start:stop]),
            'sourceSliceBase64':base64.b64encode(raw[start:stop]).decode(),
            'syntaxKind':kind,'asmSpelling':spelling,'architectureHint':hint(path,data),
            'collectionDisposition':'retained-pending-upstream-activation',
            'activationStatus':'not_checked','eligibilityStatus':'not_assessed',
            'translationStatus':'not_run','validationStatus':'not_run','semanticApproval':False,
            'productionAcceptanceComplete':False}
        rows.append(sealed(row,'siteIdentity'))
    return rows


def macro_definitions(data,path):
    # Overapproximation only: duplicate names/conditions are merged, never used
    # to grant execution or architecture membership.
    result=[]
    pattern=re.compile(rb'^[ \t]*(?:#|%:)\s*define[ \t]+([A-Za-z_]\w*)([^\n]*)',re.M)
    for match in pattern.finditer(data):
        tail=match[2];params=set();variadic=False
        if tail.startswith(b'('):
            stop=tail.find(b')')
            if stop<0: # malformed/preprocessed template: retain as unresolved paste/review
                stop=0
            else:
                params={word.decode() for word in WORD.findall(tail[1:stop])}
                variadic=b'...' in tail[1:stop]
                tail=tail[stop+1:]
        params.update({'__VA_ARGS__','__VA_OPT__'})
        identifiers={sys.intern(t[3]) for t in lex(tail)
                     if t[0]=='identifier' and t[3] not in params}
        result.append({'name':sys.intern(match[1].decode()),'sourcePath':path,
            'bodyIdentifiers':sorted(identifiers), 'formalParameters':sorted(params-{'__VA_ARGS__','__VA_OPT__'}),
            'variadic':variadic,'hasTokenPaste':b'##' in tail or b'%:%:' in tail})
    return result


def providers(definitions):
    reverse=defaultdict(set)
    names={d['name'] for d in definitions}|ROOT_ASM
    for d in definitions:
        for word in d['bodyIdentifiers']:
            if word in names:reverse[word].add(d['name'])
    found=set(ROOT_ASM); queue=deque(sorted(found))
    while queue:
        for name in sorted(reverse[queue.popleft()]-found): found.add(name);queue.append(name)
    return found-ROOT_ASM


def read_lock(root):
    lock=json.loads((root/'sources.lock.json').read_text())
    if lock['schemaVersion']!='riscv2x86.whole-project-source-lock.v2':raise ValueError('unsupported lock')
    if len({s['id'] for s in lock['sources']})!=len(lock['sources']):raise ValueError('duplicate project')
    for s in lock['sources']:
        if not re.fullmatch(r'[a-z0-9_-]+',s['id']):raise ValueError('unsafe project')
        safe_path(s['archive']);safe_path(s['root'])
        if '/' in s['archive'] or not re.fullmatch('[a-f0-9]{64}',s['sha256']):raise ValueError('invalid source lock')
    return lock


def collect(source,archive):
    if sha(archive.read_bytes())!=source['sha256']:raise ValueError('archive SHA256 mismatch')
    files=[]; retained={}; sites=[]; defs=[]; review=[]; prefix=source['root']+'/'
    with tarfile.open(archive) as tar:
        for member in tar:
            if not member.name.startswith(prefix):continue
            path=member.name[len(prefix):]
            if not path:continue
            safe_path(path)
            if member.isdir(): continue
            if not member.isfile():
                files.append({'path':path,'entryType':'nonregular','linkTarget':member.linkname,
                              'disposition':'retained-in-release-needs-build-context'});continue
            raw=tar.extractfile(member).read(); is_c=path.endswith(C_SUFFIXES)
            other_text_data=logical(raw) if not is_c and b'\0' not in raw else b''
            generator=path.endswith(GEN_SUFFIXES) or path.rsplit('/',1)[-1].startswith(('Makefile','configure'))
            generator=generator or bool(ASM_CALL.search(other_text_data))
            facts={'path':path,'entryType':'regular','bytes':len(raw),'sha256':sha(raw),
                   'fileKind':'c-cpp-or-header-template' if is_c else 'generator-or-build-input' if generator else 'other-release-file'}
            files.append(facts)
            data=logical(raw) if is_c or generator else b''
            if is_c:defs.extend(macro_definitions(data,path))
            asm_hint=bool(ASM_HINT.search(data)); paste=b'##' in data or b'%:%:' in data
            facts.update(asmTextHint=asm_hint,macroPasteHint=paste,architectureHint=hint(path,data) if is_c else 'not-c-syntax')
            license_file=path in source['licenseFiles'] or any(path.startswith(p) for p in source['licensePrefixes'])
            if is_c and asm_hint:
                retained[path]=raw
                try:sites.extend(inventory(raw,source['id'],source['version'],path))
                except (ValueError,IndexError,UnicodeError) as exc:
                    review.append({'path':path,'reason':'source-lexer-review-required','detail':str(exc)})
            elif generator and asm_hint:
                retained[path]=raw;review.append({'path':path,'reason':'generated-c-or-asm-template-review-required'})
            # Paste can synthesize asm or provider names; no zero-asm assertion.
            if is_c and paste:review.append({'path':path,'reason':'token-paste-activation-review-required'})
            if license_file:retained[path]=raw
    if len({f['path'] for f in files})!=len(files):raise ValueError('duplicate release path')
    known=providers(defs)
    known_bytes={name.encode() for name in known}
    definitions=[d for d in defs if d['name'] in known or d['hasTokenPaste']]
    # A second full-release pass records callers without demanding a literal asm
    # keyword in the caller file. Raw caller bytes remain available for materialization.
    references=[]
    with tarfile.open(archive) as tar:
        for member in tar:
            if not member.isfile() or not member.name.startswith(prefix):continue
            path=member.name[len(prefix):]
            if not path.endswith(C_SUFFIXES):continue
            raw=tar.extractfile(member).read();data=logical(raw)
            matched=sorted({match[0].decode() for match in WORD.finditer(data) if match[0] in known_bytes})
            if matched:
                references.append({'sourcePath':path,'sourceDigest':'sha256:'+sha(raw),'providerNames':matched,
                    'referenceKind':'textual-superset-may-include-definitions-comments-or-inactive-code',
                    'activationStatus':'not_checked'})
    for path in source['licenseFiles']:
        if path not in retained:raise ValueError('missing license file')
    files.sort(key=lambda x:x['path']);sites.sort(key=lambda x:(x['sourcePath'],x['beginByte']))
    definitions.sort(key=lambda x:(x['sourcePath'],x['name'],x['bodyIdentifiers']))
    review.sort(key=lambda x:(x['path'],x['reason']));references.sort(key=lambda x:x['sourcePath'])
    return files,retained,sites,definitions,references,review


def write_chunks(directory,name,raw):
    records=[]
    for number,offset in enumerate(range(0,len(raw),CHUNK)):
        data=raw[offset:offset+CHUNK]; filename=f'{name}.part-{number:03d}'
        (directory/filename).write_bytes(data);records.append({'path':filename,'bytes':len(data),'sha256':sha(data)})
    return {'bytes':len(raw),'sha256':sha(raw),'parts':records}


def read_chunks(directory,record):
    chunks=[]
    for item in record['parts']:
        safe_path(item['path']);raw=(directory/item['path']).read_bytes()
        if len(raw)!=item['bytes'] or sha(raw)!=item['sha256']:raise ValueError('data shard changed')
        chunks.append(raw)
    raw=b''.join(chunks)
    if len(raw)!=record['bytes'] or sha(raw)!=record['sha256']:raise ValueError('shard sequence incomplete')
    return raw


def jsonl(rows):return b''.join(canonical(r)+b'\n' for r in rows)


def project_payload(source,collected):
    files,retained,sites,definitions,references,review=collected
    index=io.StringIO();writer=csv.writer(index,delimiter='\t',lineterminator='\n')
    keys=['siteIdentity','sourcePath','startLine','syntaxKind','architectureHint','activationStatus']
    writer.writerow(keys)
    for row in sites:writer.writerow([row[k] for k in keys])
    payload={'release-files.jsonl.gz':gzip_bytes(jsonl(files)),
        'sources.tar.gz':V1['archive_bytes'](retained),'sites.jsonl.gz':gzip_bytes(jsonl(sites)),
        'macro-providers.jsonl.gz':gzip_bytes(jsonl(definitions)),
        'macro-references.jsonl.gz':gzip_bytes(jsonl(references)),
        'review-required.jsonl.gz':gzip_bytes(jsonl(review)), 'index.tsv.gz':gzip_bytes(index.getvalue().encode())}
    counts={'releaseEntries':len(files),'regularFiles':sum(f['entryType']=='regular' for f in files),
        'cSourceFiles':sum(f.get('fileKind')=='c-cpp-or-header-template' for f in files),
        'retainedOriginalFiles':len(retained),'syntaxSites':len(sites),
        'syntaxKinds':dict(sorted(Counter(r['syntaxKind'] for r in sites).items())),
        'architectureHints':dict(sorted(Counter(r['architectureHint'] for r in sites).items())),
        'macroProviderDefinitions':len(definitions),'macroReferenceFiles':len(references),
        'reviewRequiredRecords':len(review)}
    return payload,counts


def build(root,archives,output):
    lock=read_lock(root)
    if output.exists():raise ValueError('output exists')
    output.mkdir(parents=True);(output/'sources.lock.json').write_bytes((root/'sources.lock.json').read_bytes())
    projects=[]
    for source in lock['sources']:
        print('Collecting '+source['id'],file=sys.stderr,flush=True)
        payload,counts=project_payload(source,collect(source,archives/source['archive']))
        directory=output/source['id'];directory.mkdir()
        artifacts={name:write_chunks(directory,name,raw) for name,raw in sorted(payload.items())}
        manifest=sealed({'schemaVersion':SCHEMA,'project':source['id'],'version':source['version'],
            'sourceLockIdentity':'sha256:'+sha(canonical(source)), 'artifacts':artifacts,'counts':counts,
            'compilerActivationComplete':False,'macroExpansionClosureComplete':False,
            'runnableCorpusComplete':False,'semanticApproval':False,'productionAcceptanceComplete':False},'manifestIdentity')
        (directory/'manifest.json').write_bytes(canonical(manifest)+b'\n')
        projects.append({'id':source['id'],'version':source['version'],'manifestIdentity':manifest['manifestIdentity'],'counts':counts})
    catalog=sealed({'schemaVersion':SCHEMA,'sourceLockIdentity':'sha256:'+sha(canonical(lock)),
        'projects':projects,'compilerActivationComplete':False,'semanticApproval':False,'productionAcceptanceComplete':False},'catalogIdentity')
    (output/'catalog.json').write_bytes(canonical(catalog)+b'\n')


def verify(root,archives=None):
    lock=read_lock(root);catalog=json.loads((root/'catalog.json').read_text());V1['check_seal'](catalog,'catalogIdentity')
    if catalog['sourceLockIdentity']!='sha256:'+sha(canonical(lock)):raise ValueError('source lock changed')
    if catalog['schemaVersion']!=SCHEMA or any(catalog[k] is not False for k in
            ('compilerActivationComplete','semanticApproval','productionAcceptanceComplete')):
        raise ValueError('invalid catalog schema or acceptance label')
    projects=[]
    for source in lock['sources']:
        directory=root/source['id'];manifest=json.loads((directory/'manifest.json').read_text());V1['check_seal'](manifest,'manifestIdentity')
        if manifest['sourceLockIdentity']!='sha256:'+sha(canonical(source)):raise ValueError('project source lock changed')
        if any(manifest[k] is not False for k in ('compilerActivationComplete','macroExpansionClosureComplete',
                  'runnableCorpusComplete','semanticApproval','productionAcceptanceComplete')):raise ValueError('unearned acceptance label')
        payload={n:read_chunks(directory,r) for n,r in manifest['artifacts'].items()}
        if archives is not None:
            fresh,counts=project_payload(source,collect(source,archives/source['archive']))
            # Recompression implementations may differ. Compare decoded logical
            # data and exact original source files, not compressor byte choices.
            if set(fresh)!=set(payload) or canonical(counts)!=canonical(manifest['counts']):raise ValueError('upstream census mismatch: '+source['id'])
            for name in fresh:
                if gzip.decompress(fresh[name])!=gzip.decompress(payload[name]):raise ValueError('upstream data differs: '+source['id']+'/'+name)
        expected_artifacts={'release-files.jsonl.gz','sources.tar.gz','sites.jsonl.gz',
            'macro-providers.jsonl.gz','macro-references.jsonl.gz','review-required.jsonl.gz','index.tsv.gz'}
        if set(payload)!=expected_artifacts:raise ValueError('artifact set incomplete')
        if manifest['schemaVersion']!=SCHEMA or manifest['project']!=source['id'] or manifest['version']!=source['version']:
            raise ValueError('manifest project or version mismatch')
        file_rows=[json.loads(line) for line in gzip.decompress(payload['release-files.jsonl.gz']).splitlines()]
        file_map={r['path']:r for r in file_rows}
        if len(file_map)!=len(file_rows):raise ValueError('duplicate release file')
        for path in file_map:safe_path(path)
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'sources.tar.gz';p.write_bytes(payload['sources.tar.gz']);files=read_snapshot(p)
            for path,raw in files.items():
                f=file_map[path]
                if f['entryType']!='regular' or f['bytes']!=len(raw) or f['sha256']!=sha(raw):
                    raise ValueError('retained source differs from release census')
            rows=[json.loads(line) for line in gzip.decompress(payload['sites.jsonl.gz']).splitlines()]
            ids=set()
            for row in rows:
                V1['check_seal'](row,'siteIdentity');raw=files[row['sourcePath']]
                if row['siteIdentity'] in ids:raise ValueError('duplicate source site')
                ids.add(row['siteIdentity'])
                if (type(row['beginByte']) is not int or type(row['endByte']) is not int
                        or not 0<=row['beginByte']<row['endByte']<=len(raw)):
                    raise ValueError('invalid byte interval')
                if ('sha256:'+sha(raw)!=row['sourceDigest'] or raw[row['beginByte']:row['endByte']]!=base64.b64decode(row['sourceSliceBase64'])
                        or 'sha256:'+sha(base64.b64decode(row['sourceSliceBase64']))!=row['sourceSliceDigest']):raise ValueError('site provenance mismatch')
                if (any(row[k]!='not_run' for k in ('translationStatus','validationStatus'))
                        or row['activationStatus']!='not_checked' or row['eligibilityStatus']!='not_assessed'
                        or row['semanticApproval'] is not False or row['productionAcceptanceComplete'] is not False
                        or row['collectionDisposition']!='retained-pending-upstream-activation'):
                    raise ValueError('unearned site eligibility or acceptance')
            observed={'releaseEntries':len(file_rows),'regularFiles':sum(f['entryType']=='regular' for f in file_rows),
                'cSourceFiles':sum(f.get('fileKind')=='c-cpp-or-header-template' for f in file_rows),
                'retainedOriginalFiles':len(files),'syntaxSites':len(rows),
                'syntaxKinds':dict(sorted(Counter(r['syntaxKind'] for r in rows).items())),
                'architectureHints':dict(sorted(Counter(r['architectureHint'] for r in rows).items())),
                'macroProviderDefinitions':len(gzip.decompress(payload['macro-providers.jsonl.gz']).splitlines()),
                'macroReferenceFiles':len(gzip.decompress(payload['macro-references.jsonl.gz']).splitlines()),
                'reviewRequiredRecords':len(gzip.decompress(payload['review-required.jsonl.gz']).splitlines())}
            if canonical(observed)!=canonical(manifest['counts']):raise ValueError('counts do not match retained data')
        projects.append({'id':source['id'],'version':source['version'],'manifestIdentity':manifest['manifestIdentity'],'counts':manifest['counts']})
    if canonical(projects)!=canonical(catalog['projects']):raise ValueError('catalog mismatch')
    return {'status':'verified-whole-release-census','catalogIdentity':catalog['catalogIdentity'],'projects':projects,
        'upstreamReplayComplete':archives is not None,'compilerActivationComplete':False,
        'macroExpansionClosureComplete':False,'semanticApproval':False,'productionAcceptanceComplete':False}


def materialize(root,output,archives=None):
    result=verify(root)
    if output.exists():raise ValueError('output exists')
    output.mkdir(parents=True)
    for source in read_lock(root)['sources']:
        directory=root/source['id'];dest=output/source['id'];dest.mkdir()
        manifest=json.loads((directory/'manifest.json').read_text())
        for name,record in manifest['artifacts'].items():
            raw=read_chunks(directory,record)
            if name=='sources.tar.gz':
                with tempfile.TemporaryDirectory() as tmp:
                    path=Path(tmp)/'source.tar.gz';path.write_bytes(raw)
                    for p,data in read_snapshot(path).items():
                        target=dest/'upstream'/p;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
            else:(dest/name.removesuffix('.gz')).write_bytes(gzip.decompress(raw))
        if archives is not None:
            archive=archives/source['archive']
            if sha(archive.read_bytes())!=source['sha256']:raise ValueError('archive digest changed')
            # Materialize full regular-file source context safely; preserve link
            # facts in the census instead of creating filesystem links.
            prefix=source['root']+'/'
            with tarfile.open(archive) as tar:
                for entry in tar:
                    if not entry.isfile() or not entry.name.startswith(prefix):continue
                    p=entry.name[len(prefix):];safe_path(p)
                    target=dest/'full-release'/p;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(tar.extractfile(entry).read())
    return result


def audit_v1(root, previous):
    verify(root)
    projects=[];missing=[]
    for source in read_lock(root)['sources']:
        directory=root/source['id'];manifest=json.loads((directory/'manifest.json').read_text())
        rows=[json.loads(line) for line in gzip.decompress(read_chunks(directory,manifest['artifacts']['sites.jsonl.gz'])).splitlines()]
        key=lambda r:(r['sourcePath'],r['beginByte'],r['endByte'],r['sourceDigest'])
        current={key(r) for r in rows}
        old=[json.loads(line) for line in gzip.decompress((previous/source['id']/'sites.jsonl.gz').read_bytes()).splitlines()]
        lost=[{'project':source['id'],'sourcePath':r['sourcePath'],'beginByte':r['beginByte']}
              for r in old if key(r) not in current]
        missing.extend(lost)
        projects.append({'id':source['id'],'priorSyntaxSiteCount':len(old),
            'priorSelectedCandidateCount':sum(r['selectedByScope'] for r in old),'missingCount':len(lost)})
    if missing:raise ValueError('v1 source positions missing from v2: '+json.dumps(missing))
    return {'status':'all-v1-source-positions-retained','projects':projects,'missingCount':0,
        'compilerActivationComplete':False,'semanticApproval':False,'productionAcceptanceComplete':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__);subs=parser.add_subparsers(dest='command',required=True)
    for name in ('build','verify','materialize','download','audit-v1'):
        p=subs.add_parser(name);p.add_argument('--corpus',type=Path,default=DEFAULT)
        if name not in {'verify','audit-v1'}:p.add_argument('--output',type=Path,required=True)
        if name=='audit-v1':p.add_argument('--previous',type=Path,default=DEFAULT.with_name('real-projects-v1'))
        if name in {'build','verify','materialize'}:p.add_argument('--archives',type=Path,required=name=='build')
    args=parser.parse_args()
    try:
        if args.command=='build':build(args.corpus,args.archives,args.output);result=verify(args.output)
        elif args.command=='verify':result=verify(args.corpus,args.archives)
        elif args.command=='materialize':result=materialize(args.corpus,args.output,args.archives)
        elif args.command=='audit-v1':result=audit_v1(args.corpus,args.previous)
        else:result=download(args.corpus,args.output)
        print(json.dumps(result,indent=2));return 0
    except (OSError,ValueError,KeyError,tarfile.TarError) as exc:
        print(json.dumps({'status':'failed','error':str(exc),'semanticApproval':False}));return 1


def download(root,output):
    # Use the same pinned-archive downloader, with v2 lock validation.
    lock=read_lock(root)
    with tempfile.TemporaryDirectory() as tmp:
        directory=Path(tmp);v1=dict(lock,schemaVersion='riscv2x86.real-project-sources.v1')
        for s in v1['sources']:
            s.update(scope={'files':[],'prefixes':[],'suffix':'.h','siteRule':'all_asm_syntax_sites'},supportFiles=[])
        (directory/'sources.lock.json').write_text(json.dumps(v1))
        return V1['download'](directory,output)


if __name__=='__main__':raise SystemExit(main())
