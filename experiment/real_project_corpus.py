"""Freeze, verify and materialize upstream source candidates; never grants eligibility.

The byte-preserving snapshots are the corpus. The lexical ledger is not a
compiler AST, activation proof, runnable test suite, or translation verdict.
"""
import argparse
import base64
from collections import Counter
import csv
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import urllib.request

SCHEMA = 'riscv2x86.real-project-corpus.v1'
SCANNER = 'c-asm-token-inventory.v1'
DEFAULT = Path(__file__).resolve().parent / 'corpora/real-projects-v1'
ASM_WORDS = {'asm', '__asm', '__asm__', 'asm_inline'}
QUALIFIERS = {'volatile', '__volatile', '__volatile__', 'inline', '__inline', '__inline__', 'goto'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()


def sealed(value, key):
    return dict(value, **{key: 'sha256:' + sha(canonical(value))})


def check_seal(value, key):
    if value.get(key) != 'sha256:' + sha(canonical({k:v for k,v in value.items() if k != key})):
        raise ValueError('content identity mismatch: ' + key)


def safe_path(name):
    p = PurePosixPath(name)
    if not name or p.is_absolute() or '..' in p.parts or '\\' in name or str(p) != name:
        raise ValueError('unsafe archive path: ' + name)
    return p


def splice(raw):
    # Translation phase 2, retaining offsets into original bytes, including CRLF.
    data, offsets, i = bytearray(), [], 0
    while i < len(raw):
        if raw[i:i+2] == b'\\\n': i += 2; continue
        if raw[i:i+3] == b'\\\r\n': i += 3; continue
        data.append(raw[i]); offsets.append(i); i += 1
    return bytes(data), offsets


def tokens(data):
    """C tokens, excluding comments; strings/chars are indivisible tokens."""
    result = []; i = 0
    while i < len(data):
        start = i; c = data[i]
        if c in b' \t\r\n\v\f': i += 1; continue
        if data[i:i+2] == b'//':
            end = data.find(b'\n', i+2); i = len(data) if end < 0 else end+1; continue
        if data[i:i+2] == b'/*':
            end = data.find(b'*/', i+2)
            if end < 0: raise ValueError('unterminated C comment')
            i = end+2; continue
        if c in (34, 39):
            quote = c; i += 1
            while i < len(data):
                if data[i] == 92: i += 2
                elif data[i] == quote: i += 1; break
                else: i += 1
            else: raise ValueError('unterminated C string or character token')
            result.append(('quoted', start, i, '')); continue
        if c == 95 or 65 <= c <= 90 or 97 <= c <= 122:
            i += 1
            while i < len(data) and (data[i] == 95 or 48 <= data[i] <= 57 or 65 <= data[i] <= 90 or 97 <= data[i] <= 122): i += 1
            result.append(('identifier', start, i, data[start:i].decode('ascii'))); continue
        i += 1; result.append(('punctuation', start, i, chr(c)))
    return result


def contexts(data):
    """Conditional branches as source facts, never evaluate host CPP macros."""
    stack, records, offset = [], [], 0
    for line in data.splitlines(keepends=True):
        records.append((offset, [dict(x) for x in stack]))
        m = re.match(rb'\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)', line)
        if m:
            kind = m[1].decode(); expression = m[2].strip().decode('utf-8', errors='backslashreplace')
            if kind in {'if','ifdef','ifndef'}:
                stack.append({'directive':kind, 'expression':expression, 'logicalOffset':offset})
            elif kind == 'endif':
                if not stack: raise ValueError('unmatched #endif')
                stack.pop()
            elif kind in {'elif','else'}:
                if not stack: raise ValueError('unmatched conditional branch')
                stack[-1] = {'directive':kind, 'expression':expression, 'logicalOffset':offset}
        offset += len(line)
    if stack: raise ValueError('unclosed preprocessor conditional')
    return records


def inventory(raw, *, project, version, path, rule):
    data, mapping = splice(raw); ts = tokens(data)
    # Directive recognition must not see #if inside comments or strings.
    masked = bytearray(
        10 if c == 10 else 32 for c in data)
    for kind, begin, end, _ in ts:
        if kind != 'quoted': masked[begin:end] = data[begin:end]
    pp = contexts(bytes(masked))
    excluded_directives = []
    offset = 0
    for line in bytes(masked).splitlines(keepends=True):
        directive = re.match(rb'\s*#\s*([A-Za-z_]+)', line)
        if directive and directive[1] != b'define': excluded_directives.append((offset, offset+len(line)))
        offset += len(line)
    import bisect
    line_offsets = [x[0] for x in pp]
    rows = []
    for index, token in enumerate(ts):
        if token[0] != 'identifier' or token[3] not in ASM_WORDS: continue
        if any(a <= token[1] < b for a,b in excluded_directives): continue
        j = index+1
        while j < len(ts) and ts[j][3] in QUALIFIERS: j += 1
        parsed, has_sections, end = False, False, token[2]
        if j < len(ts) and ts[j][3] == '(':
            depth = 0
            for k in range(j, len(ts)):
                value = ts[k][3]
                if value == '(': depth += 1
                elif value == ')':
                    depth -= 1
                    if depth == 0: end = ts[k][2]; parsed = True; break
                elif value == ':' and depth == 1: has_sections = True
        context = pp[bisect.bisect_right(line_offsets, token[1])-1][1]
        # This is only a branch-membership candidate, not an evaluated #if.
        riscv_branch = any(re.search(r'\b__riscv\w*\b', x['expression'])
                           and x['directive'] in {'if','ifdef','elif'} for x in context)
        selected = rule == 'all_asm_syntax_sites' or riscv_branch
        begin = mapping[token[1]]; stop = mapping[end-1]+1
        # A fixed-register variable declaration is not automatically executable asm.
        previous = []
        for t in reversed(ts[:index]):
            if t[3] in {';', '{', '}'}: break
            previous.append(t[3])
        kind = ('unresolved_asm_token' if not parsed else 'register_binding_candidate'
                if 'register' in previous else 'extended_asm_candidate' if has_sections else 'basic_or_macro_asm_candidate')
        row = {'project':project, 'version':version, 'sourcePath':path,
               'sourceDigest':'sha256:'+sha(raw), 'beginByte':begin, 'endByte':stop,
               'startLine':raw.count(b'\n',0,begin)+1, 'endLine':raw.count(b'\n',0,stop-1)+1,
               'sourceSliceDigest':'sha256:'+sha(raw[begin:stop]),
               'sourceSliceBase64':base64.b64encode(raw[begin:stop]).decode(),
               'syntaxKind':kind, 'asmSpelling':token[3], 'conditionalContext':context,
               'selectedByScope':selected,
               'scopeDisposition':'candidate_pending_compiler' if selected else 'other_architecture_branch',
               'activationStatus':'not_checked', 'eligibilityStatus':'not_assessed',
               'translationStatus':'not_run', 'validationStatus':'not_run',
               'semanticApproval':False, 'productionAcceptanceComplete':False}
        rows.append(sealed(row, 'siteIdentity'))
    return rows


def selected(path, scope):
    return path in scope['files'] or (path.endswith(scope['suffix']) and any(path.startswith(p) for p in scope['prefixes']))


def load_lock(root):
    value = json.loads((root/'sources.lock.json').read_text())
    if value.get('schemaVersion') != 'riscv2x86.real-project-sources.v1': raise ValueError('source lock schema invalid')
    if len({s['id'] for s in value['sources']}) != len(value['sources']): raise ValueError('duplicate source project')
    for source in value['sources']:
        if not re.fullmatch(r'[a-zA-Z0-9_-]+', source['id']): raise ValueError('unsafe project id')
        safe_path(source['archive']); safe_path(source['root'])
        if '/' in source['archive'] or not re.fullmatch(r'[0-9a-f]{64}',source['sha256']):
            raise ValueError('invalid archive identity')
        scope=source['scope']
        if scope['siteRule'] not in {'all_asm_syntax_sites','riscv_preprocessor_branch'}:
            raise ValueError('unrecognized scope rule')
        for name in scope['files']+source['supportFiles']+source['licenseFiles']:
            safe_path(name)
        for prefix in scope['prefixes']+source['licensePrefixes']:
            safe_path(prefix.rstrip('/'))
            if not prefix.endswith('/'): raise ValueError('scope prefix must end in slash')
    return value


def source_subset(archive, source):
    if sha(archive.read_bytes()) != source['sha256']: raise ValueError('upstream archive SHA256 mismatch: '+source['id'])
    files = {}; roles = {}; prefix = source['root']+'/'
    with tarfile.open(archive) as stream:
        for member in stream:
            if not member.name.startswith(prefix): continue
            path = member.name[len(prefix):]
            role = ('scope' if selected(path,source['scope']) else 'support' if path in source['supportFiles'] else
                    'license' if path in source['licenseFiles'] or any(path.startswith(p) for p in source['licensePrefixes']) else None)
            if role is None: continue
            safe_path(path)
            if member.isdir(): continue
            if not member.isfile(): raise ValueError('nonregular scoped archive entry: '+path)
            if path in files: raise ValueError('duplicate upstream file: '+path)
            files[path] = stream.extractfile(member).read(); roles[path] = role
    for path in source['scope']['files'] + source['supportFiles'] + source['licenseFiles']:
        if path not in files: raise ValueError('declared source/license missing: '+path)
    if not any(r=='scope' for r in roles.values()): raise ValueError('empty source scope')
    return files, roles


def archive_bytes(files):
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output,mode='wb',filename='',mtime=0) as compressed:
        with tarfile.open(fileobj=compressed,mode='w',format=tarfile.USTAR_FORMAT) as tar:
            for path, raw in sorted(files.items()):
                info = tarfile.TarInfo(path); info.size=len(raw); info.mode=0o644; info.mtime=0
                tar.addfile(info,io.BytesIO(raw))
    return output.getvalue()


def read_snapshot(path):
    files = {}
    with tarfile.open(path) as tar:
        for m in tar:
            safe_path(m.name)
            if not m.isfile() or m.name in files: raise ValueError('invalid snapshot member')
            files[m.name] = tar.extractfile(m).read()
    return files


def derive(files, roles, source):
    rows = []
    for path, raw in sorted(files.items()):
        if roles[path]=='scope':
            rows += inventory(raw,project=source['id'],version=source['version'],path=path,rule=source['scope']['siteRule'])
    return rows


def gzip_bytes(raw):
    output=io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as stream: stream.write(raw)
    return output.getvalue()


def index_bytes(rows):
    index = io.StringIO(); writer = csv.writer(index,delimiter='\t',lineterminator='\n')
    keys = ['siteIdentity','sourcePath','startLine','endLine','syntaxKind','scopeDisposition','activationStatus','translationStatus']
    writer.writerow(keys)
    for row in rows: writer.writerow([row[k] for k in keys])
    return index.getvalue().encode()


def counts(rows, roles):
    return {'scopeFiles':sum(r=='scope' for r in roles.values()), 'lexicalSites':len(rows),
            'selectedCandidates':sum(r['selectedByScope'] for r in rows),
            'otherArchitectureSites':sum(not r['selectedByScope'] for r in rows),
            'syntaxKinds':dict(sorted(Counter(r['syntaxKind'] for r in rows if r['selectedByScope']).items()))}


def write_project(root, source, files, roles):
    output = root/source['id']; output.mkdir()
    rows = derive(files,roles,source)
    payloads = {'sources.tar.gz':archive_bytes(files),
                'sites.jsonl.gz':gzip_bytes(b''.join(canonical(r)+b'\n' for r in rows)),
                'index.tsv':index_bytes(rows)}
    for name, raw in payloads.items(): (output/name).write_bytes(raw)
    body = {'schemaVersion':SCHEMA,'project':source['id'],'version':source['version'],'scannerVersion':SCANNER,
        'sourceLockIdentity':'sha256:'+sha(canonical(source)),
        'files':[{'path':p,'sha256':sha(raw),'bytes':len(raw),'role':roles[p]} for p,raw in sorted(files.items())],
        'artifacts':{p:{'sha256':sha(raw),'bytes':len(raw)} for p,raw in sorted(payloads.items())},
        'counts':counts(rows,roles),
        'rawScopeFileEnumerationComplete':True, 'compilerActivationComplete':False, 'runnableCorpusComplete':False,
        'semanticApproval':False,'productionAcceptanceComplete':False,
        'limitations':['lexical sites include macro definitions, inactive branches and register-binding candidates',
            'compiler preprocessing, macro expansion multiplicity, function/ABI/effect closure and runtime observations not established',
            'unresolved tokens retained; no eligibility or success inferred from syntax']}
    manifest = sealed(body,'manifestIdentity'); (output/'manifest.json').write_bytes(canonical(manifest)+b'\n')
    return manifest


def build(lock_root, archives, output):
    lock = load_lock(lock_root)
    if output.exists(): raise ValueError('output exists; refusing overwrite')
    output.mkdir(parents=True)
    (output/'sources.lock.json').write_bytes((lock_root/'sources.lock.json').read_bytes())
    projects = [write_project(output,s,*source_subset(archives/s['archive'],s)) for s in lock['sources']]
    body = {'schemaVersion':SCHEMA,'sourceLockIdentity':'sha256:'+sha(canonical(lock)),
        'projects':[{'id':p['project'],'version':p['version'],'manifestIdentity':p['manifestIdentity'],'counts':p['counts']} for p in projects],
        'activationStatus':'not_checked','translationStatus':'not_run',
        'semanticApproval':False,'productionAcceptanceComplete':False}
    (output/'catalog.json').write_bytes(canonical(sealed(body,'catalogIdentity'))+b'\n')


def verify(root, archives=None):
    lock = load_lock(root); catalog = json.loads((root/'catalog.json').read_text()); check_seal(catalog,'catalogIdentity')
    if catalog['sourceLockIdentity'] != 'sha256:'+sha(canonical(lock)): raise ValueError('source lock changed')
    projects=[]
    for source in lock['sources']:
        directory=root/source['id']; m=json.loads((directory/'manifest.json').read_text()); check_seal(m,'manifestIdentity')
        if (m.get('schemaVersion')!=SCHEMA or m.get('scannerVersion')!=SCANNER
                or m.get('project')!=source['id'] or m.get('version')!=source['version']
                or any(m.get(k) is not False for k in ('compilerActivationComplete','runnableCorpusComplete',
                    'semanticApproval','productionAcceptanceComplete'))
                or set(m['artifacts'])!={'sources.tar.gz','sites.jsonl.gz','index.tsv'}):
            raise ValueError('manifest scope, stages or artifact set invalid')
        if m['sourceLockIdentity'] != 'sha256:'+sha(canonical(source)): raise ValueError('project lock changed')
        for name, facts in m['artifacts'].items():
            safe_path(name); raw=(directory/name).read_bytes()
            if len(raw)!=facts['bytes'] or sha(raw)!=facts['sha256']: raise ValueError('artifact changed: '+name)
        files=read_snapshot(directory/'sources.tar.gz')
        expected={f['path']:f for f in m['files']}
        if len(expected)!=len(m['files']) or set(files)!=set(expected): raise ValueError('snapshot file set mismatch')
        for path, raw in files.items():
            if sha(raw)!=expected[path]['sha256'] or len(raw)!=expected[path]['bytes']: raise ValueError('source file changed')
        roles={p:f['role'] for p,f in expected.items()}
        if archives is not None:
            upstream_files, upstream_roles = source_subset(archives/source['archive'],source)
            if files != upstream_files or roles != upstream_roles:
                raise ValueError('snapshot differs from complete locked upstream scope')
        rows=derive(files,roles,source)
        persisted=[json.loads(line) for line in gzip.decompress((directory/'sites.jsonl.gz').read_bytes()).splitlines()]
        if canonical(rows)!=canonical(persisted): raise ValueError('candidate ledger differs from fresh scan')
        facts={'id':m['project'],'version':m['version'],'manifestIdentity':m['manifestIdentity'],'counts':m['counts']}
        if canonical(facts['counts'])!=canonical(counts(rows,roles)):
            raise ValueError('candidate counts mismatch')
        if (directory/'index.tsv').read_bytes()!=index_bytes(rows): raise ValueError('index differs from source ledger')
        projects.append(facts)
    if canonical(projects)!=canonical(catalog['projects']): raise ValueError('catalog project mismatch')
    return {'status':'verified-source-inventory','catalogIdentity':catalog['catalogIdentity'],
            'projects':projects,'upstreamArchiveReplayComplete':archives is not None, 'compilerActivationComplete':False,'semanticApproval':False,'productionAcceptanceComplete':False}


def materialize(root, output):
    result=verify(root)
    if output.exists(): raise ValueError('output exists; refusing overwrite')
    output.mkdir(parents=True)
    for source in load_lock(root)['sources']:
        project=output/source['id']; project.mkdir()
        for path, raw in read_snapshot(root/source['id']/'sources.tar.gz').items():
            dest=project/'upstream'/path; dest.parent.mkdir(parents=True,exist_ok=True); dest.write_bytes(raw)
        (project/'sites.jsonl').write_bytes(gzip.decompress((root/source['id']/'sites.jsonl.gz').read_bytes()))
        (project/'index.tsv').write_bytes((root/source['id']/'index.tsv').read_bytes())
    return result


def download(root, output):
    output.mkdir(parents=True,exist_ok=True); records=[]
    for source in load_lock(root)['sources']:
        dest=output/source['archive']
        if dest.exists():
            if sha(dest.read_bytes())!=source['sha256']: raise ValueError('existing archive digest mismatch')
            records.append({'project':source['id'],'path':str(dest),'cached':True}); continue
        failures=[]
        for url in source['urls']:
            try:
                with urllib.request.urlopen(url,timeout=60) as response: raw=response.read()
                if sha(raw)!=source['sha256']: raise ValueError('download digest mismatch')
                dest.write_bytes(raw); records.append({'project':source['id'],'url':url,'sha256':sha(raw)}); break
            except (OSError,ValueError) as exc: failures.append(url+': '+str(exc))
        else: raise ValueError('all downloads failed: '+json.dumps(failures))
    return records


def main():
    p=argparse.ArgumentParser(description=__doc__); sub=p.add_subparsers(dest='command',required=True)
    for name in ('verify','materialize','download','build'):
        command=sub.add_parser(name); command.add_argument('--corpus',type=Path,default=DEFAULT)
        if name!='verify': command.add_argument('--output',type=Path,required=True)
        if name in {'build','verify'}: command.add_argument('--archives',type=Path,required=name=='build')
    args=p.parse_args()
    try:
        if args.command=='verify': result=verify(args.corpus,args.archives)
        elif args.command=='materialize': result=materialize(args.corpus,args.output)
        elif args.command=='download': result=download(args.corpus,args.output)
        else:
            build(args.corpus,args.archives,args.output); result=verify(args.output,args.archives)
        print(json.dumps(result,ensure_ascii=False,indent=2)); return 0
    except (OSError,ValueError,KeyError,tarfile.TarError) as exc:
        print(json.dumps({'status':'failed','error':str(exc),'semanticApproval':False})); return 1


if __name__=='__main__': raise SystemExit(main())
