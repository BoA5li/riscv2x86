"""Derive a conservative RV64 GNU C candidate view; never grant eligibility.

Excluded means outside this view, not deletion from the immutable source census.
Unknown preprocessing/configuration and unsupported instructions are retained.
"""
import argparse
import bisect
from collections import Counter, defaultdict
import gzip
import io
import json
from pathlib import Path
import re
import runpy
import tarfile

W = runpy.run_path(str(Path(__file__).resolve().with_name('whole_project_corpus.py')))
DEFAULT = Path(__file__).resolve().parent/'corpora/real-projects-rv64-c-v1'
SCHEMA = 'riscv2x86.rv64-c-candidate-view.v1'
CPP_SUFFIXES = ('.cc', '.cpp', '.cxx', '.C', '.c++')
CPP_HEADER_SUFFIXES = ('.hpp', '.hh', '.hxx', '.H', '.h++', '.ipp', '.tcc')
TEMPLATE_SUFFIXES = ('.c.in', '.h.in', '.def', '.c_shipped', '.h_shipped')
# These are declared immutable target constraints, NOT a compiler macro dump.
# Other macros, including undefined-looking CONFIG_* and __GNUC__, stay unknown.
FOREIGN_BUILTINS = ('__i386__', '__i386', 'i386', '__x86_64__', '__x86_64', '__amd64__',
    '__arm__', '__arm', '__aarch64__', '__mips__', '__mips', '__powerpc__', '__powerpc64__',
    '__ppc__', '__PPC__', '__s390__', '__s390x__', '__sparc__', '__sparc', '__alpha__',
    '__alpha', '__ia64__', '__m68k__', '__m88k__', '__hppa__', '__sh__', '__loongarch__')
PROFILE = {
    'schemaVersion': 'riscv2x86.candidate-selection-policy.v1',
    'language': 'GNU C', 'sourceIsa': 'RV64', 'march': 'rv64gc', 'abi': 'lp64d',
    'purpose': 'candidate filtering only; not proof of compiler activation or execution',
    'definedArchitectureFacts': {'__riscv': 1, '__riscv_xlen': 64},
    'undefinedArchitectureFacts': list(FOREIGN_BUILTINS),
    'unknownMacroPolicy': 'unknown, never assume zero or undefined',
    'namespacePolicy': 'upstream architecture source namespaces are not primary units for other target architectures',
    'instructionWhitelistUsed': False, 'compilerActivationComplete': False,
    'semanticApproval': False, 'productionAcceptanceComplete': False,
    'excludedCppTranslationUnitSuffixes': list(CPP_SUFFIXES),
    'cppStyleHeadersRequiringCInclusionProof': list(CPP_HEADER_SUFFIXES),
    'generatedSourceSuffixes': list(TEMPLATE_SUFFIXES),
}
REPOSITORY = Path(__file__).resolve().parents[1]
PROFILE['implementationDigests'] = {name: 'sha256:'+W['sha']((REPOSITORY/name).read_bytes()) for name in (
    'experiment/filter_rv64_c_corpus.py', 'experiment/whole_project_corpus.py',
    'experiment/real_project_corpus.py', 'pytools/riscv2x86_py/automatic_batch_cli.py',
    'pytools/riscv2x86_py/automatic_translation_command.py')}


def conjunction(a, b):
    if a == 0 or b == 0: return 0
    return None if a is None or b is None else 1


def disjunction(a, b):
    if a is not None and a != 0 or b is not None and b != 0: return 1
    return None if a is None or b is None else 0


def negate(a): return None if a is None else int(not a)


def evaluate(text, disabled=()):
    """Small, deliberately incomplete CPP integer evaluator. No eval().

    Arithmetic/bitwise results, unsigned literals and overflow stay unknown.
    Unsupported syntax or calls make the WHOLE expression unknown. Never guess
    at C integer rules; logical short-circuiting of a parsed unknown is safe.
    """
    tokens = re.findall(r'defined\b|[A-Za-z_]\w*|0[xX][0-9a-fA-F]+[uUlL]*|\d+[uUlL]*|&&|\|\||==|!=|<=|>=|<<|>>|[^\s]', text)
    facts = dict.fromkeys(FOREIGN_BUILTINS, (False, 0))
    facts.update({k: (True, v) for k, v in PROFILE['definedArchitectureFacts'].items()})
    for name in disabled: facts.pop(name, None)
    position = 0
    precedence = {'||':1,'&&':2,'|':3,'^':4,'&':5,'==':6,'!=':6,'<':7,'>':7,'<=':7,'>=':7,
                  '<<':8,'>>':8,'+':9,'-':9,'*':10,'/':10,'%':10}

    def take():
        nonlocal position
        if position >= len(tokens): raise ValueError('incomplete expression')
        token = tokens[position]; position += 1
        return token

    def atom():
        token = take()
        if token == '!': return negate(atom())
        if token in {'+','-','~'}: atom(); return None
        if token == '(':
            value = expression(1)
            if take() != ')': raise ValueError('unbalanced expression')
            return value
        if token == 'defined':
            name = take(); bracket = name == '('
            if bracket: name = take()
            if not re.fullmatch(r'[A-Za-z_]\w*', name): raise ValueError('invalid macro')
            if bracket and take() != ')': raise ValueError('invalid defined')
            return int(facts[name][0]) if name in facts else None
        if re.fullmatch(r'[A-Za-z_]\w*', token): return facts.get(token, (None, None))[1]
        if re.fullmatch(r'(?:0[xX][0-9a-fA-F]+|\d+)[uUlL]*', token):
            if 'u' in token.lower(): return None
            number = token.rstrip('lL')
            value = int(number, 16 if number.lower().startswith('0x') else 8 if len(number)>1 and number.startswith('0') else 10)
            return value if value < 2**63 else None
        raise ValueError('unsupported CPP expression')

    def expression(level):
        nonlocal position
        left = atom()
        while position < len(tokens) and precedence.get(tokens[position], 0) >= level:
            op = take(); right = expression(precedence[op] + 1)
            if op == '&&': left = conjunction(left, right)
            elif op == '||': left = disjunction(left, right)
            elif op not in {'==','!=','<','>','<=','>='}: left = None
            elif left is None or right is None: left = None
            else:
                left = int({'==': left == right, '!=': left != right, '<': left < right,
                            '>': left > right, '<=': left <= right, '>=': left >= right}[op])
        return left
    try:
        value = expression(1)
        return (None if value is None else int(value != 0)) if position == len(tokens) else None
    except (ValueError, IndexError): return None


COMMENTS = re.compile(rb'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*', re.S)


def conditional_spans(raw):
    """Map raw offsets to tri-state guards. Malformed stacks never exclude."""
    data, offsets = W['V1']['splice'](raw)
    def strip(match):
        text = match[0]
        if not text.startswith(b'/'): return text
        # Phase-3 comments are whitespace, including physical newlines inside
        # a block comment. Keep byte LENGTH so the phase-2 offset map survives.
        return b' '*len(text)
    clean = COMMENTS.sub(strip, data)
    disabled = {m[1].decode() for m in re.finditer(rb'^\s*#\s*(?:define|undef)\s+([A-Za-z_]\w*)', clean, re.M)}
    stack = []; state = 1; spans = []; offset = 0; malformed = False
    for line in clean.splitlines(keepends=True):
        directive = re.match(rb'[ \t]*#\s*([A-Za-z_]\w*)\b(.*)', line)
        kind = directive[1].decode() if directive else ''
        tail = directive[2].decode('ascii', errors='replace').strip() if directive else ''
        spans.append((offset, offset+len(line), state, kind == 'define'))
        if kind in {'if', 'ifdef', 'ifndef'}:
            test = tail if kind == 'if' else 'defined('+tail+')'
            value = evaluate(test, disabled)
            if kind == 'ifndef': value = negate(value)
            stack.append([state, value, False]); state = conjunction(state, value)
        elif kind == 'elif':
            if not stack or stack[-1][2]: malformed = True
            else:
                parent, previous, _ = stack[-1]; value = evaluate(tail, disabled)
                state = conjunction(parent, conjunction(negate(previous), value))
                stack[-1][1] = disjunction(previous, value)
        elif kind == 'else':
            if not stack or stack[-1][2] or tail: malformed = True
            else:
                parent, previous, _ = stack[-1]; state = conjunction(parent, negate(previous)); stack[-1][2] = True
        elif kind == 'endif':
            if not stack or tail: malformed = True
            else: state = stack.pop()[0]
        elif kind.startswith(('if', 'elif')): malformed = True
        offset += len(line)
    broken = malformed or bool(stack) or bool(re.search(rb'%:\s*(?:if|elif|else|endif)\b',clean))
    starts = [x[0] for x in spans]
    def lookup(raw_offset):
        logical_offset = bisect.bisect_left(offsets, raw_offset)
        i = bisect.bisect_right(starts, logical_offset)-1
        if i < 0: return None, False
        return (None if broken else spans[i][2]), spans[i][3]
    return lookup


def foreign_namespace(project, path):
    """Explicit project namespaces, not broad matching of 'arm' in filenames."""
    parts = path.split('/')
    if project == 'linux':
        for prefix in (['arch'], ['tools','arch'], ['tools','perf','arch'], ['tools','objtool','arch'],
                       ['tools','power'], ['tools','testing','selftests'],
                       ['tools','testing','selftests','kvm'], ['tools','testing','selftests','kvm','lib'],
                       ['tools','testing','selftests','kvm','include']):
            if parts[:len(prefix)] == prefix and len(parts)>len(prefix):
                arch = parts[len(prefix)]
                known = {'alpha','arc','arm','arm64','csky','hexagon','ia64','loongarch','m68k',
                         'microblaze','mips','nios2','openrisc','parisc','powerpc','riscv','s390',
                         'sh','sparc','um','x86','xtensa','x86_64','aarch64','s390x','sparc64','sparc32',
                         'i386','riscv64','riscv32'}
                if arch in known and arch not in {'riscv','riscv64'}: return '/'.join(prefix+[arch])
    elif project == 'musl':
        known = {'aarch64','arm','i386','loongarch64','m68k','microblaze','mips','mips64','mipsn32',
                 'or1k','powerpc','powerpc64','riscv32','riscv64','s390x','sh','x32','x86_64'}
        arch = parts[1] if len(parts)>2 and parts[0]=='arch' else parts[2] if len(parts)>3 and parts[0]=='src' else None
        if arch in known and arch != 'riscv64': return arch
    elif project == 'gmp' and len(parts)>2 and parts[0]=='mpn':
        known = {'alpha','arm','arm64','cray','ia64','loongarch','m68k','m88k','mips32','mips64',
                 'pa32','pa64','power','powerpc32','powerpc64','s390_32','s390_64','sh','sparc32',
                 'sparc64','thumb','vax','x86','x86_64'}
        if parts[1] in known: return 'mpn/'+parts[1]
        if parts[:3] == ['mpn','riscv','32']: return 'mpn/riscv/32'
    return None


def source_reason(project, path):
    if path.endswith(CPP_SUFFIXES): return 'OUTSIDE_GNU_C_LANGUAGE_SCOPE'
    if foreign_namespace(project, path): return 'OUTSIDE_RV64_SOURCE_NAMESPACE'
    return None


def empty_template(raw):
    data = W['logical'](raw); tokens = W['lex'](data)
    for i, token in enumerate(tokens):
        if token[3] != '(': continue
        j = i+1; quoted = []
        while j < len(tokens) and tokens[j][0] == 'quoted':
            quoted.append(data[tokens[j][1]:tokens[j][2]]); j += 1
        return bool(quoted) and all(x == b'""' for x in quoted) and j < len(tokens) and tokens[j][3] in {':',')'}
    return False


def read_rows(directory, artifacts, name):
    return [json.loads(line) for line in gzip.decompress(W['read_chunks'](directory, artifacts[name])).splitlines()]


def derive(source_root):
    W['verify'](source_root)
    catalog = json.loads((source_root/'catalog.json').read_text())
    projects = {}
    for source in W['read_lock'](source_root)['sources']:
        project = source['id']; directory = source_root/project
        manifest = json.loads((directory/'manifest.json').read_text()); artifacts = manifest['artifacts']
        snapshot = W['read_chunks'](directory, artifacts['sources.tar.gz'])
        with tarfile.open(fileobj=io.BytesIO(snapshot)) as tar:
            originals = {m.name: tar.extractfile(m).read() for m in tar if m.isfile()}
        rows = read_rows(directory, artifacts, 'sites.jsonl.gz')
        file_rows = read_rows(directory, artifacts, 'release-files.jsonl.gz')
        references = {r['sourcePath'] for r in read_rows(directory, artifacts, 'macro-references.jsonl.gz')}
        reviews = {r['path'] for r in read_rows(directory, artifacts, 'review-required.jsonl.gz')}
        guards = {}; decisions = []; groups = defaultdict(list); by_file = defaultdict(set)
        for row in rows:
            path = row['sourcePath']; reason = source_reason(project, path)
            if path not in guards: guards[path] = conditional_spans(originals[path])
            guard, macro = guards[path](row['beginByte'])
            if reason: status = 'excluded'
            elif guard == 0: status, reason = 'excluded', 'INACTIVE_UNDER_DECLARED_TARGET_GUARD'
            elif path.endswith(TEMPLATE_SUFFIXES): status, reason = 'review', 'GENERATED_SOURCE_ACTIVATION_REQUIRED'
            elif path.endswith(CPP_HEADER_SUFFIXES): status, reason = 'review', 'HEADER_C_TRANSLATION_UNIT_CONTEXT_REQUIRED'
            elif row['architectureHint'] == 'other-architecture-path-retained': status, reason = 'review', 'TARGET_ARCHITECTURE_CONFIRMATION_REQUIRED'
            elif row['syntaxKind'] == 'register-binding-candidate': status, reason = 'supporting', 'REGISTER_BINDING_NOT_INDEPENDENT_INSTRUCTION_TEST'
            elif row['syntaxKind'] == 'unresolved-asm-token': status, reason = 'review', 'COMPILER_SYNTAX_CLASSIFICATION_REQUIRED'
            elif empty_template(originals[path][row['beginByte']:row['endByte']]): status, reason = 'supporting', 'EMPTY_ASM_SEPARATE_COMPILER_SHELL_TEST'
            elif row['syntaxKind'] == 'basic-file-or-macro-asm-candidate': status, reason = 'review', 'BASIC_ASM_OR_ALIAS_REQUIRES_AST_CLASSIFICATION'
            elif guard is None: status, reason = 'review', 'CONDITIONAL_ACTIVATION_REQUIRED'
            else: status, reason = 'candidate', 'C_ASM_CANDIDATE_REQUIRES_COMPILER_ACTIVATION'
            decision = {'project': project, 'sourcePath': path, 'sourceDigest': row['sourceDigest'],
                'siteIdentity': row['siteIdentity'], 'beginByte': row['beginByte'], 'endByte': row['endByte'],
                'status': status, 'reasonCode': reason, 'guardTruthUnderPolicy': guard,
                'macroDefinition': macro, 'compilerActivationComplete': False,
                'eligibilityStatus': 'not_assessed', 'translationStatus': 'not_run', 'validationStatus': 'not_run',
                'semanticApproval': False, 'productionAcceptanceComplete': False}
            decisions.append(decision); by_file[path].add(status)
            if status != 'excluded': groups[status].append(row)
        file_decisions = []
        for row in file_rows:
            path = row['path']; reason = source_reason(project, path)
            if reason: status = 'excluded_as_primary'
            elif 'candidate' in by_file[path]: status, reason = 'candidate_source', 'HAS_RETAINED_C_ASM_CANDIDATE'
            elif 'review' in by_file[path]: status, reason = 'review_source', 'SYNTAX_OR_GENERATION_REVIEW_REQUIRED'
            elif row.get('fileKind') != 'c-cpp-or-header-template': status, reason = 'supporting_context', 'NOT_AN_INDEPENDENT_C_ASM_TEST'
            elif path in references or path in reviews: status, reason = 'review_source', 'MACRO_OR_TOKEN_PASTE_ACTIVATION_REQUIRED'
            else: status, reason = 'supporting_context', 'NO_ADMITTED_INDEPENDENT_ASM_SITE'
            file_decisions.append({'project': project, 'sourcePath': path,
                'sourceDigest': 'sha256:'+row['sha256'] if 'sha256' in row else None, 'sourceEntryType': row['entryType'],
                'status': status, 'reasonCode': reason, 'compilerActivationComplete': False,
                'semanticApproval': False, 'productionAcceptanceComplete': False})
        retained = {p: raw for p, raw in originals.items() if by_file[p] & {'candidate','review','supporting'}
                    or p in source['licenseFiles'] or any(p.startswith(prefix) for prefix in source['licensePrefixes'])}
        payload = {'site-decisions.jsonl.gz': W['gzip_bytes'](W['jsonl'](decisions)),
            'file-decisions.jsonl.gz': W['gzip_bytes'](W['jsonl'](file_decisions)),
            'candidate-sites.jsonl.gz': W['gzip_bytes'](W['jsonl'](groups['candidate'])),
            'review-sites.jsonl.gz': W['gzip_bytes'](W['jsonl'](groups['review'])),
            'supporting-sites.jsonl.gz': W['gzip_bytes'](W['jsonl'](groups['supporting'])),
            'sources.tar.gz': W['V1']['archive_bytes'](retained)}
        counts = {'sourceSites': len(rows), 'siteStatusCounts': dict(sorted(Counter(d['status'] for d in decisions).items())),
                  'siteReasonCounts': dict(sorted(Counter(d['reasonCode'] for d in decisions).items())),
                  'sourceFiles': len(file_rows), 'fileStatusCounts': dict(sorted(Counter(d['status'] for d in file_decisions).items())),
                  'retainedOriginalFiles': len(retained), 'compilerConfirmedTestInstances': 0}
        if sum(counts['siteStatusCounts'].values()) != len(rows): raise ValueError('site partition incomplete')
        projects[project] = (payload, counts)
    return catalog['catalogIdentity'], projects


def build(source_root, output):
    if output.exists(): raise ValueError('output exists')
    source_identity, projects = derive(source_root)
    output.mkdir(parents=True)
    policy = W['sealed'](PROFILE, 'policyIdentity')
    (output/'selection-policy.json').write_bytes(W['canonical'](policy)+b'\n')
    entries = []
    for project, (payload, counts) in projects.items():
        directory = output/project; directory.mkdir()
        artifacts = {name: W['write_chunks'](directory, name, data) for name, data in sorted(payload.items())}
        entries.append({'id': project, 'counts': counts, 'artifacts': artifacts})
    manifest = W['sealed']({'schemaVersion': SCHEMA, 'sourceCatalogIdentity': source_identity,
        'policyIdentity': policy['policyIdentity'], 'projects': entries, 'compilerActivationComplete': False,
        'runnableCorpusComplete': False, 'semanticApproval': False, 'productionAcceptanceComplete': False}, 'viewIdentity')
    (output/'manifest.json').write_bytes(W['canonical'](manifest)+b'\n')


def verify(source_root, root):
    manifest = json.loads((root/'manifest.json').read_text()); W['V1']['check_seal'](manifest, 'viewIdentity')
    policy = json.loads((root/'selection-policy.json').read_text()); W['V1']['check_seal'](policy, 'policyIdentity')
    if policy != W['sealed'](PROFILE, 'policyIdentity') or manifest['policyIdentity'] != policy['policyIdentity']:
        raise ValueError('selection policy differs')
    if manifest['schemaVersion'] != SCHEMA or any(manifest[k] is not False for k in
            ('compilerActivationComplete','runnableCorpusComplete','semanticApproval','productionAcceptanceComplete')):
        raise ValueError('invalid schema or unearned acceptance')
    identity, projects = derive(source_root)
    if identity != manifest['sourceCatalogIdentity']: raise ValueError('source census changed')
    if [p['id'] for p in manifest['projects']] != list(projects): raise ValueError('project set differs')
    for project in manifest['projects']:
        payload, counts = projects[project['id']]
        if counts != project['counts'] or set(payload) != set(project['artifacts']): raise ValueError('partition differs')
        for name, expected in payload.items():
            actual = W['read_chunks'](root/project['id'], project['artifacts'][name])
            if gzip.decompress(actual) != gzip.decompress(expected): raise ValueError('derived data differs: '+name)
    return {'status': 'verified-rv64-c-candidate-partition', 'viewIdentity': manifest['viewIdentity'],
        'sourceCatalogIdentity': identity, 'projects': [{'id': p['id'], 'counts': p['counts']} for p in manifest['projects']],
        'compilerActivationComplete': False, 'compilerConfirmedTestInstances': 0,
        'semanticApproval': False, 'productionAcceptanceComplete': False}


def materialize(source_root, root, output):
    result = verify(source_root, root)
    if output.exists(): raise ValueError('output exists')
    output.mkdir(parents=True)
    manifest = json.loads((root/'manifest.json').read_text())
    for project in manifest['projects']:
        dest = output/project['id']; dest.mkdir()
        for name, record in project['artifacts'].items():
            data = W['read_chunks'](root/project['id'], record)
            if name == 'sources.tar.gz':
                with tarfile.open(fileobj=io.BytesIO(data)) as tar:
                    for member in tar:
                        if not member.isfile(): raise ValueError('unexpected source entry')
                        W['safe_path'](member.name); path = dest/'upstream'/member.name
                        path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(tar.extractfile(member).read())
            else: (dest/name.removesuffix('.gz')).write_bytes(gzip.decompress(data))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__); commands = parser.add_subparsers(dest='command', required=True)
    for name in ('build','verify','materialize'):
        command = commands.add_parser(name); command.add_argument('--source-corpus', type=Path, default=W['DEFAULT'])
        command.add_argument('--corpus', type=Path, default=DEFAULT)
        if name != 'verify': command.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'build': build(args.source_corpus,args.output); result = verify(args.source_corpus,args.output)
        elif args.command == 'materialize': result = materialize(args.source_corpus,args.corpus,args.output)
        else: result = verify(args.source_corpus,args.corpus)
        print(json.dumps(result, ensure_ascii=False, indent=2)); return 0
    except (OSError, ValueError, KeyError, tarfile.TarError) as exc:
        print(json.dumps({'status':'failed','error':str(exc),'semanticApproval':False})); return 1


if __name__ == '__main__': raise SystemExit(main())
