"""Byte/AST-bound guard evidence for ORIGINAL candidates, never a translator.

Only typed integer literal compiler queries are witnessed. Unknown control flow,
queries and expressions remain unknown. Source exclusion does not prove machine
elimination or canonical instruction execution.
"""
import json
from pathlib import Path

from .verification_session import measured
from . import native_captured_deployment as d
from . import native_original_pipeline as route
from . import native_project_evaluation as project
from .native_context_bridge import validated_input
from .native_external_providers import checked
from .native_verifier_manifest import current, compare
from .project_acquisition import publish_checked
from .compiler_native_instance_binding import _nodes, byte_range
from .native_integer_contracts import builtin_contract, integer_type
from .native_instance_applicability import guard_value

SCHEMA = 'riscv2x86.original-source-applicability.v2'
_UNSTRUCTURED = {'GotoStmt', 'IndirectGotoStmt', 'LabelStmt', 'SwitchStmt', 'CaseStmt', 'DefaultStmt'}


@measured('native_original_applicability.context')
def context(spec_path):
    spec = project.check(spec_path)
    # project.check rederives freeze(), which checks this complete original
    # run graph. Re-read its exact snapshot, rather than recursively validating
    # the same graph a second time. Public checks still start from live inputs.
    d.verify_snapshot(spec['run']); run = d.read(spec['run']['path']); d.verify_snapshot(spec['run'])
    prepared = d.read(run['input']['path']); bundle = d.read(run['bundle']['path'])
    receipt = d.read(bundle['nativeInputReceiptPath']); native = validated_input(receipt)
    inventory = d.read(prepared['bindings']['path']); checked(inventory, 'bindingInventoryIdentity')
    translation = d.read(run['translation']['path']); manifest = d.read(translation['candidateManifest']['path'])
    selected = []
    for edit in manifest['edits']:
        if edit['relativePath'] != 'input.i': raise ValueError('APPLICABILITY_CPP_DOMAIN_REQUIRED')
        rows = [r for r in inventory['records']
                if r['physicalStatementRange'] == [edit['beginOffset'], edit['endOffset']]
                and r['statementDigest'] == edit['sourceSliceDigest']]
        selected.append(project.unique(rows, 'APPLICABILITY_EDIT_BINDING_REQUIRED'))
    if len({r['instanceBindingIdentity'] for r in selected}) != len(selected):
        raise ValueError('APPLICABILITY_DUPLICATE_EDIT')
    return spec, native['canonicalAst'], selected, native['inputBytes'], receipt['analysisInput']['dataModels']['native']


def obligations(ast, records, raw, model, *, collect_queries=True):
    nodes = {tuple(path): node for node, path, _ in _nodes(ast)}
    instances = []; queries = {}; unsafe_functions = {}
    def register(call, call_path):
        try:
            contract = builtin_contract(call, model, lambda ref: ref)
            if contract['operation'] != 'compiler-integer-literal-constant-query': return
            argument = call['inner'][1]
            span = byte_range(call, len(raw)); arg_span = byte_range(argument, len(raw))
            if not span[0] <= arg_span[0] < arg_span[1] <= span[1]: raise ValueError('QUERY_RANGE')
            typ = integer_type(argument, model)
            call_text = raw[span[0]:span[1]].decode('utf-8')
            arg_text = raw[arg_span[0]:arg_span[1]].decode('utf-8')
            probe = (f'_Static_assert(sizeof(({arg_text}))*__CHAR_BIT__=={typ["bits"]},"query width");\n'
                     f'_Static_assert((((__typeof__(({arg_text})))-1)<0)=={int(typ["signed"])},"query signedness");\n'
                     f'_Static_assert(({call_text})==1,"literal constant query");\n')
            if len(queries) >= 4096 and tuple(call_path) not in queries:
                raise OverflowError('APPLICABILITY_QUERY_OCCURRENCE_BUDGET_EXCEEDED')
            queries[tuple(call_path)] = {'astPath': list(call_path), 'contract': contract,
                'callRange': span, 'argumentRange': arg_span, 'probe': probe}
        except (KeyError, TypeError, ValueError):
            # Unsupported queries remain visible in the call inventory. No
            # query is guessed from source text or a reserved-looking name.
            pass
    for record in records:
        path = record['astPath']; fn = nodes.get(tuple(record['functionAstPath'] or []), {})
        owner = tuple(record['functionAstPath'] or [])
        if owner not in unsafe_functions:
            unsafe_functions[owner] = any(n.get('kind') in _UNSTRUCTURED for n, _, _ in _nodes(fn))
        unsafe = unsafe_functions[owner]
        guards = []
        for length in range(len(path)):
            prefix = path[:length]; node = nodes[tuple(prefix)]; branch = path[length]
            if (node.get('kind') != 'IfStmt' or node.get('hasInit') or node.get('hasVar')
                    or len(node.get('inner', [])) not in (2, 3) or branch not in (1, 2)):
                continue
            guards.append({'ifAstPath': prefix, 'branch': branch})
        instances.append({'instanceBindingIdentity': record['instanceBindingIdentity'],
                          'astPath': path, 'guards': guards, 'unstructuredControlFlow': unsafe})
    if collect_queries:
        # Use compiler declaration-family reachability, never a project name.
        from .compiler_native_instance_binding import call_contexts
        ids = {r['analysisInputIdentity'] for r in records}
        if len(ids) > 1: raise ValueError('APPLICABILITY_ANALYSIS_IDENTITY_MISMATCH')
        inventory = call_contexts(ast, {'records': records}, next(iter(ids), ''))
        required = {fid for root in inventory['asmOwningFunctionContexts']
                    for fid in root['reachableFunctionContexts']}
        owners = {tuple(r['functionAstPath']) for r in records if r['functionAstPath'] is not None}
        scope = owners | {tuple(f['astPath']) for f in inventory['functions']
                          if f['functionContextIdentity'] in required}
        for node, path, owner in _nodes(ast):
            if node.get('kind') == 'CallExpr' and tuple(owner or ()) in scope:
                register(node, path)
    return nodes, instances, [queries[k] for k in sorted(queries)]


def query_groups(queries):
    """Share exact typed literal probes only within this pinned project context.

    Every occurrence keeps its own AST/range/contract identity. Different
    spellings or types may produce extra groups; never merge by numeric value.
    """
    groups = {}; indices = []
    for query in queries:
        subject = {'contract': query['contract'], 'probe': query['probe']}
        key = d.identity(subject)
        if key not in groups:
            if len(groups) >= 256: raise ValueError('APPLICABILITY_QUERY_GROUP_BUDGET_EXCEEDED')
            groups[key] = {'groupIdentity': key, **subject, 'occurrenceAstPaths': []}
        groups[key]['occurrenceAstPaths'].append(query['astPath'])
        indices.append(key)
    return list(groups.values()), indices


def facts(ast, records, raw, model, answers):
    nodes, instances, _ = obligations(ast, records, raw, model, collect_queries=False)
    proofs = {tuple(q['query']['astPath']): {'contract': q['query']['contract']}
              for q in answers if q['sourceAndTargetWitnessVerified']}
    rows = []
    for instance in instances:
        excluded = False; guards = []
        for guard in instance['guards']:
            truth = None
            if not instance['unstructuredControlFlow']:
                try:
                    path = [*guard['ifAstPath'], 0]
                    truth = guard_value(nodes[tuple(path)], path, proofs, model)
                except (ValueError, KeyError, TypeError): pass
            unreachable = truth is not None and (truth if guard['branch'] == 2 else not truth)
            excluded |= unreachable
            guards.append({**guard, 'constantConditionValue': truth, 'branchExcluded': unreachable})
        rows.append({**instance, 'guards': guards,
                     'sourceGuardClassification': 'excluded-under-compiler-query-contracts' if excluded else 'unknown',
                     'canonicalMachineDisposition': 'unknown', 'canonicalInstructionExecutionVerified': False})
    return {'instances': rows, 'editedInstanceCount': len(rows),
            'sourceExcludedInstanceCount': sum(r['sourceGuardClassification'].startswith('excluded-') for r in rows),
            'canonicalInstructionCoverageVerified': False,
            'scope': 'typed-source-guards-under-pinned-compiler-profiles-not-machine-elimination'}


def argv(profile, probe):
    flags = list(profile['flags'])
    if flags[:2] != ['-x', 'cpp-output']: raise ValueError('APPLICABILITY_FROZEN_CPP_PROFILE_REQUIRED')
    return [profile['compiler']['path'], '-x', 'c', *flags[2:], '-Werror', '-fsyntax-only', str(probe)]


@measured('native_original_applicability.derive')
def derive(spec_path, root):
    spec, ast, records, raw, model = context(spec_path)
    _, _, queries = obligations(ast, records, raw, model)
    groups, membership = query_groups(queries); receipts = {}
    for i, group in enumerate(groups):
        folder = root / ('query-%06d' % i); probe = folder / 'query.c'
        if probe.read_bytes() != group['probe'].encode('utf-8'): raise ValueError('APPLICABILITY_PROBE_CHANGED')
        witnesses = {}; verified = True
        for side in ('source', 'target'):
            row = d.read(folder / side / 'execution.json')
            profile = spec['profiles'][side]['compile']
            if (row['arguments'] != argv(profile, probe) or row['environment'] != profile['environment']
                    or row['directory'] != profile['directory']):
                raise ValueError('APPLICABILITY_WITNESS_CONTEXT_MISMATCH')
            project.validate_execution_record(row)
            verified &= row['returnCode'] == 0 and row['failureReason'] is None
            witnesses[side] = {'execution': d.snapshot(folder / side / 'execution.json'),
                               'stdout': d.snapshot(folder / side / 'stdout.log'),
                               'stderr': d.snapshot(folder / side / 'stderr.log')}
        receipts[group['groupIdentity']] = {'probe': d.snapshot(probe), 'witnesses': witnesses,
            'sourceAndTargetWitnessVerified': verified}
    answers = [{'query': query, 'witnessGroupIdentity': key, **receipts[key]}
               for query, key in zip(queries, membership)]
    from .program_validation_obligations import original_layer_readiness
    from .native_call_obligations import derive as call_obligations
    return {'queries': answers, 'queryWitnessGroups': groups, 'callObligations': call_obligations(ast, records, raw, model, answers),
            'facts': facts(ast, records, raw, model, answers),
            'layerReadiness': original_layer_readiness(spec)}


def acquire(spec_path, output):
    spec, ast, records, raw, model = context(spec_path)
    root = Path(output).resolve(); root.mkdir()
    _, _, queries = obligations(ast, records, raw, model)
    groups, _ = query_groups(queries)
    for i, query in enumerate(groups):
        folder = root / ('query-%06d' % i); folder.mkdir()
        probe = folder / 'query.c'; probe.write_bytes(query['probe'].encode('utf-8'))
        for side in ('source', 'target'):
            profile = spec['profiles'][side]['compile']
            project.command(argv(profile, probe), profile['directory'], profile['environment'],
                            folder / side, spec['timeoutSeconds'])
    value = d.seal({'schemaVersion': SCHEMA, 'project': d.snapshot(spec_path), 'verifier': current(),
                    **derive(spec_path, root), 'semanticApproval': False, 'productionAcceptanceComplete': False},
                   'sourceApplicabilityIdentity')
    publish_checked(root / 'result.json', value, check)
    return value


@measured('native_original_applicability.check')
def check(path):
    path = Path(path).resolve(strict=True); value = d.read(path); checked(value, 'sourceApplicabilityIdentity')
    compare(value['verifier'], current()); d.verify_snapshot(value['project'])
    expected = d.seal({'schemaVersion': SCHEMA, 'project': value['project'], 'verifier': current(),
                      **derive(value['project']['path'], path.parent),
                      'semanticApproval': False, 'productionAcceptanceComplete': False}, 'sourceApplicabilityIdentity')
    if value != expected: raise ValueError('APPLICABILITY_REDERIVATION_MISMATCH')
    return value
