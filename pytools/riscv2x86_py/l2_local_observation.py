"""Compiler/proof-bound local scalar capture for the original L2 observer.

Pre-capture duplicates only direct, repeatable nonvolatile scalar reads. The
post observation requires an original, checked non-interference or
whole-statement observer-shell compatibility proof.
This is an isolated observation variant, never canonical machine coverage.
"""
import re
from .project_build_records import identity
from .native_external_providers import checked
from .l2_internal_value import internal_value_proof_facts_from_dict

SCHEMA = 'riscv2x86.local-operand-observation-plan.v1'


def compiler_boundary(function, asm_nodes, *, source, source_digest,
                      function_identity, candidate_ids, source_range, walk, declaration_identity=lambda x: x):
    parents = {}
    for node in walk(function):
        for child in node.get('inner', []): parents[id(child)] = node
    points = []
    for asm in asm_nodes:
        reasons = []
        parent = parents.get(id(asm), {})
        if parent.get('kind') != 'CompoundStmt':
            reasons.append('L2_LOCAL_OBSERVER_COMPOUND_STATEMENT_REQUIRED')
        expressions = []
        for expression in asm.get('inner', []):
            while expression.get('kind') in {'ImplicitCastExpr', 'ParenExpr'} and len(expression.get('inner', [])) == 1:
                expression = expression['inner'][0]
            if expression.get('kind') != 'DeclRefExpr':
                reasons.append('L2_LOCAL_OBSERVER_DIRECT_DECLARATION_REQUIRED')
            expressions.append((expression.get('referencedDecl') or {}).get('id', ''))
        bounds = source_range(asm)
        if bounds is None or source[bounds[1]:bounds[1]+1] != b';':
            reasons.append('L2_LOCAL_OBSERVER_EXACT_STATEMENT_RANGE_REQUIRED')
        body = {'candidateIdentity': candidate_ids[id(asm)],
            'beginOffset': bounds[0] if bounds else -1, 'endOffset': bounds[1]+1 if bounds else -1,
            'directDeclarationCount': len(expressions), 'complete': not reasons,
            'declarationIdentities': [declaration_identity(x) for x in expressions],
            'reasonCodes': sorted(set(reasons))}
        points.append(dict(body, siteIdentity=identity(body)))
    body = {'schemaVersion': 'riscv2x86.compiler-local-observation-boundary.v1',
            'sourceDigest': source_digest, 'functionIdentity': function_identity, 'sites': points}
    return dict(body, boundaryIdentity=identity(body))


def plan(finding, function, canonical, *, base_sidecar=None):
    a = finding['approvalArtifact']; fragment = finding['fragment']
    raw = function['l2OperandBoundary'].get('localObserverBoundary')
    if not isinstance(raw, dict): raise ValueError('L2_LOCAL_OBSERVER_COMPILER_BOUNDARY_REQUIRED')
    checked(raw, 'boundaryIdentity')
    if (raw['sourceDigest'] != function['sourceDigest'] or raw['functionIdentity'] != function['functionId']
            or raw['schemaVersion'] != 'riscv2x86.compiler-local-observation-boundary.v1'):
        raise ValueError('L2_LOCAL_OBSERVER_COMPILER_BOUNDARY_MISMATCH')
    sites = [s for s in raw['sites'] if s['beginOffset'] == finding.get('rewriteBeginOffset')
             and s['endOffset'] == finding.get('rewriteEndOffset')]
    if len(sites) != 1: raise ValueError('L2_LOCAL_OBSERVER_SITE_NOT_UNIQUE')
    site = sites[0]; checked(site, 'siteIdentity')
    if not site['complete']: raise ValueError('L2_LOCAL_OBSERVER_SITE_UNSUPPORTED:' + ','.join(site['reasonCodes']))
    proof = a.get('l2InternalValueProofFacts')
    facts = internal_value_proof_facts_from_dict(proof) if isinstance(proof, dict) else None
    if facts is not None and (facts.fragment_id != fragment['id'] or not facts.complete or not facts.non_interference.complete):
        raise ValueError('L2_LOCAL_OBSERVER_NONINTERFERENCE_PROOF_INCOMPLETE')
    shell_decision = None
    if base_sidecar is not None:
        from .l2_fragment_execution import fragment_boundary_from_dict
        from .l2_observer_shell import assess_observer_shell
        from .l2_fragment_execution import fragment_dependency_graph_from_dict
        projected = {**finding, 'approvalArtifact': {**a, 'l2AuthoritySidecar': base_sidecar.to_dict(),
                                                    'shellFactsIdentity': base_sidecar.shell_fact_identity}}
        decision = assess_observer_shell(projected, raw,
            fragment_boundary_from_dict(a['l2FragmentOperandBoundary']),
            fragment_dependency_graph_from_dict(a['l2FragmentDependencyGraph']),
            {'beforeOffset': site['beginOffset'], 'afterOffset': site['endOffset']})
        if not decision.supported:
            raise ValueError('L2_LOCAL_OBSERVER_SHELL_PROOF_REJECTED:' + ','.join(decision.reason_codes))
        shell_decision = decision.to_dict()
    if facts is None and shell_decision is None:
        raise ValueError('L2_LOCAL_OBSERVER_NONINTERFERENCE_PROOF_REQUIRED')
    if fragment.get('clobbers') or fragment.get('hasAsmGoto'):
        raise ValueError('L2_LOCAL_OBSERVER_REGISTER_ONLY_SHELL_REQUIRED')
    boundary = a['l2FragmentOperandBoundary']; checked(boundary, 'boundaryIdentity')
    from .l2_fragment_execution import fragment_dependency_graph_from_dict
    graph = fragment_dependency_graph_from_dict(a['l2FragmentDependencyGraph'])
    if not graph.complete or graph.execution_mode == 'composite':
        raise ValueError('L2_LOCAL_OBSERVER_SHARED_DEPENDENCY_PLAN_REQUIRED')
    points = []; declarations = function['l2OperandBoundary']['declarations']
    operands = fragment['outputs'] + fragment['inputs']
    if site['directDeclarationCount'] != len(operands) or len(canonical) != len(operands):
        raise ValueError('L2_LOCAL_OBSERVER_OPERAND_PARTITION_MISMATCH')
    if site['declarationIdentities'] != [o.declaration_identity for o in canonical]:
        raise ValueError('L2_LOCAL_OBSERVER_DECLARATION_PARTITION_MISMATCH')
    from .l2_semantic_profile import profile_from_finding
    profile = profile_from_finding(finding)
    if (profile.pattern_kind.value not in {'scalar', 'composite'} or not profile.complete
            or profile.memory_shape.reads or profile.memory_shape.writes
            or profile.privileged_shape.present or profile.control_flow_shape.internal_branch
            or a.get('architectureSemanticsPreserved') is not True or a.get('shellSemanticsPreserved') is not True):
        raise ValueError('L2_LOCAL_OBSERVER_PURE_REGISTER_PROOF_REQUIRED')
    if any(o.get('constraint') not in {'=r', '=&r', 'r', '%r'} for o in operands):
        raise ValueError('L2_LOCAL_OBSERVER_REGISTER_CONSTRAINT_REQUIRED')
    from .gnu_operand_relations import derive
    relation = derive([o['constraint'] for o in fragment['outputs']], [o['constraint'] for o in fragment['inputs']])
    if relation['semanticCommutativityProofRequired']:
        from .operand_permutation_proof import consume, FIELD
        consume(a[FIELD], fragment, a)
    for operand in canonical:
        if operand.static_operand is not None or operand.access_mode == 'read_write':
            raise ValueError('L2_LOCAL_OBSERVER_OPERAND_ROLE_UNSUPPORTED')
        if operand.type_kind != 'integer' or operand.width_bits not in {8,16,32,64}:
            raise ValueError('L2_LOCAL_OBSERVER_INTEGER_REQUIRED')
        declaration = declarations[operand.declaration_identity]
        typ = declaration.get('canonicalType') or declaration.get('type', '')
        if re.search(r'\b(?:volatile|_Atomic)\b', typ):
            raise ValueError('L2_LOCAL_OBSERVER_NONVOLATILE_REQUIRED')
        name = declaration['name']
        if not re.fullmatch(r'[A-Za-z_]\w*', name): raise ValueError('L2_LOCAL_OBSERVER_DECLARATION_NAME_INVALID')
        expression = operands[operand.operand_index].get('compilerType') or {}
        if re.search(r'\b(?:volatile|_Atomic)\b', str(expression.get('qualifiers', ''))):
            raise ValueError('L2_LOCAL_OBSERVER_NONVOLATILE_REQUIRED')
        if (expression.get('sideEffectFree') is not True or expression.get('expressionRepeatable') is not True
                or operand.access_mode == 'output' and expression.get('modifiableLvalue') is not True):
            raise ValueError('L2_LOCAL_OBSERVER_REPEATABLE_EXPRESSION_REQUIRED')
        if facts is not None and operand.access_mode == 'output' and not any(p.operand_index == operand.operand_index
                and p.type_contract.width_bits == operand.width_bits and p.type_contract.signedness == operand.signedness
                for p in facts.points):
            raise ValueError('L2_LOCAL_OBSERVER_OUTPUT_PROOF_POINT_REQUIRED')
        points.append({'operandIndex': operand.operand_index, 'declarationIdentity': operand.declaration_identity,
            'declarationName': name, 'valueNodeIdentity': operand.value_node_identity,
            'phase': 'pre' if operand.access_mode == 'input' else 'post',
            'widthBits': operand.width_bits, 'signedness': operand.signedness})
    body = {'schemaVersion': SCHEMA, 'fragmentId': fragment['id'], 'sourceDigest': function['sourceDigest'],
        'functionIdentity': function['functionId'], 'site': site, 'boundaryIdentity': boundary['boundaryIdentity'],
        'proofIdentity': a['proofIdentity'], 'nonInterferenceFactsIdentity': facts.facts_identity if facts else '',
        'shellCompatibilityDecision': shell_decision,
        'compilerBoundaryIdentity': raw['boundaryIdentity'], 'points': points,
        # Keep the entire static use relation. A capture does not certify all
        # uses or effects; it never arbitrarily selects one fanout destination.
        'observationSinks': boundary['observationSinks'], 'valueFlowEdges': boundary['valueFlowEdges'],
        'scope': 'approved-local-capture-not-canonical-instruction-or-whole-callee-proof'}
    return dict(body, planIdentity=identity(body))


def authority(boundary, canonical, local_plan, *, proof_identity, graph_identity):
    from .l2_fragment_execution import L2OperandObservationAuthority, L2OperandObservationBinding
    checked(local_plan, 'planIdentity')
    if local_plan['boundaryIdentity'] != boundary.boundary_identity or local_plan['proofIdentity'] != proof_identity:
        raise ValueError('L2_LOCAL_OBSERVER_AUTHORITY_JOIN_MISMATCH')
    points = {p['operandIndex']: p for p in local_plan['points']}; bindings = []
    for o in canonical:
        p = points[o.operand_index]
        if p['declarationIdentity'] != o.declaration_identity or p['valueNodeIdentity'] != o.value_node_identity:
            raise ValueError('L2_LOCAL_OBSERVER_POINT_IDENTITY_MISMATCH')
        kw = dict(closure_kind='instrumentation', instrumentation_plan_identity=local_plan['planIdentity'],
                  observation_kind='instrumentation', parameter_index=o.parameter_index)
        bindings.append(L2OperandObservationBinding(o.fragment_id, o.operand_id, o.operand_index,
            o.declaration_identity, o.value_node_identity, o.access_mode,
            width_bits=o.width_bits, signedness=o.signedness, **kw))
    return L2OperandObservationAuthority(boundary.fragment_id, boundary.boundary_identity,
                                        proof_identity, graph_identity, tuple(bindings), True)


def materialize(source, target, report, finding, local_plan, work, *, readback=False):
    from .automatic_l2_operand import _emit
    from pathlib import Path
    checked(local_plan, 'planIdentity')
    left = Path(source).read_bytes(); right = Path(target).read_bytes()
    from hashlib import sha256
    if 'sha256:' + sha256(left).hexdigest() != local_plan['sourceDigest']:
        raise ValueError('L2_LOCAL_OBSERVER_SOURCE_CHANGED')
    edits = []
    for f in report['findings']:
        name = f.get('fileName') or f.get('file')
        replacement = f.get('suggestedReplacement') or (f.get('translationAttemptArtifact') or {}).get('candidateReplacement')
        if name and Path(name).resolve() == Path(source).resolve() and isinstance(replacement, str):
            edits.append((f['rewriteBeginOffset'], f['rewriteEndOffset'], replacement.encode()))
    edits.sort()
    if any(a[1] > b[0] for a,b in zip(edits, edits[1:])):
        raise ValueError('L2_LOCAL_OBSERVER_OVERLAPPING_EDITS')
    expected = left
    for begin,end,replacement in reversed(edits): expected = expected[:begin] + replacement + expected[end:]
    prefix = b''
    if expected != right:
        if not right.endswith(expected): raise ValueError('L2_LOCAL_OBSERVER_TARGET_MAPPING_CHANGED')
        prefix = right[:-len(expected)]
        if not prefix or not all(l.startswith(b'#include <') and l.endswith(b'>') for l in prefix.rstrip(b'\n').splitlines()):
            raise ValueError('L2_LOCAL_OBSERVER_TARGET_PREFIX_UNAPPROVED')
    site = local_plan['site']; begin,end = site['beginOffset'],site['endOffset']
    selected = [(b,e,r) for b,e,r in edits if b == begin and e == end]
    if len(selected) != 1: raise ValueError('L2_LOCAL_OBSERVER_SELECTED_EDIT_REQUIRED')
    delta = sum(len(r)-(e-b) for b,e,r in edits if e <= begin)
    tb = len(prefix)+begin+delta; te = tb+len(selected[0][2])
    pre = []; values = []
    suffix = local_plan['planIdentity'][7:23]
    for p in local_plan['points']:
        name = p['declarationName']
        value = '((unsigned long long)('+name+')&0x%016xULL)' % ((1 << p['widthBits']) - 1)
        if p['phase'] == 'pre':
            temp = '__r2x_pre_' + suffix + '_' + str(p['operandIndex'])
            pre.append('unsigned long long '+temp+'='+value+';')
            values.append(temp)
        else: values.append(value)
    pre = ('{\n'+'\n'.join(pre)+'\n').encode()
    post = ('\n__r2x_l2_observe('+str(len(values))+','+','.join(values)+');\n}\n').encode()
    declaration = b'extern void __r2x_l2_observe(unsigned,...);\n'
    paths = (Path(work)/'source-local.c', Path(work)/'target-local.c')
    for path,raw,b,e in ((paths[0],left,begin,end),(paths[1],right,tb,te)):
        _emit(path, declaration+raw[:b]+pre+raw[b:e]+post+raw[e:], readback)
    return paths


def parse_visits(text, function, arity, point_count, case_count):
    """Bind every dynamic visit to a harness case and ordinal; reject gaps."""
    from .automatic_l2_operand import _traces, _internal_traces
    boundary = _traces(text, function, arity, sample_count=case_count)
    if boundary is None: raise ValueError('L2_LOCAL_OBSERVER_ENTRY_PROTOCOL_INCOMPLETE')
    rows = []; values = []; visits = []; pending = [] ; case = 0
    for line in text.splitlines():
        if line.startswith('internal_trace;'): pending.append(line)
        if line.startswith('operand_trace=' + function + ';'):
            captured = _internal_traces('\n'.join(pending), point_count)
            if not captured: raise ValueError('L2_LOCAL_OBSERVER_CASE_NOT_OBSERVED')
            if case >= case_count: raise ValueError('L2_LOCAL_OBSERVER_EXTRA_CASE')
            for ordinal, capture in enumerate(captured):
                rows.append(boundary[case]); values.append(capture); visits.append((case, ordinal))
            case += 1; pending = []
    if pending or case != case_count: raise ValueError('L2_LOCAL_OBSERVER_UNBOUND_VISIT')
    return tuple(rows), tuple(values), tuple(visits)
