"""Bounded compiler-owned straight-line scalar dependency observations.

No control-flow, address, fixed-register or memory observer is inferred here.
The projection is a test variant, not an ordering/non-interference proof.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Mapping

from .l2_fragment_execution import (
    identity, fragment_boundary_from_dict, fragment_dependency_graph_from_dict,
)

SCHEMA = 'riscv2x86.scalar-program-observation-plan.v2'

from .l2_observer_shell import (
    assess_observer_shell, validate_observer_shell_decision,
)


class DependencyObserverError(ValueError):
    def __init__(self, reason, detail):
        self.reason_code = reason
        super().__init__(detail)


def compiler_observer_boundary(function, asm_nodes, *, source, source_digest,
                               function_identity, candidate_ids, source_range, walk):
    """Certify a bounded statement domain from compiler structure, never C regex."""
    bodies = [x for x in function.get('inner', []) if x.get('kind') == 'CompoundStmt']
    allowed = {'FunctionDecl', 'ParmVarDecl', 'CompoundStmt', 'DeclStmt', 'VarDecl',
               'GCCAsmStmt', 'ReturnStmt', 'DeclRefExpr', 'ImplicitCastExpr',
               'IntegerLiteral', 'BinaryOperator', 'UnaryOperator', 'ParenExpr',
               'CStyleCastExpr', 'ConstantExpr'}
    nodes = list(walk(function))
    reasons = []
    if (len(bodies) != 1 or any(x.get('kind') not in allowed for x in nodes)
            or any(x.get('kind') == 'UnaryOperator' and x.get('opcode') in {'&', '*', '++', '--'} for x in nodes)
            or any(any(t in str(x.get('type', {}).get('qualType', ''))
                       for t in ('volatile', '_Atomic', '*', '[')) for x in nodes)):
        reasons.append('L2_DEPENDENCY_OBSERVER_CONTROL_OR_MEMORY_UNSUPPORTED')
    direct = bodies[0].get('inner', []) if len(bodies) == 1 else []
    if any(not any(x is asm for x in direct) for asm in asm_nodes):
        reasons.append('L2_DEPENDENCY_OBSERVER_STATEMENT_PLACEMENT_UNSUPPORTED')
    points = []
    for asm in asm_nodes:
        for expression in asm.get('inner', []):
            while expression.get('kind') in {'ImplicitCastExpr', 'ParenExpr'}:
                children = expression.get('inner', [])
                if len(children) != 1:
                    break
                expression = children[0]
            if expression.get('kind') != 'DeclRefExpr':
                reasons.append('L2_DEPENDENCY_OBSERVER_OPERAND_EXPRESSION_UNSUPPORTED')
        bounds = source_range(asm)
        if not bounds:
            reasons.append('L2_DEPENDENCY_OBSERVER_RANGE_MISSING')
            continue
        begin, end = bounds
        # Clang's asm range excludes the statement's terminator. Accept only
        # an exact token boundary; macro expansions and unusual trivia reject.
        if source[end:end + 1] != b';':
            reasons.append('L2_DEPENDENCY_OBSERVER_RANGE_UNSUPPORTED')
            continue
        points.append({'candidateIdentity': candidate_ids[id(asm)],
                       'beforeOffset': begin, 'afterOffset': end + 1})
    payload = {'schemaVersion': 'riscv2x86.compiler-scalar-observer-boundary.v1',
               'sourceDigest': source_digest, 'functionIdentity': function_identity,
               'statements': points, 'complete': not reasons,
               'reasonCodes': sorted(set(reasons))}
    return {**payload, 'boundaryIdentity': identity(payload)}


def build_dependency_plan(report, function):
    facts = function.get('l2OperandBoundary', {})
    raw = facts.get('scalarObserverBoundary', {})
    if not isinstance(raw, Mapping) or raw.get('complete') is not True:
        raise DependencyObserverError('L2_DEPENDENCY_OBSERVER_BOUNDARY_UNAVAILABLE',
                                      'compiler has not approved a straight-line scalar observation domain')
    payload = {k: v for k, v in raw.items() if k != 'boundaryIdentity'}
    if (raw.get('boundaryIdentity') != identity(payload) or raw.get('sourceDigest') != function.get('sourceDigest')
            or raw.get('schemaVersion') != 'riscv2x86.compiler-scalar-observer-boundary.v1'):
        raise DependencyObserverError('L2_DEPENDENCY_OBSERVER_BOUNDARY_STALE', 'compiler observer boundary identity mismatch')
    findings = []
    for finding in report.get('findings', []):
        approval = finding.get('approvalArtifact', {})
        boundary = approval.get('l2FragmentOperandBoundary')
        if isinstance(boundary, Mapping) and boundary.get('functionId') == raw.get('functionIdentity'):
            findings.append(finding)
    points, graph_ids, edges = [], set(), {}
    compatibility = []
    statements = {x['candidateIdentity']: x for x in raw['statements']}
    for finding in findings:
        approval = finding['approvalArtifact']
        boundary = fragment_boundary_from_dict(approval['l2FragmentOperandBoundary'])
        graph = fragment_dependency_graph_from_dict(approval['l2FragmentDependencyGraph'])
        if (not boundary.complete or not graph.complete or approval.get('proofStatus') != 'approved'
                or approval.get('shellSemanticsPreserved') is not True
                or approval.get('architectureSemanticsPreserved') is not True):
            raise DependencyObserverError('L2_DEPENDENCY_OBSERVER_PROOF_UNAPPROVED', 'fragment/proof/graph is incomplete')
        graph_ids.add(graph.graph_identity)
        for edge in graph.edges:
            edges[identity(edge.to_dict())] = edge.to_dict()
        fragment = finding.get('fragment', {})
        operands = fragment.get('outputs', []) + fragment.get('inputs', [])
        if any(x.get('constraint') not in {'=r', '+r', 'r', '=&r', '+&r'} for x in operands):
            raise DependencyObserverError('L2_DEPENDENCY_OBSERVER_CONSTRAINT_UNSUPPORTED', 'observer requires unconstrained scalar register carriers')
        candidates = [x for x in facts.get('fragmentCandidates', [])
                      if x.get('fragmentBindingKey', {}).get('beginOffset') == finding.get('rewriteBeginOffset')]
        if len(candidates) != 1 or candidates[0].get('candidateIdentity') not in statements:
            raise DependencyObserverError('L2_DEPENDENCY_OBSERVER_RANGE_MISMATCH', 'report/AST statement join is not unique')
        statement = statements[candidates[0]['candidateIdentity']]
        if finding.get('rewriteEndOffset') != statement['afterOffset']:
            raise DependencyObserverError('L2_DEPENDENCY_OBSERVER_RANGE_MISMATCH', 'rewrite extent differs from compiler statement')
        decision = assess_observer_shell(finding, raw, boundary, graph, statement)
        decision_payload = decision.to_dict()
        if not decision.supported:
            error = DependencyObserverError(decision.reason_codes[0],
                'observer shell obligations are not closed: ' + ','.join(decision.reason_codes))
            error.compatibility_decision = decision_payload
            raise error
        try:
            validate_observer_shell_decision(decision_payload)
        except ValueError as exc:
            error = DependencyObserverError('L2_OBSERVER_SHELL_COMPATIBILITY_INVALID', str(exc))
            error.compatibility_decision = decision_payload
            raise error from exc
        compatibility.append(decision_payload)
        for binding in boundary.output_bindings + boundary.input_bindings:
            declaration = facts.get('declarations', {}).get(binding.declaration_identity, {})
            name = declaration.get('name', '')
            if not re.fullmatch(r'[A-Za-z_]\w*', name) or binding.width_bits not in {8, 16, 32, 64}:
                raise DependencyObserverError('L2_DEPENDENCY_OBSERVER_DECLARATION_UNSUPPORTED', 'scalar declaration/type authority missing')
            for phase in (('pre', 'post') if binding.access == 'read_write' else
                          ('pre',) if binding.access == 'input' else ('post',)):
                point = {'fragmentId': boundary.fragment_id,
                         'valueNodeIdentity': binding.value_node_identity,
                         'declarationIdentity': binding.declaration_identity,
                         'declarationName': name, 'operandIndex': binding.operand_index,
                         'widthBits': binding.width_bits, 'phase': phase,
                         'offset': statement['beforeOffset' if phase == 'pre' else 'afterOffset'],
                         'proofIdentity': approval.get('proofIdentity', ''),
                         'boundaryIdentity': boundary.boundary_identity}
                points.append({**point, 'pointIdentity': identity(point)})
    if (len(graph_ids) != 1 or not edges
            or set(graph.fragment_ids) != {p['fragmentId'] for p in points}):
        raise DependencyObserverError('L2_DEPENDENCY_OBSERVER_GRAPH_MISMATCH', 'one complete dependency graph is required')
    result = {'schemaVersion': SCHEMA, 'compilerBoundaryIdentity': raw['boundaryIdentity'],
              'sourceDigest': raw['sourceDigest'], 'graphIdentity': next(iter(graph_ids)),
              'points': sorted(points, key=lambda x: (x['offset'], x['pointIdentity'])),
              'edges': [edges[k] for k in sorted(edges)],
              'shellCompatibilityDecisions': sorted(compatibility, key=lambda x: x['fragmentId'])}
    plan = {**result, 'planIdentity': identity(result)}
    validate_plan_compatibility(plan, report)
    return plan


def materialize_pair(source: Path, target: Path, report, plan, work):
    if plan.get('schemaVersion') == SCHEMA:
        validate_plan_compatibility(plan, report)
    elif any(x.get('fragment', {}).get('clobbers') for x in report.get('findings', [])):
        raise DependencyObserverError('L2_OBSERVER_LEGACY_PLAN_CLOBBER_UNSUPPORTED',
                                      'legacy observer plans cannot authorize clobbers')
    original, translated = source.read_bytes(), target.read_bytes()
    from hashlib import sha256
    if plan['sourceDigest'] != 'sha256:' + sha256(original).hexdigest():
        raise DependencyObserverError('L2_DEPENDENCY_OBSERVER_SOURCE_STALE', 'source digest mismatch')
    if plan['planIdentity'] != identity({k: v for k, v in plan.items() if k != 'planIdentity'}):
        raise DependencyObserverError('L2_DEPENDENCY_OBSERVER_PLAN_STALE', 'observer plan identity mismatch')
    edits = []
    for finding in report.get('findings', []):
        replacement = finding.get('suggestedReplacement')
        if not replacement:
            replacement = finding.get('translationAttemptArtifact', {}).get('candidateReplacement')
        if isinstance(replacement, str) and replacement:
            edits.append((finding['rewriteBeginOffset'], finding['rewriteEndOffset'], replacement.encode()))
    edits.sort()
    if any(a[1] > b[0] for a, b in zip(edits, edits[1:])):
        raise DependencyObserverError('L2_DEPENDENCY_OBSERVER_TARGET_MAPPING_INVALID', 'overlapping replacement extents')
    expected = original
    for begin, end, replacement in reversed(edits):
        expected = expected[:begin] + replacement + expected[end:]
    prefix = b''
    if translated != expected:
        if not translated.endswith(expected):
            raise DependencyObserverError('L2_DEPENDENCY_OBSERVER_TARGET_MAPPING_INVALID', 'target is not exact approved replacements')
        prefix = translated[:-len(expected)]
        if not all(x.startswith(b'#include <') and x.endswith(b'>') for x in prefix.rstrip(b'\n').splitlines()):
            raise DependencyObserverError('L2_DEPENDENCY_OBSERVER_TARGET_MAPPING_INVALID', 'target prefix is unapproved')
    inserts = {}
    for point in plan['points']:
        inserts.setdefault(point['offset'], []).append(point)
    src, dst = original, translated
    for offset in sorted(inserts, reverse=True):
        target_offset = len(prefix) + offset + sum(len(r) - (e - b) for b, e, r in edits if e <= offset)
        call = ''.join('\n__r2x_l2_dependency("' + x['pointIdentity'] + '",(unsigned long long)(' +
                       x['declarationName'] + '));\n' for x in inserts[offset]).encode()
        src = src[:offset] + call + src[offset:]
        dst = dst[:target_offset] + call + dst[target_offset:]
    declaration = b'extern void __r2x_l2_dependency(const char*,unsigned long long);\n'
    left, right = work / 'dependency-source.c', work / 'dependency-target.c'
    left.write_bytes(declaration + src); right.write_bytes(declaration + dst)
    return left, right


def parse_dependency_trace(stdout, plan, expected_samples):
    if plan.get('schemaVersion') == SCHEMA:
        validate_plan_compatibility(plan)
    points = {x['pointIdentity']: x for x in plan['points']}
    samples, current = [], {}
    for line in stdout.splitlines():
        if line.startswith('dependency_trace;'):
            fields = line.split(';')
            if len(fields) != 3 or fields[1] not in points or fields[1] in current or not re.fullmatch('[0-9a-f]{16}', fields[2]):
                raise DependencyObserverError('L2_DEPENDENCY_TRACE_EVENT_INVALID', 'unknown/duplicate/malformed dependency event')
            if fields[1] != list(points)[len(current)]:
                raise DependencyObserverError('L2_DEPENDENCY_TRACE_EVENT_ORDER_INVALID', 'event order differs from compiler observation plan')
            current[fields[1]] = int(fields[2], 16) & ((1 << points[fields[1]]['widthBits']) - 1)
        elif line.startswith('operand_trace='):
            if set(current) != set(points):
                raise DependencyObserverError('L2_DEPENDENCY_TRACE_EVENT_MISSING', 'sample does not contain every authorized point')
            samples.append(current); current = {}
    if current or len(samples) != expected_samples:
        raise DependencyObserverError('L2_DEPENDENCY_TRACE_SAMPLE_COUNT_MISMATCH', 'program/sample trace arity mismatch')
    values = {}
    for edge in plan['edges']:
        endpoints = []
        for fragment, node, phase in ((edge['producerFragmentId'], edge['valueNodeIdentity'], 'post'),
                                      (edge['consumerFragmentId'], edge['consumerValueNodeIdentity'], 'pre')):
            matches = [p for p in points.values() if (p['fragmentId'], p['valueNodeIdentity'], p['phase']) == (fragment, node, phase)]
            if len(matches) != 1:
                raise DependencyObserverError('L2_DEPENDENCY_TRACE_ENDPOINT_AMBIGUOUS', 'edge endpoint has no unique observation')
            endpoints.append(tuple(sample[matches[0]['pointIdentity']] for sample in samples))
        if endpoints[0] != endpoints[1]:
            raise DependencyObserverError('L2_DEPENDENCY_TRACE_RELATION_VIOLATED', 'observed source/target edge does not satisfy direct value flow')
        values[identity(edge)] = endpoints[0]
    return values, samples


def validate_plan_compatibility(plan, report=None):
    """Readback/replay cannot silently detach shell authorization from points."""
    try:
        if (plan.get('schemaVersion') != SCHEMA
                or plan.get('planIdentity') != identity({k: v for k, v in plan.items() if k != 'planIdentity'})):
            raise ValueError('program observation plan schema/identity mismatch')
        decisions = plan.get('shellCompatibilityDecisions')
        if not isinstance(decisions, list):
            raise ValueError('observer compatibility decisions missing')
        ids = [x['fragmentId'] for x in decisions]
        if len(ids) != len(set(ids)) or set(ids) != {x['fragmentId'] for x in plan['points']}:
            raise ValueError('observer compatibility fragment coverage mismatch')
        for decision in decisions:
            validate_observer_shell_decision(decision)
            if (decision['sourceDigest'] != plan['sourceDigest']
                    or decision['compilerBoundaryIdentity'] != plan['compilerBoundaryIdentity']
                    or decision['graphIdentity'] != plan['graphIdentity']):
                raise ValueError('observer compatibility program binding mismatch')
            for point in plan['points']:
                if point['fragmentId'] != decision['fragmentId']:
                    continue
                offset = decision['sourceRange'][0 if point['phase'] == 'pre' else 1]
                if (point['offset'] != offset or point['proofIdentity'] != decision['proofIdentity']
                        or point['boundaryIdentity'] != decision['boundaryIdentity']
                        or point['pointIdentity'] != identity({k: v for k, v in point.items() if k != 'pointIdentity'})):
                    raise ValueError('observer compatibility point binding mismatch')
            if report is not None:
                matches = [x for x in report['findings'] if
                           (x.get('fragment', {}).get('id') or x.get('fragment', {}).get('fragmentId')) == decision['fragmentId']]
                if len(matches) != 1:
                    raise ValueError('observer compatibility finding join is ambiguous')
                finding = matches[0]
                approval = finding['approvalArtifact']
                boundary = fragment_boundary_from_dict(approval['l2FragmentOperandBoundary'])
                graph = fragment_dependency_graph_from_dict(approval['l2FragmentDependencyGraph'])
                recomputed = assess_observer_shell(finding,
                    {'sourceDigest': plan['sourceDigest'], 'boundaryIdentity': plan['compilerBoundaryIdentity']},
                    boundary, graph, {'beforeOffset': decision['sourceRange'][0],
                                      'afterOffset': decision['sourceRange'][1]}).to_dict()
                if recomputed != decision:
                    raise ValueError('observer compatibility differs from current report/proof')
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise DependencyObserverError('L2_OBSERVER_SHELL_COMPATIBILITY_INVALID', str(exc)) from exc
