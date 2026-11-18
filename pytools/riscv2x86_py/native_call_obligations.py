"""Occurrence-bound source call obligations; never machine/effect approval.

Only witnesses already checked by native_original_applicability.derive may be
passed here. A compiler query's result does not discharge its caller's ABI,
object, dependency, termination or canonical execution obligations.
"""
from .compiler_native_instance_binding import call_contexts, _nodes
from .native_integer_contracts import builtin_contract
from .project_build_records import identity
from .verification_session import measured


@measured('native-call-obligations.derive')
def derive(ast, records, raw, model, checked_answers):
    # Reuse the existing compiler declaration-family resolver, including its
    # recursion/indirect-call handling. No name-only target join is introduced.
    identities = {record.get('analysisInputIdentity') for record in records}
    if records and (len(identities) != 1 or any(not isinstance(i, str) or not i for i in identities)):
        raise ValueError('CALL_OBLIGATION_ANALYSIS_IDENTITY_REQUIRED')
    analysis_identity = next(iter(identities)) if identities else ''
    inventory = call_contexts(ast, {'records': records}, analysis_identity)
    functions = {f['functionContextIdentity']: f for f in inventory['functions']}
    selected = set()
    for root in inventory['asmOwningFunctionContexts']:
        selected.update(root['reachableFunctionContexts'])
    proofs = {}; seen_queries = set()
    nodes = {tuple(path): node for node, path, _ in _nodes(ast)}
    for answer in checked_answers:
        query = answer['query']; path = tuple(query['astPath'])
        if path in seen_queries:
            raise ValueError('CALL_OBLIGATION_DUPLICATE_QUERY_WITNESS')
        seen_queries.add(path)
        if answer['sourceAndTargetWitnessVerified'] is not True:
            continue
        call = nodes[path]
        actual = builtin_contract(call, model, lambda ref: ref)
        if (actual != query['contract'] or
                actual['operation'] != 'compiler-integer-literal-constant-query'):
            raise ValueError('CALL_OBLIGATION_QUERY_SUBJECT_MISMATCH')
        proofs[path] = answer
    # Source guard classification deliberately uses the same conservative
    # evaluator as instance applicability. Unknown/control-flow cases remain.
    from .native_original_applicability import facts
    subjects = [(fid, functions[fid], call) for fid in sorted(selected)
                for call in functions[fid]['calls']]
    guards = facts(ast, [{'instanceBindingIdentity': identity({
        'function': fid, 'callAstPath': call['astPath']}),
        'astPath': call['astPath'], 'functionAstPath': function['astPath']}
        for fid, function, call in subjects], raw, model, checked_answers)['instances']
    rows = []
    for (fid, function, call), guard in zip(subjects, guards):
        path = call['astPath']
        witnessed = tuple(path) in proofs
        row = {'functionContextIdentity': fid, 'callAstPath': path,
               'resolution': call['resolution'],
               'targetDeclaration': call['targetDeclaration'],
               'targetFunctionAstPath': call['targetFunctionAstPath'],
               'sourceGuardClassification': guard['sourceGuardClassification'],
               'guards': guard['guards'],
               'localQueryContractStatus': 'checked-source-target-witness' if witnessed else 'not-discharged',
               'queryWitnessIdentity': identity(proofs[tuple(path)]) if witnessed else None,
               'callEffectClosureVerified': False, 'machineAbiVerified': False}
        row['callObligationIdentity'] = identity(row)
        rows.append(row)
    # Historical inventory stays unchanged; this is an additional checked view.
    return {'schemaVersion': 'riscv2x86.source-call-obligations.v1',
            'contextInventoryIdentity': inventory['contextInventoryIdentity'],
            'analysisInputIdentity': analysis_identity,
            'selectedInstanceBindingIdentities': [r['instanceBindingIdentity'] for r in records],
            'rootCallObligations': inventory['asmOwningFunctionContexts'],
            'globalEffectCandidatePaths': inventory['globalEffectCandidatePaths'],
            'calls': rows, 'callSiteCount': len(rows),
            'sourceExcludedCallSiteCount': sum(r['sourceGuardClassification'] ==
                'excluded-under-compiler-query-contracts' for r in rows),
            'witnessedQueryCallSiteCount': sum(r['localQueryContractStatus'] ==
                'checked-source-target-witness' for r in rows),
            'scope': 'checked-source-call-classification-not-dependency-effect-ABI-or-runtime-closure',
            'semanticApproval': False, 'productionAcceptanceComplete': False}
