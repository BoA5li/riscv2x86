"""Production joins and checkpoints; diagnostics never grant semantic authority."""
import json
from pathlib import Path
from types import SimpleNamespace
from .semantic_content import semantic_identity
from .time_trace_harness import digest


def source_build_compiler(providers):
    """Build the observed source DSO with the explicitly bound source compiler."""
    import shutil
    selected = set()
    for p in providers:
        if p['validatorType'] == 'controlled-time-validation':
            path = p['config']['sourceCompiler']
        elif p['validatorType'] == 'l2-instruction-visibility-harness':
            command = p['config']['sourceCommand']
            if command.count('--compiler') != 1:
                raise ValueError('MECHANISM_SOURCE_COMPILER_AMBIGUOUS')
            path = command[command.index('--compiler') + 1]
        else:
            continue
        resolved = Path(shutil.which(path) or path).absolute()
        if not resolved.is_file():
            raise ValueError('MECHANISM_SOURCE_COMPILER_MISSING')
        selected.add(str(resolved))
    if len(selected) != 1:
        raise ValueError('MECHANISM_SOURCE_COMPILER_CONFLICT')
    return selected.pop()


def execution_checkpoint(fragment_id, architecture, facts, state):
    """Report the execution-facts domain separately from the ISA catalogue."""
    from .route_authority import RouteAuthorityDecision
    accepted=bool(facts.complete and state.complete)
    payload={'architectureProfileIdentity':(architecture or {}).get('profileIdentity'),
        'sourceExecutionFactsIdentity':semantic_identity(facts),
        'sourceExecutionSchema':facts.schema_version,
        'executionFactsComplete':facts.complete,
        'accessPermissionsComplete':state.access_permissions_complete,
        'executionPrivilegeSpecVersion':facts.source_privilege_spec_version,
        'executionIsaExtensions':list(facts.source_isa_extensions),
        'controlledBackendIdentity':facts.user_counter_backend_identity,
        'accessEffects':[{'csrId':e.csr_id,'accessAllowed':e.access_allowed,
            'mayTrap':e.may_trap,'complete':e.complete} for e in state.csr_effects],
        'missingExecutionFactCodes':list(state.missing_fact_codes),
        'semanticApproval':False}
    return RouteAuthorityDecision('csr',fragment_id,'csr_execution_facts',
        'CSR_EXECUTION_FACTS_VALIDATED' if accepted else 'CSR_EXECUTION_FACTS_INCOMPLETE',
        'Execution facts are independent of static ISA interpretation and do not approve a lowering',
        semantic_identity(payload),accepted,payload).to_dict()


def require_suite_preserved(baseline, configured, selected_sources):
    """Compare the same source inventory and resolve selected cases via metadata."""
    baseline,configured=Path(baseline),Path(configured)
    before=json.loads((baseline/'batch-evaluation.json').read_text())
    after=json.loads((configured/'batch-evaluation.json').read_text())
    inventories=[json.loads(Path(str(p)+'-inventory','automatic-inventory.json').read_text())
                 for p in (baseline,configured)]
    fingerprints=[{x['sourceRelativePath']:(x['caseId'],x['sourceDigest']) for x in i['programs']}
                  for i in inventories]
    if (len(fingerprints[0])!=len(inventories[0]['programs'])
            or len(fingerprints[1])!=len(inventories[1]['programs'])
            or inventories[0]['sourceRoot']!=inventories[1]['sourceRoot']
            or fingerprints[0]!=fingerprints[1]):
        raise ValueError('CONFIGURED_SUITE_SOURCE_INVENTORY_CHANGED')
    expected={case for case,_digest in fingerprints[1].values()}
    if any({c['caseId'] for c in data['cases']}!=expected or len(data['cases'])!=len(expected)
           for data in (before,after)):
        raise ValueError('CONFIGURED_SUITE_CASE_INVENTORY_MISMATCH')
    verified={c['caseId'] for c in before['cases'] if c['status']=='verified'}
    current={c['caseId'] for c in after['cases'] if c['status']=='verified'}
    if verified-current:
        raise ValueError('CONFIGURED_SUITE_REGRESSION:'+','.join(sorted(verified-current)))
    selected=[]
    for source in selected_sources:
        source=Path(source).resolve()
        relative=source.relative_to(Path(inventories[1]['sourceRoot']).resolve()).as_posix()
        case_id,source_digest=fingerprints[1][relative]
        if digest(source)!=source_digest or case_id not in current:
            raise ValueError('CONFIGURED_SELECTED_ROUTE_NOT_VERIFIED:'+relative)
        selected.append(case_id)
    return {'schemaVersion':'riscv2x86.mechanism-suite-preservation.v1',
        'baselineVerifiedCases':sorted(verified),'configuredVerifiedCases':sorted(current),
        'selectedCases':selected,'sameSourceInventory':True}


def preparation_inputs(source, report, fragment_id, *, family):
    """Replay compiler provenance before using a snapshot to prepare a contract."""
    from .compiler_provenance import validate_compiler_snapshot, bind_compiler_provenance
    report = Path(report)
    data = json.loads(report.read_text())
    matches = [f for f in data.get('findings', [])
               if (f['fragment'].get('id') or f['fragment'].get('fragmentId')) == fragment_id]
    if len(matches) != 1:
        raise ValueError('MECHANISM_PREPARATION_FRAGMENT_AMBIGUOUS')
    finding = matches[0]
    source_digest = digest(source)
    if finding.get('sourceDigest') != source_digest:
        raise ValueError('MECHANISM_PREPARATION_SOURCE_STALE')
    snapshot = json.loads(report.with_name('compiler-candidates.json').read_text())
    candidates = validate_compiler_snapshot(snapshot)
    if snapshot['sourceDigest'] != source_digest:
        raise ValueError('MECHANISM_COMPILER_SNAPSHOT_SOURCE_MISMATCH')
    fragment = finding['fragment']
    authority = fragment.get('compilerFragmentAuthority') or {}
    if authority.get('sourceDigest') != source_digest:
        raise ValueError('MECHANISM_COMPILER_AUTHORITY_SOURCE_MISMATCH')
    candidate = authority.get('candidate') or {}
    original = candidates.get(candidate.get('candidateIdentity'))
    if original is None:
        raise ValueError('MECHANISM_COMPILER_CANDIDATE_NOT_IN_SNAPSHOT')
    from .compiler_fragment_closure import close_compiler_fragment_candidate
    closure_fragment = fragment
    embedded = candidate.get('expressionClosureInputs')
    if embedded is not None:
        if embedded.get('candidate') != original:
            raise ValueError('MECHANISM_COMPILER_CANDIDATE_PROVENANCE_MISMATCH')
        closure_fragment = embedded['fragment']
        if closure_fragment.get('id') != fragment_id:
            raise ValueError('MECHANISM_COMPILER_FRAGMENT_MISMATCH')
        for key in ('outputs', 'inputs'):
            before, after = closure_fragment[key], fragment[key]
            if (len(before) != len(after) or any(
                    any(item.get(k) != v for k,v in old.items())
                    for old,item in zip(before,after))):
                raise ValueError('MECHANISM_COMPILER_OPERAND_SHELL_MISMATCH')
    rebuilt = close_compiler_fragment_candidate(original, closure_fragment,
        source_digest=source_digest, function_identity=authority['functionIdentity'])
    if rebuilt != candidate:
        raise ValueError('MECHANISM_COMPILER_CANDIDATE_PROVENANCE_MISMATCH')
    operands = [SimpleNamespace(operand_index=b['operandIndex'],
        declaration_id=b['declarationIdentity'], value_node_identity=b['valueNodeIdentity'],
        access_mode=b['access'], width_bits=b['widthBits'], signedness=b['signedness'])
        for b in candidate.get('operandBindings', [])]
    bind_compiler_provenance(fragment, SimpleNamespace(fragment_id=fragment_id,
        operands=operands, authority_identity=authority.get('authorityIdentity')))
    key = 'compilerTimeReturnScope' if family == 'time' else 'compilerInstructionSyncScope'
    if family not in {'time', 'sync'}:
        raise ValueError('MECHANISM_FAMILY_UNSUPPORTED')
    functions = snapshot['functions']
    # These observers load an entire DSO. Additional C functions have no
    # established observation/non-interference contract in this route.
    if len(functions) != 1 or functions[0]['name'] != fragment.get('enclosingFunction'):
        raise ValueError('MECHANISM_PROGRAM_OBSERVATION_SCOPE_UNSUPPORTED')
    from .compiler_time_scope import validate_scope as time_scope
    from .compiler_instruction_sync_scope import validate_scope as sync_scope
    scope = (time_scope if family == 'time' else sync_scope)(
        functions[0].get(key), fragment, source_digest)
    return finding, scope


def require_consumed_approval(source, report, fragment_id, *, family, contract_path):
    """Replay the actual registry and approval, then compare the persisted receipt."""
    from .contract_consumption import consumption_receipt
    source = Path(source)
    report = Path(report)
    raw = json.loads(report.read_text())
    name = 'csr_environment' if family == 'time' else 'instruction_stream_sync'
    if family == 'time':
        from .csr_environment_contract import load_csr_environment_contract
        registry = load_csr_environment_contract(contract_path, source=source)
        kwargs = {'csr': registry}
    elif family == 'sync':
        from .instruction_stream_sync_contracts import load_instruction_stream_sync_registry
        registry = load_instruction_stream_sync_registry(contract_path, source_path=source)
        kwargs = {'sync': registry}
    else:
        raise ValueError('MECHANISM_FAMILY_UNSUPPORTED')
    rebuilt = consumption_receipt(source, raw, paths={name: contract_path}, **kwargs)
    actual = json.loads(report.with_name('contract-consumption.json').read_text())
    if (actual.get('receiptIdentity') != semantic_identity({k:v for k,v in actual.items() if k!='receiptIdentity'})
            or actual.get('sourceDigest') != digest(source)):
        raise ValueError('MECHANISM_CONSUMPTION_RECEIPT_INVALID')
    expected = rebuilt['records'][0]
    matches = [r for r in actual.get('records', []) if r.get('family') == name]
    if (len(matches) != 1 or matches[0] != expected or expected['disposition'] != 'consumed'
            or len(expected['consumptions']) != 1
            or expected['consumptions'][0]['fragmentId'] != fragment_id):
        raise ValueError('MECHANISM_APPROVAL_CONTRACT_NOT_CONSUMED')
    return expected


def checkpoints(source, report, *, family):
    """Separate static interpretation from execution facts without rewriting reasons."""
    from .csr_architecture_profile import load_profile
    from .route_authority import validate_route_decision
    report = Path(report)
    data = json.loads(report.read_text())
    if len(data.get('findings', [])) != 1:
        raise ValueError('MECHANISM_DIAGNOSTIC_REQUIRES_ONE_FRAGMENT')
    f = data['findings'][0]
    fid = f['fragment'].get('id') or f['fragment'].get('fragmentId')
    _, scope = preparation_inputs(source, report, fid, family=family)
    profile_path = report.with_name('csr-architecture.materialized.json')
    architecture = 'not_supplied'
    if profile_path.is_file():
        from .csr_architecture_profile import profiles_from_payload
        profiles = profiles_from_payload(load_profile(profile_path, source=source))
        if fid not in profiles:
            raise ValueError('MECHANISM_ARCHITECTURE_FRAGMENT_MISSING')
        architecture = 'bound'
    decisions = f.get('routeAuthorityDiagnostics', [])
    for d in decisions:
        validate_route_decision(d)
        if d['fragmentIdentity'] != fid:
            raise ValueError('MECHANISM_DIAGNOSTIC_FRAGMENT_MISMATCH')
    joins = [d for d in decisions if d['reasonCode'] == 'CSR_COMPILER_JOIN_COMPLETE' and d['accepted']]
    if family == 'time' and joins:
        from .prepare_time_trace import validate_static_join
        if len(joins) != 1 or not profile_path.is_file():
            raise ValueError('MECHANISM_DIAGNOSTIC_JOIN_AMBIGUOUS')
        validate_static_join(f, load_profile(profile_path, source=source), source=source)
    approval = f.get('approvalArtifact') or {}
    backend = (approval.get('proofPayload') or {}).get('backendContract') or {}
    payload = {'schemaVersion': 'riscv2x86.mechanism-route-checkpoints.v1',
        'sourceDigest': digest(source), 'fragmentId': fid, 'family': family,
        'architectureInterpretation': architecture,
        'compilerFragmentClosure': 'closed',
        'csrCompilerJoin': 'not_applicable' if family == 'sync' else 'closed' if joins else 'not_recorded',
        'staticCompilerJoin': 'not_applicable' if family == 'sync' else 'closed' if joins else 'not_recorded',
        'compilerScopeIdentity': scope['scopeIdentity'],
        'controlledExecutionContractIdentity': (backend.get('timeContract') or {}).get('contractIdentity'),
        'reportedApprovalStatus': approval.get('proofStatus', 'not_produced'),
        'reportedTranslationStatus': f.get('verificationStatus'),
        'blockingDecisions': [{'stage': d['failureStage'], 'reasonCode': d['reasonCode'],
            'details': d['inputsPayload']} for d in decisions if not d['accepted']],
        'diagnosticOnly': True, 'semanticApproval': False}
    return {**payload, 'checkpointIdentity': semantic_identity(payload)}


def main():
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--report',type=Path,required=True)
    p.add_argument('--family',choices=('sync','time'),required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    try:
        value=checkpoints(a.source,a.report,family=a.family)
        a.output.parent.mkdir(parents=True,exist_ok=True)
        with a.output.open('x') as stream:stream.write(json.dumps(value,indent=2)+'\n')
        print(json.dumps({'checkpointPath':str(a.output),'semanticApproval':False}));return 0
    except (OSError,ValueError,KeyError,TypeError,AttributeError) as exc:
        print(json.dumps({'failureStage':'mechanism_route_checkpoint','detail':str(exc),'semanticApproval':False}));return 2


if __name__=='__main__':raise SystemExit(main())
