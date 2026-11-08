"""Real loader observations and explicit protocol-boundary audit fixtures."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from .test_native_captured_deployment import captured
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py import native_deployment_observation as obs
from riscv2x86_py import native_deployment_prerequisites as prereq
from riscv2x86_py.native_dynamic_obligations import inspect, describe
from riscv2x86_py.project_acquisition import publish


@pytest.fixture
def observed(captured):
    root, p, plan = captured
    d.execute(plan, root/'deployment', diagnostic_only=True)
    v = obs.observe(root/'deployment/result.json', root/'observation', diagnostic=True)
    return root, p, plan, v


@pytest.mark.parametrize('key,value', [
    ('diagnosticBindings', []), ('unparsedBindingLines', ['invented']),
    ('observedReturnCode', 99), ('testExecutionPerformed', False),
    ('diagnosticRunPerformed', False), ('naturalRunCompletedWithinBudget', False),
    ('runtimeBindingClosureComplete', True), ('commands', []),
    ('dynamicObligations', {}), ('unverifiedObjectBindings', ['invented']),
])
def test_full_rederivation_rejects_rehashed_report_changes(observed, key, value):
    root, _, _, v = observed
    v[key] = value
    path = root/'observation/result.json'
    path.write_text(json.dumps(d.seal({k:x for k,x in v.items() if k!='observationIdentity'}, 'observationIdentity')))
    with pytest.raises(ValueError, match='REDERIVATION_MISMATCH'):
        obs.check_observation(path)


def test_execution_receipt_is_required_and_stage_recipe_is_checked(observed):
    root, _, _, _ = observed
    path = root/'observation/natural/execution.json'; row = d.read(path)
    row['arguments'] = ['/different/program']
    path.write_text(json.dumps(d.seal({k:x for k,x in row.items() if k!='commandIdentity'}, 'commandIdentity')))
    with pytest.raises(ValueError, match='RECEIPT_INVALID'):
        obs.check_observation(root/'observation/result.json')


def test_old_observation_cannot_be_silently_upgraded(observed):
    root, _, _, v = observed; v['schemaVersion'] = 'riscv2x86.deployment-observation.v1'
    path = root/'observation/result.json'
    path.write_text(json.dumps(d.seal({k:x for k,x in v.items() if k!='observationIdentity'}, 'observationIdentity')))
    with pytest.raises(ValueError, match='LEGACY_RECEIPTS_MISSING'):
        obs.check_observation(path)


def test_observation_replay_reexecutes_and_does_not_approve_bindings(observed):
    root, _, _, _ = observed
    result = obs.replay_observation(root/'observation/result.json', root/'fresh-observation')
    assert result['naturalObservationReproduced']
    assert not result['runtimeBindingClosureComplete'] and not result['semanticApproval']
    assert obs.check_observation(root/'fresh-observation/run/result.json')


def test_namespace_pid_duplicate_and_label_objects_are_preserved():
    # Deliberately use an arbitrary label, not a vdso spelling whitelist.
    a = " 41: binding file kernel-object [2] to kernel-object [3]: normal symbol `clock' [ABI_1]"
    rows, syntax, unknown = obs.binding_events(a+'\n'+a+'\n 42: binding file malformed')
    assert len(rows) == 2 and len(syntax) == 1 and len(unknown) == 2
    assert rows[0]['processId'] == 41 and rows[0]['requesterNamespace'] == 2
    assert rows[0]['providerNamespace'] == 3
    assert rows[0]['requester']['kind'] == 'loader-label'
    assert not rows[0]['requester']['runtimeIdentityVerified']


def test_eager_binding_and_copy_storage_come_from_elf_not_symbol_names(tmp_path):
    cc = shutil.which('gcc')
    if not cc: pytest.skip('native GCC required')
    (tmp_path/'lib.c').write_text('int arbitrary_data = 5;')
    (tmp_path/'main.c').write_text('extern int arbitrary_data;int main(void){return arbitrary_data;}')
    lib = tmp_path/'libdata.so'; exe = tmp_path/'program'
    subprocess.run([cc,'-shared','-fPIC',str(tmp_path/'lib.c'),'-Wl,-soname,libdata.so','-o',str(lib)],check=True)
    subprocess.run([cc,'-fno-pic','-no-pie',str(tmp_path/'main.c'),str(lib),
                    '-Wl,-z,now','-Wl,-rpath,'+str(tmp_path),'-o',str(exe)],check=True)
    v = inspect([str(exe),str(lib)])
    assert v['objects'][0]['bindNowDeclared']
    copies = [r for r in v['copyRelocations'] if r['destinationSymbol']['name'] == 'arbitrary_data']
    assert len(copies) == 1
    row = copies[0]
    assert row['destinationAddressMatches'] and row['candidateSizesMatch']
    assert row['initializerDefinitionCandidates'][0]['providerPath'] == str(lib)
    assert row['destination']['path'] == str(exe)
    assert not row['actualInitializerSelectionVerified'] and not row['storageAndBehaviorContractVerified']


def test_no_audit_no_formal_deployment_and_no_root_outputs(captured):
    root, _, plan = captured
    with pytest.raises(ValueError, match='SUCCESSFUL_CANDIDATE_AUDIT_REQUIRED'):
        d.execute(plan, root/'formal')
    assert not (root/'formal').exists()
    for p in ('/candidate-audit', '/', '/deployment', '/deployment-plan.json'):
        with pytest.raises(ValueError, match='RESULT_PARENT_REQUIRED'):
            prereq.output_path(p)
    with pytest.raises(ValueError, match='MODE_INVALID'):
        d.execute(plan, root/'mixed', audit_path='unused', diagnostic_only=True)


def test_fake_boolean_audit_is_not_accepted(captured):
    root, _, plan = captured
    fake = root/'fake.json'; fake.write_text(json.dumps({'nativeCandidateIndependentAuditComplete': True}))
    with pytest.raises(ValueError):
        d.execute(plan, root/'formal', audit_path=fake)
    assert not (root/'formal').exists()


def test_artifact_bound_audit_gate_and_mismatch(captured, monkeypatch):
    """Exercise orchestration, not a mock proof of real cross-ISA translation."""
    from riscv2x86_py import native_project_translation as translation
    from riscv2x86_py import native_audit_evidence, project_native_binding
    root, p, plan = captured
    cpath = Path(plan['candidatePath']); c = d.read(cpath)
    bundle = root/'bundle.json'; bundle.write_text('{}')
    c.update(tools={}, bindingBundlePath=str(bundle), bindingBundleDigest=d.digest(bundle),
             bindingReplayBundlePath=str(bundle), bindingReplayBundleDigest=d.digest(bundle))
    c = d.seal({k:x for k,x in c.items() if k!='candidateIdentity'}, 'candidateIdentity')
    cpath.write_text(json.dumps(c))
    plan = d.prepare(cpath, plan['libraryRecords']['path'], plan['testRecords']['path'],
                     plan['requirements']['path'], environment=plan['environment'])
    def protocol_audit(candidate, output, timeout):
        output.mkdir(); (output/'rebuild').mkdir()
        (output/'rebuild/candidate.json').write_text(json.dumps(candidate))
        result = {'nativeCandidateIndependentAuditComplete': True,
                  'candidateIdentity': candidate['candidateIdentity'], 'proofScope': 'protocol-fixture',
                  'comparisonPolicy': translation.AUDIT_POLICY, 'semanticApproval': False,
                  'productionAcceptanceComplete': False}
        (output/'audit.json').write_text(json.dumps(result))
        publish(output/'run-status.json', {'status': 'complete', 'primaryFailure': None,
                'acquisitionComplete': True, 'auditPath': str(output/'audit.json'),
                'comparisonPolicy': translation.AUDIT_POLICY,
                'nativeCandidateIndependentAuditComplete': True, 'auditDigest': d.digest(output/'audit.json')})
        return result
    monkeypatch.setattr(translation, 'audit', protocol_audit)
    monkeypatch.setattr(native_audit_evidence, 'command_projection', lambda c: [])
    monkeypatch.setattr(project_native_binding, 'validate_artifacts', lambda b: None)
    result = prereq.audit(plan, root/'audit')
    receipt = result['auditPrerequisitePath']
    assert prereq.check(plan, receipt)['digest'] == d.digest(receipt)
    deployed = d.execute(plan, root/'formal', audit_path=receipt)
    assert deployed['deploymentMode'] == 'audited-local-candidate'
    assert d.check_result(root/'formal/result.json')
    assert not deployed['semanticApproval']
    value = d.read(receipt); value['candidateIdentity'] = 'different'
    Path(receipt).write_text(json.dumps(d.seal({k:x for k,x in value.items() if k!='auditPrerequisiteIdentity'},'auditPrerequisiteIdentity')))
    with pytest.raises(ValueError, match='PREREQUISITE_MISMATCH'):
        prereq.check(plan, receipt)


def test_optional_version_query_failure_is_recorded_not_promoted(observed, monkeypatch):
    root, _, _, _ = observed
    # The collection return code lives in its own execution receipt. Re-derive
    # after a controlled protocol change, without pretending the query worked.
    rp = root/'observation/loader-version/execution.json'; row = d.read(rp)
    row['returnCode'] = 127
    rp.write_text(json.dumps(d.seal({k:x for k,x in row.items() if k!='commandIdentity'},'commandIdentity')))
    parent = d.check_result(root/'deployment/result.json')
    result = obs.derive(root/'observation', d.read(root/'observation/execution-plan.json'), parent)
    assert not result['loaderCapabilities']['versionQuerySucceeded']
    assert result['loaderCapabilities']['listQuerySucceeded']
    assert not result['loaderCapabilities']['exactReleaseProven']


def test_unknown_receipt_fields_and_cli_prerequisite_are_rejected(observed):
    root, _, plan, _ = observed
    rp = root/'observation/natural/execution.json'; row = d.read(rp)
    row['approval'] = True
    rp.write_text(json.dumps(d.seal({k:x for k,x in row.items() if k!='commandIdentity'},'commandIdentity')))
    with pytest.raises(ValueError, match='RECEIPT_INVALID'):
        obs.check_observation(root/'observation/result.json')
    script = Path(__file__).resolve().parents[2]/'experiment/advance_native_closure.py'
    planfile = root/'external-plan.json'; planfile.write_text(json.dumps(plan))
    result = subprocess.run([sys.executable, str(script), 'deploy', '--plan', str(planfile),
                             '--output', str(root/'unexpected')], capture_output=True, text=True)
    assert result.returncode == 2 and '--audit' in result.stderr
    assert not (root/'unexpected').exists()
    result = subprocess.run([sys.executable, str(script), 'prepare', '--requirements', 'missing',
        '--library-records', 'missing', '--test-records', 'missing', '--output', '/plan.json'],
        capture_output=True, text=True)
    assert result.returncode == 2 and 'RESULT_PARENT_REQUIRED' in result.stderr


def test_v2_reports_keep_their_original_policy_and_new_runs_are_v3(observed):
    root, _, _, current = observed
    assert current['schemaVersion'] == 'riscv2x86.deployment-observation.v3'
    coverage = current['bindingEvidenceCoverage']
    assert coverage['endpointOccurrenceCount'] == 2 * len(current['diagnosticBindings'])
    assert not coverage['diagnosticEventsProveNaturalRunBindings']
    path = root/'observation/result.json'
    parent = d.check_result(current['deploymentPath'])
    legacy = obs.derive(path.parent, d.read(path.parent/'execution-plan.json'), parent, schema=obs.LEGACY)
    legacy['artifactDigests'] = current['artifactDigests']
    legacy = d.seal(legacy, 'observationIdentity')
    path.write_text(json.dumps(legacy))
    assert obs.check_observation(path) == legacy
    assert 'bindingEvidenceCoverage' not in legacy


def test_unknown_elf_relocation_keeps_timing_unknown_even_with_bind_now(tmp_path):
    import struct
    cc = shutil.which('gcc')
    if not cc: pytest.skip('native GCC required')
    source = tmp_path/'probe.c'; source.write_text('int unrelated_value = 3;')
    output = tmp_path/'probe.so'
    subprocess.run([cc, '-shared', '-fPIC', '-Wl,-z,now', str(source), '-o', str(output)], check=True)
    raw = bytearray(output.read_bytes())
    if struct.unpack_from('<H', raw, 18)[0] != 62:
        pytest.skip('x86-64 ELF required')
    section_offset = struct.unpack_from('<Q', raw, 40)[0]
    section_size, section_count = struct.unpack_from('<HH', raw, 58)
    for index in range(section_count):
        sec = struct.unpack_from('<IIQQQQIIQQ', raw, section_offset+index*section_size)
        if sec[1] == 4 and sec[5]:
            info = struct.unpack_from('<Q', raw, sec[4]+8)[0]
            struct.pack_into('<Q', raw, sec[4]+8, (info & ~0xffffffff) | 0x7fffffff)
            break
    else:
        pytest.fail('fixture contains no RELA section')
    output.write_bytes(raw)
    v = describe(output)
    assert v['bindNowDeclared']
    unknown = [r for r in v['relocationObligations'] if r['role'] == 'unsupported']
    assert len(unknown) == 1 and unknown[0]['bindingCanOccurBeforeCall'] is None
    assert not unknown[0]['behaviorContractVerified']
