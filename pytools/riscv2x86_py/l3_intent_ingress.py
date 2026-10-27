"""Explicit reviewed-tool ingress for L3 experiment obligations.

This is an external semantic producer trust boundary, not a built-in inference
rule. Pinning a tool authenticates its identity, never proves its semantics.
Translation permission and experiment observations remain independently gated.
"""
import argparse
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import time

from .l3_intent_requirements import _hash, parse_l3_intent_profile
from .l3_provider_resolution import _binary_fingerprints

SCHEMA = 'riscv2x86.l3-intent-producer.v1'
TRUST = 'explicit-reviewed-external-semantic-producer'


def digest(path):
    return 'sha256:' + sha256(Path(path).read_bytes()).hexdigest()


def producer_manifest(source, command, review_basis, timeout=120):
    if not isinstance(command, (list, tuple)) or not command or any(not isinstance(x, str) or not x for x in command):
        raise ValueError('l3.intent.producer-command-invalid')
    value = {'schemaVersion': SCHEMA, 'sourceDigest': digest(source),
             'command': list(command), 'toolFingerprints': list(_binary_fingerprints(tuple(command))),
             'timeoutSeconds': timeout, 'trustPolicy': TRUST, 'reviewBasis': review_basis}
    value['producerIdentity'] = _hash({k: value[k] for k in
        ('command', 'toolFingerprints', 'trustPolicy', 'reviewBasis')})
    value['manifestIdentity'] = _hash(value)
    validate_manifest(value, source)
    return value


def validate_manifest(value, source):
    fields = {'schemaVersion', 'sourceDigest', 'command', 'toolFingerprints',
              'timeoutSeconds', 'trustPolicy', 'reviewBasis', 'producerIdentity', 'manifestIdentity'}
    if not isinstance(value, dict) or set(value) != fields or value['schemaVersion'] != SCHEMA:
        raise ValueError('l3.intent.producer-schema-invalid')
    command = value['command']
    if (not isinstance(command, list) or not command or
            any(not isinstance(x, str) or not x for x in command) or
            value['trustPolicy'] != TRUST or not isinstance(value['reviewBasis'], str) or
            not value['reviewBasis'].strip() or type(value['timeoutSeconds']) is not int or
            not 1 <= value['timeoutSeconds'] <= 3600):
        raise ValueError('l3.intent.producer-selection-invalid')
    if value['sourceDigest'] != digest(source):
        raise ValueError('l3.intent.source-stale')
    if value['manifestIdentity'] != _hash({k: v for k, v in value.items() if k != 'manifestIdentity'}):
        raise ValueError('l3.intent.manifest-stale')
    if value['producerIdentity'] != _hash({k: value[k] for k in
            ('command', 'toolFingerprints', 'trustPolicy', 'reviewBasis')}):
        raise ValueError('l3.intent.producer-identity-invalid')
    if value['toolFingerprints'] != list(_binary_fingerprints(tuple(command))):
        raise ValueError('l3.intent.producer-changed')


def translation_timeout(command, source, execution_timeout):
    """Give the enclosing translation enough time for its separately bound producer.

    This changes no build/program runner timeout or semantic prerequisite.
    The selected manifest is authenticated exactly as at producer invocation.
    """
    flag = '--l3-intent-producer'
    if flag not in command:
        return execution_timeout
    if command.count(flag) != 1 or command.index(flag) + 1 >= len(command):
        raise ValueError('l3.intent.producer-command-invalid')
    manifest = json.loads(Path(command[command.index(flag) + 1]).read_text())
    validate_manifest(manifest, source)
    return execution_timeout + manifest['timeoutSeconds']


def produce_intents(source, report, manifest_path, *, replay=False):
    """Run only after approval materialization; return a new report, never edit code."""
    from .mechanism_route_checks import compiler_bound_finding
    from .translation_attempt import load_translation_attempt_archive
    from .translation_artifact_binding import artifacts_from_report
    source, report, manifest_path = map(lambda p: Path(p).resolve(), (source, report, manifest_path))
    value = json.loads(manifest_path.read_text())
    validate_manifest(value, source)
    original = report.read_bytes()
    original_manifest = manifest_path.read_bytes()
    data = json.loads(original)
    archive = load_translation_attempt_archive(str(report) + '.attempts.json')
    artifacts = artifacts_from_report(report, archive)
    items = []
    prerequisite_refusals = []
    for index, finding in enumerate(data['findings']):
        fragment = finding.get('fragment') or {}
        fid = fragment.get('id', '')
        if not replay and (finding.get('l3IntentProfile') is not None or finding.get('l3IntentReceipt') is not None or finding.get('l3IntentDisposition') is not None):
            raise ValueError('l3.intent.preexisting-unreviewed-profile')
        artifact = artifacts.get(f'finding:{index}:{fid}')
        if artifact is None:
            continue  # No translation candidate is not authority to infer intent=none.
        bound, snapshot = compiler_bound_finding(source, report, fid)
        bound = {k: v for k, v in bound.items() if k not in {'l3IntentProfile', 'l3IntentReceipt', 'l3IntentDisposition'}}
        finding.pop('l3IntentProfile', None)
        finding.pop('l3IntentReceipt', None)
        finding.pop('l3IntentDisposition', None)
        if bound != finding:
            raise ValueError('l3.intent.compiler-binding-mismatch')
        if not artifact.effect_relation_set_identity:
            # No relation is not authority for intent=none. Publish a framework
            # precondition refusal so L2 requirements can still be classified.
            from .l3_intent_requirements import _unknown_profile
            profile = _unknown_profile(fid).to_dict()
            decision = {'schemaVersion':'riscv2x86.l3-intent-disposition.v1',
                'fragmentId':fid,'profileIdentity':profile['profileIdentity'],
                'status':'prerequisites_missing','reasonCodes':['l3.intent.effect-relation-required']}
            finding['l3IntentProfile']=profile
            finding['l3IntentDisposition']=dict(decision,dispositionIdentity=_hash(decision))
            prerequisite_refusals.append(fid)
            continue
        items.append({'findingIndex': index, 'finding': dict(finding),
                      'compilerFunctions': snapshot.get('functions', []),
                      'translationArtifact': artifact.to_dict() if hasattr(artifact, 'to_dict') else
                      asdict(artifact)})
    if not items and prerequisite_refusals:
        if not replay:
            transcript=report.with_name(report.name+'.l3-intent-production.json')
            with transcript.open('x') as stream:
                json.dump({'schemaVersion':'riscv2x86.l3-intent-prerequisite-refusal.v1',
                    'producerInvoked':False,'fragmentIds':prerequisite_refusals,
                    'sourceDigest':value['sourceDigest'],'semanticApproval':False},stream,indent=2)
        return data
    if not items:
        # Terminal upstream refusals do not need an experiment profile. Keep
        # their exact translation outcomes; unknown intent remains unproved.
        if data['findings'] and all(f.get('translationOutcome') in {'unsupported','failed','needs_route'} for f in data['findings']):
            return data
        raise ValueError('l3.intent.approved-candidates-unavailable')
    request = {'schemaVersion': 'riscv2x86.l3-intent-producer-request.v1',
               'sourcePath': str(source), 'sourceDigest': digest(source),
               'producerIdentity': value['producerIdentity'], 'candidates': items}
    request['requestIdentity'] = _hash(request)
    started = time.monotonic()
    try:
        completed = subprocess.run(value['command'], input=json.dumps(request, sort_keys=True),
            text=True, capture_output=True, timeout=value['timeoutSeconds'], check=False)
    except subprocess.TimeoutExpired as exc:
        tail = exc.stderr or ''
        if isinstance(tail, bytes):
            tail = tail.decode('utf-8', errors='replace')
        detail = {'reasonCode': 'l3.intent.producer-timed-out',
                  'failureStage': 'l3_intent_production',
                  'timeoutSeconds': value['timeoutSeconds'],
                  'elapsedSeconds': time.monotonic() - started,
                  'command': value['command'], 'stderrTail': tail[-8000:]}
        raise ValueError('l3.intent.producer-timed-out:' + json.dumps(detail, sort_keys=True)) from exc
    validate_manifest(value, source)
    if manifest_path.read_bytes() != original_manifest:
        raise ValueError('l3.intent.producer-modified-manifest')
    if report.read_bytes() != original:
        raise ValueError('l3.intent.producer-modified-input-report')
    if completed.returncode:
        raise ValueError('l3.intent.producer-failed:' + str(completed.returncode) + ':' + completed.stderr[-2000:])
    response = json.loads(completed.stdout)
    response_version=response.get('schemaVersion') if isinstance(response,dict) else None
    response_fields={'schemaVersion','requestIdentity','profiles'}
    if response_version=='riscv2x86.l3-intent-producer-response.v2': response_fields.add('dispositions')
    if (not isinstance(response, dict) or set(response) != response_fields or
            response_version not in {'riscv2x86.l3-intent-producer-response.v1','riscv2x86.l3-intent-producer-response.v2'} or
            response['requestIdentity'] != request['requestIdentity'] or not isinstance(response['profiles'], list) or
            (response_version.endswith('.v2') and not isinstance(response['dispositions'], list))):
        raise ValueError('l3.intent.producer-response-invalid')
    expected = {(item['finding']['fragment']['id']): item for item in items}
    if len(expected) != len(items):
        raise ValueError('l3.intent.duplicate-candidate-fragment')
    profiles = [parse_l3_intent_profile(p) for p in response['profiles']]
    if len(profiles) != len(expected) or {p.fragment_id for p in profiles} != set(expected):
        raise ValueError('l3.intent.producer-fragment-coverage-invalid')
    decisions={}
    for decision in response.get('dispositions',[]):
        from .l3_intent_requirements import validate_intent_disposition
        validate_intent_disposition(decision)
        fid=decision['fragmentId']
        if fid in decisions or fid not in expected: raise ValueError('l3.intent.disposition-coverage-invalid')
        decisions[fid]=decision
    for profile in profiles:
        item = expected[profile.fragment_id]
        artifact = artifacts[f"finding:{item['findingIndex']}:{profile.fragment_id}"]
        decision=decisions.get(profile.fragment_id)
        if decision is not None:
            if profile.complete or profile.intent_kind.value!='unknown' or decision['profileIdentity']!=profile.profile_identity:
                raise ValueError('l3.intent.disposition-profile-mismatch')
        elif not profile.complete:
            raise ValueError('l3.intent.incomplete-profile-without-disposition')
        if (profile.producer_identity != value['producerIdentity'] or
                profile.proof_identity != artifact.proof_identity or
                (profile.intent_kind.value != 'none' and
                 profile.approved_target_relation_identity != artifact.effect_relation_set_identity)):
            raise ValueError('l3.intent.producer-approval-binding-mismatch')
        finding = data['findings'][item['findingIndex']]
        finding['l3IntentProfile'] = profile.to_dict()
        if decision is not None: finding['l3IntentDisposition']=decision
        receipt = {'schemaVersion': 'riscv2x86.l3-intent-consumption.v1',
            'sourceDigest': value['sourceDigest'], 'profileIdentity': profile.profile_identity,
            'translationArtifactIdentity': artifact.identity, 'requestIdentity': request['requestIdentity'],
            'producerManifestPath': str(manifest_path), 'producerManifestDigest': digest(manifest_path),
            'trustPolicy': TRUST}
        finding['l3IntentReceipt'] = dict(receipt, receiptIdentity=_hash(receipt))
    for item in items:
        bound, _ = compiler_bound_finding(source, report, item['finding']['fragment']['id'])
        consumed = {k: v for k, v in item['finding'].items()
                    if k not in {'l3IntentProfile', 'l3IntentReceipt', 'l3IntentDisposition'}}
        bound = {k: v for k, v in bound.items() if k not in {'l3IntentProfile', 'l3IntentReceipt', 'l3IntentDisposition'}}
        if bound != consumed:
            raise ValueError('l3.intent.compiler-binding-changed')
    if replay:
        return data
    transcript = report.with_name(report.name + '.l3-intent-production.json')
    with transcript.open('x') as stream:
        json.dump({'schemaVersion': 'riscv2x86.l3-intent-production-transcript.v1',
                   'producerManifest': value, 'request': request, 'response': response,
                   'producerExecution': {'timeoutSeconds': value['timeoutSeconds'],
                       'elapsedSeconds': time.monotonic() - started,
                       'stderrTail': completed.stderr[-8000:]},
                   'semanticApproval': False}, stream, indent=2, ensure_ascii=False)
    return data


def validate_receipt(finding, artifact, source, report):
    receipt = finding.get('l3IntentReceipt')
    fields = {'schemaVersion', 'sourceDigest', 'profileIdentity', 'translationArtifactIdentity',
              'requestIdentity', 'producerManifestPath', 'producerManifestDigest', 'trustPolicy', 'receiptIdentity'}
    if (not isinstance(receipt, dict) or set(receipt) != fields or
            receipt['schemaVersion'] != 'riscv2x86.l3-intent-consumption.v1' or
            receipt['trustPolicy'] != TRUST or receipt['receiptIdentity'] !=
            _hash({k: v for k, v in receipt.items() if k != 'receiptIdentity'})):
        raise ValueError('l3.intent.receipt-missing-or-invalid')
    path = Path(receipt['producerManifestPath'])
    if digest(path) != receipt['producerManifestDigest']:
        raise ValueError('l3.intent.producer-manifest-changed')
    value = json.loads(path.read_text())
    validate_manifest(value, source)
    profile = parse_l3_intent_profile(finding['l3IntentProfile'], fragment_id=artifact.fragment_id)
    if (receipt['sourceDigest'] != digest(source) or receipt['profileIdentity'] != profile.profile_identity or
            receipt['translationArtifactIdentity'] != artifact.identity or
            profile.producer_identity != value['producerIdentity'] or profile.proof_identity != artifact.proof_identity or
            (profile.intent_kind.value != 'none' and profile.approved_target_relation_identity != artifact.effect_relation_set_identity)):
        raise ValueError('l3.intent.receipt-binding-mismatch')
    # Re-run the selected semantic producer against current compiler-bound
    # approval inputs. A rehashed profile/receipt is not semantic authority.
    replayed = produce_intents(source, report, path, replay=True)
    matches = [f for f in replayed['findings']
               if (f.get('fragment') or {}).get('id') == artifact.fragment_id]
    if len(matches) != 1 or matches[0].get('l3IntentProfile') != profile.to_dict() or matches[0].get('l3IntentReceipt') != receipt or matches[0].get('l3IntentDisposition') != finding.get('l3IntentDisposition'):
        raise ValueError('l3.intent.producer-replay-mismatch')
    return profile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--command-json', required=True)
    parser.add_argument('--review-basis', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    value = producer_manifest(args.source, json.loads(args.command_json), args.review_basis)
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
    print(json.dumps({'manifestPath': str(path.resolve()), 'semanticApproval': False}))


if __name__ == '__main__':
    main()
