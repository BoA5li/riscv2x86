"""Real host GCC erasure experiments, not cross-ISA semantics fixtures."""
from copy import deepcopy
import os
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
import pytest

from riscv2x86_py import native_instance_erasure as e
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py import native_project_evaluation as p
from riscv2x86_py.schema import (Finding, AsmFragment, TranslationOutcome,
    ValidationOutcome, PublicationOutcome, make_translation_attempt_artifact, save_report)
from riscv2x86_py.translation_attempt import save_translation_attempt_archive, terminal_attempt_from_finding
from riscv2x86_py.candidate_materialization import materialize_candidate_tree


def experiment(tmp_path, active=False):
    cc = shutil.which('gcc')
    if not cc: pytest.skip('host GCC required')
    source = tmp_path/'source'; source.mkdir(); inp = source/'input.i'
    statement = '__asm__ volatile("nop")'
    raw = ('void exercise(void){if ('+str(int(active))+') '+statement+';}\n').encode()
    inp.write_bytes(raw); begin = raw.index(statement.encode()); end = begin+len(statement)
    physical = d.seal({'schemaVersion': 'riscv2x86.frozen-physical-edit-binding.v1',
        'source': d.snapshot(inp), 'findingIndex': 0, 'instanceBindingIdentity': 'instance',
        'physicalRange': [begin,end], 'statementDigest': e.bytes_identity(raw[begin:end])}, 'physicalEditBindingIdentity')
    finding = Finding(fileName='input.i', hasRewriteRange=True, rewriteBeginOffset=begin,
        rewriteEndOffset=end, rawSourceText=statement, physicalEditBinding=physical,
        fragment=AsmFragment(id='site', fileName='input.i', beginOffset=begin, endOffset=end, rawAsmText='nop'),
        translationOutcome=TranslationOutcome.EMITTED.value, validationOutcome=ValidationOutcome.FAILED.value,
        publicationOutcome=PublicationOutcome.WITHHELD.value)
    finding.translationAttemptArtifact = make_translation_attempt_artifact(
        fragment_id='site', candidate_kind='c', candidate_route='phase6f_rendered',
        candidate_replacement='do { __asm__ volatile("nop"); } while(0);',
        candidate_rule_name='phase6.lower_to_c', translation_outcome=TranslationOutcome.EMITTED,
        validation_outcome=finding.validationOutcome, publication_outcome=finding.publicationOutcome,
        reason_codes=('fixture-owned-original-translation-ingress',))
    report = tmp_path/'report.json'; archive = tmp_path/'archive.json'; manifest = tmp_path/'manifest.json'
    save_report([finding],str(report)); save_translation_attempt_archive((terminal_attempt_from_finding(finding,0),),archive)
    target = tmp_path/'target'
    # The test owns the native frontend/preparation ingress. Use the original
    # materializer, archive and manifest; no fake erasure checker/result.
    from unittest.mock import patch
    with patch('riscv2x86_py.candidate_materialization._source_path', return_value=inp):
        materialize_candidate_tree(source_root=source,staging_root=target,translated_report=report,
            attempt_archive=archive,manifest_output=manifest)
    translation = tmp_path/'translation.json'
    p.write(translation,{'report':d.snapshot(report),'candidateManifest':d.snapshot(manifest),'attemptArchive':d.snapshot(archive)})
    run = tmp_path/'run.json'; p.write(run,{'translation':d.snapshot(translation)})
    profile = {'compiler':d.snapshot(cc),'flags':['-x','cpp-output','-O2','-fPIC'],
        'environment':{'PATH':os.environ['PATH']},'directory':str(tmp_path)}
    spec = {'run':d.snapshot(run),'profiles':{s:{'compile':deepcopy(profile)} for s in ('source','target')},'timeoutSeconds':10}
    specpath = tmp_path/'spec.json'; p.write(specpath,spec)
    builds = {}
    for side, body in [('source',inp),('target',target/'input.i')]:
        obj = body.parent/'canonical.o'
        subprocess.run([cc,*profile['flags'],'-c',str(body),'-o',str(obj)],capture_output=True,check=True)
        builds[side] = {'input':d.snapshot(body),'object':d.snapshot(obj)}
    def verify():
        for b in builds.values():
            for ref in b.values(): d.verify_snapshot(ref)
        d.verify_snapshot(spec['run']); d.verify_snapshot(profile['compiler'])
    backend = SimpleNamespace(spec=spec,builds=builds,verify=verify,
        config={'typedProjectEntry':{'specPath':str(specpath)}},selected={'functionBindingIdentity':'function'})
    disposition = d.seal({'sourceConditionExcluded':True,'instanceBindingIdentities':['instance'],
        'fragmentId':'site','functionBindingIdentity':'function','project':d.snapshot(specpath)},'dispositionIdentity')
    return backend, d.read(report)['findings'][0], disposition


@pytest.mark.parametrize('active',[False,True])
def test_original_object_bytes_decide_erasure_not_source_exclusion_boolean(tmp_path,active,monkeypatch):
    backend,finding,disposition = experiment(tmp_path,active)
    result = e.inspect(backend,finding,disposition,tmp_path/'evidence')
    assert result['objectErasureInvariant'] is not active
    receipt = d.read(result['receipt']['path'])
    assert not receipt['machineEliminationVerified'] and not receipt['canonicalInstructionCoverageVerified']
    def forbidden(*a,**kw): raise AssertionError('readback ran compiler')
    monkeypatch.setattr(p,'command',forbidden)
    assert e.inspect(backend,finding,disposition,tmp_path/'evidence',readback=True)==result
    # Even a resealed compiler receipt cannot hide a changed original subject.
    finding = deepcopy(finding); finding['physicalEditBinding']['instanceBindingIdentity']='other'
    with pytest.raises(ValueError,match='PHYSICAL_INSTANCE'):e.inspect(backend,finding,disposition,tmp_path/'evidence',readback=True)


def test_readback_rejects_changed_variant_and_keeps_original_files(tmp_path):
    backend,finding,disposition = experiment(tmp_path)
    before = {r['input']['path']:Path(r['input']['path']).read_bytes() for r in backend.builds.values()}
    e.inspect(backend,finding,disposition,tmp_path/'evidence')
    variant = tmp_path/'evidence/source/input.i'; variant.write_bytes(variant.read_bytes()+b'\n')
    with pytest.raises(ValueError,match='MATERIALIZATION_CHANGED'):
        e.inspect(backend,finding,disposition,tmp_path/'evidence',readback=True)
    assert before=={name:Path(name).read_bytes() for name in before}


def test_original_mapping_covers_multiple_length_changes_and_header_prefix(tmp_path):
    from .test_candidate_materialization import _materialize
    from riscv2x86_py.translation_attempt import load_translation_attempt_archive
    source,inp,report,archive,target,_,manifest = _materialize(tmp_path)
    attempts = {a.artifact_id:a for a in load_translation_attempt_archive(archive).attempts}
    edit = manifest.edits[0].to_dict()
    spans = e.mapped_ranges(inp.read_bytes(),(target/'test.c').read_bytes(),[edit],attempts,edit['findingId'])
    assert spans['source']==[edit['beginOffset'],edit['endOffset']]
    assert (target/'test.c').read_bytes()[slice(*spans['target'])]==b'out = lhs + rhs;'
    changed = deepcopy(edit); changed['candidateReplacementDigest']='sha256:'+'0'*64
    with pytest.raises(ValueError,match='EDIT_BYTES'):e.mapped_ranges(inp.read_bytes(),(target/'test.c').read_bytes(),[changed],attempts,edit['findingId'])


def test_mapping_uses_all_preceding_edit_lengths_without_searching_repeated_text():
    source = b'AAA same BBB same CCC'
    target = b'AAA x BBB much_longer CCC'
    spans = [(4,8),(13,17)]; replacements = ['x','much_longer']
    edits = []; attempts = {}
    for i,((begin,end),replacement) in enumerate(zip(spans,replacements)):
        aid = str(i); fid = 'finding:'+str(i)
        edits.append({'findingId':fid,'attemptArtifactId':aid,'beginOffset':begin,'endOffset':end,
            'sourceSliceDigest':e.bytes_identity(source[begin:end]),
            'candidateReplacementDigest':e.bytes_identity(replacement.encode()),
            'beforeFileDigest':e.bytes_identity(source),'afterFileDigest':e.bytes_identity(target),'requiredHeaders':[]})
        attempts[aid] = SimpleNamespace(finding_id=fid,candidate_replacement=replacement)
    mapped = e.mapped_ranges(source,target,edits,attempts,'finding:1')
    assert mapped=={'source':[13,17],'target':[10,21]}
    # Wrong target bytes with the right lengths cannot be joined.
    with pytest.raises(ValueError,match='EDIT_BYTES'):
        e.mapped_ranges(source,target.replace(b'much_longer',b'other_value'),edits,attempts,'finding:1')
