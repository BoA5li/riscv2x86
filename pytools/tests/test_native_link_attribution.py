"""Real bfd links, repeated archives, attribution, and forged receipts."""
from copy import deepcopy
import json
import subprocess
import pytest
from .test_native_link_evidence import candidate
from riscv2x86_py.native_link_evidence import request, build
from riscv2x86_py.native_link_attribution import acquire, derive, contributions
from riscv2x86_py.project_build_records import identity


def test_v2_repeated_archive_group_and_independent_attribution(candidate):
    p, cc, receipt = candidate
    subprocess.run(['ar', 'rcs', str(p/'support.a'), str(p/'main.o')], check=True)
    plan = [{'group':'start'}, {'file':str(p/'support.a')},
            {'file':str(p/'support.a')}, {'group':'end'}]
    req = request(receipt, 'target', cc, [], ordered_inputs=plan)
    assert len(req['inputs']) == 2
    out = p/'linked';out.mkdir();value = build(req, out)
    (out/'result.json').write_text(json.dumps(value))
    result = derive(value, out)
    assert result['candidateDefinitionAttributionVerified'], result['blockers']
    assert not result['actualLinkSelectionVerified']
    assert not result['typedCallContractVerified']
    again = p/'again';again.mkdir()
    assert acquire(out/'result.json', again)['independentLinkRebuildComplete']
    assert subprocess.run([str(out/'program')]).returncode == 7


def test_v2_plan_grammar_and_environment(candidate, monkeypatch):
    p, cc, receipt = candidate
    for plan in ([{'group':'end'}], [{'group':'start'}], [{'option':'--wrap=translated_entry'}],
                 [{'file':str(p/'main.o'), 'group':'start'}]):
        with pytest.raises(ValueError):request(receipt, 'target', cc, [], ordered_inputs=plan)
    with pytest.raises(ValueError, match='MIXED_INPUT'):
        request(receipt, 'target', cc, [p/'main.o'], ordered_inputs=[])
    monkeypatch.setenv('LIBRARY_PATH', '/nonexistent-injected-library')
    monkeypatch.setenv('GCC_EXEC_PREFIX', '/nonexistent-injected-prefix')
    out = p/'out';out.mkdir()
    value = build(request(receipt, 'target', cc, [], ordered_inputs=[{'file':str(p/'main.o')}]), out)
    assert value['linkEnvironment'] == {'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C'}


def test_changed_map_or_rehashed_claim_cannot_gain_attribution(candidate):
    p, cc, receipt = candidate;out = p/'out';out.mkdir()
    value = build(request(receipt, 'target', cc, [], ordered_inputs=[{'file':str(p/'main.o')}]), out)
    forged = deepcopy(value);forged['typedCallContractVerified'] = True
    forged['linkBuildIdentity'] = identity({k:v for k,v in forged.items() if k!='linkBuildIdentity'})
    (out/'result.json').write_text(json.dumps(forged));again = p/'again';again.mkdir()
    with pytest.raises(ValueError, match='REBUILD_RECEIPT_MISMATCH'):
        acquire(out/'result.json', again)
    (out/'link.map').write_text('changed')
    with pytest.raises(ValueError, match='ARTIFACT_CHANGED'):derive(value, out)


def test_map_parser_excludes_discarded_and_handles_wrapped_contributions():
    rows = contributions('Discarded input sections\n .text 0x0 0x10 bad.o\n'
        'Linker script and memory map\n .text.function\n  0x100 0x10 good.o\n')
    assert rows == [{'section':'.text.function','address':256,'size':16,'owner':'good.o'}]
    with pytest.raises(ValueError):contributions('unknown map format')
