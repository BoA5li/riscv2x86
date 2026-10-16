"""Pre-backend failures have a bound terminal artifact, not an archive error."""
from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys

import pytest
from riscv2x86_py import automatic_translation_command as command
from riscv2x86_py.automatic_batch_cli import _l2_operand_boundary_facts
from riscv2x86_py.compiler_fragment_closure import (
    close_compiler_fragment_candidate, CompilerOperandClosureError)
from riscv2x86_py.evaluation import CommandRecord, run_evaluation
from riscv2x86_py.translation_preflight import write_preflight_failure, read_preflight_failure
from riscv2x86_py.validation_status import ValidationStatus
from tests.test_evaluation_runner import _setup
from tests.test_automatic_batch_evaluation import _ast_range, _ast_ref


@pytest.mark.parametrize('expression', [
    {'kind':'IntegerLiteral', 'value':'7', 'type':{'qualType':'int'}},
    {'kind':'UnaryOperator', 'opcode':'*', 'inner':[_ast_ref('ptr', 34)]},
    {'kind':'ArraySubscriptExpr', 'inner':[_ast_ref('ptr',34), {'kind':'IntegerLiteral','value':'0'}]},
    {'kind':'MemberExpr', 'name':'member', 'inner':[_ast_ref('ptr',34)]},
    {'kind':'BinaryOperator', 'opcode':'+', 'inner':[_ast_ref('x',34), _ast_ref('y',35)]},
])
def test_unknown_expression_keeps_its_slot_and_does_not_shift_next_operand(expression):
    expression = {**expression, 'range':_ast_range(33,36)}
    function = {'kind':'FunctionDecl', 'name':'probe', 'range':_ast_range(0,100),
        'type':{'qualType':'void (uint64_t)'}, 'inner':[
            {'kind':'ParmVarDecl','id':'x','name':'x','range':_ast_range(1,3),'type':{'qualType':'uint64_t'}},
            {'kind':'VarDecl','id':'out','name':'out','range':_ast_range(4,6),'type':{'qualType':'uint64_t'}},
            {'kind':'GCCAsmStmt','range':_ast_range(20,50),
             'inner':[_ast_ref('out',30), expression, _ast_ref('x',38)]}]}
    boundary = _l2_operand_boundary_facts(function, source_digest='sha256:'+'1'*64,
        function_identity='sha256:'+'2'*64, source_file='/src/probe.c', source_bytes=b' '*101)
    candidate = boundary['fragmentCandidates'][0]
    assert [s['operandIndex'] for s in candidate['operandSlotFacts']['slots']] == [0,1,2]
    assert candidate['operandSlotFacts']['slots'][1]['complete'] is False
    assert candidate['asmOperandDeclarationIds'][1] == ''
    assert [c['operandIndex'] for c in candidate['operandCarriers']] == [0,2]
    assert boundary['asmOperandDeclarationIds'][1] == ''
    with pytest.raises(CompilerOperandClosureError) as caught:
        close_compiler_fragment_candidate(candidate,
            {'outputs':[{'constraint':'=r'}], 'inputs':[{'constraint':'r'},{'constraint':'r'}]},
            source_digest='sha256:'+'1'*64, function_identity='sha256:'+'2'*64)
    assert caught.value.incomplete
    assert caught.value.diagnostics['missingOperandIndexes'] == [1]
    assert caught.value.diagnostics['compilerOperandSlotCount'] == 3


@pytest.mark.parametrize('mutation', ['source','command','content','returncode','report'])
def test_preflight_rejects_stale_or_unbound_payload(tmp_path, mutation):
    source = tmp_path/'source.c'; source.write_text('void f(void) {}')
    report = tmp_path/'report.json'; argv = ['python','translator']
    write_preflight_failure(report, source, argv, stage='compiler_fragment_closure',
        reason_code='COMPILER_FRONTEND_OPERAND_ARITY_MISMATCH', exc=ValueError('arity mismatch'))
    assert read_preflight_failure(report, source, argv, 2)['backendExecuted'] is False
    if mutation == 'source': source.write_text('void g(void) {}')
    if mutation == 'command': argv = ['other-command']
    if mutation == 'returncode':
        with pytest.raises(ValueError): read_preflight_failure(report, source, argv, 1)
        return
    if mutation == 'report':
        other = tmp_path/'other.json'
        Path(str(other)+'.preflight.json').write_bytes(Path(str(report)+'.preflight.json').read_bytes())
        report = other
    if mutation == 'content':
        path = Path(str(report)+'.preflight.json'); value=json.loads(path.read_text())
        value['failureStage']='other'; path.write_text(json.dumps(value))
    with pytest.raises(ValueError): read_preflight_failure(report, source, argv, 2)


def test_evaluator_reports_preflight_root_reason_not_missing_archive(tmp_path):
    request, source, _ = _setup(tmp_path)
    Path(request.attempt_archive).unlink()
    request = replace(request, translation_command=('translator', '--report', '${TRANSLATED_REPORT}'))
    calls = []
    def execute(argv, work, timeout, phase):
        calls.append(phase)
        write_preflight_failure(request.translated_report, source/'case.c', argv,
            stage='compiler_fragment_closure', reason_code='COMPILER_FRONTEND_OPERAND_ARITY_MISMATCH',
            exc=CompilerOperandClosureError('arity mismatch',diagnostics={'missingOperandIndexes':[1]}))
        return CommandRecord(phase,tuple(argv),2,'','diagnostic',False,ValidationStatus.FAILED)
    result = run_evaluation(request, work_directory=tmp_path/'work', command_executor=execute)
    assert calls == ['translation']
    assert result['status'] == 'failed'
    assert 'evaluation.translation-attempt-archive-missing' not in result['reasonCodes']
    assert 'COMPILER_FRONTEND_OPERAND_ARITY_MISMATCH' in result['reasonCodes']
    failure = result['translationEvaluationLink']['preflightFailure']
    assert failure['diagnostics']['missingOperandIndexes'] == [1]
    assert failure['failureStage'] == 'compiler_fragment_closure'
    assert failure['backendExecuted'] is False


def test_stale_preflight_prevents_new_execution(tmp_path):
    request, source, _ = _setup(tmp_path)
    write_preflight_failure(request.translated_report, source/'case.c', ['old'],
        stage='compiler_inspection', reason_code='old-error', exc=ValueError('old'))
    request = replace(request, translation_command=('translator',))
    def execute(*args): pytest.fail('must not reuse an existing preflight artifact')
    result = run_evaluation(request, work_directory=tmp_path/'work',command_executor=execute)
    assert result['reasonCodes'] == ['evaluation.translation-preflight-artifact-stale']


def test_command_writes_preflight_before_backend_on_closure_conflict(tmp_path,monkeypatch):
    source=tmp_path/'source.c'; source.write_text('void f(void) {}')
    report=tmp_path/'translated.json'
    calls=[]
    def run(argv, **kwargs):
        calls.append(list(argv))
        if '-print-sysroot' in argv: return subprocess.CompletedProcess(argv,0,'/sysroot','')
        if '--analysis-only' in argv:
            (tmp_path/'raw_report.json').write_text('{"findings":[]}')
            return subprocess.CompletedProcess(argv,0,'','')
        pytest.fail('backend must not execute after conflicting authority')
    monkeypatch.setattr(command.subprocess,'run',run)
    monkeypatch.setattr(command,'inspect_entry_points',lambda _: (False,()))
    def reject(*args):
        raise CompilerOperandClosureError('arity mismatch',diagnostics={'frontendInputCount':2,'compilerOperandSlotCount':1})
    monkeypatch.setattr(command,'_inject_compiler_fragment_authority',reject)
    args=['translation','--frontend','/frontend','--source',str(source),'--source-root',str(tmp_path),'--report',str(report)]
    monkeypatch.setattr(sys,'argv',args)
    assert command.main() == 2
    failure=read_preflight_failure(report,source,[sys.executable,'-m','riscv2x86_py.automatic_translation_command',*args[1:]],2)
    assert failure['failureStage']=='compiler_fragment_closure'
    assert failure['diagnostics']['frontendInputCount']==2
    assert not Path(str(report)+'.attempts.json').exists()
    assert len(calls)==2


def test_incomplete_expression_is_recorded_without_crashing_injection(tmp_path):
    from tests.test_production_route_authority import _compiler_authority
    authority = _compiler_authority()
    candidate = authority['candidate']
    candidate['operandCarriers'] = candidate['operandCarriers'][:1]
    candidate['compilerStructureComplete'] = False
    candidate['operandSlotFacts'] = {'schemaVersion':'riscv2x86.compiler-operand-slots.v1',
        'expressionSlotCount':2, 'complete':False, 'slots':[
            {'operandIndex':0,'complete':True,'expressionKind':'DeclRefExpr'},
            {'operandIndex':1,'complete':False,'expressionKind':'UnaryOperator'}]}
    report=tmp_path/'raw.json'
    report.write_text(json.dumps({'findings':[{'fragment':{
        'id':'/tmp/source.c:7:3','outputs':[{'constraint':'+r'}], 'inputs':[{'constraint':'r'}]}}]}))
    function = {'sourceDigest':authority['sourceDigest'], 'functionId':authority['functionIdentity'],
                'l2OperandBoundary':{'fragmentCandidates':[candidate]}}
    command._inject_compiler_fragment_authority(report,tmp_path/'source.c',(function,))
    fragment=json.loads(report.read_text())['findings'][0]['fragment']
    assert fragment['compilerFragmentJoin']['disposition']=='rejected'
    assert fragment['compilerFragmentJoin']['reasonCode']=='COMPILER_OPERAND_EXPRESSION_AUTHORITY_INCOMPLETE'
    assert 'compilerFragmentAuthority' not in fragment


def test_invalid_preflight_is_precise_and_never_falls_back_to_archive_missing(tmp_path):
    request, source, _ = _setup(tmp_path)
    Path(request.attempt_archive).unlink()
    request=replace(request,translation_command=('translator',))
    def execute(argv, work, timeout, phase):
        write_preflight_failure(request.translated_report,source/'case.c',argv,
            stage='compiler_inspection', reason_code='preflight-failed', exc=ValueError('failure'))
        path=Path(request.translated_report+'.preflight.json')
        value=json.loads(path.read_text()); value['sourceDigest']='wrong'; path.write_text(json.dumps(value))
        return CommandRecord(phase,tuple(argv),2,'','',False,ValidationStatus.FAILED)
    result=run_evaluation(request,work_directory=tmp_path/'work',command_executor=execute)
    assert result['reasonCodes']==['evaluation.translation-preflight-artifact-invalid']
    assert result['translationEvaluationLink']['preflightFailure']['failureStage']=='preflight_ingress'


def test_success_exit_cannot_override_preflight_rejection(tmp_path):
    request, source, _ = _setup(tmp_path)
    Path(request.attempt_archive).unlink()
    request=replace(request,translation_command=('translator',))
    def execute(argv, work, timeout, phase):
        write_preflight_failure(request.translated_report,source/'case.c',argv,
            stage='compiler_inspection', reason_code='preflight-failed', exc=ValueError('failure'))
        return CommandRecord(phase,tuple(argv),0,'','',False,ValidationStatus.VERIFIED)
    result=run_evaluation(request,work_directory=tmp_path/'work',command_executor=execute)
    assert result['status']=='failed'
    assert result['reasonCodes']==['evaluation.translation-preflight-artifact-invalid']


def test_success_without_any_terminal_artifact_is_real_archive_failure(tmp_path):
    request, _, _ = _setup(tmp_path)
    Path(request.attempt_archive).unlink()
    request=replace(request,translation_command=('translator',))
    def execute(argv, work, timeout, phase):
        return CommandRecord(phase,tuple(argv),0,'','',False,ValidationStatus.VERIFIED)
    result=run_evaluation(request,work_directory=tmp_path/'work',command_executor=execute)
    assert result['reasonCodes']==['evaluation.translation-attempt-archive-missing']
