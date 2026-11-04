"""Static target facts must never become execution or semantic approval."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import pytest

from riscv2x86_py.compiler_call_inventory import derive, closure, identity, inspect_source


def ranged(node, start=0):
    return dict(node, range={'begin': {'offset': start}, 'end': {'offset': start + 1, 'tokLen': 1}})


def function(name, calls=(), *, internal=False, attrs=()):
    return ranged({'id': name, 'kind': 'FunctionDecl', 'name': name,
        'type': {'qualType': 'unsigned long (unsigned long)'},
        **({'storageClass': 'static'} if internal else {}),
        'inner': [{'kind': a} for a in attrs] + [{'kind': 'CompoundStmt', 'inner': list(calls)}]})


def call(name, offset=0):
    target = {'kind': 'DeclRefExpr', 'referencedDecl': {'id': name, 'kind': 'FunctionDecl',
        'name': name, 'type': {'qualType': 'unsigned long (unsigned long)'}}}
    return ranged({'kind': 'CallExpr', 'inner': [{'kind': 'ImplicitCastExpr',
        'castKind': 'FunctionToPointerDecay', 'inner': [target]}, {'kind': 'IntegerLiteral'}]}, offset)


def inventory(*functions):
    return derive({'kind': 'TranslationUnitDecl', 'inner': list(functions)},
                  source_path='case.c', source_digest='sha256:' + '1' * 64)


def root(value, name='entry'):
    return next(f['functionIdentity'] for f in value['functions'] if f['symbol']['name'] == name)


def test_internal_helper_and_repeated_static_call_sites_are_retained():
    value = inventory(function('entry', [call('helper'), call('helper', 3)]),
                      function('helper', internal=True), function('unused', [call('missing')]))
    result = closure(value, root(value))
    assert result['staticCallTargetsResolved']
    assert len(result['reachableFunctions']) == 2 and len(result['calls']) == 2
    assert len(result['notStaticallyReachedFunctions']) == 1
    assert result['effectClosureStatus'] == result['abiClosureStatus'] == 'not_proved'
    assert result['executionStatus'] == result['independentAuditStatus'] == 'not_run'
    assert not result['semanticApproval'] and not result['productionAcceptanceComplete']


@pytest.mark.parametrize('cycle', [False, True])
def test_unresolved_external_and_recursive_calls_never_resolve(cycle):
    value = inventory(function('entry', [call('helper')]),
        function('helper', [call('entry' if cycle else 'library')], internal=True))
    result = closure(value, root(value))
    assert not result['staticCallTargetsResolved']
    assert result['unresolvedPrerequisites'][0]['reasonCode'] == (
        'M6_RECURSIVE_SUMMARY_REQUIRED' if cycle else 'M6_EXTERNAL_OR_HEADER_CALLEE_SUMMARY_REQUIRED')


def test_function_pointer_is_not_resolved_by_spelling():
    value = call('helper')
    value['inner'][0]['inner'][0]['referencedDecl']['kind'] = 'VarDecl'
    result = inventory(function('entry', [value]), function('helper'))
    assert closure(result, root(result))['unresolvedPrerequisites'][0]['reasonCode'] == 'M6_INDIRECT_CALL_TARGET_PROOF_REQUIRED'


def test_macro_offsets_do_not_masquerade_as_ordinary_sites():
    node = call('helper')
    node['range']['begin'] = {'expansionLoc': {'offset': 10}, 'spellingLoc': {'offset': 20}}
    result = inventory(function('entry', [node]), function('helper'))
    assert closure(result, root(result))['unresolvedPrerequisites'][0]['reasonCode'] == 'M6_CALL_SITE_SOURCE_RANGE_REQUIRED'


def test_unreferenced_constructor_is_a_startup_obligation():
    value = inventory(function('entry'), function('startup', attrs=['ConstructorAttr']))
    result = closure(value, root(value))
    assert not result['staticCallTargetsResolved']
    assert result['unresolvedPrerequisites'][-1]['reasonCode'] == 'M6_TRANSLATION_UNIT_STARTUP_CLOSURE_REQUIRED'


def test_inventory_identity_and_root_ambiguity_fail_closed():
    value = inventory(function('entry'))
    with pytest.raises(ValueError, match='ROOT_IDENTITY'):
        closure(value, 'entry')
    value['functions'][0]['calls'].append(call('missing'))
    with pytest.raises(ValueError, match='IDENTITY_INVALID'):
        closure(value, root(value))


def test_header_definition_is_not_implicitly_approved():
    helper = function('helper', internal=True)
    helper['loc'] = {'file': '/another/header.h', 'includedFrom': {'file': 'case.c'}}
    entry = function('entry', [call('helper')])
    entry['loc'] = {'file': str(Path('case.c').resolve())}
    value = inventory(helper, entry)
    assert len(value['functions']) == 1
    assert not closure(value, root(value))['staticCallTargetsResolved']


def test_duplicate_definition_and_bad_digest_rejected():
    with pytest.raises(ValueError, match='DEFINITION_AMBIGUOUS'):
        inventory(function('entry'), function('entry'))
    with pytest.raises(ValueError, match='SOURCE_DIGEST'):
        derive({'kind': 'TranslationUnitDecl'}, source_path='x.c', source_digest='sha256:' + 'z' * 64)


def test_real_clang_sees_static_helpers_and_forward_declarations(tmp_path):
    clang = shutil.which('clang')
    if not clang:
        pytest.skip('real clang required for compiler AST inspection')
    source = tmp_path / 'calls.c'
    source.write_text('static unsigned long helper(unsigned long);\n'
        'unsigned long entry(unsigned long x){return helper(x);}\n'
        'static unsigned long helper(unsigned long x){return x+1;}\n'
        'unsigned long unused(unsigned long x){return x;}\n')
    result = inspect_source(source, clang=clang, target='x86_64')
    value = result['inventory']
    assert len(value['functions']) == 3
    assert closure(value, root(value))['staticCallTargetsResolved']
    assert result['dependencyClosureVerified'] is False
