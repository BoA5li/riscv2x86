"""Diagnostics must not turn a name join into original L2 authority."""
import pytest
from riscv2x86_py.program_validation_obligations import l2_function_binding_diagnostic as diagnose


@pytest.mark.parametrize('count,disposition', [
    (0, 'function-record-not-found'), (1, 'one-name-match-not-a-proof'),
    (2, 'multiple-function-records'),
])
def test_missing_unique_and_multiple_records_remain_distinct(count, disposition):
    finding = {'fragment': {'enclosingFunction': 'arbitrary_owner'}}
    functions = [{'name': 'arbitrary_owner', 'id': str(i)} for i in range(count)]
    result = diagnose(finding, functions)
    assert result['nameMatchCount'] == count and result['disposition'] == disposition
    assert not result['fragmentBoundaryPresent']
    assert not result['scalarAuthorityDecisionPresent']
    assert 'authorityConsumerReady' not in result
    assert 'semanticApproval' not in result


def test_missing_name_or_malformed_table_is_not_inferred_from_function_names():
    assert diagnose({'fragment': {}}, [])['disposition'] == 'enclosing-function-name-missing'
    with pytest.raises(ValueError, match='FUNCTION_TABLE_INVALID'):
        diagnose({'fragment': {'enclosingFunction': 'owner'}}, {'owner': {}})
