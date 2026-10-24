"""Explicit property-to-comparator bindings; names never select semantics.

Legacy contracts mean one whole-contract obligation per dimension. They cannot
silently certify several distinct predicates in one dimension. V7 may explicitly
bind several properties to the same whole-contract comparison. Selectors must
cover the entire comparator obligation: this version never weakens it by slicing.
"""
from collections import Counter

PROPERTY_CONTRACT_SCHEMA = 'riscv2x86.microarchitecture-experiment-contract.v7'
_COMPARATORS = {
    'access_pattern': 'logical-access-contract.v1',
    'control_flow': 'logical-control-contract.v1',
    'synchronization': 'synchronization-contract.v1',
    'performance_trend': 'platform-statistical-contract.v1',
    'side_channel_speculation': 'registered-platform-experiment.v1',
}


def comparator_obligations(contract):
    result = {}
    if contract.required_access_pattern:
        result['access_pattern'] = sorted(x.event_id for x in contract.required_access_pattern)
    if contract.required_control_flow:
        result['control_flow'] = sorted(x.event_id for x in contract.required_control_flow)
    if contract.required_sync_semantics:
        result['synchronization'] = sorted(contract.required_sync_semantics)
    metrics = contract.payload.get('statisticalExperiment', {}).get('metrics') or contract.metrics
    if metrics:
        result['performance_trend'] = sorted(
            x['metricId'] if isinstance(x, dict) else x.metric_id for x in metrics)
    specialized = contract.payload.get('specializedExperiment')
    if specialized:
        result['side_channel_speculation'] = sorted(x['metricId'] for x in specialized['metrics'])
    return result


def validate_property_bindings(contract, properties):
    obligations = comparator_obligations(contract)
    if any(x['dimension'] not in obligations for x in properties):
        raise ValueError('l3.property.comparator-unavailable')
    bindings = contract.payload.get('propertyBindings')
    if bindings is None:
        if any(n > 1 for n in Counter(x['dimension'] for x in properties).values()):
            raise ValueError('l3.property.explicit-binding-required')
        return
    if not isinstance(bindings, list):
        raise ValueError('l3.property.bindings-invalid')
    by_id = {}
    for binding in bindings:
        if not isinstance(binding, dict) or set(binding) != {
                'propertyId', 'dimension', 'unit', 'comparatorId', 'obligationIds'}:
            raise ValueError('l3.property.binding-fields-invalid')
        pid = binding['propertyId']
        if not isinstance(pid, str) or not pid or pid in by_id:
            raise ValueError('l3.property.binding-identity-invalid')
        dimension = binding['dimension']
        if (dimension not in obligations or binding['comparatorId'] != _COMPARATORS[dimension]
                or binding['obligationIds'] != obligations[dimension]):
            raise ValueError('l3.property.comparator-obligations-mismatch')
        by_id[pid] = binding
    if list(by_id) != sorted(by_id) or set(by_id) != {x['propertyId'] for x in properties}:
        raise ValueError('l3.property.binding-set-mismatch')
    for prop in properties:
        if any(by_id[prop['propertyId']][name] != prop[name] for name in ('dimension', 'unit')):
            raise ValueError('l3.property.binding-type-mismatch')
