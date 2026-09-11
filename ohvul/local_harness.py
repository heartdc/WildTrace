"""Synthetic-input local harness; never executes audited target code."""
from .verification_gate import can_request_local_verification

def evaluate_synthetic(*, workflow_state, recheck_results, synthetic_case):
    from .isolation_contract import validate_input
    validate_input(synthetic_case)
    if not isinstance(synthetic_case, dict) or not synthetic_case.get('id'):
        raise ValueError('synthetic case id required')
    ready, reason = can_request_local_verification(workflow_state=workflow_state, recheck_results=recheck_results)
    output = {'case_id': synthetic_case['id'], 'ready': ready, 'reason': reason,
              'review_required': True, 'verdict': 'undetermined', 'no_target_execution': True}
    from .isolation_contract import validate_output
    validate_output(output)
    return output

def to_record(result, recheck_results):
    from .harness_record import validate_record
    record = {'schema':'0.1','case_id':result['case_id'],'verdict':'undetermined','review_required':True,
              'reproducible':bool(recheck_results) and all(x.get('reproducible') is True for x in recheck_results)}
    validate_record(record); return record
